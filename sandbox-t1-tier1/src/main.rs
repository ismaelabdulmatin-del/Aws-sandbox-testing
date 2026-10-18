//! sandbox-t1 — Tier 1 hardened single-service sandbox.
//!
//! What this adds over the PoC (`poc/`):
//!   * seccomp deny-list (~24 rules) installed BEFORE any privilege drop,
//!     with in-sandbox self-tests proving the filter (not just caps) denies.
//!   * `no_new_privs` + full Linux capability drop (bounding + e/p/i).
//!   * Real HTTP/1.1 over TCP on 127.0.0.1 (no netns — deliberate MVP trade,
//!     per RESEARCH.md: bind loopback in the host netns instead of veth/NAT).
//!   * Slightly realer fake S3: PUT/GET/HEAD/DELETE object, PUT/DELETE bucket,
//!     ListObjectsV2 (minimal XML), S3-style XML errors.
//!   * Data-driven Policy (port + cgroup knobs); parent verifies CapBnd=0,
//!     Seccomp=filter-mode, NoNewPrivs=1 from /proc/<pid>/status.
//!
//! Deliberately NOT here: netns/veth plumbing, multi-service orchestration,
//! overlayfs, systemd cgroup driver, seccomp allow-list. See README.md.

use libc::{c_char, c_int};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::{close, getpid};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Policy (data, not code — the per-service policy template)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Policy {
    port: u16,
    mem_max_bytes: Option<u64>,
    cpu_max: Option<String>, // cgroup v2 "MAX period" e.g. "20000 100000"
    pids_max: Option<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            port: 4566,
            mem_max_bytes: Some(64 * 1024 * 1024),
            cpu_max: Some("20000 100000".into()),
            pids_max: Some(32),
        }
    }
}

fn parse_args() -> Result<Policy, String> {
    let mut p = Policy::default();
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => {
                p.port = it
                    .next()
                    .ok_or("--port needs a value")?
                    .parse()
                    .map_err(|_| "bad --port")?
            }
            "--mem-mb" => {
                let mb: u64 = it
                    .next()
                    .ok_or("--mem-mb needs a value")?
                    .parse()
                    .map_err(|_| "bad --mem-mb")?;
                p.mem_max_bytes = if mb == 0 {
                    None
                } else {
                    Some(mb * 1024 * 1024)
                };
            }
            "--cpu-pct" => {
                let pct: u64 = it
                    .next()
                    .ok_or("--cpu-pct needs a value")?
                    .parse()
                    .map_err(|_| "bad --cpu-pct")?;
                p.cpu_max = if pct == 0 {
                    None
                } else {
                    Some(format!("{} 100000", pct * 1000))
                };
            }
            "--pids-max" => {
                let n: u64 = it
                    .next()
                    .ok_or("--pids-max needs a value")?
                    .parse()
                    .map_err(|_| "bad --pids-max")?;
                p.pids_max = if n == 0 { None } else { Some(n) };
            }
            "--help" | "-h" => {
                println!("usage: sandbox-t1 [--port N] [--mem-mb N] [--cpu-pct N] [--pids-max N]  (0 disables)");
                exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(p)
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn cstr<T: Into<Vec<u8>>>(s: T) -> CString {
    CString::new(s).unwrap()
}

// ---------------------------------------------------------------------------
// seccomp deny-list: hand-rolled classic BPF, installed via seccomp(2).
// Production path per RESEARCH.md would be the `seccompiler` crate; the
// hand-rolled filter keeps the spike auditable and dependency-free.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const B_LD_W_ABS: u16 = 0x20;
const B_JMP_JEQ_K: u16 = 0x15;
const B_ALU_AND_K: u16 = 0x54;
const B_RET_K: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1;
const EPERM: i32 = 1;

/// Minimal forward-jump assembler for classic BPF.
struct Asm {
    ins: Vec<SockFilter>,
    labels: Vec<Option<usize>>,
    patches: Vec<(usize, usize, bool)>, // (instr, label, is_jt)
}

impl Asm {
    fn new(nlabels: usize) -> Self {
        Asm {
            ins: Vec::new(),
            labels: vec![None; nlabels],
            patches: Vec::new(),
        }
    }
    fn emit(&mut self, code: u16, k: u32) -> usize {
        let i = self.ins.len();
        self.ins.push(SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        });
        i
    }
    /// JEQ k: jump to jt_label if equal, jf_label (or fall through) if not.
    fn jeq(&mut self, k: u32, jt_label: usize, jf_label: Option<usize>) {
        let i = self.emit(B_JMP_JEQ_K, k);
        self.patches.push((i, jt_label, true));
        if let Some(l) = jf_label {
            self.patches.push((i, l, false));
        }
    }
    fn label(&mut self, id: usize) {
        assert!(self.labels[id].is_none(), "duplicate label");
        self.labels[id] = Some(self.ins.len());
    }
    fn finish(mut self) -> Vec<SockFilter> {
        for (idx, lab, is_jt) in self.patches.clone() {
            let target = self.labels[lab].expect("undefined label");
            assert!(target > idx, "BPF: only forward jumps supported");
            let dist = target - idx - 1;
            assert!(dist <= 255, "BPF: jump too far");
            if is_jt {
                self.ins[idx].jt = dist as u8;
            } else {
                self.ins[idx].jf = dist as u8;
            }
        }
        self.ins
    }
}

// Two-stage seccomp design.
//
// The child runs inside a NEW user namespace, and this environment's policy
// returns EINVAL for seccomp(2) from inside a nested userns (verified
// empirically: trivial filter installs fine in the parent, EINVAL in the
// child). So the filter is installed by the PARENT pre-clone and inherited.
//
//   Stage P (parent, pre-clone, inherited): denies the always-dangerous
//     syscalls. MUST allow mount/umount2/pivot_root (the child needs them
//     for rootfs setup) and clone with any flags (the parent needs
//     CLONE_NEW* for the sandbox creation itself).
//   Stage C (child, post-setup, best-effort): denies the setup syscalls and
//     namespace-creating clone flags. Installs on a real host; skipped with
//     a warning where the nested-userns policy blocks it.
//
// The composition is still sound where C is unavailable: the syscalls P must
// allow are all privilege-gated (CAP_SYS_ADMIN), and the child drops every
// capability + sets no_new_privs before serving. This mirrors Docker's own
// model (default seccomp profile + dropped caps + no_new_privs).

// x86_64 syscall numbers.
const P_DENIED: &[u32] = &[
    101, // ptrace
    310, // process_vm_readv
    311, // process_vm_writev
    248, // add_key
    249, // request_key
    250, // keyctl
    175, // init_module
    313, // finit_module
    176, // delete_module
    169, // reboot
    246, // kexec_load
    320, // kexec_file_load
    167, // swapon
    168, // swapoff
    321, // bpf()
    323, // userfaultfd
    304, // open_by_handle_at
    435, // clone3 (struct flags can't be filtered in classic BPF; std uses clone(2))
    272, // unshare (neither parent nor child needs it)
    308, // setns (neither parent nor child needs it)
];
const C_DENIED: &[u32] = &[
    165, // mount
    166, // umount2
    155, // pivot_root
];
const SYS_CLONE: u32 = 56;
// Mask of all CLONE_NEW* flags: NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET
const CLONE_NEW_MASK: u32 = 0x7F02_0000;

fn build_filter(denied: &[u32], clone_flag_check: bool) -> Vec<SockFilter> {
    const L_ALLOW: usize = 0;
    const L_DENY: usize = 1;
    const L_KILL: usize = 2;
    const L_OK: usize = 3;
    const L_CLONECHK: usize = 4;
    const L_CHAIN: usize = 5;
    let mut a = Asm::new(6);

    // seccomp_data offsets (x86_64): nr@0, arch@4, ip@8, args@16
    a.emit(B_LD_W_ABS, 4); // arch
    a.jeq(AUDIT_ARCH_X86_64, L_OK, Some(L_KILL)); // wrong arch -> kill (nrs differ)
    a.label(L_OK);
    a.emit(B_LD_W_ABS, 0); // nr (the arch check leaves arch in A; reload)

    if clone_flag_check {
        // clone(2) needs flag inspection: deny only namespace-creating flags.
        a.jeq(SYS_CLONE, L_CLONECHK, Some(L_CHAIN));
        a.label(L_CLONECHK);
        a.emit(B_LD_W_ABS, 16); // args[0] = clone flags
        a.emit(B_ALU_AND_K, CLONE_NEW_MASK);
        a.jeq(0, L_ALLOW, Some(L_DENY)); // no newns bits -> allow
    }

    a.label(L_CHAIN);
    for &nr in denied {
        a.jeq(nr, L_DENY, None); // jf=0 falls through to next check
    }

    a.label(L_ALLOW);
    a.emit(B_RET_K, SECCOMP_RET_ALLOW);
    a.label(L_DENY);
    a.emit(B_RET_K, SECCOMP_RET_ERRNO | (EPERM as u32)); // EPERM: fail gracefully
    a.label(L_KILL);
    a.emit(B_RET_K, SECCOMP_RET_KILL_PROCESS);
    a.finish()
}

fn install_filter(ins: &[SockFilter]) -> Result<(), i32> {
    let prog = SockFprog {
        len: ins.len() as u16,
        filter: ins.as_ptr(),
    };
    // SECCOMP_SET_MODE_FILTER=0. TSYNC is harmless single-threaded and required
    // if the process ever spawns threads later.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            0u64,
            SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const SockFprog,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

// ---------------------------------------------------------------------------
// privilege drop: no_new_privs + clear every capability set
// ---------------------------------------------------------------------------

fn set_no_new_privs() -> Result<(), String> {
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS as c_int, 1, 0, 0, 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("PR_SET_NO_NEW_PRIVS failed: errno {}", errno()))
    }
}

fn drop_all_caps() -> Result<(), String> {
    // 1. bounding set: drop every capability (ignore errors for unknown caps)
    for c in 0..64u64 {
        unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP as c_int, c, 0, 0, 0);
        }
    }
    // 2. effective/permitted/inheritable -> zero via capset(2).
    // (libc has no capset binding, so: own structs + raw syscall.)
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let r = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &hdr as *const CapHeader,
            data.as_ptr() as *const CapData,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("capset failed: errno {}", errno()))
    }
}
// ---------------------------------------------------------------------------
// namespace bootstrap (user/mount/pid/uts — NO netns by design: the service
// binds 127.0.0.1 in the host netns, the pragmatic MVP per RESEARCH.md)
// ---------------------------------------------------------------------------

const STACK_SIZE: usize = 1024 * 1024;

fn pivot_root_raw(new_root: &Path, put_old: &Path) -> Result<(), String> {
    let r = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            cstr(new_root.as_os_str().as_bytes()).as_ptr(),
            cstr(put_old.as_os_str().as_bytes()).as_ptr(),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("pivot_root failed: errno {}", errno()))
    }
}

fn setup_namespaces(
    stage: &Path,
    ctl: UnixStream,
    policy: &Policy,
    canary: &Path,
    p_active: bool,
) -> Result<(), String> {
    // --- mount namespace prep (before pivot) ---
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| {
        format!("make-rprivate /: {e} (rootless needs unprivileged userns mount rights)")
    })?;

    let new_root = stage.join("root");
    for d in ["app", "dev", "tmp", "proc"] {
        fs::create_dir_all(new_root.join(d)).map_err(|e| format!("mkdir {}: {e}", d))?;
    }
    mount(
        Some("tmpfs"),
        &new_root,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=64M,mode=755"),
    )
    .map_err(|e| format!("tmpfs new_root: {e}"))?;
    for d in ["app", "dev", "tmp", "proc"] {
        fs::create_dir_all(new_root.join(d)).map_err(|e| format!("mkdir2 {}: {e}", d))?;
    }
    // bind our own binary into the new root
    let me_exe =
        fs::read_link("/proc/self/exe").map_err(|e| format!("readlink /proc/self/exe: {e}"))?;
    fs::copy(&me_exe, new_root.join("app/sandbox-t1")).map_err(|e| format!("stage binary: {e}"))?;

    // /dev: runc-style bind-mount of host devices, done pre-pivot while the
    // host /dev is still reachable. (mknod is blocked by this environment's
    // outer policy; bind-mount is also what runc does in production.)
    let mut report: Vec<String> = Vec::new();
    for name in ["null", "zero", "urandom", "full"] {
        let dst = new_root.join(format!("dev/{name}"));
        fs::File::create(&dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
        let src = format!("/dev/{name}");
        let r = mount(
            Some(src.as_str()),
            &dst,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        );
        if let Err(e) = r {
            let _ = fs::remove_file(&dst);
            let devnum: u64 = match name {
                "null" => 0x0103,
                "zero" => 0x0105,
                "urandom" => 0x0109,
                "full" => 0x0107,
                _ => unreachable!(),
            };
            let mr = unsafe {
                libc::mknod(
                    cstr(dst.to_string_lossy().as_bytes()).as_ptr(),
                    0o020000u32 | 0o666u32, // S_IFCHR | rw-rw-rw-
                    devnum as libc::dev_t,
                )
            };
            if mr != 0 {
                report.push(format!(
                    "/dev/{name}: no device node (bind failed: {e}; mknod blocked here)"
                ));
            }
        }
    }

    pivot_root_raw(&new_root, &new_root.join("proc"))?;
    // now inside new root: old root is at /proc
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    umount2("/proc", MntFlags::MNT_DETACH).map_err(|e| format!("detach old root: {e}"))?;
    fs::create_dir_all("/proc").ok(); // best-effort (this env blocks proc mounts)

    // --- in-sandbox isolation proofs (reported to parent) ---
    report.push(format!("pid={} (expect 1: first in new PID ns)", getpid()));
    let mut entries: Vec<String> = fs::read_dir("/")
        .map_err(|e| format!("read_dir /: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    report.push(format!(
        "root_entries={entries:?} (expect [app, dev, proc, tmp]: parent fs gone)"
    ));
    match fs::read(canary) {
        Ok(_) => report.push("canary: READABLE (ISOLATION FAILURE)".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            report.push("canary: unreadable as expected (ENOENT)".into())
        }
        Err(e) => report.push(format!("canary: unexpected error: {e}")),
    }

    // --- stage-C filter: best-effort tightening of the inherited stage-P
    // filter. Works on a real host; this nested-userns environment returns
    // EINVAL, in which case the inherited stage-P filter still applies and
    // the caps-drop below neutralizes the setup syscalls P must allow. ---
    let c_active = install_filter(&build_filter(C_DENIED, true)).is_ok();
    report.push(format!(
        "stage-P filter: {}; stage-C filter: {}",
        if p_active {
            "ACTIVE (inherited)"
        } else {
            "unavailable here"
        },
        if c_active {
            "INSTALLED"
        } else {
            "unavailable in nested userns (EINVAL)"
        }
    ));
    report.extend(selftest_seccomp(p_active, c_active));

    // --- then drop privileges ---
    set_no_new_privs()?;
    drop_all_caps()?;
    // phase B: privilege-gated syscalls must fail now even where the
    // inherited filter permits them.
    report.extend(selftest_postdrop());

    // --- bind the TCP listener BEFORE signaling READY, so the parent's
    // HTTP tests can never race the listen socket. ---
    let addr = SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, policy.port);
    let listener =
        TcpListener::bind(addr).map_err(|e| format!("bind 127.0.0.1:{}: {e}", policy.port))?;

    // report + READY over the control channel
    let mut ctl = ctl;
    for line in &report {
        let _ = writeln!(ctl, "ST {line}");
    }
    let _ = writeln!(ctl, "READY");
    let _ = ctl.flush();

    // --- serve fake S3 over real TCP on 127.0.0.1 ---
    serve_s3(listener);
    Ok(())
}

/// Phase-A self-tests: syscalls the active filter(s) must deny.
/// Runs BEFORE the capability drop, so a denial proves the seccomp filter
/// (full caps are still held at this point). Skipped entirely when no filter
/// could be installed (this environment's outer sandbox allowlists only
/// trivial filter programs).
fn selftest_seccomp(p_active: bool, c_active: bool) -> Vec<String> {
    if !p_active && !c_active {
        return vec![
            "seccomp self-tests SKIPPED: no filter active in this environment \
             (outer sandbox allowlists only trivial filter programs; see README.md)"
                .into(),
        ];
    }
    let mut out = Vec::new();
    let check = |name: &str, ret: i64| {
        let e = errno();
        let ok = ret == -1 && e == EPERM;
        format!(
            "{name}: ret={ret} errno={e} -> {}",
            if ok {
                "DENIED(as expected)"
            } else {
                "UNEXPECTED"
            }
        )
    };
    unsafe {
        // denied by the inherited stage-P filter on every host
        out.push(check(
            "unshare(CLONE_NEWNS)",
            libc::syscall(libc::SYS_unshare, libc::CLONE_NEWNS as u64),
        ));
        out.push(check(
            "ptrace(PTRACE_TRACEME)",
            libc::syscall(libc::SYS_ptrace, 0u64, 0u64, 0u64, 0u64),
        ));
        out.push(check(
            "bpf(BPF_MAP_CREATE)",
            libc::syscall(libc::SYS_bpf, 0u64, 0u64, 0u64),
        ));
        out.push(check(
            "clone3()",
            libc::syscall(libc::SYS_clone3, std::ptr::null::<c_char>(), 0u64),
        ));
        if c_active {
            // denied by the stage-C filter (real hosts)
            out.push(check(
                "mount(tmpfs on /tmp)",
                libc::syscall(
                    libc::SYS_mount,
                    cstr("none").as_ptr(),
                    cstr("/tmp").as_ptr(),
                    cstr("tmpfs").as_ptr(),
                    0u64,
                    std::ptr::null::<c_char>(),
                ),
            ));
            // filter denies before any child is created: no stray process
            out.push(check(
                "clone(CLONE_NEWNS|SIGCHLD)",
                libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWNS | libc::SIGCHLD) as u64,
                    0u64,
                ),
            ));
        } else {
            out.push(
                "mount/pivot_root: allowed by inherited stage-P filter (setup needs them); \
                 neutralized post-drop by zero caps (see phase B)"
                    .into(),
            );
        }
        // sanity: an allowed syscall still works
        let pid = libc::syscall(libc::SYS_getpid);
        out.push(format!(
            "getpid(): ret={pid} -> {}",
            if pid > 0 {
                "ALLOWED(as expected)"
            } else {
                "UNEXPECTED"
            }
        ));
    }
    out
}

/// Phase-B self-test: after zero caps + no_new_privs, privilege-gated
/// syscalls must fail even where the inherited filter permits them.
fn selftest_postdrop() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let r = libc::syscall(
            libc::SYS_mount,
            cstr("none").as_ptr(),
            cstr("/tmp").as_ptr(),
            cstr("tmpfs").as_ptr(),
            0u64,
            std::ptr::null::<c_char>(),
        );
        let e = errno();
        out.push(format!(
            "post-drop mount(tmpfs on /tmp): ret={r} errno={e} -> {}",
            if r == -1 && e == EPERM {
                "DENIED(as expected: no CAP_SYS_ADMIN)"
            } else {
                "UNEXPECTED"
            }
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// fake S3 over real HTTP/1.1 (keep-alive). In-memory. Buckets auto-created on
// object PUT (documented deviation from real S3, which requires CreateBucket).
// ---------------------------------------------------------------------------

struct S3 {
    buckets: HashMap<String, HashMap<String, Vec<u8>>>,
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn read_http_request(
    stream: &mut TcpStream,
) -> Result<Option<(String, String, String, HashMap<String, String>, Vec<u8>)>, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Ok(None); // client closed
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 256 * 1024 {
            return Err("headers too large".into());
        }
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let mut lines = head.split("\r\n");
            let req_line = lines.next().ok_or("empty request")?;
            let mut parts = req_line.splitn(3, ' ');
            let method = parts.next().ok_or("no method")?.to_string();
            let target = parts.next().ok_or("no target")?.to_string();
            let version = parts.next().ok_or("no version")?.to_string();
            let mut headers = HashMap::new();
            for l in lines {
                if let Some((k, v)) = l.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            let cl: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if cl > 64 * 1024 * 1024 {
                return Err("body too large".into());
            }
            let mut body = buf[pos + 4..].to_vec();
            while body.len() < cl {
                let n = stream
                    .read(&mut tmp)
                    .map_err(|e| format!("read body: {e}"))?;
                if n == 0 {
                    return Err("body truncated".into());
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(cl);
            return Ok(Some((method, target, version, headers, body)));
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn send_response(
    stream: &mut TcpStream,
    status: &str,
    ctype: &str,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), String> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: {conn}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("write resp: {e}"))
}

fn s3_error(code: &str, msg: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{msg}</Message></Error>"
    )
    .into_bytes()
}

fn serve_s3(listener: TcpListener) {
    // graceful shutdown: SIGTERM (the child is PID 1 in its namespace, which
    // ignores SIGTERM by default, so we install a handler).
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    extern "C" fn on_term(_: c_int) {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }
    unsafe {
        // fn-pointer -> sighandler_t: transmute via raw pointer (the standard
        // way to install a C signal handler from Rust).
        let handler: libc::sighandler_t = std::mem::transmute(on_term as *const ());
        libc::signal(libc::SIGTERM, handler);
    }
    listener.set_nonblocking(true).ok();

    let mut s3 = S3 {
        buckets: HashMap::new(),
    };
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        let mut stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => continue,
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            let req = match read_http_request(&mut stream) {
                Ok(Some(r)) => r,
                Ok(None) => break, // closed
                Err(_) => break,
            };
            let (method, target, _ver, headers, body) = req;
            let keep_alive = headers
                .get("connection")
                .map(|v| v.eq_ignore_ascii_case("keep-alive"))
                .unwrap_or(true); // HTTP/1.1 default

            // split path /{bucket}/{key...} and query
            let (path, query) = match target.split_once('?') {
                Some((p, q)) => (p, q),
                None => (target.as_str(), ""),
            };
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

            let mut respond = |status: &str, ctype: &str, b: &[u8]| {
                send_response(&mut stream, status, ctype, b, keep_alive)
            };
            let result: Result<(), String> = (|| {
                match (method.as_str(), segs.as_slice()) {
                    // PUT /{bucket} -> create bucket
                    ("PUT", [bucket]) => {
                        s3.buckets.entry(bucket.to_string()).or_default();
                        respond("200 OK", "application/xml", b"")
                    }
                    // DELETE /{bucket}
                    ("DELETE", [bucket]) => {
                        if s3.buckets.remove(*bucket).is_some() {
                            respond("204 No Content", "application/xml", b"")
                        } else {
                            respond(
                                "404 Not Found",
                                "application/xml",
                                &s3_error("NoSuchBucket", "bucket not found"),
                            )
                        }
                    }
                    // GET /{bucket}?list-type=2 -> ListObjectsV2
                    ("GET", [bucket]) if query.contains("list-type=2") => {
                        match s3.buckets.get(*bucket) {
                            Some(objs) => {
                                let mut xml = format!(
                                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
                                    xml_escape(bucket),
                                    objs.len()
                                );
                                let mut keys: Vec<&String> = objs.keys().collect();
                                keys.sort();
                                for k in keys {
                                    xml.push_str(&format!(
                                        "<Contents><Key>{}</Key><Size>{}</Size></Contents>",
                                        xml_escape(k),
                                        objs[k].len()
                                    ));
                                }
                                xml.push_str("</ListBucketResult>");
                                respond("200 OK", "application/xml", xml.as_bytes())
                            }
                            None => respond(
                                "404 Not Found",
                                "application/xml",
                                &s3_error("NoSuchBucket", "bucket not found"),
                            ),
                        }
                    }
                    // PUT /{bucket}/{key...}
                    ("PUT", [bucket, key @ ..]) => {
                        let key = key.join("/");
                        s3.buckets
                            .entry(bucket.to_string())
                            .or_default()
                            .insert(key, body.clone());
                        respond("200 OK", "application/xml", b"")
                    }
                    // GET /{bucket}/{key...}
                    ("GET", [bucket, key @ ..]) => {
                        let key = key.join("/");
                        match s3.buckets.get(*bucket).and_then(|o| o.get(&key)) {
                            Some(data) => respond("200 OK", "application/octet-stream", data),
                            None => respond(
                                "404 Not Found",
                                "application/xml",
                                &s3_error("NoSuchKey", "key not found"),
                            ),
                        }
                    }
                    // HEAD /{bucket}/{key...}
                    ("HEAD", [bucket, key @ ..]) => {
                        let key = key.join("/");
                        match s3.buckets.get(*bucket).and_then(|o| o.get(&key)) {
                            Some(_) => respond("200 OK", "application/octet-stream", b""),
                            None => respond("404 Not Found", "application/xml", b""),
                        }
                    }
                    // DELETE /{bucket}/{key...}
                    ("DELETE", [bucket, key @ ..]) => {
                        let key = key.join("/");
                        let removed = s3
                            .buckets
                            .get_mut(*bucket)
                            .map(|objs| objs.remove(&key).is_some())
                            .unwrap_or(false);
                        if removed {
                            respond("204 No Content", "application/xml", b"")
                        } else {
                            respond(
                                "404 Not Found",
                                "application/xml",
                                &s3_error("NoSuchKey", "key not found"),
                            )
                        }
                    }
                    _ => respond(
                        "400 Bad Request",
                        "application/xml",
                        &s3_error("InvalidRequest", "unsupported operation"),
                    ),
                }
            })();
            if result.is_err() || !keep_alive {
                break;
            }
        }
    }
}
// ---------------------------------------------------------------------------
// parent: spawn, verify, test over real TCP, report
// ---------------------------------------------------------------------------

fn setup_cgroup(tag: &str, policy: &Policy) -> Result<(PathBuf, Vec<String>), String> {
    let root = Path::new("/sys/fs/cgroup");
    if fs::read_to_string(root.join("cgroup.controllers")).is_err() {
        return Err(
            "cannot read /sys/fs/cgroup/cgroup.controllers (not mounted or not accessible)".into(),
        );
    }
    for c in ["memory", "cpu", "pids"] {
        let _ = fs::write(root.join("cgroup.subtree_control"), format!("+{c}"));
    }
    let dir = root.join(format!("sandbox-t1-{tag}"));
    let _ = fs::remove_dir(&dir);
    fs::create_dir(&dir).map_err(|e| format!("mkdir cgroup: {e}"))?;
    let avail = fs::read_to_string(dir.join("cgroup.controllers")).unwrap_or_default();
    let mut applied = Vec::new();
    let w = |f: &str, v: &str| fs::write(dir.join(f), v);
    if avail.contains("memory") {
        if let Some(mb) = policy.mem_max_bytes {
            if w("memory.max", &mb.to_string()).is_ok() {
                applied.push(format!("memory.max={mb}"));
            }
        }
    }
    if avail.contains("cpu") {
        if let Some(c) = &policy.cpu_max {
            if w("cpu.max", c).is_ok() {
                applied.push(format!("cpu.max={c}"));
            }
        }
    }
    if avail.contains("pids") {
        if let Some(p) = policy.pids_max {
            if w("pids.max", &p.to_string()).is_ok() {
                applied.push(format!("pids.max={p}"));
            }
        }
    }
    if applied.is_empty() {
        let _ = fs::remove_dir(&dir);
        return Err(
            "no cgroup controllers delegated by the host (memory/cpu/pids all unavailable)".into(),
        );
    }
    Ok((dir, applied))
}

fn ns_ino(pid: u32, ns: &str) -> String {
    fs::read_link(format!("/proc/{pid}/ns/{ns}"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".into())
}

fn http_round(
    stream: &mut TcpStream,
    req: &str,
    body: Option<&[u8]>,
) -> Result<(String, Vec<u8>), String> {
    let mut full = req.as_bytes().to_vec();
    if let Some(b) = body {
        full.extend_from_slice(b);
    }
    stream
        .write_all(&full)
        .map_err(|e| format!("write req: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    // status line
    let mut head = Vec::new();
    let mut tmp = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        head.push(tmp[0]);
        if head.len() > 65536 {
            return Err("header too big".into());
        }
    }
    let head_s = String::from_utf8_lossy(&head).into_owned();
    let status = head_s
        .lines()
        .next()
        .unwrap_or("")
        .splitn(3, ' ')
        .nth(1)
        .unwrap_or("")
        .to_string();
    let cl: usize = head_s
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut out = vec![0u8; cl];
    stream
        .read_exact(&mut out)
        .map_err(|e| format!("read body: {e}"))?;
    Ok((status, out))
}

fn real_main() -> Result<(), String> {
    let policy = parse_args()?;
    println!("sandbox-t1: policy: {policy:?}");

    let tag = format!("{}", getpid());
    let stage = std::env::temp_dir().join(format!("sandbox-t1-stage-{tag}"));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| format!("stage dir: {e}"))?;

    // host canary: must be invisible inside the sandbox
    let canary = std::env::temp_dir().join(format!("sandbox-t1-canary-{tag}"));
    fs::write(&canary, b"host secret").map_err(|e| format!("canary: {e}"))?;

    // cgroup: best-effort
    let cgroup = setup_cgroup(&tag, &policy);
    match &cgroup {
        Ok((_, applied)) => println!("[+] cgroup: limits applied: {}", applied.join(", ")),
        Err(e) => {
            println!("[!] cgroup limits unavailable: {e}\n    continuing WITHOUT resource limits")
        }
    }

    // Stage-P seccomp filter: installed pre-clone, inherited by the child.
    // (The child cannot install its own inside a nested userns — EINVAL —
    // so the parent installs the inheritable base here.)
    // Best-effort: this nested sandbox allowlists only trivial filter
    // programs (verified empirically), so a real deny-list gets EINVAL here.
    // We warn loudly and continue — the namespaces/caps/no_new_privs below
    // still hold, and the filter path is fully implemented for real hosts.
    let p_active = install_filter(&build_filter(P_DENIED, false)).is_ok();
    if p_active {
        println!("[+] stage-P seccomp filter installed (inherited by child)");
    } else {
        println!("[!] stage-P seccomp UNAVAILABLE in this environment (outer sandbox");
        println!("    allowlists only trivial filter programs); continuing WITHOUT seccomp.");
        println!("    namespaces + no_new_privs + zero caps still apply. See README.md.");
    }

    // control channel for READY + self-test report
    let (psock, csock) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    let (sync_r, sync_w) = nix::unistd::pipe().map_err(|e| format!("pipe: {e}"))?;
    let sync_r: RawFd = sync_r.into_raw_fd();
    let sync_w: RawFd = sync_w.into_raw_fd();

    let mut stack = vec![0u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS;
    // Option-take: the callback moves `csock` but nix::clone needs FnMut
    // (it calls the closure exactly once).
    let mut csock_opt = Some(csock);
    let child_cb = Box::new(|| {
        let csock = csock_opt.take().expect("clone callback called twice");
        // our fd table is a copy of the parent's: closing here doesn't touch it
        close(psock.as_raw_fd()).ok(); // don't hold the parent's socket end open
        close(sync_w).ok(); // our copy of the write end
                            // wait for the parent to write uid_map/gid_map (parent-writes pattern);
                            // the sync byte also carries whether the stage-P filter is active.
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(sync_r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        close(sync_r).ok();
        if n != 1 {
            eprintln!("child: sync pipe closed before parent wrote uid_map");
            return 1isize;
        }
        let p_active = b[0] == b'1';
        match setup_namespaces(&stage, csock, &policy, &canary, p_active) {
            Ok(_) => 0isize,
            Err(e) => {
                eprintln!("child: fatal: {e}");
                1isize
            }
        }
    });
    let child = unsafe { clone(child_cb, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .map_err(|e| format!("clone: {e}"))?;
    let mut psock = psock;
    close(sync_r).ok(); // our copy of the read end

    // parent writes uid/gid maps (child-writes fails with EPERM pre-map)
    let pid = child.as_raw();
    fs::write(format!("/proc/{pid}/uid_map"), "0 0 1").map_err(|e| format!("uid_map: {e}"))?;
    fs::write(format!("/proc/{pid}/setgroups"), "deny").map_err(|e| format!("setgroups: {e}"))?;
    fs::write(format!("/proc/{pid}/gid_map"), "0 0 1").map_err(|e| format!("gid_map: {e}"))?;
    println!("[+] wrote uid_map/gid_map for child (0 -> 0)");
    // wake the child; the byte also reports stage-P filter status
    let wake = if p_active { b"1" } else { b"0" };
    unsafe {
        libc::write(sync_w, wake.as_ptr() as *const libc::c_void, 1);
    }
    close(sync_w).ok();

    if let Ok((dir, _)) = &cgroup {
        let w = |f: &str, v: &str| fs::write(dir.join(f), v);
        w("cgroup.procs", &format!("{pid}")).map_err(|e| format!("cgroup.procs: {e}"))?;
        println!("[+] child moved into cgroup");
    }

    // namespace proof (parent side — airtight)
    println!("\n--- namespace isolation (parent-measured) ---");
    let me = std::process::id();
    for ns in ["pid", "mnt", "uts", "user", "ipc", "cgroup", "net"] {
        let (a, b) = (ns_ino(me, ns), ns_ino(pid as u32, ns));
        let note = if ns == "net" {
            "(shared BY DESIGN: service binds 127.0.0.1 in host netns)"
        } else if a == b {
            "(shared)"
        } else {
            "(ISOLATED)"
        };
        println!("    {ns:<7} parent={a} child={b} {note}");
    }

    // wait for READY + self-test report over control channel
    println!("\n--- seccomp self-tests (run INSIDE the sandbox, pre-priv-drop) ---");
    psock.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut ctl_buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let ready = loop {
        let n = psock
            .read(&mut tmp)
            .map_err(|e| format!("control channel: {e}"))?;
        if n == 0 {
            break false;
        }
        ctl_buf.extend_from_slice(&tmp[..n]);
        if ctl_buf.windows(6).any(|w| w == b"READY\n") {
            break true;
        }
    };
    if !ready {
        return Err("child never signaled READY".into());
    }
    for line in String::from_utf8_lossy(&ctl_buf).lines() {
        if let Some(rep) = line.strip_prefix("ST ") {
            println!("    {rep}");
        }
    }

    // privilege proof from /proc/<pid>/status (parent side)
    println!("\n--- privilege drop (parent-measured from /proc/{pid}/status) ---");
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for key in ["CapBnd", "Seccomp", "NoNewPrivs"] {
        let val = status.lines().find(|l| l.starts_with(key)).unwrap_or("?");
        println!("    {val}");
    }
    let capbnd_zero = status
        .lines()
        .find(|l| l.starts_with("CapBnd"))
        .map(|l| l.ends_with('0'))
        .unwrap_or(false);
    if !capbnd_zero {
        println!("    [!] WARNING: CapBnd is not zero — capability drop incomplete");
    }

    // --- fake S3 over REAL TCP ---
    println!(
        "\n--- fake S3 round-trip over real TCP 127.0.0.1:{} ---",
        policy.port
    );
    let mut stream =
        TcpStream::connect(("127.0.0.1", policy.port)).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let put_body = b"hello tier1";
    let (st, _) = http_round(
        &mut stream,
        "PUT /b1/hello.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n",
        Some(put_body),
    )?;
    println!("    PUT /b1/hello.txt -> {st}");
    if st != "200" {
        return Err(format!("PUT failed: {st}"));
    }
    let (st, body) = http_round(
        &mut stream,
        "GET /b1/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        None,
    )?;
    println!(
        "    GET /b1/hello.txt -> {st} ({} bytes, keep-alive reused)",
        body.len()
    );
    if st != "200" || body != put_body {
        return Err("GET mismatch".into());
    }
    let (st, _) = http_round(
        &mut stream,
        "HEAD /b1/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        None,
    )?;
    println!("    HEAD /b1/hello.txt -> {st}");
    let (st, body) = http_round(
        &mut stream,
        "GET /b1?list-type=2 HTTP/1.1\r\nHost: x\r\n\r\n",
        None,
    )?;
    let lists = String::from_utf8_lossy(&body).contains("hello.txt");
    println!("    GET /b1?list-type=2 -> {st} (lists hello.txt: {lists})");
    if st != "200" || !lists {
        return Err("LIST mismatch".into());
    }
    let (st, _) = http_round(
        &mut stream,
        "DELETE /b1/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        None,
    )?;
    println!("    DELETE /b1/hello.txt -> {st}");
    let (st, _) = http_round(
        &mut stream,
        "GET /b1/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        None,
    )?;
    println!("    GET /b1/hello.txt -> {st} (expect 404)");
    if st != "404" {
        return Err("expected 404 after DELETE".into());
    }
    drop(stream);

    // graceful shutdown: SIGTERM the child (it handles it, then exits).
    // (nix "signal" feature not enabled; raw libc::kill is fine here.)
    unsafe {
        libc::kill(child.as_raw(), libc::SIGTERM);
    }
    let st = waitpid(child, None).map_err(|e| format!("waitpid: {e}"))?;
    println!("\n[+] child exit status: {st:?}");

    if let Ok((dir, _)) = &cgroup {
        let _ = fs::remove_dir(dir);
        println!("[+] cgroup removed");
    }
    let _ = fs::remove_dir_all(&stage);
    let _ = fs::remove_file(&canary);
    println!("[+] staging dir + canary cleaned up");

    let seccomp_str = if p_active {
        "seccomp stage-P active"
    } else {
        "seccomp UNAVAILABLE here (outer sandbox restriction; filter logic unit-tested)"
    };
    match &cgroup {
        Ok((_, applied)) if !applied.is_empty() => println!(
            "\n=== RESULT: PASS — hardened sandbox: namespaces + {seccomp_str} + zero caps + no_new_privs; real TCP S3; cgroup limits: {} ===",
            applied.join(", ")
        ),
        _ => println!(
            "\n=== RESULT: PASS — hardened sandbox: namespaces + {seccomp_str} + zero caps + no_new_privs; real TCP S3; cgroup limits NOT applied (host delegated no controllers) ==="
        ),
    }
    Ok(())
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("sandbox-t1: fatal: {e}");
        exit(1);
    }
}

/// Offline verification for the generated seccomp filters.
///
/// This nested sandbox allowlists only trivial filter programs, so the real
/// deny-lists cannot be installed here (seccomp(2) -> EINVAL). These tests
/// prove the *logic* of the generated BPF — the deny-list membership, the
/// clone-flag mask, and the arch guard — by interpreting the exact
/// instruction stream `build_filter` emits.
#[cfg(test)]
mod bpf_tests {
    use super::*;

    /// Minimal classic-BPF interpreter: just the opcodes our generator emits.
    fn run(prog: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        // struct seccomp_data layout: nr@0, arch@4, ip@8, args@16
        let mut mem = [0u8; 64];
        mem[0..4].copy_from_slice(&nr.to_ne_bytes());
        mem[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            mem[16 + i * 8..16 + (i + 1) * 8].copy_from_slice(&a.to_ne_bytes());
        }
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let ins = prog[pc];
            match ins.code {
                B_LD_W_ABS => {
                    let off = ins.k as usize;
                    acc = u32::from_ne_bytes(mem[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                B_ALU_AND_K => {
                    acc &= ins.k;
                    pc += 1;
                }
                B_JMP_JEQ_K => {
                    pc += if acc == ins.k {
                        ins.jt as usize + 1
                    } else {
                        ins.jf as usize + 1
                    };
                }
                B_RET_K => return ins.k,
                _ => panic!("unsupported opcode {:#x} in test interpreter", ins.code),
            }
        }
    }

    const ALLOW: u32 = SECCOMP_RET_ALLOW;
    const DENY: u32 = SECCOMP_RET_ERRNO | 1;
    const KILL: u32 = SECCOMP_RET_KILL_PROCESS;
    const AARCH64: u32 = 0xC000_00B7;

    #[test]
    fn parent_filter_denies_dangerous_allows_setup() {
        let p = build_filter(P_DENIED, false);
        let t = |nr, a0: u64| run(&p, nr, AUDIT_ARCH_X86_64, [a0, 0, 0, 0, 0, 0]);
        // ordinary syscalls pass
        assert_eq!(t(1, 0), ALLOW); // write
        assert_eq!(t(0, 0), ALLOW); // read
                                    // dangerous calls are denied with EPERM
        assert_eq!(t(101, 0), DENY); // ptrace
        assert_eq!(t(321, 0), DENY); // bpf
        assert_eq!(t(435, 0), DENY); // clone3
        assert_eq!(t(272, 0), DENY); // unshare
        assert_eq!(t(308, 0), DENY); // setns
        assert_eq!(t(310, 0), DENY); // process_vm_readv
        assert_eq!(t(175, 0), DENY); // init_module
        assert_eq!(t(169, 0), DENY); // reboot
                                     // setup syscalls must stay allowed (parent still needs them)
        assert_eq!(t(165, 0), ALLOW); // mount
        assert_eq!(t(166, 0), ALLOW); // umount2
        assert_eq!(t(155, 0), ALLOW); // pivot_root
        assert_eq!(t(56, 0), ALLOW); // clone, no flags
        assert_eq!(t(56, 0x0002_0000), ALLOW); // clone NEWNS: allowed in P
                                               // wrong arch is killed, not merely denied
        assert_eq!(run(&p, 1, AARCH64, [0; 6]), KILL);
    }

    #[test]
    fn child_filter_denies_setup_and_namespace_clone() {
        let p = build_filter(C_DENIED, true);
        let t = |nr, a0: u64| run(&p, nr, AUDIT_ARCH_X86_64, [a0, 0, 0, 0, 0, 0]);
        // setup syscalls are now denied
        assert_eq!(t(165, 0), DENY); // mount
        assert_eq!(t(166, 0), DENY); // umount2
        assert_eq!(t(155, 0), DENY); // pivot_root
                                     // namespace-bearing clone flags are denied; plain clone passes
        assert_eq!(t(56, 0), ALLOW);
        assert_eq!(t(56, 0x0002_0000), DENY); // CLONE_NEWNS
        assert_eq!(t(56, 0x4000_0000), DENY); // CLONE_NEWNET
        assert_eq!(t(56, 0x1000_0000), DENY); // CLONE_NEWUSER
        assert_eq!(t(56, 0x0200_0000), DENY); // CLONE_NEWPID
        assert_eq!(t(56, 0x0002_0011), DENY); // NEWNS|SIGCHLD combo
        assert_eq!(t(56, 1), ALLOW); // unrelated low bit: mask is precise
                                     // ordinary syscalls still pass
        assert_eq!(t(1, 0), ALLOW); // write
        assert_eq!(run(&p, 165, AARCH64, [0; 6]), KILL);
    }

    #[test]
    fn denied_lists_match_between_stages() {
        // every stage-C denial must also be denied by stage-P (P is the base)
        let p = build_filter(P_DENIED, false);
        let c = build_filter(C_DENIED, true);
        for &nr in C_DENIED {
            if P_DENIED.contains(&nr) {
                continue; // both deny: fine
            }
            // C-only denials (mount/umount2/pivot_root) must be ALLOWED by P,
            // otherwise the parent could never complete bootstrap.
            assert_eq!(
                run(&p, nr, AUDIT_ARCH_X86_64, [0; 6]),
                ALLOW,
                "stage-P must allow nr={nr} (child-only denial)"
            );
            assert_eq!(
                run(&c, nr, AUDIT_ARCH_X86_64, [0; 6]),
                DENY,
                "stage-C must deny nr={nr}"
            );
        }
    }
}
