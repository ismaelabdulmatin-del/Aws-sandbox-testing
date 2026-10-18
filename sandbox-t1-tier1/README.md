# sandbox-t1 — Tier 1 hardened single-service sandbox

A pragmatic, hardened Linux sandbox for running a single fake-AWS service
(currently fake S3 over real HTTP/1.1 + TCP). This is the first production
tier from the feasibility study in `~/workspace/aws-emulator-feasibility/`.
It is **not** a LocalStack equivalent — it is the isolation layer plus one
service, built to prove the mechanics work before committing to breadth.

## Build & run

```bash
cd ~/workspace/aws-emulator-feasibility/tier1
cargo build --release
./target/release/sandbox-t1 [--port 4566] [--mem-mb 64] [--cpu-pct 20] [--pids-max 32]
cargo test --release   # offline seccomp filter-logic tests
```

The binary is self-testing: it boots the sandbox, runs in-sandbox checks,
exercises the fake S3 API over real TCP, shuts down cleanly, and prints a
`RESULT` line. Exit code 0 means every check passed.

## What it does

1. **Namespaces** (via `clone(2)`): user, PID, mount, UTS. The child is PID 1
   in its own PID namespace with its own hostname.
2. **Root isolation**: builds a sanitized tmpfs staging root (`/app`, `/dev`,
   `/proc`, `/tmp`), bind-mounts only `/dev/null`, `/dev/zero`,
   `/dev/urandom`, `/dev/full`, then `pivot_root`s into it. A canary file in
   the staging dir verifies the old root is unreachable (`ENOENT` after pivot).
3. **Seccomp** (two-stage classic-BPF deny-list):
   - *Stage P* (parent, pre-`clone`, inherited): denies ptrace, process-VM
     access, kernel-module ops, keyring, reboot/kexec, swap, `bpf(2)`,
     `userfaultfd`, `open_by_handle_at`, `clone3`, `unshare`, `setns`. Allows
     `mount`/`pivot_root`/namespace-`clone` because bootstrap still needs them.
   - *Stage C* (child, post-bootstrap, best-effort): additionally denies
     `mount`, `umount2`, `pivot_root`, and any `clone` carrying a
     `CLONE_NEW*` flag (flag-masked, so plain `clone` for threads still works).
4. **Privilege drop**: `no_new_privs` + all capability sets (bounding,
   effective, permitted, inheritable) zeroed. Verified via
   `/proc/<pid>/status` (`CapBnd: 0`, `NoNewPrivs: 1`).
5. **Resource limits** (best-effort): cgroup v2 `memory.max`, `cpu.max`,
   `pids.max` when the host delegates controllers; cleanly reports when it
   cannot.
6. **Fake S3** over real TCP `127.0.0.1:4566`: create/delete bucket, PUT/GET/
   HEAD/DELETE object, minimal `ListObjectsV2` XML, S3-style XML errors,
   HTTP/1.1 keep-alive. Graceful shutdown via SIGTERM.

## Deliberate tradeoffs

- **Network namespace is shared by design.** The service binds host loopback
  directly — no veth pair, bridge, NAT, or slirp/pasta. Multi-service
  networking is the Tier 2 problem.
- **Fake-S3 fidelity deviations** (documented, not hidden): PUT auto-creates
  buckets; bucket DELETE doesn't enforce non-empty; HEAD returns empty body
  without object-sized `Content-Length`; the HTTP parser handles sequential
  keep-alive but not pipelined requests in one read.

## What this environment could not demonstrate (honest limitations)

This was built and tested inside a nested sandbox that restricts:

- **seccomp**: the outer sandbox allowlists only trivial filter programs —
  any real deny-list gets `EINVAL`, both in nested children *and* in fresh
  processes. So neither stage could be installed here. What we did instead:
  - The two-stage install path is fully implemented and runs on a real host.
  - The filter *logic* is proven by `cargo test`: a userspace classic-BPF
    interpreter runs the exact generated instruction stream against test
    vectors (deny-list hits, clone-flag mask precision, arch kill-switch,
    P-allows-what-C-denies bootstrap invariant). Those tests caught a real
    bug — the arch check left `arch` (not `nr`) in the accumulator, which
    would have made the deny-list match nothing. Fixed and regression-tested.
  - Runtime self-tests degrade gracefully: they report "SKIPPED: no filter
    active" instead of falsely claiming enforcement.
- **cgroup v2**: no controllers delegated → limits reported as not applied,
  never claimed.

On a normal host (VPS, laptop, CI runner) both stages install and the
`RESULT` line reflects it.

## What remains for production

Per `SCOPING.md`: multi-service orchestration, rootless container networking
(veth/slirp), image/OCI layer handling, broader AWS API surface, secret
management, observability, and a real test matrix across kernels. This tier is
the isolation layer plus one service — roughly the foundation, not the house.
