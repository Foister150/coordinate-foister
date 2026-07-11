# Coordinate-Foister Bug Audit and Fix Backlog

Audit date: 2026-07-09
Status refresh: 2026-07-10
Scope: the complete working tree, including the prior agent's uncommitted changes
Status vocabulary: `open`, `partial`, `done`

This document is intentionally implementation-oriented. Each `CF-*` section is
meant to be assignable to an agent as a bounded task. Unless a task explicitly
says otherwise, preserve current CLI compatibility and add a regression test
before changing behavior.

## Priority definitions

- **P0 — critical:** can compromise the operator or a managed host.
- **P1 — high:** data loss, silent privilege/correctness failure, hangs, or a
  readily triggered denial of service.
- **P2 — medium:** broken advertised behavior, significant performance loss, or
  unsafe behavior that needs additional conditions.
- **P3 — low:** maintainability, diagnostics, or repository hygiene.

## Current verification snapshot

- `go test ./...`, `go test -race ./...`, `go vet ./...`, `go mod verify`, and
  `git diff --check` pass on the refreshed working tree.
- A coverage run reports: `cmd` 64.0%, `cli` 53.5%, `config`
  74.5%, `globals` 98.2%, `logger` 70.2%, `runner` 49.6%, `safepath` 76.0%,
  `ssh` 30.4%, and `utils` 65.5%.
- CI uses Go 1.26.3 and gates formatting, tests, the race detector, vet,
  `staticcheck`, `govulncheck`, and cross-builds for Linux amd64/arm64, Darwin amd64/arm64,
  Windows amd64, FreeBSD amd64, OpenBSD amd64, and NetBSD amd64.
- Dependency upgrades moved `golang.org/x/crypto` to v0.52.0 and the required
  toolchain to Go 1.26.3. A fresh local `govulncheck` reports no reachable
  vulnerabilities. `staticcheck` passes with the tracked legacy dot-import
  style rule explicitly excluded; `gosec` reports intentional user-selected/contained file paths
  and owner-only directory/executable modes rather than an unreviewed sink.
- Subprocess CLI tests now cover help/usage streams, status 0/1/2 behavior,
  output modes, secret redaction, malformed config, authentication failure, and
  truthful run summaries. Config, output, tar, sudo-boundary, transfer,
  cancellation, concurrency, and cross-platform helpers have focused tests.

## Resolution status

| ID | Status | Implementation / evidence |
|---|---|---|
| CF-001 | done | Component-aware extraction rejects traversal, links, special files, symlink components, duplicates, and portable-name collisions; malicious archive tests cover the policy. |
| CF-002 | done | Sudo scripts are streamed into root-created owner-only storage, never executed from a user-writable pathname, and cleanup is verified even after success. |
| CF-003 | done | SSH dependencies and CI Go toolchain were upgraded; CI runs `govulncheck`. |
| CF-004 | done | Sudo uses a three-state decision and requested escalation fails closed. |
| CF-005 | done | Target cardinality is checked before materialization with configurable and absolute ceilings. |
| CF-006 | done | TCP/SSH handshakes, sessions, probes, payloads, rsync, tar, SFTP, and transfer operations now have bounded cancellation paths. |
| CF-007 | done | Password-bearing structs, command bodies, environment values, and child diagnostics are redacted or omitted; sentinel-secret tests cover CLI and logger paths. |
| CF-008 | done | Existing entries are loaded before mutation and config is written atomically with mode 0600 and platform-specific replacement. |
| CF-009 | done | The private config store uses synchronized update/snapshot APIs and race tests. |
| CF-010 | done | Partial/nonzero transfers propagate errors; successful fallback requires partial cleanup and payloads stop after transfer failure. |
| CF-011 | done | Shared safe-path rules contain output/downloads, reject absolute/traversing/symlink destinations, and sanitize remote-derived components portably. |
| CF-012 | partial | Payload paths are uniquely reserved and existing files are never truncated. Atomic output install currently depends on same-filesystem hard-link support, so filesystems without hard links fail safely instead of saving output. |
| CF-013 | done | One structured host result records auth and all requested work; runtime/config failures exit 1, CLI usage exits 2, and success exits 0. |
| CF-014 | done | The banner preflight was removed; one bounded SSH connection establishes reachability and authentication. |
| CF-015 | done | Password and keyboard-interactive methods share one handshake; expected credential rejection continues the matrix while terminal host failures stop it. |
| CF-016 | done | Help uses stdout/status 0, usage diagnostics use stderr/status 2, and runtime failures use status 1. |
| CF-017 | done | Bare `-k` means agent; key paths require `-k=PATH` or `--key=PATH`. |
| CF-018 | done | Output modes have explicit precedence and stream/filter tests, including true errors-only behavior. |
| CF-019 | done | Environment keys are validated, values are shell-quoted as whole assignments, and repeated CLI values override `env.json`. |
| CF-020 | done | Remote shell operands are quoted, rsync protects local/remote operands, IPv6 hosts are bracketed, and diagnostics escape control text. |
| CF-021 | done | Recursive SFTP downloads support files, directories, and remote `/` while rejecting links/special files and normalizing local modes. |
| CF-022 | done | Hostname/shell/sudo/rsync capabilities are probed once per host and normalized script contents are cached once per process. |
| CF-023 | done | Host and per-host payload limits are joined by a process-wide 64-operation budget; even `--max-hosts=0` retains the absolute 4096-host safety ceiling, and download roots are reserved/overlap-checked. |
| CF-024 | done | **User policy overrides the audit's opt-in proposal:** automatic remote rsync installation remains supported, bounded to 90 seconds, verified after installation, and disabled with `--no-rsync`; unsafe `pacman -Sy` was removed. |
| CF-025 | done | Host, authentication, payload, transfer-phase, failure, skip, and timeout counters are synchronized, reconcilable, and printed in the final summary. |
| CF-026 | done | Config/manual modes are mutually constrained, malformed/read/save failures are honored, config-only updates follow authentication, and the missing legacy helper fails during validation. |
| CF-027 | done | Numeric ceilings, OS-native private temp paths, 0700 directories, setup failure propagation, and transfer timeout validation have boundary tests. |
| CF-028 | partial | CI and broad focused/subprocess/race coverage exist. A local end-to-end SSH/SFTP server suite, fuzz targets, and a `staticcheck` CI gate remain open. |
| CF-029 | open | The environment-specific untracked benchmark and unrelated untracked `reader_poc.py`/`reader_writeup.md` remain intentionally untouched; benchmark validity/repository cleanup is not complete. |
| CF-030 | partial | Misleading `TotalRuns`/error replay state was replaced with structured results, but dot imports, duplicated help metadata, and compatibility/dead globals remain. |
| CF-031 | open | Both transports still explicitly disable host-key verification; no strict/TOFU shared trust store exists. |
| CF-032 | open | Transfer time is bounded, but a fast malicious archive/tree has no configurable aggregate byte/file quota and can still exhaust local disk/inodes before the deadline. |

### Known portability fallbacks

- Native Windows cannot use the POSIX password `SSH_ASKPASS` helper for rsync.
  Password-mode rsync therefore fails its capability path and automatically
  uses the bounded built-in transfer; key/agent rsync remains supported.
- Exclusive stdout installation (and Unix SFTP file installation) uses a
  same-directory temporary file followed by `os.Link`. Lack of hard-link
  support is reported as a local persistence failure and makes the payload/run
  fail; no overwrite fallback is attempted.

## Work queue

| ID | Pri | Area | Summary | Confidence |
|---|---:|---|---|---|
| CF-001 | P0 | Downloads | Prevent tar extraction from writing outside its destination | High |
| CF-002 | P0 | Sudo/scripts | Stop executing world-writable uploaded scripts as root | High |
| CF-003 | P1 | Dependencies | Upgrade reachable vulnerable SSH dependencies and build toolchain | High |
| CF-004 | P1 | Sudo | Never silently run a sudo-requested payload without sudo | High |
| CF-005 | P1 | Targeting | Bound or stream CIDR/range expansion | High |
| CF-006 | P1 | SSH/timeouts | Apply deadlines to connection, probes, execution, and transfers | High |
| CF-007 | P1 | Secrets | Remove passwords and environment secrets from logs | High |
| CF-008 | P1 | Config | Preserve existing config and save it atomically with mode 0600 | High |
| CF-009 | P1 | Config/concurrency | Synchronize `ConfigEntries` access | High |
| CF-010 | P1 | Transfers | Stop reporting partial or failed transfers as successful | High |
| CF-011 | P1 | Local files | Contain output/download paths and sanitize remote-derived names | High |
| CF-012 | P1 | Output | Prevent concurrent output-file collisions and overwrites | High |
| CF-013 | P1 | Results | Return nonzero status for failed runs and report accurate outcomes | High |
| CF-014 | P1 | SSH detection | Replace the incorrect port/banner validation | High |
| CF-015 | P1 | Authentication | Bound expected auth errors and avoid duplicate SSH handshakes | High |
| CF-016 | P2 | CLI | Print parse errors and use correct usage exit codes/streams | High |
| CF-017 | P2 | CLI/key auth | Remove the optional-key positional-argument ambiguity | High |
| CF-018 | P2 | CLI/output | Implement the advertised `--errors` behavior | High |
| CF-019 | P2 | Environment | Validate and safely encode environment assignments | High |
| CF-020 | P2 | Transfers/shell | Quote all remote paths and protect rsync arguments | High |
| CF-021 | P2 | Downloads | Implement a real no-tar SFTP fallback | High |
| CF-022 | P2 | Performance | Probe once per host and prepare scripts once per run | High |
| CF-023 | P2 | Concurrency | Apply a single bounded resource budget to transfers and payloads | Medium |
| CF-024 | P2 | Rsync/policy | Make remote package installation explicit and correct sudo docs | High |
| CF-025 | P2 | Metrics | Separate hosts reached, payload successes, failures, and timeouts | High |
| CF-026 | P2 | Config modes | Repair or remove legacy/config mode edge cases | High |
| CF-027 | P2 | Filesystem/ports | Validate numeric flags and use secure portable temp/output paths | High |
| CF-028 | P2 | Testing/CI | Add integration coverage and mandatory security checks | High |
| CF-031 | P2 | SSH trust | Provide a verifiable host-key policy for both SSH transports | High |
| CF-032 | P1 | Download resources | Bound aggregate downloaded bytes/files and clean quota failures | Medium |
| CF-029 | P3 | Repository | Remove unrelated artifacts and make the benchmark reproducible | High |
| CF-030 | P3 | Maintenance | Remove dead globals/dot imports and centralize CLI metadata | High |

---

## CF-001 — Secure tar extraction against traversal and link attacks

```yaml
priority: P0
area: downloads/local-security
status: done
files:
  - internal/utils/utils.go:111-158
  - internal/ssh/ssh.go:712-782
depends_on: []
```

### Problem

Downloaded tar content is controlled by the remote host. The containment check
uses a string prefix:

```go
strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir))
```

For destination `/tmp/out`, a header such as `../outside` resolves to
`/tmp/outside`, which still has the string prefix `/tmp/out`. Symlink entries can
also point outside the destination, and a later regular-file entry can follow
that symlink. Hard-link targets are joined without any containment check. Link,
flush, and close errors are ignored.

### Impact

A compromised target can create or truncate files outside `output/` on the
administrator's machine. That is a workstation-compromise primitive in the
project's adversarial-host threat model.

### Fix direction

- Replace string-prefix checking with a component-aware `filepath.Rel` check.
- Reject absolute names, `..` escapes, invalid/empty names, device nodes, FIFOs,
  and unsupported entry types.
- Do not follow symlinks while creating later entries. Prefer a root-scoped API
  such as `os.Root` where the supported Go version permits it.
- Validate both symlink and hard-link targets, or initially reject links.
- Propagate every mkdir, create, write, flush, link, and close error.

### Acceptance criteria

- Archives containing `../`, absolute paths, sibling-prefix escapes, symlink
  chains, and hard-link escapes cannot modify anything outside the destination.
- A rejected archive returns an error and the host is marked failed.
- Valid nested files continue to extract.

### Required tests

- Table-driven malicious archive tests for traversal and both link types.
- A test proving `/tmp/outside` is not accepted for destination `/tmp/out`.
- Disk/write failure propagation test where practical.

---

## CF-002 — Do not execute world-writable temporary scripts with sudo

```yaml
priority: P0
area: remote-execution/privilege
status: done
files:
  - internal/ssh/ssh.go:298-369
  - internal/ssh/ssh.go:785-817
depends_on: []
```

### Problem

`Upload` sends script files with mode `0777`, places them in shared `/tmp`, and
the sudo path later executes that pathname as root. Another user on the target
can replace or modify the file between upload and execution.

### Impact

An unprivileged user on a managed host can race Coordinate and obtain root code
execution whenever an operator uses `--sudo`.

### Fix direction

- Upload scripts with mode `0700` at most, owned by the authenticated user.
- Prefer a per-run directory created with `mktemp -d` and mode `0700` rather
  than a bare shared-`/tmp` filename.
- Verify ownership/type immediately before sudo execution.
- Always clean up through a separate best-effort session so timeout paths do
  not leave executable files behind.

### Acceptance criteria

- No remotely uploaded payload is group/world writable.
- Root execution is refused if the file is not a regular file owned by the
  expected user or root.
- Timeout and nonzero-exit paths attempt cleanup.

### Required tests

- SSH integration test asserting remote mode and owner before execution.
- Test that a replaced/symlinked payload is rejected.

---

## CF-003 — Upgrade reachable vulnerable SSH dependencies and builders

```yaml
priority: P1
area: dependencies/security
status: done
files:
  - go.mod:5-24
  - go.sum
depends_on: []
```

### Problem

`govulncheck` found reachable call paths for:

- `GO-2026-5020`, `GO-2026-5019`, `GO-2026-5018`, `GO-2026-5017`, and
  `GO-2026-5013` in `golang.org/x/crypto/ssh`, fixed in `x/crypto v0.52.0`;
- `GO-2025-4116`, fixed in `x/crypto v0.43.0`;
- `GO-2025-3487`, fixed in `x/crypto v0.35.0`;
- `GO-2026-4971` in the Go 1.26.2 standard library used during the initial audit, fixed
  in Go 1.26.3.

Official reports:
[5020](https://pkg.go.dev/vuln/GO-2026-5020),
[5019](https://pkg.go.dev/vuln/GO-2026-5019),
[5018](https://pkg.go.dev/vuln/GO-2026-5018),
[5017](https://pkg.go.dev/vuln/GO-2026-5017),
[5013](https://pkg.go.dev/vuln/GO-2026-5013),
[4116](https://pkg.go.dev/vuln/GO-2025-4116),
[3487](https://pkg.go.dev/vuln/GO-2025-3487), and
[4971](https://pkg.go.dev/vuln/GO-2026-4971).

### Fix direction

- Upgrade `golang.org/x/crypto` to at least v0.52.0 and update compatible
  `x/sys`, `x/term`, and transitive modules.
- Confirm the upgraded module's minimum Go version and make an explicit project
  decision if it exceeds the current `go 1.23` declaration.
- Build release artifacts only with a patched Go toolchain.

### Acceptance criteria

- `govulncheck ./...` reports no reachable known vulnerability.
- All tests, race tests, and advertised cross-builds pass.
- The supported Go version is documented and enforced in CI.

---

## CF-004 — Fail closed when requested sudo escalation fails

```yaml
priority: P1
area: remote-execution/sudo
status: done
files:
  - internal/ssh/ssh.go:245-278
  - internal/ssh/ssh.go:298-351
  - internal/ssh/ssh.go:372-394
depends_on: []
```

### Problem

`shouldSudo` returns `false` both when sudo was not requested and when an
explicit `--sudo` attempt failed. Callers interpret `false` as "run normally",
so a root-intended command is silently run as the SSH user.

### Impact

Administrative scripts may partially modify user-owned state while the tool
appears to have attempted privileged work. This can leave hosts inconsistent
and can make success output misleading.

### Fix direction

Return a three-state result: not requested, available, failed. Treat failed as a
host/payload failure. If unprivileged fallback is desired, require a separate,
explicit flag.

### Acceptance criteria

- `--sudo` plus failed escalation never executes the payload unprivileged.
- The failure affects the final exit status and result summary.
- Root and NOPASSWD cases continue to work.

---

## CF-005 — Bound or stream target expansion

```yaml
priority: P1
area: targeting/resource-control
status: done
files:
  - internal/utils/ip_helper.go:100-132
  - internal/utils/ip_helper.go:168-178
  - internal/utils/ip_helper.go:219-240
  - internal/utils/utils.go:20-51
depends_on: []
```

### Problem

Every IP in every range is materialized into `[]netaddr.IP` before the host
limiter is used. IPv4 `/0` requires billions of entries, and an IPv6 `/64` is
not practically enumerable. Four-octet range syntax can likewise request up to
the whole IPv4 space.

### Impact

A plausible typo or broad range causes extreme CPU/memory consumption or an
out-of-memory crash before any host work begins. The new host concurrency limit
does not protect this stage.

### Fix direction

- Introduce a configurable maximum target count with a conservative default and
  an explicit override.
- Prefer a lazy iterator feeding a fixed worker pool rather than a complete
  address slice.
- Calculate range cardinality before expansion and reject oversized values.

### Acceptance criteria

- `/64`, `/0`, and full-octet ranges fail quickly with a clear message by
  default and do not allocate proportional memory.
- Normal `/24` and small mixed targets preserve deduplication and ordering
  semantics.

---

## CF-006 — Enforce end-to-end SSH deadlines and cancellation

```yaml
priority: P1
area: ssh/reliability
status: done
files:
  - internal/runner/runner.go:58-87
  - internal/runner/runner.go:127-149
  - internal/ssh/ssh.go:68-104
  - internal/ssh/ssh.go:125-157
  - internal/ssh/ssh.go:498-587
  - internal/ssh/ssh.go:712-782
depends_on: [CF-003]
```

### Problem

All `goph.Config` literals omit `Timeout`; zero disables the library's SSH
handshake timeout. A service can pass the TCP preflight and then stall forever.
Hostname/shell probes and built-in transfers mostly use unbounded `client.Run`
or `session.Wait`. The non-sudo payload path uses goph's `RunContext`, whose
v1.4.0 implementation returns on cancellation without closing the session and
can leave its worker goroutine blocked sending to an unbuffered channel.

### Fix direction

- Set an explicit connect/handshake timeout in every SSH config.
- Create one context-aware session runner and use it for sudo and non-sudo
  commands, probes, cleanup, and transfer control commands.
- Give streaming transfers both idle and overall cancellation semantics.
- Propagate a root run context so Ctrl-C stops scheduling and closes clients.

### Acceptance criteria

- A TCP listener that never emits an SSH handshake cannot occupy a host slot
  beyond the configured connection deadline.
- Timed-out commands close their sessions and do not leak goroutines.
- Stalled upload/download operations terminate predictably.

---

## CF-007 — Redact credentials and secret environment values

```yaml
priority: P1
area: logging/secrets
status: done
files:
  - cmd/main.go:101-103
  - cmd/main.go:134-136
  - cmd/main.go:151-154
  - internal/runner/runner.go:58-60
  - internal/runner/runner.go:115-121
  - benchmark_coordinate.sh:4-14
depends_on: []
```

### Problem

Debug logs print raw passwords in connection attempts, password lists, and full
config entries. Normal startup output prints environment assignments, which can
contain tokens and the `ROOTPASS` generated by `--create-config`. The benchmark
contains a credential-like password in source.

### Impact

Terminal capture, CI logs, shell transcripts, or competition evidence bundles
can disclose host credentials.

### Fix direction

- Never format password-bearing structs with `%+v`.
- Log counts and usernames only; redact all values for keys matching a broad
  secret pattern and preferably all environment values.
- Parameterize benchmark credentials through required environment variables.

### Acceptance criteria

- Tests capture debug and normal output and assert that sentinel secrets never
  appear.
- Diagnostics retain enough host/username context to troubleshoot attempts.

---

## CF-008 — Preserve and securely save configuration

```yaml
priority: P1
area: config/data-integrity
status: done
files:
  - cmd/main.go:32-52
  - internal/config/config.go:19-42
  - internal/config/config.go:73-99
depends_on: [CF-009]
```

### Problem

Manual `--CO`/`--create-config` runs never load the existing `config.json`
before collecting entries. `SaveConfig` then truncates the file, so a failed or
partial run can replace an existing credential database with an empty or
partial list. `os.Create` produces a generally world-readable `0666 & umask`
file and the write is not atomic.

### Fix direction

- Load and validate existing config before any mutation mode.
- Write a mode-0600 temporary file in the same directory, flush/sync/close it,
  then atomically rename it over the destination.
- Preserve the existing file if collection or save fails.
- Return and honor all read/save errors.

### Acceptance criteria

- Adding one host preserves unrelated existing entries.
- Zero successful hosts does not erase the file.
- Interrupted/failed writes leave the prior JSON intact.
- Newly created config is mode 0600 on Unix.

---

## CF-009 — Synchronize config state

```yaml
priority: P1
area: config/concurrency
status: done
files:
  - internal/config/config.go:17-78
  - internal/ssh/ssh.go:179-183
  - internal/ssh/ssh.go:409-422
depends_on: []
```

### Problem

Up to `--max-hosts` workers and per-host payload goroutines call `UpdateEntry`
concurrently, but `ConfigEntries` is an unprotected package-level slice. The
existing race test covers only globals helpers, not config mutation.

### Fix direction

Encapsulate entries behind a mutex-protected store or send updates to one
collector goroutine. Provide snapshot methods for save/read operations; stop
exporting the mutable slice.

### Acceptance criteria

- A race test with hundreds of concurrent updates is clean under `-race`.
- No entries are lost; same-IP conflict behavior is deterministic and tested.

---

## CF-010 — Make transfer success mean complete success

```yaml
priority: P1
area: transfer/data-integrity
status: done
files:
  - internal/ssh/rsync.go:207-246
  - internal/ssh/ssh.go:428-494
  - internal/ssh/ssh.go:641-658
  - internal/ssh/ssh.go:682-745
  - internal/utils/utils.go:203-260
depends_on: [CF-001]
```

### Problem

- rsync exit 23 or 24 returns `nil`; callers then print "Successfully" and do
  not fall back. Exit 23 includes disk-full, I/O, and permission failures.
- `streamTarOverSSH` ignores every remote tar exit error.
- local tar creation silently skips walk, stat, readlink, header, and open
  failures and ignores `tar.Writer.Close` errors.
- upload/download wrapper functions return no aggregate result, so the host can
  be counted successful after every transfer failed.

### Fix direction

Define a transfer result that distinguishes complete, partial, failed, and
fallback-success. Treat partial as failure by default. Aggregate all entry
results into the host result and propagate write/close/session errors.

### Acceptance criteria

- Disk-full, unreadable-source, vanished-source, remote tar nonzero, and local
  extraction failures cannot produce a success log/result.
- Fallback runs only when safe and reports which method ultimately succeeded.
- Partial content is either cleaned up or clearly retained and reported.

---

## CF-011 — Contain local output and sanitize remote-derived path components

```yaml
priority: P1
area: local-files/security
status: done
files:
  - internal/logger/logger.go:36-62
  - internal/ssh/ssh.go:125-142
  - internal/ssh/ssh.go:603-610
  - internal/ssh/ssh.go:661-676
depends_on: []
```

### Problem

Output formats can contain `..` or absolute-like paths, and `%h%` is populated
from remote command output without sanitization. Downloads likewise use the
remote hostname as a directory component. A target can therefore influence
local paths; IPv6 colons also produce invalid Windows filenames. Explicit
download destinations can escape `output/` without the docs making this clear.

### Fix direction

- Sanitize IP, hostname, and script/command labels to a portable filename
  alphabet.
- Resolve the final absolute path and verify it remains beneath an absolute
  output root using a component-aware check.
- Decide whether absolute custom download destinations are a supported escape
  hatch; if so, require an explicit flag.

### Acceptance criteria

- Hostnames/output formats containing slashes, backslashes, `..`, control
  characters, or Windows-reserved characters cannot escape the output root.
- Normal IPv4, IPv6, DNS, and script names produce deterministic portable paths.

---

## CF-012 — Prevent output collisions and destructive overwrites

```yaml
priority: P1
area: output/data-integrity
status: partial
files:
  - internal/logger/logger.go:36-62
  - internal/ssh/ssh.go:194-214
  - internal/ssh/ssh.go:256-260
depends_on: [CF-011]
```

### Problem

Every direct command substitutes `%s%` with the literal `command`. Multiple
commands on one host therefore call `os.Create` concurrently on the same file.
Formats without a host/script placeholder also collide across hosts, and
same-basename scripts from different directories collide. `os.Create`
truncates existing output and write/close errors are ignored.

### Fix direction

- Give every payload a stable unique ID/index and expose a placeholder for it.
- Precompute all output paths before execution and reject collisions unless an
  explicit append/overwrite policy was selected.
- Write atomically and propagate write/close errors.

### Acceptance criteria

- Two commands and two same-basename scripts retain four distinct outputs.
- Cross-host path collisions are diagnosed before work starts.
- Existing files are not silently truncated by default.

---

## CF-013 — Return truthful exit codes and structured results

```yaml
priority: P1
area: cli/results
status: done
files:
  - cmd/main.go:20-63
  - internal/runner/runner.go:46-174
  - internal/ssh/ssh.go:160-243
depends_on: [CF-004, CF-010]
```

### Problem

Target parse failures, missing arguments, no reachable hosts, auth failures,
transfer failures, timeouts, and remote nonzero exits commonly end with process
status 0. Per-host functions mostly log instead of returning results. This also
makes `benchmark_coordinate.sh` failure counts meaningless.

### Fix direction

- Refactor `main` into `run(...) error` or an explicit summary result.
- Return typed host/payload/transfer results rather than relying on globals.
- Define exit semantics, for example: 0 all requested work succeeded, 1 runtime
  partial/failure, 2 usage error, 130 cancellation.

### Acceptance criteria

- Each major failure class has an integration test asserting status and stream.
- Partial multi-host failure is visible in both status and summary.

---

## CF-014 — Replace incorrect SSH port/banner validation

```yaml
priority: P1
area: ssh/connectivity
status: done
files:
  - internal/ssh/ssh.go:820-838
  - internal/runner/runner.go:90-98
  - internal/runner/runner.go:158-166
depends_on: [CF-006]
```

### Problem

`IsValidPort` accepts every TCP service except banners matching
`windows|winssh`; it never requires an `SSH-` identification. It therefore
accepts HTTP and silent services, yet rejects a legitimate Windows OpenSSH
banner. It also adds a second TCP connection before every real SSH handshake.

### Fix direction

Prefer removing the preflight and relying on a correctly bounded SSH handshake.
If retained, require a valid SSH protocol identification and return a typed
reason; do not filter by operating-system name.

### Acceptance criteria

- HTTP/silent listeners fail quickly; valid `SSH-2.0-*` banners are accepted.
- Each credential attempt does not require an unnecessary duplicate connection.

---

## CF-015 — Treat expected auth failures efficiently

```yaml
priority: P1
area: authentication/performance
status: done
files:
  - internal/runner/runner.go:46-87
  - internal/runner/runner.go:90-155
  - internal/runner/runner.go:158-173
depends_on: [CF-006, CF-014]
```

### Problem

Every failed password combination is logged immediately, appended to
`AnnoyingErrs`, and replayed later. A large credential matrix can allocate and
print hundreds of thousands of expected errors. Password and
keyboard-interactive authentication use two separate SSH connections for every
password. Config mode also adds a second generic failure after the detailed
failure.

### Fix direction

- Keep expected per-credential rejection at debug level and retain only a
  bounded final host failure plus optional attempt count.
- Offer password and keyboard-interactive methods in one bounded handshake when
  the SSH library supports it.
- When key auth is explicitly requested, define and document whether it is tried
  before passwords to avoid unnecessary lockout risk.

### Acceptance criteria

- Memory/log volume is O(hosts), not O(hosts × users × passwords).
- A host failure appears once in normal output.
- Authentication fallback remains covered by an SSH test server.

---

## CF-016 — Correct CLI error output and exit behavior

```yaml
priority: P2
area: cli/help
status: done
files:
  - internal/cli/cli.go:17-33
  - internal/cli/cli.go:186-190
  - cmd/main.go:23-30
depends_on: [CF-013]
```

### Problem

`ContinueOnError` does not print usage automatically. Unknown flags currently
exit 2 with no output. Validation errors print the full help to stdout and then
return status 0.

### Fix direction

Make usage accept an `io.Writer`. Print parse/validation errors and concise
usage to stderr, reserve full help/stdout/status 0 for `--help`, and return 2 for
usage mistakes.

### Acceptance criteria

- Golden subprocess tests cover help, unknown flag, missing value, missing
  required arguments, and mutually exclusive actions.

---

## CF-017 — Remove optional key-path ambiguity

```yaml
priority: P2
area: cli/key-auth
status: done
files:
  - internal/cli/cli.go:57-78
  - internal/cli/cli_test.go:1-49
depends_on: []
```

### Problem

The normalizer always consumes a non-flag token after `-k`/`--key` as the key
path. Thus `coordinate ... -k audit.sh` cannot mean "agent auth, run audit.sh";
the script disappears from positional arguments. This was reproduced.

### Fix direction

Use unambiguous flags, for example `--agent` and `--key PATH`, or require
`--key=PATH` while bare `-k` always means agent. Provide a compatibility warning
for the ambiguous legacy spelling.

### Acceptance criteria

- Bare `-k` followed by a positional script leaves the script positional.
- Explicit key paths work in short and long form, including paths beginning
  with `-` through `=` or `--` conventions.

---

## CF-018 — Implement `--errors`

```yaml
priority: P2
area: cli/output
status: done
files:
  - internal/globals/globals.go:79
  - internal/logger/logger.go:36-118
  - cmd/main.go:125-137
depends_on: []
```

### Problem

The `Errs` flag is declared and documented as "errors only" but is never read.
Normal warnings, target/action summaries, info, and stdout still appear.

### Fix direction

Define a single output-mode enum with precedence rules for normal, quiet,
super-quiet, errors-only, and debug rather than independent booleans.

### Acceptance criteria

- Subprocess golden tests verify every mode and conflicting combination.
- Errors-only emits errors to stderr and no stdout/info/warning noise.

---

## CF-019 — Safely parse and apply environment variables

```yaml
priority: P2
area: execution/environment
status: done
files:
  - internal/cli/cli.go:90-107
  - internal/config/env.go:13-52
  - internal/ssh/ssh.go:45-60
depends_on: [CF-007]
```

### Problem

Environment assignments are concatenated directly into a shell command.
Whitespace, quotes, substitutions, or semicolons in values can break execution
or add shell syntax. Keys are not validated. Leading whitespace can defeat the
env-file merge match. `env.json` currently overrides explicit `-E` values,
which is counter to typical CLI precedence and is undocumented.

### Fix direction

- Parse into `map[string]string`; validate keys against `[A-Za-z_][A-Za-z0-9_]*`.
- Apply values through SSH `Setenv` where supported or a safely quoted `env`
  invocation; do not concatenate raw assignments.
- Make precedence explicit, preferably CLI over file.

### Acceptance criteria

- Values containing spaces, quotes, dollar signs, backticks, and semicolons are
  received byte-for-byte by scripts/commands without executing extra syntax.
- Invalid keys fail before connecting.

---

## CF-020 — Quote remote paths and protect rsync operands

```yaml
priority: P2
area: transfer/path-handling
status: done
files:
  - internal/ssh/rsync.go:175-225
  - internal/ssh/rsync.go:269-313
  - internal/ssh/ssh.go:498-587
  - internal/ssh/ssh.go:682-707
  - internal/ssh/ssh.go:749-817
depends_on: [CF-010]
```

### Problem

Many remote commands interpolate upload/download paths without `shQuote`.
Single quotes, whitespace, glob characters, and shell metacharacters either
break legitimate transfers or change the remote command. Rsync operands lack
`--` and protected-argument handling; key paths with spaces are joined into an
unquoted remote-shell string.

### Fix direction

- Route every remote command through one tested command builder and quote each
  data argument exactly once.
- Use `--` before rsync operands and `--protect-args`/capability handling for
  supported rsync versions.
- Normalize local paths that rsync could misclassify as remote operands.

### Acceptance criteria

- Round-trip tests cover spaces, single quotes, leading dashes, glob syntax,
  unicode, and shell metacharacters in local and remote paths.
- No path content is evaluated as shell syntax.

---

## CF-021 — Implement a real no-tar download fallback

```yaml
priority: P2
area: downloads/compatibility
status: done
files:
  - internal/ssh/ssh.go:589-658
  - internal/ssh/ssh.go:747-782
depends_on: [CF-001, CF-010]
```

### Problem

When `probeRemote` says tar is absent, `downloadEntry` calls
`downloadFallbackSFTP`; that function immediately runs remote `tar`. The
advertised no-tar fallback therefore cannot work.

### Fix direction

Implement recursive SFTP stat/walk/download for files, directories, and links,
or return a clear unsupported-capability error instead of claiming fallback.

### Acceptance criteria

- An SSH test server with SFTP but no tar can download a nested directory.
- Permission and link policy is explicit and errors affect final status.

---

## CF-022 — Probe once per host and prepare scripts once per run

```yaml
priority: P2
area: performance
status: done
files:
  - internal/ssh/ssh.go:145-158
  - internal/ssh/ssh.go:160-243
  - internal/ssh/ssh.go:245-369
depends_on: [CF-004, CF-006]
```

### Problem

Every payload repeats the shell-usability probe and sudo verification. With the
default `-l 3`, bad sudo credentials can be tested concurrently several times,
which also risks PAM lockout. Every script is read, copied to a local temp file,
and converted from CRLF separately for every host.

### Fix direction

- Resolve hostname, shell capability, and sudo state once per host before
  launching payload workers.
- Read/validate/normalize each local script once before scheduling any host.
  Share immutable bytes; create only the remote-specific transfer state per
  host.

### Acceptance criteria

- N payloads cause one shell probe and at most one sudo probe per host.
- N hosts cause one local read/normalization per script.
- Failed validation prevents transfers/execution for that host.

---

## CF-023 — Bound all expensive concurrency

```yaml
priority: P2
area: concurrency/resource-control
status: done
files:
  - cmd/main.go:165-213
  - internal/ssh/ssh.go:191-243
  - internal/ssh/ssh.go:428-449
  - internal/ssh/ssh.go:603-638
depends_on: [CF-005]
```

### Problem

`--max-hosts` bounds host goroutines and `--limit` bounds payloads, but upload
and download entries create unbounded goroutines. Rsync launches one external
process per entry. Across 100 hosts this can still exhaust processes, file
descriptors, bandwidth, and SSH channels. Overlapping downloads can write the
same local paths concurrently.

### Fix direction

Use a shared weighted semaphore/resource budget for host connections, SSH
sessions, and external transfer processes. Validate download destinations for
overlap before starting.

### Acceptance criteria

- Stress tests prove configured maxima are never exceeded.
- Overlapping destination trees are rejected or serialized deterministically.

---

## CF-024 — Make rsync installation opt-in and align sudo behavior/docs

```yaml
priority: P2
area: rsync/remote-policy
status: done
files:
  - internal/ssh/rsync.go:45-173
  - internal/ssh/rsync.go:175-204
  - README.md:105-120
  - docs/coordinate.1.md:39-46
depends_on: [CF-004, CF-010]
```

### Problem

Ordinary `-F`/`-D` flags can invoke a remote package manager for up to 90
seconds, hold package locks, access mirrors, and mutate managed hosts. The
`pacman -Sy` command also creates partial-upgrade risk. Conversely, transfers
themselves are not elevated, so the help example implying `--sudo` permits an
upload to `/opt` is false.

### Policy resolution

The original opt-in recommendation below is superseded by the user's explicit
requirement to retain automatic remote package installation. The implemented
policy keeps one bounded, memoized, post-verified installation attempt and
provides `--no-rsync` as the deterministic no-mutation opt-out. Transfer writes
remain unprivileged and the documentation states that distinction.

### Original fix direction (superseded)

- Use rsync only when already available by default.
- Require an explicit `--install-rsync` or separate provisioning action for
  package installation, with a dry-run/confirmation policy suitable for
  automation.
- Either implement a safe privileged transfer strategy or clearly document
  that `--sudo` affects payload execution only.

### Original acceptance criteria (superseded)

- No transfer flag installs packages without explicit opt-in.
- Package-manager commands avoid known unsafe update patterns.
- CLI help, README, and man page match actual transfer privilege behavior.

---

## CF-025 — Report meaningful metrics

```yaml
priority: P2
area: results/observability
status: done
files:
  - internal/globals/globals.go:24-57
  - internal/ssh/ssh.go:185-188
  - internal/ssh/ssh.go:281-295
  - internal/ssh/ssh.go:354-369
  - cmd/main.go:61
depends_on: [CF-013]
```

### Problem

`TotalRuns` is labeled "Total hosts hit" but increments per command/script,
increments after timeouts and nonzero exits, and increments for transfer-only
hosts even if every transfer failed.

### Fix direction

Track distinct hosts attempted, connected, authenticated, completed, partially
failed, plus payload/transfer success, failure, and timeout counts.

### Acceptance criteria

- Multi-command one-host runs do not claim multiple hosts.
- A failed transfer or timed-out command is not counted as success.
- Summary totals reconcile and are testable without parsing colored logs.

---

## CF-026 — Repair configuration-mode edge cases

```yaml
priority: P2
area: config/cli-modes
status: done
files:
  - cmd/main.go:32-42
  - cmd/main.go:65-112
  - internal/cli/cli.go:80-109
  - internal/ssh/ssh.go:179-183
depends_on: [CF-008, CF-009, CF-013]
```

### Problem

- `-U` plus `-k` can run config deployment and then enter manual deployment
  even though manual usernames/passwords were never prepared.
- `--create-config` hardcodes `scripts/misc/password.sh`, which is not present in
  the repository, so the advertised legacy flow fails late on every host.
- Config-only updates happen after transfers, although authentication has
  already succeeded.
- `ReadConfig`/`SaveConfig` errors are ignored by callers.

### Fix direction

Model config/manual deployment as mutually exclusive explicit modes. Remove or
bundle the legacy script feature; otherwise fail during local validation. Save
credentials immediately after successful auth and honor storage errors.

### Acceptance criteria

- A mode matrix test covers `-U`, targets filter, `-k`, `-O`, `-C`, transfers,
  missing/malformed config, and missing helper assets.

---

## CF-027 — Validate numeric flags and use secure portable paths

```yaml
priority: P2
area: cli/filesystem/portability
status: done
files:
  - internal/globals/globals.go:60-86
  - internal/cli/cli.go:35-54
  - internal/ssh/ssh.go:301-319
depends_on: []
```

### Problem

Port, timeout, host limit, and payload limit lack coherent validation. Zero or
negative timeout immediately cancels payloads; an invalid port is converted to
`uint`; huge limits can allocate huge channels. The default local temp path is
hardcoded `/tmp` even for Windows builds, nested temp paths use `os.Mkdir`
instead of `MkdirAll`, and setup failures are logged but execution continues.
Output/temp directories are created with mode 0777.

### Fix direction

- Validate all numeric ranges before side effects.
- Default to `os.TempDir()` and use `filepath.Join`/`MkdirAll`.
- Return setup failures and use 0700 directories/0600 temporary files when they
  contain scripts, output, or collected data.

### Acceptance criteria

- Boundary table tests cover invalid/zero/huge values.
- Windows and Unix tests use platform-correct temp paths.
- Directory-creation failure stops before host connections.

---

## CF-028 — Add integration tests and CI gates

```yaml
priority: P2
area: quality/ci
status: partial
files:
  - internal/cli/*_test.go
  - internal/config/*_test.go
  - internal/logger/*_test.go
  - internal/runner/*_test.go
  - internal/ssh/*_test.go
  - internal/utils/*_test.go
  - .github/workflows/ci.yml (new)
depends_on: []
```

### Problem

The tests mostly cover pure helpers. Core process flow, config persistence,
logging modes, SSH lifecycle, sudo behavior, transfer integrity, and output
files are untested. The race suite passes because it never reaches the known
config race. No CI configuration exists.

### Fix direction

- Add a local SSH/SFTP test server or injectable client/session interfaces.
- Add subprocess tests for CLI status/stdout/stderr.
- Gate `go test`, `go test -race`, `go vet`, `staticcheck`, `govulncheck`,
  formatting, and representative cross-builds in CI.
- Add focused fuzzing for target parsing, env parsing, and tar extraction.

### Acceptance criteria

- Every P0/P1 item gains a regression test.
- CI fails on a reachable known vulnerability or formatting drift.
- Coverage targets prioritize risk rather than an arbitrary global percentage.

---

## CF-029 — Clean repository artifacts and make benchmarking valid

```yaml
priority: P3
area: repository/benchmark
status: open
files:
  - benchmark_coordinate.sh
  - reader_poc.py
  - reader_writeup.md
  - .gitignore
depends_on: [CF-013, CF-025]
```

### Problem

The reader exploit and writeup are unrelated to Coordinate and include a live
challenge endpoint and flag. The benchmark hardcodes a subnet, username,
password, missing binary names, and a missing script. It runs old and new in
large sequential blocks without warmup/randomization and checks only process
status—which is currently 0 for many failures—rather than equivalent completed
work. Benchmark logs are not ignored.

### Fix direction

- Remove the unrelated CTF files from this change set.
- Move a sanitized benchmark under `scripts/` or `bench/`; require target and
  credentials through arguments/environment.
- Interleave/randomize versions, include warmups, capture host/payload success
  counts, and fail if outputs are not equivalent.
- Ignore generated benchmark logs.

### Acceptance criteria

- A fresh checkout can run `--help` for the benchmark without private inputs.
- No credential or environment-specific path/subnet is committed.
- Performance is compared only across functionally equivalent successful runs.

---

## CF-030 — Remove dead state and centralize CLI metadata

```yaml
priority: P3
area: maintenance
status: partial
files:
  - internal/globals/globals.go:24-102
  - internal/logger/logger.go
  - internal/cli/cli.go:112-190
  - README.md
  - docs/coordinate.1.md
depends_on: [CF-016, CF-018]
```

### Problem

`ShortTimeout`, `PrivKey`, `DownloadPaths`, `CallbackIPs`, `Tabber`, and
`Stderr` are unused; `Callbacks` is accepted only as undocumented compatibility
state. Dot imports obscure ownership throughout the code. CLI help is manually
duplicated in source, README, and the man page, so drift is likely.

### Fix direction

- Remove dead values or mark/deprecate intentional compatibility flags.
- Replace dot imports with named imports.
- Define flags/help metadata once and generate or golden-test documentation.

### Acceptance criteria

- `staticcheck ./...` is clean under the agreed style configuration.
- Registered flags and documented flags are checked automatically.

---

## CF-031 — Provide a verifiable host-key policy

```yaml
priority: P2
area: ssh/trust
status: open
files:
  - internal/runner/runner.go:68-85
  - internal/runner/runner.go:142-148
  - internal/ssh/rsync.go:269-313
  - README.md:170-178
depends_on: [CF-003]
```

### Problem

In-process SSH always uses `InsecureIgnoreHostKey`, while external rsync SSH
disables strict checking and both user/global known-host files. The behavior is
documented, but on a hostile competition network it allows a man-in-the-middle
to collect passwords, substitute command output, and receive uploaded scripts.
The two transports also have no shared trust decision.

### Fix direction

- Add an explicit policy such as `known-hosts`, `accept-new`/TOFU, and
  `insecure`; document the compatibility/default decision.
- Use the same known-hosts database and policy for goph and external rsync SSH.
- Surface host-key changes as hard failures outside explicit insecure mode.

### Acceptance criteria

- Tests cover first connection, known key, changed key, unknown key in strict
  mode, and explicit insecure mode.
- A host accepted by the in-process client is evaluated under the same policy
  when rsync opens its second SSH connection.

---

## CF-032 — Bound aggregate download bytes and file counts

```yaml
priority: P1
area: downloads/resource-exhaustion
status: open
files:
  - internal/utils/utils.go
  - internal/ssh/ssh.go
  - internal/ssh/rsync.go
depends_on: [CF-006, CF-010, CF-021]
```

### Problem

The transfer deadline prevents an indefinitely slow or stalled download, but
it is not a storage quota. A fast remote tar/gzip stream, recursive SFTP tree,
or rsync transfer can consume all available local bytes or inodes before the
deadline. Compressed archives can amplify this sharply during extraction.

### Fix direction

- Add explicit per-transfer and optional per-run byte/file ceilings.
- Count extracted bytes and entries after decompression, not only wire bytes.
- Apply the same aggregate policy to tar, SFTP, and rsync; do not advertise a
  limit that one fallback bypasses.
- Stage quota-controlled downloads and remove incomplete staging content when
  the quota is exceeded, while reporting the exact limit and retained state.

### Acceptance criteria

- Tar/gzip expansion, SFTP recursion, and rsync all stop at the configured
  aggregate byte/file ceilings.
- Quota failures return exit status 1, never run dependent payloads, and do not
  leave a result that can be mistaken for a complete download.
- Tests cover one oversized file, many tiny files/inode pressure, compressed
  expansion, fallback transitions, and concurrent per-run accounting.

---

## Suggested implementation order

1. **Contain immediate security risk:** CF-001, CF-002, CF-003, CF-004, CF-007.
2. **Make execution bounded and truthful:** CF-005, CF-006, CF-010, CF-013,
   CF-014, CF-015.
3. **Protect local/config data:** CF-008, CF-009, CF-011, CF-012.
4. **Repair user-facing behavior:** CF-016 through CF-021, then CF-024-CF-027.
5. **Optimize and harden delivery:** CF-022, CF-023, CF-028-CF-032.

## Common definition of done

For every completed task:

1. Add a regression test that fails on the pre-fix code.
2. Run `gofmt` on changed Go files.
3. Run `go test ./...`, `go test -race ./...`, and `go vet ./...`.
4. Run `govulncheck ./...` for dependency or SSH-related changes.
5. Cross-build every platform affected by the change.
6. Update CLI help, README, and man page when behavior changes.
7. Do not mix the unrelated `reader_*` files or machine-specific benchmark
   inputs into implementation commits.
