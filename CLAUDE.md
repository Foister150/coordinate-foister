# coordinate-foister

A Go CLI tool for SSH remote management targeting CCDC-style lab operations.
It delivers shell scripts, direct commands, files, and download jobs to many
remote hosts concurrently over SSH.

## Build

```sh
go build -o coordinate ./cmd
go mod download
```

## Test

```sh
go test ./...
go test -race ./...
```

## Package Layout

| Package | File(s) | Responsibility |
|---|---|---|
| `main` | `cmd/main.go` | Entry point and per-host goroutine orchestration |
| `internal/cli` | `cli.go` | Flag init, `InputCheck`, arg normalization |
| `internal/globals` | `globals.go` | Flags, shared globals, `Instance` struct |
| `internal/runner` | `runner.go` | SSH auth loop and credential-based runners |
| `internal/ssh` | `ssh.go` | SSH execution, sudo wrapping, file upload/download, port validation |
| `internal/utils` | `ip_helper.go`, `utils.go` | IP/CIDR/range/DNS parsing and tar helpers |
| `internal/config` | `config.go`, `env.go` | `config.json` and `env.json` read/write |
| `internal/logger` | `logger.go` | Colored leveled logging |

## Key Patterns

`Instance` carries per-connection context: IP, username, password, script path,
port, outfile template, resolved hostname, and goroutine ID. It is passed by
value into SSH functions so goroutines do not share mutable struct state.

`BrokenHosts`, `AnnoyingErrs`, and `TotalRuns` are written by multiple
goroutines. Use `AppendBrokenHost`, `AppendAnnoyingErr`, `IncrementTotalRuns`,
and snapshot helpers instead of mutating or reading shared state directly from
concurrent code.

`useConfigDeploy()` reads `config.json` and calls `RunnerCred` with one
credential per entry. `useManualDeploy()` calls `RunnerBf`, which iterates all
username/password combinations. Both paths converge at `SsherWrapper`.

Script files are pre-read into `ScriptContentsMap` before goroutines launch.
`SsherWrapper` reads script contents from that map instead of rereading from
disk per host.

`SsherWrapper` prepares command/script execution once per SSH connection before
payload goroutines launch. It validates that the remote shell produces stdout,
resolves the hostname, and builds an immutable execution context that tells
workers whether to wrap payload commands with `sudo -S`. Do not treat a sudo
probe as a persistent root shell; each non-root `--sudo` payload must still be
wrapped explicitly.

`-l` / `--limit` caps concurrent script executions per host. `-m` /
`--max-hosts` caps concurrent host connections globally when nonzero.

Outfile templates support `%i%` for IP, `%h%` for hostname, and `%s%` for script
or command name.

## Security Notes

- SSH host key verification is disabled with `InsecureIgnoreHostKey`.
- Command-line passwords are visible to local process inspection.
- `config.json` stores credentials in plaintext. Keep it out of git.
- `--sudo` sends the SSH user's password over the remote shell via `sudo -S`.
- Only target hosts you own or are explicitly authorized to administer.
- Passwords containing `"` characters can break sudo shell quoting.

## Development Notes

- Run `go test -race ./...` before committing concurrency changes.
- `inet.af/netaddr` `IPSetBuilder` is not goroutine-safe; do DNS lookups in
  parallel, then merge results into the builder from one goroutine.
- Live DNS tests are skipped by default. Set `COORDINATE_LIVE_DNS_TEST=1` to run
  them.
