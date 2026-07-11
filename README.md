# coordinate-foister

`coordinate-foister` is a remote management CLI for delivering commands, scripts,
files, and collection jobs to targeted hosts over SSH. It was originally built
for CCDC-style operations where speed, repeatability, and broad host targeting
matter.

Use it only on systems you own or are explicitly authorized to administer.

# Disclaimer
This project was created for CCDC by Nigerald and Kalipatriot for Linux Administration, and later contributed to by BHBarlow and I.
I do not claim to have created or own this project, but it is my goal to keep it public and contribute to building a better tool. 

## Features

- Target DNS names, individual IPv4 addresses, comma-separated lists, ranges, and CIDR blocks.
- Authenticate with password lists, prompted passwords, SSH agent keys, SSH private keys, or saved config entries.
- Bounded, parallel host fan-out (`--max-hosts`) for fast, stable sweeps of large ranges instead of an unbounded goroutine per IP.
- Run shell scripts or direct commands across many hosts, each script run once per host.
- Install managed recurring commands through systemd timers or portable five-field crontabs on Unix-like targets.
- Upload files or directories to remote hosts, and download remote directories into local per-host output folders.
- rsync-accelerated transfers when available — installed automatically on the remote when permitted — with automatic streaming tar/SFTP fallback.
- Broad Unix compatibility: payloads run under POSIX `sh` (works with csh/tcsh login shells on the BSDs) and sudo passwords are fed over stdin rather than the command line.
- Optionally require sudo escalation before running commands and scripts; failed escalation stops the payload instead of silently running it unprivileged.
- Save command/script stdout with placeholders for IP, hostname, and script name.
- Load reusable environment values from `env.json`.
- Create and reuse `config.json` credential entries.

## Install

Download a release binary for your platform from GitHub Releases, then make it
executable on Unix-like systems:

```sh
chmod +x coordinate-linux-amd64
./coordinate-linux-amd64 --help
```

Build from source:

```sh
git clone https://github.com/LanodonF/coordinate-foister.git
cd coordinate-foister
go build -o coordinate ./cmd
```

## Usage

Requires **Go 1.26.3 or higher.** This minimum includes the standard-library
fixes used by the supported Windows builds.

Ensure module dependencies are installed.

`go mod download`

Run `coordinate --help` (or `go run ./cmd --help`) for the full grouped reference:

```text
USAGE
  coordinate [options] [script ...]
  coordinate -t <targets> -u <users> -p <passwords> <script.sh>
  coordinate -t <targets> -u <users> -x <command>
  coordinate -U [-t <targets>] [script ...]

TARGETING
  -t, --targets TARGETS   DNS names or IPs: singles, comma lists, ranges, CIDR
  -P, --port PORT         SSH port, 1..65535 (default 22)
  -m, --max-hosts N       max concurrent hosts, 0..4096 (default 100; 0 = safety ceiling)
      --max-targets N     max expanded addresses, 1..1048576 (default 65536)

AUTHENTICATION
  -u, --usernames USERS   comma-separated usernames to try
  -p, --passwords PASSES  comma-separated passwords to try (prompted if omitted)
  -k, --key[=PATH]        bare -k uses ssh-agent; key paths require -k=PATH
  -U, --use-config        use plaintext credentials from config.json

EXECUTION
  -x, --command COMMAND   run direct command(s) instead of scripts (repeatable)
      --schedule COMMAND  install recurring command(s) instead of running now
      --interval DURATION required with --schedule (e.g. 5m, 90m, 1h)
      --scheduler BACKEND auto (systemd then cron), systemd, or cron
  -E, --env KEY=VALUE     export an environment value; repeat for multiple values
  -S, --sudo              require sudo for commands/scripts/schedules when not root
  -T, --timeout SECONDS   positive time limit per script/command (default 30)
  -l, --limit N           per-host payload concurrency, 1..1024 (default 3)
  -n, --no-validate       skip the shell-usability probe before running

FILE TRANSFER (rsync when available, else built-in streaming transfer)
  -F, --upload LOCAL;REMOTE     upload a local file/dir to a remote path (repeatable)
  -D, --download REMOTE[;LOCAL] download a remote path into output/ (repeatable)
  -W, --tmpdir DIR             private local temp dir (default: OS temp/coordinate)
      --transfer-timeout N     overall seconds per transfer, 1..86400 (default 900)
      --no-rsync               never use rsync; always use the built-in transfer

OUTPUT
  -o, --outfile-fmt FORMAT  save stdout under output/ using %i% %h% %s%
  -q, --quiet               print payload output and tool errors only
  -Q, --super-quiet         print payload output; suppress tool errors
  -e, --errors              print tool errors; suppress console payload output
  -d, --debug               normal output plus debug messages

  Combined-mode precedence: --errors, --super-quiet, --debug, --quiet, normal.

CONFIG HELPERS
  -O, --CO ROOTPASS       create a config entry from working credentials
  -C, --create-config P   unavailable: password.sh is not bundled
  -I, -A, -c              unavailable legacy password-helper options
```

Scripts, direct commands, and scheduled commands are mutually exclusive. Invalid flags and invalid
flag combinations print a concise diagnostic to stderr and exit with status 2;
`--help` prints the grouped reference to stdout and exits successfully.
Runtime failures exit with status 1, including authentication exhaustion,
nonzero/timeout payloads, failed transfers or cleanup, and failed local output
or config persistence. Status 0 means every requested host operation succeeded.

`--max-targets` limits expansion before any host workers start, protecting
against accidentally materializing an enormous range or CIDR. `--max-hosts`
then limits concurrent hosts. `--limit` is a separate per-host cap: it controls
how many requested scripts or commands run concurrently on each connected host,
and every requested payload still runs once. Numeric values outside the ranges
shown above are rejected. `--max-hosts=0` removes the lower operator-selected
cap but still uses the absolute 4096-host safety ceiling; negative values are
invalid.

By default, generated local temporary files live in the platform's temporary
directory under a `coordinate` subdirectory (for example,
`${TMPDIR:-/tmp}/coordinate` on many Unix systems). Coordinate creates or
hardens its app-owned temporary and `output/` roots to owner-only access on
Unix-like systems. An explicitly selected, already-existing `--tmpdir` must
already be owner-only; coordinate will not change the mode of an arbitrary
shared directory.

## File transfer with rsync

When both this machine and the target support it, `-F`/`-D` use `rsync` over SSH
for delta transfers and resume. Uploads use rsync archive semantics, including
source permissions and timestamps; the directory streaming fallback also
carries tar metadata, while its single-file fallback writes mode `0644` or
`0755` according to whether the source is executable. If the remote lacks
rsync, coordinate makes one installation attempt for that
authenticated host via `apt-get`, `dnf`, `yum`, `zypper`, `pacman`, `apk`,
`pkg`, or `pkg_add`. Installation requires a root login or `--sudo`, is bounded
to 90 seconds, and is accepted only after a second probe verifies that rsync is
actually available.

`--sudo` permits privileged package installation but does not elevate the file
transfer itself. The authenticated user must be able to write the selected
remote upload destination.

If rsync cannot be used — local `rsync`/`ssh` is missing or unsuitable, remote
installation is not permitted or fails, authentication cannot be passed to the
system SSH client, or the transfer itself fails — coordinate automatically
falls back to its built-in streaming transfer. Downloads use tar when possible
and SFTP as the last fallback. A partial rsync exit is treated as a failure and
also triggers fallback; it is not reported as a successful transfer. Pass
`--no-rsync` to skip probing/installation and always use the built-in path.

Every individual transfer has a 900-second overall deadline by default; change
it with `--transfer-timeout` (maximum 86400 seconds). Rsync retains its separate
60-second idle-data timeout. Streaming SSH, tar, recursive SFTP, and local rsync
close their active resources when the deadline expires and report that partial
content may remain. Unix builds terminate the complete local rsync/ssh process
group. A fixed process-wide budget allows at most 64 expensive payload or
transfer operations at once, in addition to per-host `--limit`, so fleet fan-out
cannot multiply resource use to `max-hosts × limit`. Queued work receives its
full runtime deadline after obtaining a slot.

On native Windows, password-mode rsync safely falls back to the built-in
transfer because the POSIX askpass helper is unavailable. Key-mode rsync remains
supported, and platform null-device paths are used for SSH known-host settings.

Downloaded content does not retain the remote host's permissions. Every
download method normalizes local directories to `0700` and regular files to
`0600`; links and special files are rejected or skipped. This keeps collected
host data owner-only regardless of the remote metadata or local umask.

`REMOTE;LOCAL` download destinations are relative subdirectories beneath that
host's `output/downloads/<host>/` directory. Absolute paths, traversal, symlink
components, overlapping downloads, and nonempty destinations for remote `/`
are rejected. Remote-derived names are mapped to deterministic portable names.
Existing download artifacts are not merged or overwritten.

Saved stdout is also confined beneath `output/`. `%i%` and `%h%` are sanitized,
and `%s%` contains a stable payload label plus its per-host index. If a format
omits host or payload placeholders, coordinate adds the missing labels so
concurrent payloads remain distinct. Existing files are never overwritten;
even successful empty output creates an owner-only, zero-byte result file.
Remote stdout/stderr capture is bounded at 1 MiB per payload. A truncation
marker is retained, and truncation makes the payload and process fail rather
than being reported as success.

Password logins drive rsync's `ssh` through a temporary `SSH_ASKPASS` helper, so
no extra local software (such as `sshpass`) is required and the password is
never placed on a command line. Key and ssh-agent authentication pass through to
`ssh` natively.

## Examples

Run a script across a small range:

```sh
coordinate -t 192.168.1.10-20 -u root -p 'password1,password2' ./audit.sh
```

Run a direct command with keys loaded in `ssh-agent`:

```sh
coordinate -t 10.10.1.0/24 -u admin -k -x 'hostname && whoami'
```

Run a direct command with a key in a custom location:

```sh
coordinate -t 10.10.1.0/24 -u admin -k="$HOME/.ssh/id_ed25519" -x 'hostname && whoami'
```

Install a root-owned recurring firewall check every five minutes:

```sh
coordinate -t 10.10.1.5 -u admin -k -S --schedule '/usr/local/bin/check-firewall' --interval 5m
```

Upload a local tool directory and run a command:

```sh
coordinate -t 172.16.1.15 -u root -p 'secret' -F './tools;/opt/tools' -x 'ls -la /opt/tools'
```

Download remote logs into `output/downloads/<hostname>/logs`:

```sh
coordinate -t 172.16.1.15 -u root -p 'secret' -D '/var/log;logs'
```

Save command output by host and command:

```sh
coordinate -t 192.168.1.5 -u root -p 'secret' -o '%h%/%s%.txt' -x 'uname -a'
```

## Files

- `config.json`: optional credential store used by `--use-config`.
- `env.json`: optional map of environment variable names to values. Repeat `-E KEY=VALUE` to add command-line values; command-line values override matching file entries. Names must match `[A-Za-z_][A-Za-z0-9_]*`, while values are passed literally.
- `output/`: local runtime output directory for saved stdout and downloads.

Example `config.json`:

```json
[
  {
    "IP": "192.168.1.5",
    "Username": "root",
    "Password": "secret"
  }
]
```

Example `env.json`:

```json
{
  "TOKEN": "example",
  "MODE": "audit"
}
```

## Security Notes

- Passwords supplied on the command line may be visible to local process inspection.
- `config.json` stores credentials in plaintext. Keep it out of git and restrict local filesystem access.
- `-F`/`-D` may automatically install rsync with the remote package manager. Use `--no-rsync` when package mutation is not acceptable.
- `--schedule` uses `--scheduler=auto` by default: with root privileges it prefers a usable systemd manager, then falls back to `crontab`. Force `--scheduler=systemd` or `--scheduler=cron` when deterministic backend selection matters. Systemd uses root-owned units and supports arbitrary positive intervals; cron works on the BSDs, Solaris, Alpine, and non-systemd Linux but accepts only portable whole-minute/hour intervals that divide evenly into 24 hours. Cron installs an owner-only script in `~/.coordinate/` and an idempotent, tagged crontab entry; `--sudo` installs into root's crontab. Cron output is discarded to avoid mail, while systemd output goes to the journal. `--timeout` bounds only schedule installation; use a timeout mechanism in the scheduled command itself if required.
- Downloaded directories and regular files are normalized to owner-only modes (`0700` and `0600`) instead of preserving remote permissions.
- `--sudo` sends the authenticated password over SSH stdin, not in the remote command line. For a non-root login, failed sudo verification prevents commands and scripts from running unprivileged.
- Privileged scripts are streamed into a root-owned, mode-restricted temporary directory before execution. Download extraction rejects links and special files rather than following them outside the destination.
- Local output paths reject traversal, absolute destinations, symlink components, collisions, and existing files. Remote-derived filename components are sanitized for Unix and Windows portability.
- Password-mode rsync uses a mode-restricted temporary `SSH_ASKPASS` helper and passes the password through the child process environment, not its command line.
- Verify target ownership and authorization before running commands or scripts.

## Release Builds

Maintainers can build the release artifacts with:

```sh
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/coordinate-linux-amd64 ./cmd
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/coordinate-darwin-amd64 ./cmd
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/coordinate-darwin-arm64 ./cmd
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/coordinate-windows-amd64.exe ./cmd
git archive --format=zip --output=dist/coordinate-foister-v0.1.0-source.zip HEAD
```
