# COORDINATE(1)

## NAME

coordinate - run commands, scripts, uploads, and downloads across SSH targets

## SYNOPSIS

```text
coordinate [options] [script ...]
coordinate -t TARGETS -u USERS -p PASSWORDS script.sh
coordinate -t TARGETS -u USERS -x "command"
coordinate -U [-t TARGETS] [script ...]
```

## DESCRIPTION

`coordinate` connects to SSH targets, finds usable credentials from the provided
user/password/key/config inputs, and then runs the requested scripts or direct
commands. It can also upload local files/directories before execution and
download remote directories into local output folders.

Building from source requires Go 1.26.3 or newer.

## OPTIONS

Run `coordinate --help` for the full grouped flag list. The options are grouped
below by purpose.

### Targeting

- `-t, --targets`: DNS names or IP targets as singles, lists, ranges, or CIDR blocks.
- `-P, --port`: SSH port in the range 1 through 65535 (default 22).
- `-m, --max-hosts`: maximum hosts processed concurrently, 0 through 4096 (default 100). Zero uses the absolute 4096-host safety ceiling; negative values are invalid.
- `--max-targets`: maximum addresses expanded from ranges/CIDRs before work begins, 1 through 1048576 (default 65536).

### Authentication

- `-u, --usernames`: comma-separated usernames.
- `-p, --passwords`: comma-separated passwords; coordinate prompts if omitted.
- `-k, --key[=PATH]`: bare `-k` uses ssh-agent; a private key path must use `-k=PATH` or `--key=PATH`.
- `-U, --use-config`: read plaintext credentials from `config.json`.

### Execution

- `-x, --command`: direct command; repeat for multiple commands.
- `-E, --env KEY=VALUE`: export one environment value; repeat the flag for multiple values.
- `-S, --sudo`: require verified sudo escalation for commands/scripts when the SSH user is not root.
- `-T, --timeout`: positive time limit in seconds for each script or command (default 30).
- `-l, --limit`: maximum scripts/commands run concurrently on each host, 1 through 1024 (default 3). This is not a repeat count; each requested payload runs once.
- `-n, --no-validate`: skip the shell-usability probe before running.

### File transfer

- `-F, --upload`: upload `local_path;remote_path`; repeatable.
- `-D, --download`: download `remote_path` or `remote_path;local_subdir`; repeatable. The local subdirectory must remain relative beneath the per-host output directory.
- `-W, --tmpdir`: private local temporary directory (default: the operating system's temporary directory plus `coordinate`).
- `--transfer-timeout`: positive overall seconds per transfer, 1 through 86400 (default 900).
- `--no-rsync`: never use rsync for transfers; always use the built-in streaming path.

### Output

- `-o, --outfile-fmt`: write stdout under `output/` with `%i%`, `%h%`, `%s%`. Remote labels are sanitized and `%s%` includes a stable payload index; missing host/payload dimensions are appended automatically.
- `-q, --quiet`: print payload output and tool errors, suppressing routine tool messages.
- `-Q, --super-quiet`: print payload output and suppress tool errors and other tool messages.
- `-e, --errors`: print tool errors and suppress console payload output.
- `-d, --debug`: add debug messages to normal output.

### Config helpers

- `-O, --CO`: create a config entry from working credentials using the supplied root password.
- `-C, --create-config`: unavailable because the legacy `scripts/misc/password.sh` helper is not bundled.
- `-I, --ignore-users`, `-A, --all-pass`, and `-c, --callbacks`: rejected unavailable legacy helper options.

`env.json` is an optional JSON object of environment names and values.
Command-line `-E` values override matching file entries. Environment names
must match `[A-Za-z_][A-Za-z0-9_]*`. Values are passed
literally, including spaces and shell metacharacters; quote the complete
`KEY=VALUE` argument as needed to prevent the local shell from expanding it.

Scripts and direct commands are mutually exclusive. Numeric options outside the
ranges above are rejected.

The default temporary path is computed using the operating system rather than
being hard-coded to `/tmp`. On Unix-like systems, coordinate creates or hardens
its app-owned temporary and `output/` roots to mode `0700`. An explicitly
selected, already-existing `--tmpdir` must already deny group and other access;
coordinate does not chmod an arbitrary shared directory.

## OUTPUT

- Normal mode prints status, informational messages, payload output, warnings, and errors.
- `-q, --quiet` prints payload output and tool errors, suppressing status, informational messages, and warnings.
- `-Q, --super-quiet` prints payload output but suppresses tool errors and other tool messages.
- `-e, --errors` prints tool errors and suppresses payload output from the console. Output requested with `-o` is still saved.
- `-d, --debug` adds debug messages to normal output.

When output flags are combined, precedence is `--errors`, `--super-quiet`,
`--debug`, `--quiet`, then normal. Invalid flags and invalid flag combinations
write a concise diagnostic to stderr and exit with status 2. `--help` writes the
grouped reference to stdout and exits successfully.

## SUDO

For a non-root SSH login, `--sudo` first performs a bounded privilege probe. If
that probe fails, coordinate refuses to execute the command or script rather
than silently running a root-intended payload as the authenticated user. The
password is passed to `sudo -S` over SSH stdin instead of appearing in the
remote process command line. Privileged scripts are streamed into a root-owned,
mode-restricted temporary directory before execution.

## FILE TRANSFER

`-F`/`-D` use `rsync` over SSH when both ends support it, giving delta transfers
and resume. Uploads use rsync archive semantics, preserving source modes and
timestamps. The directory streaming fallback carries tar metadata; its
single-file fallback writes mode `0644` or `0755` depending on whether the
source is executable. If rsync is absent, coordinate makes one remote package-manager
installation attempt for the authenticated host when logged in as root or when
`--sudo` is enabled. The attempt is bounded to 90 seconds and coordinate probes
again to verify that rsync was installed.

`--sudo` permits privileged package installation but does not elevate the file
transfer itself. The authenticated user must be able to write the selected
remote upload destination.

If local tooling is unsuitable, installation is unavailable or fails, or an
rsync transfer fails (including partial-transfer exits), coordinate falls back
to the built-in streaming path. Downloads use tar when available and SFTP as a
last fallback. Use `--no-rsync` to prevent all rsync probing and automatic
package installation. Password logins use a mode-restricted temporary
`SSH_ASKPASS` helper; no `sshpass` installation is required.

Each transfer has a configurable end-to-end deadline (`--transfer-timeout`, 900
seconds by default) in addition to rsync's 60-second idle timeout. Expiry closes
streaming SSH/tar/SFTP resources and terminates local rsync; errors explicitly
warn about possible partial content. At most 64 expensive payload or transfer
operations run process-wide, while `--limit` remains the per-host bound. Queued
operations receive their full deadline after entering that global budget.

Native Windows password authentication uses the built-in transfer rather than
the POSIX rsync askpass helper. Key-mode rsync remains available.

Downloads deliberately do not preserve the remote permissions. All transfer
paths normalize downloaded directories to `0700` and regular files to `0600`.
Links and special files are rejected or skipped, so downloaded host data remains
owner-only regardless of its source metadata or the local umask.

Absolute/traversing download destinations, symlink components, overlapping
artifact roots, existing artifacts, and nonempty destinations for remote `/`
are rejected. Remote-derived path components are mapped to deterministic
portable names before local creation. Saved stdout follows the same containment
rules, never overwrites an existing file, and creates a zero-byte `0600` file
for successful payloads with empty output.

Merged remote stdout/stderr is capped at 1 MiB per payload. Coordinate retains
the prefix and a truncation marker, but classifies truncation as a payload
failure. The final run summary reconciles host, payload, and transfer-phase
outcomes. Exit status is 0 only when all requested host work succeeds, 1 for a
runtime/authentication/persistence failure, and 2 for invalid command usage.

## EXAMPLES

```sh
coordinate -t 192.168.1.10-20 -u root -p 'secret' ./audit.sh
coordinate -t 10.10.1.0/24 -u admin -k -x 'hostname'
coordinate -t 10.10.1.0/24 -u admin -k="$HOME/.ssh/id_ed25519" -x 'hostname'
coordinate -t 172.16.1.15 -u root -p 'secret' -D '/var/log;logs'
```

## FILES

- `config.json`: plaintext credential entries for `--use-config`.
- `env.json`: optional environment variable map. Repeated command-line
  `-E KEY=VALUE` entries override matching file entries; names must match
  `[A-Za-z_][A-Za-z0-9_]*`.
- `output/`: saved stdout and downloaded files.

## SECURITY NOTES

Coordinate is intended for authorized administration and lab operations. It uses
insecure SSH host key verification, can expose command-line passwords to local
process inspection, and stores config credentials in plaintext. File transfers
may install rsync remotely; use `--no-rsync` if package changes are unacceptable.
Password-mode rsync passes its secret through the child process environment,
not its command line. Download extraction rejects links and special files, and
downloaded directories/files are normalized to modes `0700`/`0600`.
