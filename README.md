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

- Target individual IPv4 addresses, comma-separated lists, ranges, and CIDR blocks.
- Authenticate with password lists, prompted passwords, SSH private keys, or saved config entries.
- Run shell scripts or direct commands across many hosts.
- Upload files or directories to remote hosts over SSH.
- Download remote directories into local per-host output folders.
- Optionally attempt sudo escalation before running payloads.
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

```text
coordinate [options] [script ...]
coordinate -t TARGETS -u USERS -p PASSWORDS script.sh
coordinate -t TARGETS -u USERS -x "command"
coordinate -U [-t TARGETS] [script ...]
```

Scripts are positional arguments. Direct commands use `--command`/`-x`; scripts
and direct commands are mutually exclusive.

### Options

| Option | Description |
| --- | --- |
| `-t, --targets string` | Target IPs. Supports single IPs, comma-separated lists, ranges like `192.168.1.10-20`, and CIDR blocks like `192.168.1.0/24`. |
| `-u, --usernames string` | Comma-separated usernames. |
| `-p, --passwords string` | Comma-separated passwords. If omitted and no key/config mode is used, coordinate prompts for one password. |
| `-k, --key string` | SSH private key path. |
| `-P, --port int` | SSH port. Default: `22`. |
| `-l, --limit int` | Thread limit per IP. Default: `3`. |
| `-T, --timeout int` | Time limit per script or command, in seconds. Default: `30`. |
| `-x, --command stringArray` | Execute direct command(s) instead of scripts. Repeat the flag to run multiple commands. |
| `-E, --env string` | Environment assignments to prefix before scripts/commands, separated by semicolons. |
| `-W, --tmpdir string` | Local temporary directory for generated script files. Default: `/tmp`. |
| `-F, --upload stringArray` | Upload local file or directory. Format: `local_path;remote_path`. Repeatable. |
| `-D, --download stringArray` | Download remote directory or file tree. Format: `remote_path` or `remote_path;local_subdir`. Repeatable. |
| `-o, --outfile-fmt string` | Save stdout under `output/` using placeholders `%i%`, `%h%`, and `%s%`. |
| `-S, --sudo` | Attempt sudo escalation when the authenticated user is not root. |
| `-q, --quiet` | Print only script output. |
| `-Q, --super-quiet` | Print only script output and suppress errors. |
| `-e, --errors` | Print errors only. |
| `-d, --debug` | Print debug messages. |
| `-n, --no-validate` | Do not validate shell/script completion behavior. |
| `-U, --use-config` | Load credentials from `config.json`. |
| `-O, --CO string` | Create a config entry from existing credentials without running `password.sh`; value is the root password to store. |
| `-C, --create-config string` | Legacy config helper for `scripts/misc/password.sh`. That script is not bundled in this repository. |
| `-I, --ignore-users string` | Legacy `password.sh` helper value for users to ignore. |
| `-A, --all-pass string` | Legacy `password.sh` helper value to set a shared password for users except root and ignored users. |
| `-c, --callbacks string` | Callback IP address value retained for compatibility with existing scripts. |

## Examples

Run a script across a small range:

```sh
coordinate -t 192.168.1.10-20 -u root -p 'password1,password2' ./audit.sh
```

Run a direct command:

```sh
coordinate -t 10.10.1.0/24 -u admin -k ~/.ssh/id_ed25519 -x 'hostname && whoami'
```

Upload a local tool directory and run a command:

```sh
coordinate -t 172.16.1.15 -u root -p 'secret' -F './tools;/opt/tools' -x 'ls -la /opt/tools'
```

Download remote logs into `output/downloads/<hostname>/logs`:

```sh
coordinate -t 172.16.1.15 -u root -p 'secret' -D '/var/log;logs' -x 'true'
```

Save command output by host and command:

```sh
coordinate -t 192.168.1.5 -u root -p 'secret' -o '%h%/%s%.txt' -x 'uname -a'
```

## Files

- `config.json`: optional credential store used by `--use-config`.
- `env.json`: optional map of environment variable names to values. Values from this file are merged into command/script environment prefixes.
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

- Coordinate disables SSH host key verification for speed and lab flexibility.
- Passwords supplied on the command line may be visible to local process inspection.
- `config.json` stores credentials in plaintext. Keep it out of git and restrict local filesystem access.
- `--sudo` sends the authenticated password through sudo over the remote shell.
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
