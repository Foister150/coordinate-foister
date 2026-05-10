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

Requires **Go 1.23 or higher.**

Ensure module dependencies are installed.

`go mod download`

```text
go run ./cmd -h

usage: coordinate [options] [script ...]
       coordinate -t <targets> -u <usernames> -p <passwords> <script>
       coordinate -t <targets> -u <usernames> -x <command>
       coordinate -U [-t <targets>] [script ...]

Coordinate is a Go utility for SSH remote management. It delivers commands,
scripts, uploads, and downloads to targeted hosts over SSH.

positional arguments:
  script ...                local shell script(s) to upload and execute

targeting:
  -t, --targets TARGETS     target DNS names or IPs as singles, comma lists,
                            ranges, or CIDR
                            examples: host.example, 192.168.1.5,
                            192.168.1.10-20, 192.168.1.0/24
  -P, --port PORT           SSH port to use (default: 22)

authentication:
  -u, --usernames USERS     comma-separated username list
  -p, --passwords PASSES    comma-separated password list
  -k, --key[=KEY]           use SSH agent keys, or optionally pass a private
                            key path
  -U, --use-config          use plaintext credentials from config.json

execution:
  -x, --command COMMAND     execute direct command(s) instead of scripts
  -E, --env ENV             prefix scripts/commands with environment values
                            separated by semicolons
  -S, --sudo                attempt sudo escalation if the SSH user is not root
  -T, --timeout SECONDS     time limit per script or command (default: 30)
  -l, --limit THREADS       thread limit per IP (default: 3)
  -n, --no-validate         skip shell/script completion validation

file transfer:
  -F, --upload LOCAL;REMOTE
                            upload a local file or directory to a remote path
                            repeat the flag for multiple uploads
  -D, --download REMOTE[;LOCAL]
                            download a remote directory or file tree into output
                            repeat the flag for multiple downloads
  -W, --tmpdir DIR          local temp directory for generated script files
                            (default: /tmp)

output:
  -o, --outfile-fmt FORMAT  save stdout under output/ using %i%, %h%, and %s%
  -q, --quiet               print only script output
  -Q, --super-quiet         print only script output and suppress errors
  -e, --errors              print errors only
  -d, --debug               print debug messages

config helpers:
  -O, --CO ROOTPASS         create a config entry from existing credentials
                            without running password.sh
  -C, --create-config PASS  legacy helper for scripts/misc/password.sh
                            that script is not bundled in this repository
  -I, --ignore-users USERS  legacy password.sh helper value
  -A, --all-pass PASS       legacy password.sh helper value
  -c, --callbacks IPS       callback IP value retained for script compatibility
```

Scripts and direct commands are mutually exclusive.

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
