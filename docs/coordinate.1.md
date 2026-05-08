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

## OPTIONS

Run `coordinate --help` for the generated flag list. The most common flags are:

- `-t, --targets`: IP targets as singles, lists, ranges, or CIDR blocks.
- `-u, --usernames`: comma-separated usernames.
- `-p, --passwords`: comma-separated passwords.
- `-k, --key`: SSH private key.
- `-x, --command`: direct command; repeat for multiple commands.
- `-F, --upload`: upload `local_path;remote_path`; repeatable.
- `-D, --download`: download `remote_path` or `remote_path;local_subdir`; repeatable.
- `-o, --outfile-fmt`: write stdout under `output/` with `%i%`, `%h%`, `%s%`.
- `-S, --sudo`: try sudo when the user is not root.
- `-U, --use-config`: read credentials from `config.json`.

## EXAMPLES

```sh
coordinate -t 192.168.1.10-20 -u root -p 'secret' ./audit.sh
coordinate -t 10.10.1.0/24 -u admin -k ~/.ssh/id_ed25519 -x 'hostname'
coordinate -t 172.16.1.15 -u root -p 'secret' -D '/var/log;logs' -x 'true'
```

## FILES

- `config.json`: plaintext credential entries for `--use-config`.
- `env.json`: optional environment variable map.
- `output/`: saved stdout and downloaded files.

## SECURITY NOTES

Coordinate is intended for authorized administration and lab operations. It uses
insecure SSH host key verification, can expose command-line passwords to local
process inspection, and stores config credentials in plaintext.
