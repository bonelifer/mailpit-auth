# mailpit-auth

A CLI tool for managing a [Mailpit](https://mailpit.axllent.org/) htpasswd-style
authentication file shared by the web UI, SMTP, and POP3: add, update, delete,
list, and verify users, with support for multiple password hash formats, plus
automatic sync of Mailpit's SMTP allowed-recipients list. Also includes
`set-bind-address.py`, a helper for switching Mailpit's listen addresses
between `0.0.0.0` and the host's private IP.

## Requirements

- Python 3
- [`passlib`](https://pypi.org/project/passlib/) (`pip install --break-system-packages passlib`)

## Usage

```bash
# Add or update a user (prompts for the password if omitted)
./mailpit-auth.py alice
./mailpit-auth.py alice:hunter2

# Add/update several users at once
./mailpit-auth.py alice:hunter2 bob:correcthorse

# List users
./mailpit-auth.py -l

# Verify a password against the stored hash
./mailpit-auth.py -v alice:hunter2

# Delete a user (asks two confirmations by default; -s for just one)
./mailpit-auth.py -d alice
./mailpit-auth.py -s -d alice

# Bulk-add/update from a file of "username:password" lines
./mailpit-auth.py -i users.txt

# Skip interactive y/N confirmations (useful for scripting)
./mailpit-auth.py -f -d alice

# Resync the SMTP allowed-recipients env file without adding/deleting a user
# (e.g. after editing passwords.txt by hand)
./mailpit-auth.py -u
```

Run `./mailpit-auth.py -h` for the full option list.

### Encryption types

`-e`/`--encryption` accepts `plain`, `SSHA`, `MD5Crypt`, `APR1Crypt`, `SHA`,
`Bcrypt`, `Crypt-SHA-256`, `Crypt-SHA-512`, or the default `auto`. `auto`
picks the strongest type the local tooling supports (preferring Bcrypt, then
falling back through the glibc `crypt()`-backed types).

## Configuration

Copy `config.ini.example` to `config.ini` (in the same directory as the
script, or point elsewhere with `-c`/`--config`) to set defaults for
`output`, `encryption`, `force`, `domain`, `double_confirm_delete`, and
`compose_file`. Command-line options always override the config file, which
in turn overrides the built-in defaults.

Deleting a user asks two confirmations by default: the original `[y/N]`
prompt, then a stronger warning that the delete is permanent. Set
`double_confirm_delete = false` in `config.ini`, or pass
`-s`/`--single-confirm-delete`, to go back to the original single prompt.
`-f`/`--force` still skips both prompts entirely.

### SMTP allowed-recipients sync

Every add, update, or delete (also `-u`/`--update`) regenerates
`<output dir>/smtp_allowed_recipients.env` with a `MP_SMTP_ALLOWED_RECIPIENTS`
regex matching exactly the current users
(each as `<username>@<domain>`, `-m`/`--domain`, default `mailpit`), and then
checks a docker-compose file for a `mailpit:` service. Use `-y`/`--compose-file`
(or the `compose_file` config setting) to point at one explicitly; otherwise
the script auto-detects it next to the script, checking `compose.yaml`,
`compose.yml`, `docker-compose.yaml`, and `docker-compose.yml` in that
order. If the `mailpit:` service doesn't already reference the env
file, an `env_file:` entry is added automatically, creating the env file
itself first (with a deny-all `^$` default) if it doesn't exist yet either.
Any existing compose file that predates this feature gets fully wired up on
the next run with no manual editing. If a `mailpit:` service or its
`environment:` key can't be found, nothing is changed and a note is printed
instead of guessing. Read-only commands (`-l`, `-v`) touch neither file.

The inserted `env_file:` entry is still marked `required: false`, as a
safety net in case `smtp_allowed_recipients.env` is ever deleted by hand
after being wired up. Mailpit would then start with
`MP_SMTP_ALLOWED_RECIPIENTS` unset (no recipient restriction) instead of
failing to start.

## Bind address helper

`set-bind-address.py` rewrites `MP_UI_BIND_ADDR`, `MP_SMTP_BIND_ADDR`, and
`MP_POP3_BIND_ADDR` in a docker-compose file, switching the host portion
between `0.0.0.0` and a specific IP while leaving the port and any trailing
comment untouched. It shares `config.ini`'s `compose_file` setting and
compose-file auto-detection with `mailpit-auth.py`.

```bash
# Point all three at the host's auto-detected private IP
./set-bind-address.py -a

# Use a specific IP instead of auto-detecting
./set-bind-address.py -i 192.168.1.70

# Preview the auto-detected change without writing
./set-bind-address.py -a -n

# Revert back to 0.0.0.0
./set-bind-address.py -r
```

Run `./set-bind-address.py -h` for the full option list. Running the script
with none of `-a`/`-i`/`-r` (including with just `-n` on its own) only prints
help and changes nothing. Already-correct lines are left alone, so running
it twice in a row with the same target is a no-op the second time.

## Contributing

Contributions are welcome!

- **Bug reports**: [Open an issue](https://github.com/bonelifer/mailpit-auth/issues).
- **Everything else** (questions, feature requests, ideas, general discussion): [Use Discussions](https://github.com/bonelifer/mailpit-auth/discussions).
- Pull requests are welcome for bug fixes or discussed features.

## Acknowledgments

- Code review, bug fixes, and documentation assisted by [Claude](https://www.anthropic.com/claude).

## License

This project is licensed under the **GNU General Public License v3.0**.

See [LICENSE](LICENSE) for more information.
