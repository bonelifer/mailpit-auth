#!/usr/bin/env python3
"""
Script: mailpit-auth.py
Description: This script manages a password file for Mailpit authentication.
Input: Username and password combinations.
Output: Password file in plain text or encrypted format.
Usage: ./mailpit-auth.py [options] [<username>[:<password>] ...]
Options:
  -o, --output <output_file>: Specify the output file for the password file. Default is "./data/passwords.txt".
  -e, --encryption <encryption_type>: Specify the encryption type for the passwords. Default is "auto"
                        (the strongest type this system's tooling supports).
                        Supported encryption types: auto, plain, SSHA, MD5Crypt, APR1Crypt, SHA, Bcrypt (most secure), Crypt-SHA-256, Crypt-SHA-512
  -d, --delete <username>: Delete the specified user from the password file. Asks two
                        confirmations by default (see -s/--single-confirm-delete).
  -l, --list: List the usernames currently in the password file.
  -v, --verify <username[:password]>: Verify a username/password pair against the stored hash.
  -i, --input <input_file>: Bulk-add/update users from a file of "username:password" lines.
  -f, --force: Skip interactive y/N confirmation prompts for updates and deletions.
  -c, --config <config_file>: Path to the config file. Default is "config.ini" next to this script.
  -m, --domain <domain>: Mail domain used to build the SMTP allowed-recipients env file. Default is "mailpit".
  -u, --update: Regenerate the SMTP allowed-recipients env file without adding/updating/deleting a user.
  -s, --single-confirm-delete: Ask only one [y/N] prompt before deleting a user, instead
                        of the default double confirmation.
  -y, --compose-file <path>: Path to the docker-compose file to keep in sync with the
                        SMTP allowed-recipients env file. Default: auto-detected next
                        to this script (compose.yaml, compose.yml,
                        docker-compose.yaml, docker-compose.yml, in that order).

Note: If a <username>:<password> pair omits the password, or -d/-v is given a bare
username, you will be prompted for the password via a hidden getpass prompt instead
of passing it on the command line.

Config file: settings in the config file (see config.ini.example) are used as
defaults and are overridden by the matching command-line option.

Allowed-recipients sync: any command that adds, updates, or deletes a user
(also -u/--update) regenerates "<output dir>/smtp_allowed_recipients.env", containing a
MP_SMTP_ALLOWED_RECIPIENTS regex that matches exactly the current users
(each as "<username>@<domain>"). The same command also checks the
docker-compose file (-y/--compose-file, or auto-detected) for a "mailpit:"
service and adds an env_file: entry pointing at the generated file if one
isn't already there, creating that file with a deny-all default first if it
doesn't exist yet either, so any existing compose file ends up fully wired
up automatically. If a mailpit service or its environment: key can't be
found, nothing is changed and a note is printed instead of guessing.
"""

import argparse
import base64
import configparser
import getpass
import hashlib
import os
import random
import re
import string
import sys

from passlib.hash import bcrypt

try:
    import crypt
except ImportError:
    crypt = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.ini")
DEFAULT_OUTPUT = "./data/passwords.txt"
CONFIG_SECTION = "mailpit-auth"
ENCRYPTION_CHOICES = ["auto", "plain", "SSHA", "MD5Crypt", "APR1Crypt", "SHA", "Bcrypt", "Crypt-SHA-256", "Crypt-SHA-512"]

# Checked in this order next to the script when -y/--compose-file and the
# "compose_file" config setting are both unset: Docker Compose's own
# standard search order, which also matches this project's own file name.
COMPOSE_FILE_CANDIDATES = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]

# Strongest to weakest; used by detect_strongest_encryption().
ENCRYPTION_STRENGTH_ORDER = ["Bcrypt", "Crypt-SHA-512", "Crypt-SHA-256", "APR1Crypt", "MD5Crypt", "SHA", "SSHA", "plain"]


def load_config(config_path):
    """
    Load the config file, if present.

    Args:
        config_path (str): Path to the config file.

    Returns:
        configparser.ConfigParser: Parsed config (empty section if the file doesn't exist).
    """
    config = configparser.ConfigParser()
    config[CONFIG_SECTION] = {}
    if os.path.exists(config_path):
        config.read(config_path)
    return config


def is_bcrypt_available():
    """Return True if passlib has a working Bcrypt backend on this system."""
    try:
        bcrypt.hash("mailpit-auth-selftest")
        return True
    except Exception:
        return False


def crypt_method_available(method_name):
    """Return True if the stdlib crypt module supports the given METHOD_* name."""
    if crypt is None:
        return False
    method = getattr(crypt, method_name, None)
    if method is None:
        return False
    return method in crypt.methods


def detect_strongest_encryption():
    """
    Detect the strongest encryption type supported by the local tooling.

    Returns:
        str: The strongest available entry from ENCRYPTION_STRENGTH_ORDER.
    """
    if is_bcrypt_available():
        return "Bcrypt"
    if crypt_method_available("METHOD_SHA512"):
        return "Crypt-SHA-512"
    if crypt_method_available("METHOD_SHA256"):
        return "Crypt-SHA-256"
    if crypt is not None:
        # glibc's crypt() has supported MD5-based hashes for decades; if the
        # module imported at all, $apr1$/$1$ are safe to assume.
        return "APR1Crypt"
    return "SHA"


def resolve_encryption(encryption_type):
    """Resolve the "auto" placeholder to a concrete encryption type."""
    if encryption_type == "auto":
        return detect_strongest_encryption()
    return encryption_type


def prompt_for_password(username):
    """Prompt for a password without echoing it to the terminal."""
    password = getpass.getpass(f"Password for '{username}': ")
    confirm = getpass.getpass(f"Confirm password for '{username}': ")
    if password != confirm:
        print("Error: passwords did not match.", file=sys.stderr)
        sys.exit(1)
    return password


def split_user_pass(pair):
    """
    Split a "username[:password]" string, prompting for the password if omitted.

    Args:
        pair (str): The "username" or "username:password" string.

    Returns:
        tuple[str, str]: (username, password)
    """
    if ':' in pair:
        username, password = pair.split(':', 1)
    else:
        username, password = pair, ''
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if not password:
        password = prompt_for_password(username)
    return username, password


def add_or_update_user(output_file, username, password, encryption_type, force=False):
    """
    Add or update a user's password in the password file.

    Args:
        output_file (str): The path to the password file.
        username (str): The username.
        password (str): The password.
        encryption_type (str): The type of encryption to use.
        force (bool): Skip the interactive confirmation prompt when overwriting.

    Returns:
        None
    """
    lines = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            lines = f.readlines()

    prefix = f"{username}:"
    existing_index = next((i for i, line in enumerate(lines) if line.startswith(prefix)), None)

    if existing_index is not None:
        if not force:
            choice = input(f"User '{username}' already exists. Do you want to change its password? [y/N]: ")
            if choice.lower() != 'y':
                print("Password not updated.")
                return
        hashed_password = hash_password(password, encryption_type)
        lines[existing_index] = f"{username}:{hashed_password}\n"
        with open(output_file, 'w') as f:
            f.writelines(lines)
        print(f"Password for user '{username}' updated successfully.")
    else:
        hashed_password = hash_password(password, encryption_type)
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'a') as f:
            f.write(f"{username}:{hashed_password}\n")
        print(f"User '{username}' added successfully.")


def delete_user(output_file, username, force=False, double_confirm=True):
    """
    Delete a user from the password file.

    Args:
        output_file (str): The path to the password file.
        username (str): The username to delete.
        force (bool): Skip the interactive confirmation prompt(s) entirely.
        double_confirm (bool): Ask a second, stronger confirmation after the first.

    Returns:
        None
    """
    if not force:
        if input(f"Are you sure you want to delete user '{username}'? [y/N]: ").lower() != 'y':
            return
        if double_confirm:
            if input(f"This is permanent and cannot be undone. Delete '{username}'? [y/N]: ").lower() != 'y':
                return
    with open(output_file, 'r') as f:
        lines = f.readlines()

    with open(output_file, 'w') as f:
        for line in lines:
            if not line.startswith(username + ':'):
                f.write(line)

    print(f"User '{username}' deleted successfully.")


def get_usernames(output_file):
    """
    Read the usernames currently in the password file.

    Args:
        output_file (str): The path to the password file.

    Returns:
        list[str]: Usernames in file order.
    """
    if not os.path.exists(output_file):
        return []
    with open(output_file, 'r') as f:
        return [line.split(':', 1)[0] for line in f if line.strip() and ':' in line]


def list_users(output_file):
    """
    Print the usernames currently in the password file.

    Args:
        output_file (str): The path to the password file.

    Returns:
        None
    """
    usernames = get_usernames(output_file)
    if not usernames:
        print("No users found.")
        return
    for username in usernames:
        print(username)


def recipients_env_path(output_file):
    """Path to the generated SMTP allowed-recipients env file, next to the password file."""
    return os.path.join(os.path.dirname(output_file) or '.', "smtp_allowed_recipients.env")


def sync_allowed_recipients(output_file, domain):
    """
    Regenerate the MP_SMTP_ALLOWED_RECIPIENTS env file to match the users
    currently in the password file, so Mailpit's allowed recipients always
    track who's actually in passwords.txt.

    Args:
        output_file (str): The path to the password file.
        domain (str): The mail domain to append to each username.

    Returns:
        None
    """
    usernames = get_usernames(output_file)
    if usernames:
        pattern = "(?i)^(" + "|".join(re.escape(u) for u in usernames) + ")@" + re.escape(domain) + "$"
    else:
        pattern = "^$"  # No users: matches nothing, since a real recipient is never empty.

    env_path = recipients_env_path(output_file)
    os.makedirs(os.path.dirname(env_path) or '.', exist_ok=True)
    with open(env_path, 'w') as f:
        f.write(f"MP_SMTP_ALLOWED_RECIPIENTS={pattern}\n")
    print(f"Updated {env_path} ({len(usernames)} user(s)).")


def find_compose_file():
    """
    Look for a docker-compose file next to the script, checking common
    filenames in COMPOSE_FILE_CANDIDATES order.

    Returns:
        str | None: Path to the first matching file, or None if none exist.
    """
    for name in COMPOSE_FILE_CANDIDATES:
        candidate = os.path.join(SCRIPT_DIR, name)
        if os.path.exists(candidate):
            return candidate
    return None


def ensure_env_file_exists(env_path):
    """
    Create the SMTP allowed-recipients env file with a deny-all default if
    it doesn't exist yet. Never overwrites an existing file.

    Args:
        env_path (str): Path to the SMTP allowed-recipients env file.

    Returns:
        None
    """
    if os.path.exists(env_path):
        return
    os.makedirs(os.path.dirname(env_path) or '.', exist_ok=True)
    with open(env_path, 'w') as f:
        f.write("MP_SMTP_ALLOWED_RECIPIENTS=^$\n")
    print(f"Created {env_path} (no users yet; deny-all default).")


def ensure_compose_env_file(compose_path, env_path):
    """
    Make sure the mailpit service in a docker-compose file references the
    generated SMTP allowed-recipients env file, adding an env_file: entry if
    it's missing (and creating the env file itself, with a deny-all default,
    if it doesn't exist yet either). Leaves the compose file untouched if it
    doesn't exist (or isn't set), if the env file is already referenced
    anywhere in it, or if a "mailpit:" service with an "environment:" key
    can't be confidently located (edits are only ever additive, never
    guessed).

    Args:
        compose_path (str): Path to the docker-compose YAML file.
        env_path (str): Path to the generated SMTP allowed-recipients env file.

    Returns:
        None
    """
    if not compose_path or not os.path.exists(compose_path):
        return

    with open(compose_path, 'r') as f:
        lines = f.readlines()

    env_basename = os.path.basename(env_path)
    if any(env_basename in line for line in lines):
        return  # Already referenced somewhere; don't touch the file.

    rel_env_path = os.path.relpath(env_path, os.path.dirname(compose_path) or '.')
    if not rel_env_path.startswith('.'):
        rel_env_path = './' + rel_env_path

    service_indent = None
    insert_index = None
    for i, line in enumerate(lines):
        stripped = line.rstrip('\n')
        service_match = re.match(r'^(\s+)mailpit:\s*$', stripped)
        if service_match:
            service_indent = len(service_match.group(1))
            continue
        if service_indent is None:
            continue
        key_match = re.match(r'^(\s*)\S', stripped)
        if not key_match:
            continue
        indent = len(key_match.group(1))
        if indent <= service_indent:
            service_indent = None  # Left the mailpit service block.
            continue
        if indent == service_indent + 2 and re.match(r'^\s*environment:\s*$', stripped):
            insert_index = i
            break

    if insert_index is None:
        print(f"Note: couldn't find a 'mailpit:' service with an 'environment:' key in {compose_path}; add env_file: for {rel_env_path} manually.")
        return

    ensure_env_file_exists(env_path)

    indent_str = ' ' * (service_indent + 2)
    new_lines = [
        f"{indent_str}env_file:\n",
        f"{indent_str}  - path: {rel_env_path}   # Added by mailpit-auth.py: MP_SMTP_ALLOWED_RECIPIENTS\n",
        f"{indent_str}    required: false\n",
    ]
    lines[insert_index:insert_index] = new_lines
    with open(compose_path, 'w') as f:
        f.writelines(lines)
    print(f"Added env_file: entry for {rel_env_path} to {compose_path}.")


def check_password(password, stored_hash):
    """
    Check a plaintext password against a stored hash of any supported type.

    Args:
        password (str): The plaintext password to check.
        stored_hash (str): The hash (or plaintext) value stored in the password file.

    Returns:
        bool: True if the password matches.
    """
    if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        return bcrypt.verify(password, stored_hash)
    if stored_hash.startswith(("$apr1$", "$1$", "$5$", "$6$")):
        if crypt is None:
            raise RuntimeError("The stdlib 'crypt' module is unavailable; cannot verify this hash type.")
        return crypt.crypt(password, stored_hash) == stored_hash

    ssha_value = stored_hash[len("{SSHA}"):] if stored_hash.startswith("{SSHA}") else stored_hash
    try:
        raw = base64.b64decode(ssha_value, validate=True)
    except Exception:
        raw = None
    # SSHA/SHA values decode to a 20-byte SHA1 digest plus a 4-byte salt. This
    # is a heuristic: a plaintext password that happens to be valid base64 of
    # exactly that length would be misread as SSHA. Not expected in practice.
    if raw is not None and len(raw) > 20:
        digest, salt = raw[:20], raw[20:]
        hash_obj = hashlib.sha1(password.encode())
        hash_obj.update(salt)
        return hash_obj.digest() == digest

    return password == stored_hash


def verify_user(output_file, username, password):
    """
    Verify a username/password pair against the password file.

    Args:
        output_file (str): The path to the password file.
        username (str): The username to look up.
        password (str): The plaintext password to check.

    Returns:
        None
    """
    if not os.path.exists(output_file):
        print(f"No password file found at '{output_file}'.")
        return
    with open(output_file, 'r') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or ':' not in line:
                continue
            stored_user, stored_hash = line.split(':', 1)
            if stored_user != username:
                continue
            if check_password(password, stored_hash):
                print(f"OK: password for '{username}' is correct.")
            else:
                print(f"FAIL: password for '{username}' is incorrect.")
            return
    print(f"User '{username}' not found.")


def bulk_import(output_file, input_file, encryption_type, force=False):
    """
    Add or update users from a file of "username:password" lines.

    Args:
        output_file (str): The path to the password file.
        input_file (str): Path to a file containing one "username:password" pair per line.
        encryption_type (str): The type of encryption to use.
        force (bool): Skip interactive confirmation prompts.

    Returns:
        None
    """
    with open(input_file, 'r') as f:
        raw_lines = [line.strip() for line in f]

    for raw_line in raw_lines:
        if not raw_line or raw_line.startswith('#'):
            continue
        if ':' not in raw_line:
            print(f"Error: skipping invalid line (missing ':'): {raw_line}")
            continue
        username, password = raw_line.split(':', 1)
        username, password = username.strip(), password.strip()
        if not username or not password:
            print(f"Error: skipping invalid line (empty username/password): {raw_line}")
            continue
        add_or_update_user(output_file, username, password, encryption_type, force=force)


def hash_password(password, encryption_type):
    """
    Hash the password using the specified encryption type.

    Args:
        password (str): The password to hash.
        encryption_type (str): The type of encryption to use.

    Returns:
        str: The hashed password.
    """
    if encryption_type == "plain":
        return password
    elif encryption_type == "SSHA":
        salt = os.urandom(4)
        hash_obj = hashlib.sha1(password.encode())
        hash_obj.update(salt)
        return base64.b64encode(hash_obj.digest() + salt).decode()
    elif encryption_type == "MD5Crypt":
        return crypt.crypt(password, "$1$")
    elif encryption_type == "APR1Crypt":
        return crypt.crypt(password, "$apr1$")
    elif encryption_type == "SHA":
        salt = os.urandom(4)
        hash_obj = hashlib.sha1(password.encode())
        hash_obj.update(salt)
        return "{SSHA}" + base64.b64encode(hash_obj.digest() + salt).decode()
    elif encryption_type == "Crypt-SHA-256":
        return crypt.crypt(password, "$5$" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16)))
    elif encryption_type == "Crypt-SHA-512":
        return crypt.crypt(password, "$6$" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16)))
    elif encryption_type == "Bcrypt":
        return bcrypt.hash(password)
    else:
        raise ValueError("Unsupported encryption type.")


def main():
    """
    Main function to parse command line arguments and execute appropriate actions.
    """
    parser = argparse.ArgumentParser(description="Manage a password file for Mailpit authentication.")
    parser.add_argument("username_password_pairs", nargs='*', help="Username and password pairs (username:password). Omit the password to be prompted.")
    parser.add_argument("-o", "--output", default=None, help=f"Output file for the password file. Default is \"{DEFAULT_OUTPUT}\".")
    parser.add_argument("-e", "--encryption", default=None, choices=ENCRYPTION_CHOICES, help="Encryption type for passwords. Default is \"auto\" (strongest available).")
    parser.add_argument("-d", "--delete", help="Delete the specified user from the password file.")
    parser.add_argument("-l", "--list", action="store_true", help="List the usernames currently in the password file.")
    parser.add_argument("-v", "--verify", help="Verify a username:password pair (or bare username, to be prompted) against the stored hash.")
    parser.add_argument("-i", "--input", help="Bulk-add/update users from a file of username:password lines.")
    parser.add_argument("-f", "--force", action="store_true", default=None, help="Skip interactive y/N confirmation prompts for updates and deletions.")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help=f"Path to the config file. Default is \"{DEFAULT_CONFIG_PATH}\".")
    parser.add_argument("-m", "--domain", default=None, help="Mail domain used to build the SMTP allowed-recipients env file. Default is \"mailpit\".")
    parser.add_argument("-u", "--update", action="store_true", help="Regenerate the SMTP allowed-recipients env file from the current password file, without adding/updating/deleting a user.")
    parser.add_argument("-s", "--single-confirm-delete", action="store_true", help="Ask only the original single [y/N] prompt before deleting a user, instead of the default double confirmation.")
    parser.add_argument("-y", "--compose-file", default=None, help="Path to the docker-compose file to keep in sync with the SMTP allowed-recipients env file. Default: auto-detected next to this script (" + ", ".join(COMPOSE_FILE_CANDIDATES) + ").")
    args = parser.parse_args()

    config = load_config(args.config)[CONFIG_SECTION]

    output = args.output or config.get("output", DEFAULT_OUTPUT)
    encryption = resolve_encryption(args.encryption or config.get("encryption", "auto"))
    force = args.force if args.force is not None else config.getboolean("force", fallback=False)
    domain = args.domain or config.get("domain", "mailpit")
    double_confirm_delete = config.getboolean("double_confirm_delete", fallback=True)
    if args.single_confirm_delete:
        double_confirm_delete = False
    compose_file = args.compose_file or config.get("compose_file", None) or find_compose_file()

    mutating = False
    if args.list:
        list_users(output)
    elif args.verify:
        username, password = split_user_pass(args.verify)
        verify_user(output, username, password)
    elif args.delete:
        delete_user(output, args.delete, force=force, double_confirm=double_confirm_delete)
        mutating = True
    elif args.input:
        bulk_import(output, args.input, encryption, force=force)
        mutating = True
    elif args.update:
        mutating = True
    elif args.username_password_pairs:
        for pair in args.username_password_pairs:
            try:
                username, password = split_user_pass(pair)
            except ValueError as exc:
                print(f"Error: {exc}")
                continue
            add_or_update_user(output, username, password, encryption, force=force)
        mutating = True
    else:
        parser.print_help(sys.stderr)

    if mutating:
        sync_allowed_recipients(output, domain)
        ensure_compose_env_file(compose_file, recipients_env_path(output))


if __name__ == "__main__":
    main()
