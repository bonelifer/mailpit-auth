#!/usr/bin/env python3
"""
Script: set-bind-address.py
Description: Points Mailpit's UI/SMTP/POP3 bind addresses (MP_UI_BIND_ADDR,
             MP_SMTP_BIND_ADDR, MP_POP3_BIND_ADDR) in a docker-compose file at
             the host's private IP instead of 0.0.0.0, or reverts them back.
Input: One of -a/--auto, -i/--ip, or -r/--revert is required to change anything;
       running with none of those just prints this help and exits.
Output: An updated docker-compose file.
Usage: ./set-bind-address.py [options]
Options:
  -y, --compose-file <path>: Path to the docker-compose file to update. Default:
                        the "compose_file" setting in config.ini, or auto-detected
                        next to this script (compose.yaml, compose.yml,
                        docker-compose.yaml, docker-compose.yml, in that order).
  -a, --auto: List candidate addresses (the host's auto-detected private IP and
                        127.0.0.1) and prompt for which one to apply. Non-interactively
                        (stdin isn't a TTY), applies the auto-detected IP, or 127.0.0.1
                        if that couldn't be detected.
  -i, --ip <address>: Apply this specific IP address instead of auto-detecting.
  -r, --revert: Revert MP_UI_BIND_ADDR/MP_SMTP_BIND_ADDR/MP_POP3_BIND_ADDR back to
                        0.0.0.0 instead of setting a private IP.
  -n, --dry-run: Show what would change without writing the file. Only takes
                        effect combined with -a, -i, or -r.
  -c, --config <config_file>: Path to the config file (shares config.ini/compose_file
                        with mailpit-auth.py). Default is "config.ini" next to this
                        script.
"""

import argparse
import configparser
import os
import re
import socket
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.ini")
CONFIG_SECTION = "mailpit-auth"

# Same search order as mailpit-auth.py, so both scripts agree on which
# compose file to touch when neither -y/--compose-file nor the compose_file
# config setting is given.
COMPOSE_FILE_CANDIDATES = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]

BIND_ADDR_RE = re.compile(r'^(\s*MP_(?:UI|SMTP|POP3)_BIND_ADDR:\s*)([0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d+)(.*)$')


def load_config(config_path):
    """
    Load the config file, if present.

    Args:
        config_path (str): Path to the config file.

    Returns:
        configparser.SectionProxy: Parsed config section (empty if the file doesn't exist).
    """
    config = configparser.ConfigParser()
    config[CONFIG_SECTION] = {}
    if os.path.exists(config_path):
        config.read(config_path)
    return config[CONFIG_SECTION]


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


def get_private_ip():
    """
    Detect the host's private IP: the address the OS would use to reach the
    outside network. No packets are actually sent (UDP connect just picks a
    route).

    Returns:
        str: The detected IP address.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    finally:
        s.close()


def choose_address(candidates):
    """
    Prompt the user to pick one of several candidate addresses. Falls back
    to the first candidate without prompting when stdin isn't a TTY (e.g.
    scripted/non-interactive use).

    Args:
        candidates (list[tuple[str, str]]): (ip, label) pairs, in the order
            they should be offered; the first is the default.

    Returns:
        str: The chosen IP address.
    """
    if not sys.stdin.isatty():
        return candidates[0][0]

    print("Available addresses:")
    for i, (ip, label) in enumerate(candidates, start=1):
        print(f"  {i}) {ip} ({label})")

    while True:
        choice = input(f"Choose an address [1]: ").strip()
        if not choice:
            return candidates[0][0]
        if choice.isdigit() and 1 <= int(choice) <= len(candidates):
            return candidates[int(choice) - 1][0]
        print(f"Enter a number between 1 and {len(candidates)}.")


def update_bind_addresses(compose_path, target_ip, dry_run=False):
    """
    Rewrite the host portion of every MP_UI_BIND_ADDR/MP_SMTP_BIND_ADDR/
    MP_POP3_BIND_ADDR line in a docker-compose file to target_ip, leaving the
    port and any trailing comment untouched. Lines already set to target_ip
    are left alone.

    Args:
        compose_path (str): Path to the docker-compose YAML file.
        target_ip (str): The IP address to set (or "0.0.0.0" to revert).
        dry_run (bool): Show what would change without writing.

    Returns:
        int: 0 on success, 1 if the compose file couldn't be found.
    """
    if not compose_path or not os.path.exists(compose_path):
        print(f"Error: compose file not found: {compose_path}")
        return 1

    with open(compose_path, 'r') as f:
        lines = f.readlines()

    changed = []
    for i, line in enumerate(lines):
        match = BIND_ADDR_RE.match(line.rstrip('\n'))
        if not match:
            continue
        prefix, old_ip, port, rest = match.groups()
        if old_ip == target_ip:
            continue
        new_line = f"{prefix}{target_ip}:{port}{rest}\n"
        changed.append((line.rstrip('\n'), new_line.rstrip('\n')))
        lines[i] = new_line

    if not changed:
        print(f"No MP_*_BIND_ADDR lines to update in {compose_path} (already {target_ip}, or none found).")
        return 0

    for old, new in changed:
        print(f"  {old.strip()}")
        print(f"    -> {new.strip()}")

    if dry_run:
        print(f"Dry run: {len(changed)} line(s) would change in {compose_path}.")
        return 0

    with open(compose_path, 'w') as f:
        f.writelines(lines)
    print(f"Updated {len(changed)} line(s) in {compose_path}.")
    return 0


def main():
    """
    Main function to parse command line arguments and update bind addresses.
    """
    parser = argparse.ArgumentParser(description="Point Mailpit's UI/SMTP/POP3 bind addresses at the system's private IP instead of 0.0.0.0.")
    parser.add_argument("-y", "--compose-file", default=None, help="Path to the docker-compose file to update. Default: compose_file config setting, or auto-detected next to this script.")
    parser.add_argument("-a", "--auto", action="store_true", help="Auto-detect the private IP and apply it.")
    parser.add_argument("-i", "--ip", default=None, help="IP address to bind to.")
    parser.add_argument("-r", "--revert", action="store_true", help="Revert MP_UI_BIND_ADDR/MP_SMTP_BIND_ADDR/MP_POP3_BIND_ADDR back to 0.0.0.0.")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Show what would change without writing the file. Only takes effect combined with -a, -i, or -r.")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help=f"Path to the config file. Default is \"{DEFAULT_CONFIG_PATH}\".")
    args = parser.parse_args()

    if not (args.auto or args.ip or args.revert):
        parser.print_help(sys.stderr)
        return 0

    config = load_config(args.config)
    compose_file = args.compose_file or config.get("compose_file", None) or find_compose_file()

    if args.revert:
        target_ip = "0.0.0.0"
    elif args.ip:
        target_ip = args.ip
    else:
        candidates = []
        try:
            candidates.append((get_private_ip(), "auto-detected"))
        except OSError as exc:
            print(f"Note: couldn't auto-detect a private IP ({exc}).")
        candidates.append(("127.0.0.1", "localhost"))
        target_ip = choose_address(candidates)

    return update_bind_addresses(compose_file, target_ip, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
