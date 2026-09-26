#!/usr/bin/env python3
"""VaultCheck password check entrypoint (HIBP Pwned Passwords k-anonymity).

Usage:
  python vaultcheck_password_cli.py

Only the first 5 hex chars of the SHA-1 hash are sent to HIBP.
No API key required. See also patches/001-wire-check-password-cli.patch
to wire the same flow into vaultcheck.py as --check-password.
"""
import getpass
import sys

from hibp_passwords import check_password_pwned, print_password_result


def main():
    print("\n" + "=" * 56)
    print("  🔐 VAULTCHECK — Password Check (k-anonymity)")
    print("  By Michael Chaves | github.com/michael-chaves-dev")
    print("=" * 56)
    print("\n🔑 Only the SHA-1 hash prefix is sent to HIBP.")
    print("Password input is not echoed. Press ENTER to cancel.\n")
    try:
        password = getpass.getpass("  🔑 Password: ")
    except Exception:
        password = input("  🔑 Password: ")
    if not password:
        print("❌ No password provided.")
        sys.exit(1)
    print("\n🔍 Checking password via HIBP range API...")
    count = check_password_pwned(password)
    print_password_result(count)
    print("=" * 56 + "\n")


if __name__ == "__main__":
    main()
