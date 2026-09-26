"""HIBP Pwned Passwords range API (k-anonymity).

Reuses VaultCheck HTTP patterns: requests + user-agent + 429 retry.
Only the first 5 hex chars of the SHA-1 hash are sent to HIBP.
"""
import hashlib
import time

import requests


def check_password_pwned(password):
    """
    Check if a password appears in known breaches via HIBP Pwned Passwords
    range API (k-anonymity). Only the first 5 hex chars of the SHA-1 hash
    are sent; the full password and full hash never leave this process.

    Returns:
        int | None: occurrence count if found, 0 if not found, None on error.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "user-agent": "VaultCheck-Security-Audit-Tool",
        "Add-Padding": "true",
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            for line in response.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) != 2:
                    continue
                if parts[0].upper() == suffix:
                    return int(parts[1])
            return 0
        elif response.status_code == 429:
            retry_after = int(response.headers.get("retry-after", 2))
            print(f"  ⏳ Rate limited — waiting {retry_after}s...")
            time.sleep(retry_after + 1)
            return check_password_pwned(password)  # Retry
        else:
            print(f"  ⚠️  Unexpected response {response.status_code} from Pwned Passwords")
            return None

    except requests.exceptions.RequestException as e:
        print(f"  ❌ Network error checking password: {e}")
        return None


def print_password_result(count):
    """Print terminal output for a password range check."""
    if count is None:
        print("  ⚠️  ERROR — Could not check this password")
        return
    if count == 0:
        print("  🟢 NOT FOUND — Password not in known breach corpora")
        print("  ✅ Still use unique passwords + 2FA everywhere")
        return
    print(f"  🔴 PWNED — Seen {count:,} times in breach corpora")
    print("  🔧 ACTION: Stop using this password immediately")
    print("  🔐 ENABLE: Unique password via a password manager + 2FA")
