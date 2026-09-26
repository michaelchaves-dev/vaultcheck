# vaultcheck

Python email breach detection tool powered by the HaveIBeenPwned API.

## Features

- **Email breach lookup** via HIBP API v3 (`breachedaccount`) — requires API key
- **Password check** via HIBP Pwned Passwords **range API** (k-anonymity) — no API key
- Risk scoring + Excel security audit report

## Setup

1. Create a `.env` file: `HIBP_API_KEY=your_actual_key_here`
2. Install deps: `pip install requests pandas openpyxl`

## Usage

```bash
# Interactive email check
python vaultcheck.py

# Bulk CSV (column named email)
python vaultcheck.py emails.csv

# Password check (only SHA-1 prefix leaves your machine)
python vaultcheck_password_cli.py
```

Optional: apply `patches/001-wire-check-password-cli.patch` to expose the same
flow as `python vaultcheck.py --check-password`.

## Privacy (password mode)

VaultCheck hashes the password with SHA-1 locally, sends only the first 5 hex characters to `api.pwnedpasswords.com/range/{prefix}`, and matches the remaining suffix locally. The full password and full hash never leave the process.

## Tests

```bash
python -m unittest test_password_check.py -v
```
