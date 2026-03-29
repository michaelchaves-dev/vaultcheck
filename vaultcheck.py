"""
=============================================================
  VAULTCHECK — Email Breach Detection & Security Audit Tool
  By Michael Chaves | github.com/michael-chaves-dev
=============================================================

HOW TO SET UP YOUR API KEY SECURELY:
  1. Create a file called .env in the same folder as this script
  2. Add this line to it:  HIBP_API_KEY=your_actual_key_here
  3. Save the file — it will NEVER be uploaded to GitHub
  4. Run: python vaultcheck.py

HOW TO RUN:
  Single email:  python vaultcheck.py
  Bulk CSV:      python vaultcheck.py emails.csv

CSV FORMAT (emails.csv):
  email
  john@example.com
  jane@company.com
=============================================================
"""

import os
import sys
import time
import hashlib
import requests
import pandas as pd
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
#  LOAD API KEY FROM .env FILE
# ─────────────────────────────────────────────
def load_api_key():
    """Load API key from .env file — never hardcode keys in source code."""
    env_path = Path(".env")
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("HIBP_API_KEY="):
                    key = line.split("=", 1)[1].strip()
                    if key and key != "your_actual_key_here":
                        return key
    print("\n⚠️  API KEY NOT FOUND")
    print("Please create a .env file in this folder with:")
    print("  HIBP_API_KEY=your_actual_key_here\n")
    sys.exit(1)

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
NAVY        = "1B2A4A"
RED         = "DC2626"
GREEN       = "16A34A"
YELLOW      = "EAB308"
ACCENT      = "2563EB"
WHITE       = "FFFFFF"
LIGHT_RED   = "FEF2F2"
LIGHT_GREEN = "F0FDF4"
LIGHT_YELLOW= "FEFCE8"
LIGHT_BLUE  = "EFF6FF"
GRAY        = "F8FAFC"
MID_GRAY    = "64748B"
BLACK       = "0F172A"

# ─────────────────────────────────────────────
#  HIBP API — CHECK EMAIL FOR BREACHES
# ─────────────────────────────────────────────
def check_email_breaches(email, api_key):
    """
    Check if an email appears in known data breaches.
    Uses the HaveIBeenPwned API v3.
    Returns list of breaches or empty list if clean.
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "VaultCheck-Security-Audit-Tool"
    }
    params = {"truncateResponse": "false"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return []  # Clean — not found in any breach
        elif response.status_code == 429:
            retry_after = int(response.headers.get("retry-after", 2))
            print(f"  ⏳ Rate limited — waiting {retry_after}s...")
            time.sleep(retry_after + 1)
            return check_email_breaches(email, api_key)  # Retry
        elif response.status_code == 401:
            print("❌ Invalid API key. Please check your .env file.")
            sys.exit(1)
        else:
            print(f"  ⚠️  Unexpected response {response.status_code} for {email}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"  ❌ Network error checking {email}: {e}")
        return None

# ─────────────────────────────────────────────
#  RISK SCORING ENGINE
# ─────────────────────────────────────────────
def calculate_risk_score(breaches):
    """
    Calculate risk score (0-100) based on breach data.
    Factors: number of breaches, recency, data types exposed.
    """
    if not breaches:
        return 0, "LOW", GREEN

    score = 0
    sensitive_classes = [
        "Passwords", "Credit cards", "Bank account numbers",
        "Social security numbers", "Phone numbers", "Physical addresses"
    ]

    for breach in breaches:
        # Base score per breach
        score += 15

        # Recency factor
        breach_date = breach.get("BreachDate", "2000-01-01")
        breach_year = int(breach_date[:4]) if breach_date else 2000
        current_year = datetime.now().year
        years_ago = current_year - breach_year
        if years_ago <= 2:
            score += 20
        elif years_ago <= 5:
            score += 10
        else:
            score += 5

        # Sensitive data factor
        data_classes = breach.get("DataClasses", [])
        for cls in data_classes:
            if cls in sensitive_classes:
                score += 10

        # Verified breach factor
        if breach.get("IsVerified", False):
            score += 5

    # Cap at 100
    score = min(score, 100)

    # Risk level
    if score >= 70:
        return score, "CRITICAL", RED
    elif score >= 40:
        return score, "HIGH", "E85D04"
    elif score >= 20:
        return score, "MEDIUM", YELLOW
    else:
        return score, "LOW", GREEN

# ─────────────────────────────────────────────
#  TERMINAL OUTPUT
# ─────────────────────────────────────────────
def print_results(email, breaches, risk_score, risk_level):
    """Print clean terminal output for each email checked."""
    print(f"\n  📧 {email}")

    if breaches is None:
        print(f"  ⚠️  ERROR — Could not check this email")
        return

    if not breaches:
        print(f"  🟢 CLEAN — No breaches found")
        print(f"  ✅ RISK LEVEL: LOW")
        return

    breach_count = len(breaches)
    emoji = "🔴" if risk_level in ["CRITICAL", "HIGH"] else "🟡"
    print(f"  {emoji} BREACHED — Found in {breach_count} known breach{'es' if breach_count > 1 else ''}")

    # Show top 3 breaches
    for breach in breaches[:3]:
        name = breach.get("Title", breach.get("Name", "Unknown"))
        date = breach.get("BreachDate", "Unknown date")
        count = breach.get("PwnCount", 0)
        print(f"     • {name} ({date[:4]}) — {count:,} accounts affected")

    if breach_count > 3:
        print(f"     • ...and {breach_count - 3} more breach{'es' if breach_count - 3 > 1 else ''}")

    print(f"  ⚠️  RISK LEVEL: {risk_level} (Score: {risk_score}/100)")
    print(f"  🔧 ACTION: Change passwords on all affected accounts immediately")
    print(f"  🔐 ENABLE: Two-factor authentication on all accounts")

# ─────────────────────────────────────────────
#  EXCEL REPORT GENERATOR
# ─────────────────────────────────────────────
def thin_border():
    s = Side(style="thin", color="CBD5E1")
    return Border(left=s, right=s, top=s, bottom=s)

def style_cell(cell, bold=False, color=None, bg=None, align="left", size=10, wrap=False):
    cell.font = Font(name="Arial", bold=bold, size=size, color=color or BLACK)
    if bg:
        cell.fill = PatternFill("solid", start_color=bg)
    cell.alignment = Alignment(horizontal=align, vertical="center", wrap_text=wrap)
    cell.border = thin_border()

def generate_excel_report(results, output_path):
    """Generate a professional 3-tab Excel security audit report."""
    wb = openpyxl.Workbook()

    # ── SHEET 1: EXECUTIVE SUMMARY ──────────────────────────────
    ws1 = wb.active
    ws1.title = "📊 Executive Summary"
    ws1.sheet_view.showGridLines = False
    ws1.column_dimensions["A"].width = 3

    # Header
    ws1.merge_cells("B2:H2")
    c = ws1["B2"]
    c.value = "VAULTCHECK — EMAIL SECURITY AUDIT REPORT"
    style_cell(c, bold=True, color=WHITE, bg=NAVY, align="center", size=16)
    ws1.row_dimensions[2].height = 36

    ws1.merge_cells("B3:H3")
    c = ws1["B3"]
    c.value = f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}  |  Powered by HaveIBeenPwned API"
    style_cell(c, color=WHITE, bg=ACCENT, align="center", size=10)
    ws1.row_dimensions[3].height = 20

    # KPI calculations
    total = len(results)
    breached = sum(1 for r in results if r["breach_count"] > 0)
    clean = total - breached
    critical = sum(1 for r in results if r["risk_level"] == "CRITICAL")
    high = sum(1 for r in results if r["risk_level"] == "HIGH")
    total_breaches = sum(r["breach_count"] for r in results)
    avg_score = sum(r["risk_score"] for r in results) / total if total else 0

    kpis = [
        ("Total Emails Audited", total, WHITE, NAVY),
        ("Compromised Emails", breached, WHITE, RED),
        ("Clean Emails", clean, WHITE, GREEN),
        ("Critical Risk", critical, WHITE, "7F1D1D"),
        ("High Risk", high, WHITE, "92400E"),
        ("Total Breach Events", total_breaches, WHITE, ACCENT),
        ("Avg Risk Score", f"{avg_score:.0f}/100", WHITE, MID_GRAY),
    ]

    kpi_cols = ["B", "C", "D", "E", "F", "G", "H"]
    col_widths = [20, 20, 18, 16, 16, 20, 18]
    for col, w in zip(kpi_cols, col_widths):
        ws1.column_dimensions[col].width = w

    ws1.row_dimensions[5].height = 26
    ws1.row_dimensions[6].height = 44
    ws1.row_dimensions[7].height = 26

    for i, (label, value, fcolor, bg) in enumerate(kpis):
        col = kpi_cols[i]
        lc = ws1[f"{col}5"]
        lc.value = label
        style_cell(lc, bold=True, color="94A3B8", bg="1E293B", align="center", size=9)

        vc = ws1[f"{col}6"]
        vc.value = value
        style_cell(vc, bold=True, color=fcolor, bg=bg, align="center", size=14)

    # Recommendations section
    ws1.row_dimensions[9].height = 24
    ws1.merge_cells("B9:H9")
    c = ws1["B9"]
    c.value = "  🔧 SECURITY RECOMMENDATIONS"
    style_cell(c, bold=True, color=WHITE, bg=NAVY, size=11)

    recommendations = [
        ("🔴 IMMEDIATE", "Change passwords on ALL breached accounts right now", RED),
        ("🔐 HIGH PRIORITY", "Enable two-factor authentication on every account", "E85D04"),
        ("🛡️ IMPORTANT", "Use a unique password for every single account", YELLOW),
        ("✅ BEST PRACTICE", "Use a password manager like Bitwarden or 1Password", GREEN),
        ("📧 MONITOR", "Set up breach notifications at haveibeenpwned.com", ACCENT),
    ]

    for r, (priority, action, color) in enumerate(recommendations):
        rn = 10 + r
        ws1.row_dimensions[rn].height = 22

        pc = ws1[f"B{rn}"]
        pc.value = priority
        style_cell(pc, bold=True, color=WHITE, bg=color, align="center", size=10)

        ac = ws1[f"C{rn}"]
        ws1.merge_cells(f"C{rn}:H{rn}")
        ac.value = action
        style_cell(ac, color=BLACK, bg=LIGHT_BLUE if r % 2 == 0 else WHITE, size=10)

    # ── SHEET 2: ALL EMAILS DETAIL ───────────────────────────────
    ws2 = wb.create_sheet("📧 All Emails")
    ws2.sheet_view.showGridLines = False
    ws2.freeze_panes = "A2"

    headers = ["Email Address", "Status", "Breach Count", "Risk Score", "Risk Level", "Most Recent Breach", "Data Types Exposed", "Recommended Action"]
    col_widths2 = [32, 14, 14, 12, 14, 20, 40, 30]

    for i, (h, w) in enumerate(zip(headers, col_widths2)):
        c = ws2.cell(row=1, column=i+1)
        c.value = h
        style_cell(c, bold=True, color=WHITE, bg=NAVY, align="center", size=10)
        ws2.column_dimensions[get_column_letter(i+1)].width = w
    ws2.row_dimensions[1].height = 24

    # Sort by risk score descending
    sorted_results = sorted(results, key=lambda x: x["risk_score"], reverse=True)

    for r, result in enumerate(sorted_results):
        rn = r + 2
        is_breached = result["breach_count"] > 0

        if result["risk_level"] == "CRITICAL":
            bg = LIGHT_RED
        elif result["risk_level"] in ["HIGH", "MEDIUM"]:
            bg = LIGHT_YELLOW
        elif is_breached:
            bg = LIGHT_YELLOW
        else:
            bg = LIGHT_GREEN if r % 2 == 0 else WHITE

        # Most recent breach
        most_recent = ""
        data_types = ""
        if result["breaches"]:
            sorted_breaches = sorted(result["breaches"],
                key=lambda x: x.get("BreachDate", "0000"), reverse=True)
            most_recent = f"{sorted_breaches[0].get('Title', 'Unknown')} ({sorted_breaches[0].get('BreachDate', '')[:4]})"
            all_classes = set()
            for b in result["breaches"]:
                all_classes.update(b.get("DataClasses", []))
            data_types = ", ".join(list(all_classes)[:5])
            if len(all_classes) > 5:
                data_types += f" +{len(all_classes)-5} more"

        action = "✅ No action needed" if not is_breached else "🔴 Change passwords immediately + enable 2FA"

        row_data = [
            result["email"],
            "🔴 BREACHED" if is_breached else "🟢 CLEAN",
            result["breach_count"],
            f"{result['risk_score']}/100",
            result["risk_level"],
            most_recent,
            data_types,
            action
        ]

        for j, val in enumerate(row_data):
            c = ws2.cell(row=rn, column=j+1)
            c.value = val
            align = "center" if j in [1, 2, 3, 4] else "left"
            c.alignment = Alignment(horizontal=align, vertical="center", wrap_text=True)
            c.font = Font(name="Arial", size=10)
            c.fill = PatternFill("solid", start_color=bg)
            c.border = thin_border()
        ws2.row_dimensions[rn].height = 20

    # ── SHEET 3: BREACHED EMAILS ONLY ───────────────────────────
    ws3 = wb.create_sheet("🔴 Breached Emails")
    ws3.sheet_view.showGridLines = False

    breached_results = [r for r in sorted_results if r["breach_count"] > 0]

    ws3.merge_cells("A1:G1")
    c = ws3["A1"]
    c.value = f"BREACHED EMAILS — {len(breached_results)} accounts compromised — Immediate action required"
    style_cell(c, bold=True, color=WHITE, bg=RED, align="center", size=12)
    ws3.row_dimensions[1].height = 28

    headers3 = ["Email Address", "Breach Name", "Breach Date", "Accounts Affected", "Data Types Exposed", "Verified", "Risk Level"]
    col_widths3 = [30, 22, 14, 20, 40, 12, 14]

    for i, (h, w) in enumerate(zip(headers3, col_widths3)):
        c = ws3.cell(row=2, column=i+1)
        c.value = h
        style_cell(c, bold=True, color=WHITE, bg="7F1D1D", align="center", size=10)
        ws3.column_dimensions[get_column_letter(i+1)].width = w

    row_num = 3
    for result in breached_results:
        for breach in result["breaches"]:
            bg = LIGHT_RED if row_num % 2 == 0 else "FFF1F1"
            data_classes = ", ".join(breach.get("DataClasses", [])[:4])

            row_data = [
                result["email"],
                breach.get("Title", breach.get("Name", "Unknown")),
                breach.get("BreachDate", "Unknown"),
                f"{breach.get('PwnCount', 0):,}",
                data_classes,
                "✅ Yes" if breach.get("IsVerified") else "⚠️ Unverified",
                result["risk_level"]
            ]

            for j, val in enumerate(row_data):
                c = ws3.cell(row=row_num, column=j+1)
                c.value = val
                c.alignment = Alignment(horizontal="center" if j in [2,3,5,6] else "left", vertical="center", wrap_text=True)
                c.font = Font(name="Arial", size=10)
                c.fill = PatternFill("solid", start_color=bg)
                c.border = thin_border()
            ws3.row_dimensions[row_num].height = 18
            row_num += 1

    wb.save(output_path)

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print("\n" + "="*56)
    print("  🔐 VAULTCHECK — Email Breach Detection Tool")
    print("  By Michael Chaves | github.com/michael-chaves-dev")
    print("="*56)

    api_key = load_api_key()

    # Get emails to check
    emails = []

    if len(sys.argv) > 1:
        # CSV file provided
        csv_path = sys.argv[1]
        if not os.path.exists(csv_path):
            print(f"❌ File not found: {csv_path}")
            sys.exit(1)
        df = pd.read_csv(csv_path)
        email_col = next((c for c in df.columns if "email" in c.lower()), df.columns[0])
        emails = df[email_col].dropna().tolist()
        print(f"\n📂 Loaded {len(emails)} emails from {csv_path}")
    else:
        # Interactive single email mode
        print("\nEnter email addresses to check (one per line)")
        print("Press ENTER twice when done:\n")
        while True:
            email = input("  📧 Email: ").strip()
            if not email:
                if emails:
                    break
                print("  Please enter at least one email address.")
                continue
            emails.append(email)

    if not emails:
        print("❌ No emails provided.")
        sys.exit(1)

    print(f"\n🔍 Checking {len(emails)} email{'s' if len(emails) > 1 else ''}...\n")
    print("-" * 56)

    results = []
    for i, email in enumerate(emails, 1):
        print(f"\n[{i}/{len(emails)}] Checking {email}...")

        breaches = check_email_breaches(email, api_key)
        risk_score, risk_level, risk_color = calculate_risk_score(breaches or [])

        result = {
            "email": email,
            "breaches": breaches or [],
            "breach_count": len(breaches) if breaches else 0,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }
        results.append(result)

        print_results(email, breaches, risk_score, risk_level)

        # Rate limiting — HIBP allows 10 RPM on Pwned 1
        if i < len(emails):
            time.sleep(6.5)

    # Summary
    print("\n" + "="*56)
    print("  📊 AUDIT COMPLETE")
    print("="*56)
    breached_count = sum(1 for r in results if r["breach_count"] > 0)
    print(f"  Total checked:    {len(results)}")
    print(f"  Compromised:      {breached_count}")
    print(f"  Clean:            {len(results) - breached_count}")

    # Generate Excel report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"VaultCheck_Report_{timestamp}.xlsx"
    print(f"\n📁 Generating Excel report...")
    generate_excel_report(results, output_path)
    print(f"✅ Report saved: {output_path}")
    print("="*56 + "\n")

if __name__ == "__main__":
    main()
