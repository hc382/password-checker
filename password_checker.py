#!/usr/bin/env python3
"""
Password Strength Checker + Policy Analyzer

Educational tool:
- Checks common password rules (length, character classes)
- Flags weak/common passwords (small built-in list)
- Estimates strength score (simple heuristic)
- Gives actionable feedback

This is NOT a password cracker. It does not brute force or attempt to recover passwords.
"""

from __future__ import annotations
import argparse
import getpass
import re
from dataclasses import dataclass


COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein", "admin",
    "welcome", "iloveyou", "111111", "000000", "abc123", "password1"
}


@dataclass
class Policy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True

    # Optional controls
    forbid_whitespace: bool = True
    max_repeated_char_run: int = 3  # e.g., "aaaa" is a run of 4 (fails if > 3)


def has_upper(s: str) -> bool:
    return any(c.isupper() for c in s)


def has_lower(s: str) -> bool:
    return any(c.islower() for c in s)


def has_digit(s: str) -> bool:
    return any(c.isdigit() for c in s)


def has_symbol(s: str) -> bool:
    return any(not c.isalnum() for c in s)


def has_whitespace(s: str) -> bool:
    return any(c.isspace() for c in s)


def max_run_length(s: str) -> int:
    if not s:
        return 0
    best = 1
    run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best


def simple_entropy_score(pw: str) -> int:
    """
    Simple scoring heuristic (NOT true entropy):
    - Base on length and character variety
    - Adds points for longer passwords
    - Penalizes common patterns
    Score range: 0–100
    """
    if not pw:
        return 0

    score = 0
    length = len(pw)

    # Length contribution
    score += min(60, length * 4)  # up to 60 points

    # Variety contribution
    variety = sum([has_lower(pw), has_upper(pw), has_digit(pw), has_symbol(pw)])
    score += variety * 10  # up to 40 points

    # Penalties for common patterns
    lowered = pw.lower()
    if lowered in COMMON_PASSWORDS:
        score = max(0, score - 50)

    if re.fullmatch(r"\d+", pw):  # all digits
        score = max(0, score - 25)

    if re.fullmatch(r"[a-zA-Z]+", pw):  # all letters
        score = max(0, score - 15)

    if "password" in lowered:
        score = max(0, score - 20)

    if max_run_length(pw) >= 4:
        score = max(0, score - 10)

    return max(0, min(100, score))


def rating(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Good"
    if score >= 40:
        return "Fair"
    return "Weak"


def analyze_password(pw: str, policy: Policy) -> list[str]:
    findings: list[str] = []

    # Policy checks
    if len(pw) < policy.min_length:
        findings.append(f"[FAIL] Length < {policy.min_length} (current: {len(pw)})")
    else:
        findings.append(f"[PASS] Length >= {policy.min_length}")

    if policy.require_upper:
        findings.append("[PASS] Has uppercase" if has_upper(pw) else "[FAIL] Missing uppercase")
    if policy.require_lower:
        findings.append("[PASS] Has lowercase" if has_lower(pw) else "[FAIL] Missing lowercase")
    if policy.require_digit:
        findings.append("[PASS] Has digit" if has_digit(pw) else "[FAIL] Missing digit")
    if policy.require_symbol:
        findings.append("[PASS] Has symbol" if has_symbol(pw) else "[FAIL] Missing symbol")

    if policy.forbid_whitespace:
        findings.append("[PASS] No whitespace" if not has_whitespace(pw) else "[FAIL] Contains whitespace")

    run = max_run_length(pw)
    if run > policy.max_repeated_char_run:
        findings.append(f"[WARN] Repeated character run too long (max run: {run})")
    else:
        findings.append(f"[PASS] Repeated character run acceptable (max run: {run})")

    # Weak password hints
    if pw.lower() in COMMON_PASSWORDS:
        findings.append("[WARN] Password is in a common-password list")

    if len(set(pw)) <= max(3, len(pw) // 4):
        findings.append("[WARN] Low character diversity (many repeats)")

    return findings


def recommendations(pw: str, policy: Policy) -> list[str]:
    rec: list[str] = []
    if len(pw) < policy.min_length:
        rec.append(f"- Use at least {policy.min_length} characters (longer is better).")
    if policy.require_upper and not has_upper(pw):
        rec.append("- Add at least one uppercase letter (A–Z).")
    if policy.require_lower and not has_lower(pw):
        rec.append("- Add at least one lowercase letter (a–z).")
    if policy.require_digit and not has_digit(pw):
        rec.append("- Add at least one number (0–9).")
    if policy.require_symbol and not has_symbol(pw):
        rec.append("- Add at least one symbol (e.g., !@#$%).")
    if policy.forbid_whitespace and has_whitespace(pw):
        rec.append("- Remove spaces/tabs from the password.")
    if max_run_length(pw) > policy.max_repeated_char_run:
        rec.append(f"- Avoid long repeats like 'aaaa' (keep repeats ≤ {policy.max_repeated_char_run}).")
    if pw.lower() in COMMON_PASSWORDS or "password" in pw.lower():
        rec.append("- Avoid common words like 'password' and common patterns.")
    if not rec:
        rec.append("- Password meets the selected policy. Consider using a password manager for unique passwords.")
    return rec


def main() -> int:
    parser = argparse.ArgumentParser(description="Password Strength Checker + Policy Analyzer")
    parser.add_argument("--min-length", type=int, default=12, help="Minimum password length (default: 12)")
    parser.add_argument("--no-symbol", action="store_true", help="Do not require symbols")
    parser.add_argument("--no-upper", action="store_true", help="Do not require uppercase")
    parser.add_argument("--no-digit", action="store_true", help="Do not require digits")
    parser.add_argument("--allow-space", action="store_true", help="Allow whitespace in passwords")
    parser.add_argument("--max-run", type=int, default=3, help="Max repeated character run (default: 3)")
    parser.add_argument("--password", type=str, default=None, help="Provide password via argument (not recommended)")
    args = parser.parse_args()

    policy = Policy(
        min_length=args.min_length,
        require_upper=not args.no_upper,
        require_lower=True,
        require_digit=not args.no_digit,
        require_symbol=not args.no_symbol,
        forbid_whitespace=not args.allow_space,
        max_repeated_char_run=args.max_run,
    )

    pw = args.password
    if pw is None:
        pw = getpass.getpass("Enter password to evaluate: ")

    score = simple_entropy_score(pw)
    print("=== Password Strength Checker + Policy Analyzer ===")
    print(f"Policy: min_length={policy.min_length}, upper={policy.require_upper}, lower={policy.require_lower}, "
          f"digit={policy.require_digit}, symbol={policy.require_symbol}, whitespace_allowed={not policy.forbid_whitespace}, "
          f"max_repeat_run={policy.max_repeated_char_run}")
    print()
    print(f"Strength Score: {score}/100 ({rating(score)})")
    print()

    print("== Policy Checks ==")
    for line in analyze_password(pw, policy):
        print(line)
    print()

    print("== Recommendations ==")
    for line in recommendations(pw, policy):
        print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
