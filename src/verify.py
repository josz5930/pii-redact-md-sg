"""Second-pass independent regex audit of redacted output.

If any of these fire, the redactor missed something and we refuse to emit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# 13-19 consecutive digits, allowing spaces/dashes in between (card format).
_CARD = re.compile(r"\d[\d -]{11,17}\d")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_NRIC = re.compile(r"\b[STFGM]\d{7}[A-Z]\b")
_SG_MOBILE = re.compile(r"\b[89]\d{3}\s?\d{4}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_US_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# BTC legacy (P2PKH starts with 1, P2SH starts with 3); Bech32 SegWit starts with bc1.
_BTC_LEGACY = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32 = re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b")
# Solana: 32-44 base58 chars not surrounded by more base58 chars.
_SOL_ADDR = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])")


def _luhn(digits: str) -> bool:
    s = [int(c) for c in digits if c.isdigit()]
    if len(s) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(s)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


CHECKS = {
    "CREDIT_CARD": (_CARD, True),  # bool: apply Luhn to reduce false positives
    "EMAIL": (_EMAIL, False),
    "IPV4": (_IPV4, False),
    "ETH_WALLET": (_ETH, False),
    "NRIC": (_NRIC, False),
    "SG_MOBILE": (_SG_MOBILE, False),
    "IBAN": (_IBAN, False),
    "US_SSN": (_US_SSN, False),
    "BTC_LEGACY": (_BTC_LEGACY, False),
    "BTC_BECH32": (_BTC_BECH32, False),
    "SOL_ADDRESS": (_SOL_ADDR, False),
    # KNOWN GAPS: PERSON (names), LOCATION, URL, non-SG PHONE_NUMBER cannot be
    # reliably detected by regex alone; NLP-based detection is handled upstream
    # by the redactor. If the redactor misses these, they will not be caught here.
}


@dataclass
class Leak:
    kind: str
    value: str
    line_no: int
    line: str


def audit(text: str) -> list[Leak]:
    leaks: list[Leak] = []
    lines = text.splitlines()
    for kind, (pattern, luhn_check) in CHECKS.items():
        for m in pattern.finditer(text):
            value = m.group(0)
            if luhn_check and not _luhn(value):
                continue
            # Find which line this offset falls on.
            line_no = text.count("\n", 0, m.start()) + 1
            line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            leaks.append(Leak(kind=kind, value=value, line_no=line_no, line=line))
    return leaks


class VerificationFailed(RuntimeError):
    def __init__(self, leaks: list[Leak]):
        self.leaks = leaks
        summary = "\n".join(f"  line {l.line_no} [{l.kind}]: {l.value!r}" for l in leaks[:20])
        super().__init__(
            f"Redaction verification FAILED — {len(leaks)} sensitive pattern(s) still present:\n{summary}"
        )


def assert_clean(text: str) -> None:
    leaks = audit(text)
    if leaks:
        raise VerificationFailed(leaks)
