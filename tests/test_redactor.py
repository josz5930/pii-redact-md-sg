"""Golden-file-style test. Requires Presidio + spaCy model installed.

Run:  pytest -q
"""
from __future__ import annotations

import pytest

from src.verify import audit, assert_clean, VerificationFailed, _luhn
from src.extract import extract_csv, extract_markdown, extract_file


SYNTHETIC = """\
Cardholder: John Tan
Card number: 4532 0151 1283 0366
Email: john.tan@example.com
Mobile: +65 9123 4567
Home mobile: 91234567
NRIC: S1234567D
IP: 192.168.1.1
ETH wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
Address: 123 Orchard Road Singapore 238888

Transactions:
12 Mar  NTUC FAIRPRICE     42.50
13 Mar  SHELL ESSO         65.00
"""


@pytest.fixture(scope="module")
def redactor():
    from src.redactor import Redactor
    return Redactor()


def test_luhn_card_detected_by_verifier():
    assert _luhn("4532015112830366") is True
    assert _luhn("1234567890123456") is False


def test_end_to_end_no_pii_leaks(redactor):
    result = redactor.redact(SYNTHETIC)

    # None of the sensitive literals should remain.
    sensitive = [
        "4532 0151 1283 0366",
        "4532015112830366",
        "john.tan@example.com",
        "9123 4567",
        "91234567",
        "S1234567D",
        "192.168.1.1",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "238888",
    ]
    for s in sensitive:
        assert s not in result.text, f"Leaked: {s!r}"

    # Merchants and amounts must be preserved.
    assert "NTUC FAIRPRICE" in result.text
    assert "SHELL" in result.text
    assert "42.50" in result.text
    assert "65.00" in result.text

    # Independent verifier agrees.
    assert audit(result.text) == []


def test_verifier_catches_unredacted_card():
    dirty = "Leaked card: 4532015112830366"
    with pytest.raises(VerificationFailed):
        assert_clean(dirty)


def test_verifier_ignores_random_digits_without_luhn():
    # Non-Luhn 16-digit run should not trip the credit-card check.
    assert_clean("Reference ID: 1234567890123456")  # no raise; no other patterns match


# ---------------------------------------------------------------------------
# CSV and Markdown extraction tests (no Presidio required)
# ---------------------------------------------------------------------------

def test_extract_csv_basic(tmp_path):
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("name,email,amount\nJohn Tan,john@example.com,42.50\n", encoding="utf-8")
    extracted = extract_csv(csv_file)
    assert extracted.raw_rows == [["name", "email", "amount"], ["John Tan", "john@example.com", "42.50"]]
    assert len(extracted.pages) == 1
    assert "john@example.com" in extracted.pages[0].tables_md[0]


def test_extract_csv_empty_raises(tmp_path):
    csv_file = tmp_path / "empty.csv"
    csv_file.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="No data"):
        extract_csv(csv_file)


def test_extract_markdown_basic(tmp_path):
    md_file = tmp_path / "report.md"
    content = "# Report\n\nJohn Tan, john@example.com\n"
    md_file.write_text(content, encoding="utf-8")
    extracted = extract_markdown(md_file)
    assert extracted.pages[0].text == content
    assert extracted.raw_rows is None
    assert extracted.pages[0].tables_md == []


def test_extract_markdown_empty_raises(tmp_path):
    md_file = tmp_path / "empty.md"
    md_file.write_text("   \n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="No content"):
        extract_markdown(md_file)


def test_extract_file_unsupported(tmp_path):
    fake = tmp_path / "data.xlsx"
    fake.write_text("fake")
    with pytest.raises(ValueError, match="Unsupported"):
        extract_file(fake)


# ---------------------------------------------------------------------------
# End-to-end CSV redaction (requires Presidio)
# ---------------------------------------------------------------------------

def test_csv_redaction_end_to_end(redactor, tmp_path):
    from redact import _redact_csv_cells

    csv_file = tmp_path / "data.csv"
    csv_file.write_text(
        "name,email,amount\nJohn Tan,john.tan@example.com,42.50\n",
        encoding="utf-8",
    )
    out_csv = tmp_path / "data.redacted.csv"

    extracted = extract_csv(csv_file)
    counts, findings, redacted_rows = _redact_csv_cells(extracted.raw_rows, redactor, out_csv)

    assert "john.tan@example.com" not in redacted_rows[1][1]
    assert redacted_rows[1][2] == "42.50"  # amount must be preserved
    combined = "\n".join("\t".join(row) for row in redacted_rows)
    assert audit(combined) == []
    assert out_csv.exists()


def test_markdown_redaction_end_to_end(redactor, tmp_path):
    from redact import _redact_markdown_text

    text = "Contact: john.tan@example.com, mobile 91234567\n\nAmount: 42.50"
    md_text, counts, findings = _redact_markdown_text(text, redactor)

    assert "john.tan@example.com" not in md_text
    assert "42.50" in md_text
    assert audit(md_text) == []
