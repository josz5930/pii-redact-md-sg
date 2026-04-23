"""Extraction: narrative text + tables + heuristic transactions from PDF, CSV, or Markdown."""
from __future__ import annotations

import csv as _csv
import re
from dataclasses import dataclass, field
from pathlib import Path

import pdfplumber


@dataclass
class Page:
    number: int
    text: str
    tables_md: list[str] = field(default_factory=list)


@dataclass
class Transaction:
    date: str
    description: str
    amount: str


@dataclass
class Extracted:
    pages: list[Page]
    transactions: list[Transaction]
    raw_rows: list[list[str]] | None = field(default=None)


_MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MB raw file size cap (decompression bombs are caught separately)
_MAX_PDF_PAGES = 500

_DATE_COL = re.compile(r"date|posting|trans", re.I)
_AMOUNT_COL = re.compile(r"amount|debit|credit|sgd|usd", re.I)
_DESC_COL = re.compile(r"desc|detail|merchant|particular|narration", re.I)

# Fallback narrative-line regex: "12 Mar  MERCHANT NAME  42.50"
_TXN_LINE = re.compile(
    r"^\s*(?P<date>\d{1,2}[/\s-][A-Za-z]{3,9}(?:[/\s-]\d{2,4})?)\s+"
    r"(?P<desc>.+?)\s+"
    r"(?P<amount>-?\$?\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\s*$"
)


def _row_to_md(row: list[str | None]) -> str:
    return "| " + " | ".join((c or "").replace("|", "\\|").replace("\n", " ").strip() for c in row) + " |"


def _table_to_md(table: list[list[str | None]]) -> str:
    if not table or not table[0]:
        return ""
    header, *rest = table
    sep = "| " + " | ".join("---" for _ in header) + " |"
    lines = [_row_to_md(header), sep] + [_row_to_md(r) for r in rest]
    return "\n".join(lines)


def _find_col(header: list[str | None], pattern: re.Pattern) -> int | None:
    for i, cell in enumerate(header):
        if cell and pattern.search(cell):
            return i
    return None


def _extract_transactions(table: list[list[str | None]]) -> list[Transaction]:
    if not table or not table[0]:
        return []
    header = table[0]
    d_idx = _find_col(header, _DATE_COL)
    a_idx = _find_col(header, _AMOUNT_COL)
    desc_idx = _find_col(header, _DESC_COL)
    if d_idx is None or a_idx is None:
        return []
    if desc_idx is None:
        # Pick the widest non-date/amount column as description.
        candidates = [i for i in range(len(header)) if i not in (d_idx, a_idx)]
        desc_idx = candidates[0] if candidates else None
    out: list[Transaction] = []
    for row in table[1:]:
        if not row or len(row) <= max(d_idx, a_idx):
            continue
        date = (row[d_idx] or "").strip()
        amount = (row[a_idx] or "").strip()
        desc = (row[desc_idx] or "").strip() if desc_idx is not None else ""
        if not date or not amount:
            continue
        out.append(Transaction(date=date, description=desc, amount=amount))
    return out


def _fallback_transactions(text: str) -> list[Transaction]:
    out: list[Transaction] = []
    for line in text.splitlines():
        m = _TXN_LINE.match(line)
        if m:
            out.append(Transaction(m["date"].strip(), m["desc"].strip(), m["amount"].strip()))
    return out


def extract(pdf_path: Path) -> Extracted:
    size = pdf_path.stat().st_size
    if size > _MAX_PDF_BYTES:
        raise ValueError(
            f"{pdf_path.name} is {size // (1024 * 1024)} MB; "
            f"maximum allowed is {_MAX_PDF_BYTES // (1024 * 1024)} MB."
        )

    pages: list[Page] = []
    transactions: list[Transaction] = []

    try:
        with pdfplumber.open(pdf_path) as pdf:
            if len(pdf.pages) > _MAX_PDF_PAGES:
                raise ValueError(
                    f"{pdf_path.name} has {len(pdf.pages)} pages; "
                    f"maximum allowed is {_MAX_PDF_PAGES}."
                )
            for i, page in enumerate(pdf.pages, start=1):
                text = page.extract_text() or ""
                raw_tables = page.extract_tables() or []
                tables_md = [md for md in (_table_to_md(t) for t in raw_tables) if md]
                pages.append(Page(number=i, text=text, tables_md=tables_md))
                for t in raw_tables:
                    transactions.extend(_extract_transactions(t))
    except MemoryError:
        raise RuntimeError(
            f"Ran out of memory processing {pdf_path.name}. "
            "The file may contain a decompression bomb or excessively complex content."
        )

    if not transactions:
        joined = "\n".join(p.text for p in pages)
        transactions = _fallback_transactions(joined)

    has_any_content = any(p.text.strip() or p.tables_md for p in pages)
    if not has_any_content:
        raise RuntimeError(
            f"No text or tables extracted from {pdf_path}. This may be a scanned/image PDF.\n"
            "OCR fallback is not enabled by default. To enable, install:\n"
            "  pip install pytesseract pdf2image\n"
            "and a local Tesseract binary (https://github.com/UB-Mannheim/tesseract/wiki),\n"
            "then re-run with --ocr (not yet implemented)."
        )

    return Extracted(pages=pages, transactions=transactions)


def extract_csv(csv_path: Path) -> Extracted:
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        rows = list(_csv.reader(f))
    if not rows:
        raise RuntimeError(f"No data found in {csv_path}")
    table_md = _table_to_md(rows)
    transactions = _extract_transactions(rows)
    page = Page(number=1, text="", tables_md=[table_md] if table_md else [])
    return Extracted(pages=[page], transactions=transactions, raw_rows=rows)


def extract_markdown(md_path: Path) -> Extracted:
    text = md_path.read_text(encoding="utf-8")
    if not text.strip():
        raise RuntimeError(f"No content found in {md_path}")
    return Extracted(pages=[Page(number=1, text=text, tables_md=[])], transactions=[])


_SUPPORTED_SUFFIXES = {".pdf", ".csv", ".md", ".markdown"}


def extract_file(path: Path) -> Extracted:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract(path)
    if suffix == ".csv":
        return extract_csv(path)
    if suffix in (".md", ".markdown"):
        return extract_markdown(path)
    raise ValueError(
        f"Unsupported file type {suffix!r}. Supported: {', '.join(sorted(_SUPPORTED_SUFFIXES))}"
    )
