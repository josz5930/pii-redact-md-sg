"""CLI: redact PII/PCI from PDF, CSV, or Markdown files. All processing is fully local."""
from __future__ import annotations

import argparse
import csv
import json
import os
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path

from src.extract import extract_file
from src.redactor import Redactor
from src.verify import assert_clean, VerificationFailed


def _render_markdown(extracted, redactor: Redactor) -> tuple[str, Counter, list[dict]]:
    total_counts: Counter = Counter()
    all_findings: list[dict] = []
    parts: list[str] = []
    for page in extracted.pages:
        parts.append(f"## Page {page.number}\n")
        if page.text.strip():
            r = redactor.redact(page.text)
            total_counts.update(r.counts)
            all_findings.extend(r.findings)
            parts.append(r.text.rstrip() + "\n")
        for t_md in page.tables_md:
            r = redactor.redact(t_md)
            total_counts.update(r.counts)
            all_findings.extend(r.findings)
            parts.append("\n" + r.text + "\n")
        parts.append("\n")
    return "\n".join(parts), total_counts, all_findings


def _redact_markdown_text(text: str, redactor: Redactor) -> tuple[str, Counter, list[dict]]:
    r = redactor.redact(text)
    return r.text, r.counts, r.findings


def _render_csv(extracted, redactor: Redactor, csv_path: Path) -> tuple[Counter, int]:
    counts: Counter = Counter()
    n = 0
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["date", "merchant", "amount", "description"])
        for txn in extracted.transactions:
            desc_r = redactor.redact(txn.description)
            merch_r = redactor.redact(txn.description.split("  ")[0] if txn.description else "")
            counts.update(desc_r.counts)
            counts.update(merch_r.counts)
            w.writerow([_csv_safe(str(txn.date)), _csv_safe(merch_r.text), _csv_safe(str(txn.amount)), _csv_safe(desc_r.text)])
            n += 1
    return counts, n


def _redact_csv_cells(
    raw_rows: list[list[str]], redactor: Redactor, csv_path: Path
) -> tuple[Counter, list[dict], list[list[str]]]:
    counts: Counter = Counter()
    findings: list[dict] = []
    redacted_rows: list[list[str]] = []
    for row in raw_rows:
        new_row: list[str] = []
        for cell in row:
            r = redactor.redact(cell)
            counts.update(r.counts)
            findings.extend(r.findings)
            new_row.append(r.text)
        redacted_rows.append(new_row)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for row in redacted_rows:
            writer.writerow([_csv_safe(cell) for cell in row])
    return counts, findings, redacted_rows


def _write_leak_report(report_path: Path, total: Counter, leaks: list) -> None:
    report_path.write_text(
        json.dumps({"counts": dict(total), "leaks": [l.__dict__ for l in leaks]}, indent=2),
        encoding="utf-8",
    )


def _csv_safe(cell: str) -> str:
    """Neutralize spreadsheet formula injection by prefixing dangerous lead chars."""
    if cell and cell[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + cell
    return cell


def _harden_outdir(outdir: Path) -> None:
    """Restrict the output directory to the current user only (FIND-10)."""
    try:
        if sys.platform == "win32":
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    [
                        "icacls", str(outdir),
                        "/inheritance:r",
                        "/grant:r", f"{username}:(OI)(CI)F",
                    ],
                    check=True, capture_output=True, text=True,
                )
        else:
            outdir.chmod(stat.S_IRWXU)
    except Exception as exc:
        print(f"warning: could not restrict output directory permissions: {exc}", file=sys.stderr)


_SUPPORTED = {".pdf", ".csv", ".md", ".markdown"}


def _process_one(path: Path, outdir: Path, allow_leaks: bool) -> int:
    """Process a single file. Returns exit code: 0=success, 2=bad input, 3=verification failed."""
    try:
        path = path.resolve(strict=True)
    except (OSError, ValueError):
        print(f"error: cannot resolve path {path}", file=sys.stderr)
        return 2
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 2

    suffix = path.suffix.lower()
    if suffix not in _SUPPORTED:
        print(f"error: unsupported file type {suffix!r}. Supported: .pdf, .csv, .md", file=sys.stderr)
        return 2

    outdir.mkdir(parents=True, exist_ok=True)
    _harden_outdir(outdir)
    stem = path.stem
    report_path = outdir / f"{stem}.report.json"

    print(f"Extracting {path} ...")
    extracted = extract_file(path)
    print(f"  pages: {len(extracted.pages)}, transactions: {len(extracted.transactions)}")

    print("Loading Presidio analyzer (this takes a few seconds) ...")
    redactor = Redactor()

    total: Counter = Counter()
    all_findings: list[dict] = []
    n_txn = 0
    output_paths: list[Path] = []
    leaked: list = []  # populated when --allow-leaks overrides a failed verification

    if suffix == ".csv":
        csv_path = outdir / f"{stem}.redacted.csv"
        print("Redacting CSV cells ...")
        counts, findings, redacted_rows = _redact_csv_cells(extracted.raw_rows, redactor, csv_path)
        total.update(counts)
        all_findings.extend(findings)

        print("Verifying redacted CSV ...")
        combined = "\n".join("\t".join(row) for row in redacted_rows)
        try:
            assert_clean(combined)
        except VerificationFailed as e:
            print(str(e), file=sys.stderr)
            if not allow_leaks:
                print("Refusing to write CSV output. Re-run with --allow-leaks to override.", file=sys.stderr)
                _write_leak_report(report_path, total, e.leaks)
                return 3
            unsafe_path = outdir / f"{stem}.redacted.UNSAFE.csv"
            csv_path.rename(unsafe_path)
            csv_path = unsafe_path
            leaked = e.leaks
        output_paths = [csv_path]

    elif suffix in (".md", ".markdown"):
        md_path = outdir / f"{stem}.redacted.md"
        print("Redacting Markdown ...")
        md_text, counts, findings = _redact_markdown_text(extracted.pages[0].text, redactor)
        total.update(counts)
        all_findings.extend(findings)

        print("Verifying redacted Markdown ...")
        try:
            assert_clean(md_text)
        except VerificationFailed as e:
            print(str(e), file=sys.stderr)
            if not allow_leaks:
                print("Refusing to write Markdown output. Re-run with --allow-leaks to override.", file=sys.stderr)
                _write_leak_report(report_path, total, e.leaks)
                return 3
            md_path = outdir / f"{stem}.redacted.UNSAFE.md"
            leaked = e.leaks
        md_path.write_text(md_text, encoding="utf-8")
        output_paths = [md_path]

    else:  # PDF
        md_path = outdir / f"{stem}.redacted.md"
        csv_path = outdir / f"{stem}.redacted.csv"

        print("Redacting narrative text + tables ...")
        md_text, md_counts, findings = _render_markdown(extracted, redactor)
        total.update(md_counts)
        all_findings.extend(findings)

        print("Redacting transactions for CSV ...")
        csv_counts, n_txn = _render_csv(extracted, redactor, csv_path)
        total.update(csv_counts)

        print("Verifying redacted Markdown ...")
        try:
            assert_clean(md_text)
        except VerificationFailed as e:
            print(str(e), file=sys.stderr)
            if not allow_leaks:
                print("Refusing to write Markdown output. Re-run with --allow-leaks to override.", file=sys.stderr)
                _write_leak_report(report_path, total, e.leaks)
                return 3
            md_path = outdir / f"{stem}.redacted.UNSAFE.md"
            leaked = e.leaks
        md_path.write_text(md_text, encoding="utf-8")
        output_paths = [md_path, csv_path]

    if leaked:
        print(
            "\n*** WARNING: this output contains unredacted PII! ***\n"
            "*** --allow-leaks was set — the file was written with PII still present. ***\n"
            "*** DO NOT paste this file into an LLM or share it externally. ***\n",
            file=sys.stderr,
        )

    report_data: dict = {
        "counts": dict(total),
        "n_transactions": n_txn,
        "findings": all_findings[:500],
        "total_findings": len(all_findings),
        "findings_truncated": len(all_findings) > 500,
    }
    if leaked:
        report_data["UNSAFE_leaks"] = [l.__dict__ for l in leaked]
    report_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

    print("\n=== Redaction summary ===")
    if not total:
        print("  (nothing matched — double-check your file actually has text)")
    else:
        for entity, c in total.most_common():
            print(f"  {entity:<20} {c}")
    for p in [*output_paths, report_path]:
        ext = p.suffix.lower()
        label = "Markdown" if ext == ".md" else ("CSV" if ext == ".csv" else "Report")
        print(f"{label:<10}: {p}")
    print("\nOpen the output file, Ctrl-F for your own card last-4, email, phone, postal code.")
    print("If those still appear, DO NOT paste into the LLM — re-run with --allow-leaks or file a bug.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Redact PII/PCI from a file (.pdf, .csv, .md). All processing is fully local."
    )
    parser.add_argument(
        "input", nargs="?", type=Path,
        help="File to redact (.pdf, .csv, .md / .markdown). Omit when using --all.",
    )
    parser.add_argument("-o", "--outdir", type=Path, default=Path("out"), help="Output directory.")
    parser.add_argument(
        "--all", dest="process_all", action="store_true",
        help="Redact every .pdf, .csv, .md, and .markdown file in the current directory.",
    )
    parser.add_argument(
        "--allow-leaks",
        action="store_true",
        help="Skip the verifier refusal (DANGEROUS — prints leaks and still writes).",
    )
    args = parser.parse_args(argv)

    if args.process_all and args.input is not None:
        parser.error("--all cannot be combined with a positional input file.")
    if not args.process_all and args.input is None:
        parser.error("Provide an input file, or use --all to process all supported files in the current directory.")

    if args.process_all:
        outdir_resolved = args.outdir.resolve()
        files = []
        for p in Path.cwd().iterdir():
            if p.is_symlink():
                print(f"warning: skipping {p.name} — symbolic links are not followed in --all mode", file=sys.stderr)
                continue
            if not p.is_file():
                continue
            if p.suffix.lower() not in _SUPPORTED:
                continue
            if p.name.endswith((".redacted.md", ".redacted.csv")):
                continue
            if p.resolve().parent == outdir_resolved:
                continue
            files.append(p)
        files = sorted(files)
        if not files:
            print("No supported files found in the current directory.", file=sys.stderr)
            return 2

        results: dict[Path, int] = {}
        for p in files:
            print(f"\n{'=' * 60}")
            print(f"Processing: {p.name}")
            print(f"{'=' * 60}")
            results[p] = _process_one(p, args.outdir, args.allow_leaks)

        passed = [p for p, code in results.items() if code == 0]
        failed = [p for p, code in results.items() if code != 0]
        print(f"\n--- Batch complete: {len(passed)} succeeded, {len(failed)} failed ---")
        for p in failed:
            print(f"  FAILED: {p}", file=sys.stderr)
        return 0 if not failed else 1

    return _process_one(args.input, args.outdir, args.allow_leaks)


if __name__ == "__main__":
    sys.exit(main())
