# Security Findings — PII Redactor CLI

**Tool:** `redact.py` (Local PII/PCI redactor for PDF, CSV, Markdown)
**Date:** 2026-04-23
**Method:** OWASP pyTM threat model + manual code review
**pyTM findings file:** `findings.json` (220 raw STRIDE threats; web-generic threats filtered below)

---

## Executive Summary

The tool is a local, offline CLI — there is no network exposure, no authentication surface, and no multi-tenant trust boundary during normal operation. The primary attack surfaces are:

1. **Untrusted input files** parsed by a complex PDF/CSV library stack
2. **Redaction gaps** — patterns the NLP + regex pipeline misses
3. **Weak placeholder hashing** — trivial collision risk
4. **Output file exposure** — no ACL hardening on the output directory
5. **Dependency integrity** — ML model weights loaded without verification
6. **Operator escape hatch** — `--allow-leaks` bypasses the only safety net

---

## Findings

### FIND-01 — Path Traversal via Unsanitized Input Path
**STRIDE:** Tampering · Elevation of Privilege
**Severity:** High (pyTM: HA01 Path Traversal)
**pyTM target:** `Open and read input file` (df2), `--all` batch mode

**Description:**
`_process_one()` calls `path.is_file()` and passes the result directly to `extract_file()`.
In `--all` mode, `Path.cwd().iterdir()` is used but the resolved path of the **output** directory
is compared; individual file paths are never canonicalized. A symlink inside the working directory
pointing outside it would be silently followed.

```python
# redact.py:102 — no canonicalization before open
extracted = extract_file(path)
```

**Impact:** An attacker who can place a symlink in the working directory can read any file the
process owner can access (e.g., `/etc/shadow`, another user's documents).

**Remediation:**
```python
resolved = path.resolve()
allowed = Path.cwd().resolve()
if not str(resolved).startswith(str(allowed)):
    print(f"error: {path} is outside the working directory", file=sys.stderr)
    return 2
```

---

### FIND-02 — Crafted PDF Triggering Parser DoS / Memory Exhaustion
**STRIDE:** Denial of Service
**Severity:** High (pyTM: DO02 Excessive Allocation, INP02 Overflow Buffers)
**pyTM target:** `File Extractor (pdfplumber / csv / markdown)`, `Input Document`

**Description:**
`extract()` in `src/extract.py` calls `pdfplumber.open(pdf_path)` with no size limit, page limit,
or timeout. A crafted PDF with thousands of pages, deeply nested XObject streams, or a
decompression bomb (zlib/deflate, e.g. 10 MB → 1 GB decompressed) will exhaust RAM and hang
or crash the process. The RuntimeError raised when no text is found only covers the empty-text
case, not memory/time exhaustion.

```python
# src/extract.py:104-111 — no resource guardrails
with pdfplumber.open(pdf_path) as pdf:
    for i, page in enumerate(pdf.pages, start=1):
        text = page.extract_text() or ""
```

**Impact:** On a machine without swap limits, a malicious PDF can OOM-kill the process or the
entire session, causing data loss.

**Remediation:**
- Enforce a page limit: `if len(pdf.pages) > MAX_PAGES: raise RuntimeError(...)`
- Enforce a file-size limit before opening: `if path.stat().st_size > MAX_BYTES: ...`
- Consider running extraction in a subprocess with a memory ceiling (`resource.setrlimit` on Linux;
  job objects on Windows).

---

### FIND-03 — ReDoS via Crafted Input in Verifier Regex
**STRIDE:** Denial of Service
**Severity:** Medium
**pyTM target:** `Regex Verifier — verify.py assert_clean()`

**Description:**
`verify.py` uses `_CARD = re.compile(r"(?:\d[ -]?){13,19}")`. This pattern uses a nested
quantifier with optional separator. Python's `re` engine is not immune to catastrophic backtracking
for inputs that almost-but-not-quite match. A crafted string like `1 2 3 4 5 6 7 8 9 0 1 2 3!`
may cause exponential backtracking.

Similarly, `_SOL_ADDR = Pattern(name="sol_address", regex=r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", score=0.3)`
in `recognizers.py` matches a wide character class over a wide length range, potentially slow
on long base58-like strings.

**Impact:** Processing a crafted document stalls the CLI indefinitely (CPU-bound loop in the verifier).

**Remediation:**
- Use `re.compile(r"\d(?:[ -]?\d){12,18}")` (anchored start + bounded repetition) instead.
- Add a character-count pre-filter before the regex: skip if `len(text) > SANITY_LIMIT`.
- Consider `regex` library (drop-in replacement) which supports timeout on match operations.

---

### FIND-04 — Trivially Colliding Placeholder Hash (BLAKE2b digest_size=2) 
**STRIDE:** Information Disclosure · Tampering
**Severity:** High
**pyTM target:** `Presidio + spaCy NLP Analyzer` (df7)

**Description:**
`src/redactor.py:41` computes placeholder tokens using:

```python
def _token(entity_type: str, value: str) -> str:
    h = hashlib.blake2b(f"{entity_type}|{value}".encode(), digest_size=2).hexdigest()
    return f"<{entity_type}_{h}>"
```

`digest_size=2` → 2 bytes → **4 hex characters → only 65,536 unique hash values**.
On a statement with more than ~256 unique PII values of the same entity type, collisions are
statistically certain (birthday paradox threshold ≈ 321 values for 50% probability).

**Impact:**
- Two distinct card numbers produce the same placeholder token (`<CREDIT_CARD_a3f1>`).
  The LLM incorrectly infers they are the same card, defeating the stated design goal
  ("the same original value always maps to the same token").
- A second-party with knowledge of the collision space can brute-force which real value a
  placeholder represents (65,536 guesses).

**Remediation:** Use at least `digest_size=8` (16 hex chars), giving 1.8 × 10¹⁹ unique values.
At `digest_size=4` (32-bit) collisions are still possible for large documents.

```python
h = hashlib.blake2b(f"{entity_type}|{value}".encode(), digest_size=8).hexdigest()
```

---

### FIND-05 — `--allow-leaks` Bypasses All Verification 
**STRIDE:** Information Disclosure
**Severity:** High
**pyTM target:** `redact.py — CLI Entry Point`

**Description:**
When `--allow-leaks` is passed, `_process_one()` catches `VerificationFailed` but continues
to write the output file unconditionally:

```python
# redact.py:126-129
if not allow_leaks:
    print("Refusing to write CSV output ...", file=sys.stderr)
    _write_leak_report(report_path, total, e.leaks)
    return 3
# ← falls through: output is written even with PII present
```

The flag name "allow-leaks" is misleading — it actively **produces** a file containing raw PII.
There is no warning printed to stdout that the written file is unsafe.

**Impact:** Operators in a hurry re-run with `--allow-leaks` when the verifier fires, not
realizing they are producing an unsafe output that they will then paste into an LLM.

**Remediation:**
1. Print a prominent red-text warning when `--allow-leaks` produces output.
2. Append `.UNSAFE` to the output filename: `statement.redacted.UNSAFE.md`.
3. Write the leak details into the report JSON alongside the output.
4. Consider requiring an additional `--i-understand-this-is-unsafe` flag to prevent casual use.

---

### FIND-06 — CSV Injection in Redacted Output 
**STRIDE:** Tampering
**Severity:** Medium
**pyTM target:** `Output Directory` (df10)

**Description:**
`_render_csv()` and `_redact_csv_cells()` write rows directly with `csv.writer` without
sanitizing cell values that begin with `=`, `+`, `-`, or `@` (spreadsheet formula injection
characters). If a transaction description like `=SUM(A1:A100)` or `+cmd|' /C calc'!A0`
passes through unredacted (e.g., not a PII entity), it is written verbatim to the output CSV.
If the operator opens that CSV in Excel/Google Sheets, the formula executes.

```python
# redact.py:52
w.writerow([txn.date, merch_r.text, txn.amount, desc_r.text])
```

**Impact:** Remote Code Execution on the operator's machine when the output CSV is opened in a
spreadsheet application.

**Remediation:**
```python
def _csv_safe(cell: str) -> str:
    if cell and cell[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + cell  # prefix with single-quote to neutralize
    return cell
```
Apply to every cell before writing.

---

### FIND-07 — NLP Model Integrity Not Verified at Load Time
**STRIDE:** Tampering
**Severity:** Medium (pyTM: DS Schema Poisoning)
**pyTM target:** `NLP Models (.venv)` (df6)

**Description:**
`build_analyzer()` in `src/redactor.py:66-71` calls `AnalyzerEngine()` which loads spaCy's
`en_core_web_lg` from the local `.venv`. There is no hash comparison against a known-good
manifest at runtime. If `.venv` is writable by other users or has been tampered with (e.g.,
supply-chain compromise of a dependency, or a compromised `pip` install), the model weights
could be altered to systematically miss certain PII patterns (e.g., always returning low scores
for NRIC or PERSON entities).

**Impact:** Silent false-negative bias — the tool appears to work but consistently fails to
detect specific PII types. The operator has no feedback that redaction quality has degraded.

**Remediation:**
- Pin all dependencies with hashes in `requirements.txt` (`pip install --require-hashes`).
- Store the SHA-256 of the downloaded spaCy model and verify at startup.
- Use a read-only `.venv` (set directory ACL to deny writes for non-admin users).

---

### FIND-08 — PII Retained in Python Heap / Process Memory
**STRIDE:** Information Disclosure
**Severity:** Medium
**pyTM target:** `redact.py — CLI Entry Point`, `Presidio + spaCy NLP Analyzer`

**Description:**
The full raw PII text is held in Python strings throughout the pipeline:
`extracted.pages[n].text`, `r.text` in `_render_markdown`, and the analyzer's `text` argument.
Python strings are immutable and GC'd lazily — the underlying buffer is not zeroed on
collection. On a system with a swap file, this data may be written to disk in cleartext.

**Impact:** A memory dump or swap-file analysis by another process or a forensic investigator
could recover PII long after the tool has exited.

**Remediation:**
- Use `bytearray` + explicit zeroing where feasible (`memset`-equivalent).
- In practice for a Python CLI this is largely a platform OS concern; document it in the
  security assumptions: "requires full-disk encryption (BitLocker / FileVault) on the host."

---

### FIND-09 — Verifier Coverage Gaps (False-Negative Blind Spots)
**STRIDE:** Information Disclosure
**Severity:** High
**pyTM target:** `Regex Verifier — verify.py assert_clean()`

**Description:**
`verify.py:CHECKS` audits for: CREDIT_CARD (Luhn), EMAIL, IPv4, ETH_WALLET, NRIC, SG_MOBILE, IBAN.
The following entity types detected by the **redactor** are **not checked** by the verifier:

| Entity (redactor) | Verifier check? |
|---|---|
| PHONE_NUMBER (non-SG) | No |
| PERSON (names) | No |
| LOCATION / GPE | No |
| URL | No |
| US_SSN | No |
| CRYPTO (BTC, SOL) | No (only ETH) |
| SG Postal Code | No |

If NLP fails to redact a person's name or a non-SG phone number, the verifier does not catch it
and the file is written with a false "clean" verdict.

**Impact:** Silent data leakage — names and non-SG phone numbers pass through undetected.

**Remediation:**
- Add regex patterns for US SSN (`\b\d{3}-\d{2}-\d{4}\b`), BTC addresses, SOL addresses.
- For PERSON/LOCATION, the verifier cannot use NLP (it's a second-pass, speed-focused audit);
  document the limitation explicitly and consider running a lightweight NER check on the output.

---

### FIND-10 — Output Directory Insecure Default Permissions
**STRIDE:** Information Disclosure
**Severity:** Medium (pyTM: AC01 Privilege Abuse)
**pyTM target:** `Output Directory (redacted files + report.json)`

**Description:**
`outdir.mkdir(parents=True, exist_ok=True)` creates the output directory with the process's
default umask. On Windows, new directories in user-writable locations inherit the parent's
DACL, which often grants read access to `BUILTIN\Users`. The output contains redacted text
(which may still contain names/locations if FIND-09 applies) and `report.json` with entity
offsets.

**Impact:** Other local users on a shared Windows machine can read the output files.

**Remediation:**
```python
import stat
outdir.mkdir(parents=True, exist_ok=True)
# Restrict to owner only (Unix)
outdir.chmod(stat.S_IRWXU)
```
For Windows, use `icacls` via subprocess or `win32security` to restrict to the current user.

---

### FIND-11 — `findings` List Truncated at 500 Silently
**STRIDE:** Repudiation
**Severity:** Low
**pyTM target:** `Output Directory` (report.json)

**Description:**
```python
# redact.py:177
json.dumps({"counts": dict(total), "n_transactions": n_txn, "findings": all_findings[:500]}, ...)
```
If more than 500 PII entities are found, the report silently drops the remainder. An operator
reviewing the report to audit redaction quality sees only the first 500 findings with no
indication that the list is truncated.

**Impact:** Incomplete audit trail; operator cannot verify full coverage.

**Remediation:** Add a `"findings_truncated": True, "total_findings": len(all_findings)` field
to the report JSON so truncation is visible.

---

## Threat Matrix Summary

| ID | Threat | Target | Severity | STRIDE |
|---|---|---|---|---|
| FIND-01 | Path traversal via symlink | CLI arg handling | High | T, E |
| FIND-02 | PDF decompression bomb / parser DoS | pdfplumber extractor | High | D |
| FIND-03 | ReDoS in verifier card regex | verify.py | Medium | D |
| FIND-04 | Placeholder hash collision (BLAKE2b 2-byte) | redactor.py | High | I, T |
| FIND-05 | `--allow-leaks` produces unsafe output silently | CLI | High | I |
| FIND-06 | CSV injection in output | csv writer | Medium | T |
| FIND-07 | ML model tampering (no integrity check) | .venv / spaCy | Medium | T |
| FIND-08 | PII retained in heap / swap | Python process | Medium | I |
| FIND-09 | Verifier coverage gaps (names, URLs, non-SG phones, BTC) | verify.py | High | I |
| FIND-10 | Output directory world-readable (default umask) | output dir | Medium | I |
| FIND-11 | Silent truncation of findings list at 500 | report.json | Low | R |

---

## pyTM Artifacts

| File | Description |
|---|---|
| `threat_model.py` | pyTM source defining actors, processes, datastores, and dataflows |
| `findings.json` | 220 raw STRIDE findings generated by pyTM (includes generic web threats) |
| `dfd.dot` | Graphviz DOT source for the Data Flow Diagram |

To render the DFD (requires Graphviz):
```bash
dot -Tsvg ThreatModelExercise/dfd.dot -o ThreatModelExercise/dfd.svg
dot -Tpng ThreatModelExercise/dfd.dot -o ThreatModelExercise/dfd.png
```
