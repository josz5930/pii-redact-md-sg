#  PII Redact to MD, with a Singapore add on

Local PII redactor for PDFs (credit card statements, invoices, etc.) before you paste them into a remote LLM. Nothing leaves your machine.

## Setup
### Windows

```bash
cd pii-redact-md-sg
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### MacOS

```bash
cd pii-redact-md-sg
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

## Usage

```bash
python redact.py path\to\statement.pdf
```

Outputs:
- `out/statement.redacted.md` — full text + tables, paste into Claude/ChatGPT/Grok/Gemini
- `out/statement.redacted.csv` — transaction rows only (date, merchant, amount, description)
- `out/statement.report.json` — entity counts + per-finding audit

## What it does
It reads the text off PDFs and CSVs. It then does a first pass to remove/mask PII.
The CLI runs an second-pass regex audit on the redacted Markdown. If any raw card/email/IP/wallet/NRIC slips through, it doesn't write the file.

If any file is written, the script has a high confidence that it has most of the instances have been removed.

Note: If `pdfplumber` finds no text, the PDF is image-only. OCR is not auto-enabled. Install Tesseract + `pytesseract` + `pdf2image` separately if needed.

### What's redacted

Credit cards (Luhn-validated), emails, IPs, phones, IBAN, crypto wallets (BTC/ETH/SOL), people names, locations, URLs, SG NRIC (checksum-validated), bare SG mobile numbers, SG postal codes.

### What's preserved

Merchant names, transaction dates, amounts — so the LLM can still analyze your spending.

## How this differs from typical PII sanitizers

Most open-source PII sanitizers share a common set of limitations that make them unsuitable for the specific job of preparing a financial PDF for LLM analysis. This tool was built to address all of them.

### 1. They only accept plain text — not PDFs

Nearly every sanitizer takes a string as input. You are expected to get the text yourself first. This tool extracts text, tables, and transaction rows directly from the PDF, handles multi-page layouts, and falls back gracefully when a page contains no selectable text.

### 2. They use regex only — missing names, addresses, and unstructured PII

Regex catches well-structured patterns (emails, IPs, card numbers written as digits). It cannot detect a person's name, a home address written in free prose, or a location embedded in a sentence. This tool adds a full NLP named-entity recognition pass (spaCy `en_core_web_lg`) on top of the regex layer, catching `PERSON`, `LOCATION`, `GPE`, and `FAC` entities that pure-regex tools miss entirely.

### 3. They skip checksum validation — producing false positives

Applying a raw `\d{13,19}` regex to a bank statement matches reference numbers, account numbers, and product barcodes, not just card numbers. This tool validates every card-number candidate against the Luhn algorithm before redacting it, and validates every NRIC candidate against Singapore's weighted-checksum rule, so legitimate numbers are not destroyed.

### 4. They redact too aggressively — breaking LLM analysis

Many tools replace every detected entity with a generic `[REDACTED]` token — including merchant names, transaction dates, and currency amounts. If you then paste the result into an LLM to ask "which merchant charged me the most?", the answer is `[REDACTED] charged you [REDACTED]`. This tool deliberately preserves `ORG`, `DATE_TIME`, and numeric amounts so the LLM retains full analytical context.

### 5. They use generic tokens — losing cross-document correlation

Tools that emit `[HIDDEN_CARD]` or `[REDACTED]` for every hit make it impossible to tell whether two redacted values are the same or different. This tool uses deterministic hash-suffix placeholders (`<CREDIT_CARD_a3f1>`): the same original value always maps to the same token, so an LLM can reason "transactions 3 and 7 both used `<CREDIT_CARD_a3f1>`" without ever seeing the real number.

### 6. They have no safety net — a miss is silent

If a regex fails to match a card number formatted with spaces, or NLP misses a name, the sensitive value passes through undetected and you have no way to know. This tool runs an independent second-pass verifier after redaction using a separate set of patterns. If anything slips through, it **refuses to write the output file and prints the offending lines** — you will never silently paste a leaked PAN into a chat window.

### 7. They are US/EU-centric — missing Singapore-specific formats

Standard libraries do not recognise a bare 8-digit Singapore mobile number (`91234567`), a Singapore NRIC/FIN (`S1234567D`), or a 6-digit Singapore postal code without a country-code prefix to disambiguate it. This tool ships dedicated, checksum-aware recognisers for all three.

### 8. Some send your data to the cloud to detect PII

Several popular sanitization services wrap AWS Comprehend, GCP Cloud DLP, or Azure Text Analytics under the hood. Your document leaves your machine to be analysed remotely before it is redacted — the opposite of what you want. Every step of this tool runs fully locally: extraction, NLP inference, redaction, and verification.

## ⚠️ Disclaimer and Limitation of Liability

**This software is provided "AS IS" and "WITH ALL FAULTS", without any warranty of any kind, express or implied.**

By using any code in this repository or using the tool(s) provided you acknowledge and agree to the following:

- The tool is a "best effort" redaction utility that relies on heuristics and machine-learning models (spaCy en_core_web_lg). It is **not guaranteed** (or expected) to detect or redact every instance of personally identifiable information (PII), protected health information (PHI), or other sensitive data in every context, language, or document format.
- False negatives are an inherent risk. Redacted output **must be manually reviewed** before any further use, storage, sharing, or publication.
- You are **solely responsible** for:
  - Verifying that the redacted documents meet your specific compliance requirements (GDPR, CCPA/CPRA, PDPA, HIPAA, or any other applicable privacy law).
  - Implementing additional controls within your own threat model (encryption, access controls, audit logging, etc.).
  - Any regulatory fines, data-breach notifications, lawsuits, or other consequences that result from residual PII remaining in your documents.

**TO THE MAXIMUM EXTENT PERMITTED BY LAW**, the authors, contributors, and copyright holders of this project disclaim **any and all liability** for any direct, indirect, incidental, special, exemplary, or consequential damages—including but not limited to loss of data, loss of profits, regulatory penalties, legal fees, or business interruption—arising out of the use, misuse, or inability to use this software, even if advised of the possibility of such damage.

This disclaimer forms part of the license terms under which the software is distributed (AGPL-3.0). Nothing in this project constitutes legal, compliance, or security advice. Consult qualified legal and technical professionals for your specific situation.

**Use of this software is entirely at your own risk.**
