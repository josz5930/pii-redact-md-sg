"""Presidio analyze + anonymize with hash-suffix placeholders."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .recognizers import all_custom
from .verify import CHECKS, _luhn

_MANIFEST_PATH = Path(__file__).parent.parent / "model_manifest.json"
_NLP_MODEL = "en_core_web_lg"


def _check_model_integrity() -> None:
    """TOFU integrity check for the spaCy NLP model (FIND-07).

    On first run: computes sha256(meta.json) and writes model_manifest.json.
    On subsequent runs: compares against the stored hash and raises RuntimeError
    if the model has been altered (tampered weights, supply-chain compromise).
    """
    try:
        import spacy.util
        model_path = spacy.util.get_package_path(_NLP_MODEL)
    except Exception:
        print(
            f"warning: could not locate NLP model '{_NLP_MODEL}' for integrity check",
            file=sys.stderr,
        )
        return

    meta_path = model_path / "meta.json"
    if not meta_path.exists():
        print(
            f"warning: {_NLP_MODEL}/meta.json not found — skipping integrity check",
            file=sys.stderr,
        )
        return

    current_hash = hashlib.sha256(meta_path.read_bytes()).hexdigest()

    if not _MANIFEST_PATH.exists():
        _MANIFEST_PATH.write_text(
            json.dumps({_NLP_MODEL: {"meta_sha256": current_hash}}, indent=2),
            encoding="utf-8",
        )
        print(
            f"info: NLP model manifest initialized at {_MANIFEST_PATH}\n"
            f"      sha256({_NLP_MODEL}/meta.json) = {current_hash[:16]}...\n"
            "      Commit this file to lock the trusted model version (TOFU).",
            file=sys.stderr,
        )
        return

    try:
        manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"warning: could not read model manifest: {exc}", file=sys.stderr)
        return

    expected = manifest.get(_NLP_MODEL, {}).get("meta_sha256")
    if expected and expected != current_hash:
        raise RuntimeError(
            f"NLP model integrity check FAILED for '{_NLP_MODEL}'!\n"
            f"  Expected: {expected}\n"
            f"  Got:      {current_hash}\n"
            "The model may have been tampered with. "
            "Delete model_manifest.json to re-trust the currently installed model."
        )


# Entities we want redacted. Notably excludes ORG and DATE_TIME: merchants and
# transaction dates are kept so the LLM can still analyze the statement.
REDACT_ENTITIES = [
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "IP_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    "CRYPTO",
    "PERSON",
    "LOCATION",
    "US_SSN",
    "SG_NRIC",
    "URL",
]


@dataclass
class RedactionResult:
    text: str
    counts: Counter
    findings: list[dict]


def _token(entity_type: str, value: str) -> str:
    h = hashlib.blake2b(f"{entity_type}|{value}".encode(), digest_size=8).hexdigest()
    return f"<{entity_type}_{h}>"


def _regex_second_pass(text: str) -> tuple[str, Counter]:
    """Catch whatever Presidio missed using the same patterns as the verifier."""
    counts: Counter = Counter()
    for kind, (pattern, luhn_check) in CHECKS.items():
        pieces: list[str] = []
        last = 0
        for m in pattern.finditer(text):
            value = m.group(0)
            if luhn_check and not _luhn(value):
                pieces.append(text[last : m.end()])
                last = m.end()
                continue
            pieces.append(text[last : m.start()])
            pieces.append(_token(kind, value))
            counts[kind] += 1
            last = m.end()
        pieces.append(text[last:])
        text = "".join(pieces)
    return text, counts


def build_analyzer() -> AnalyzerEngine:
    _check_model_integrity()
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    for r in all_custom():
        registry.add_recognizer(r)
    return AnalyzerEngine(registry=registry)


class Redactor:
    def __init__(self, analyzer: AnalyzerEngine | None = None):
        self.analyzer = analyzer or build_analyzer()
        self.anonymizer = AnonymizerEngine()

    def redact(self, text: str) -> RedactionResult:
        # FIND-08: 'text' holds raw PII in the Python heap. Python strings are immutable
        # and their underlying buffer is not zeroed on GC. On systems with a swap file,
        # this data may be written to disk in cleartext. Mitigation: enable full-disk
        # encryption (BitLocker on Windows, FileVault on macOS) on the host machine.
        if not text.strip():
            return RedactionResult(text=text, counts=Counter(), findings=[])

        results = self.analyzer.analyze(
            text=text,
            entities=REDACT_ENTITIES,
            language="en",
            score_threshold=0.4,
        )

        # Sort descending so offsets remain valid during string replacement.
        results_sorted = sorted(results, key=lambda r: r.start, reverse=True)

        out = text
        counts: Counter = Counter()
        findings: list[dict] = []
        for r in results_sorted:
            original = text[r.start:r.end]
            placeholder = _token(r.entity_type, original)
            out = out[: r.start] + placeholder + out[r.end :]
            counts[r.entity_type] += 1
            findings.append(
                {
                    "entity_type": r.entity_type,
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                    "placeholder": placeholder,
                }
            )
        # Second pass: regex sweep for anything Presidio missed (e.g. card numbers
        # in reference strings, PayLah wallet numbers, etc.).
        out, regex_counts = _regex_second_pass(out)
        counts.update(regex_counts)

        return RedactionResult(text=out, counts=counts, findings=findings)
