"""Singapore-specific and extra Presidio recognizers."""
from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer, EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


# NRIC / FIN checksum.
# Format: [STFGM]\d{7}[A-Z]
# Weights: 2,7,6,5,4,3,2
# Add 4 (T/G) or 8 (M) before mod 11.
_NRIC_TABLES = {
    "S": ("JZIHGFEDCBA", 0),
    "T": ("JZIHGFEDCBA", 4),
    "F": ("XWUTRQPNMLK", 0),
    "G": ("XWUTRQPNMLK", 4),
    "M": ("KLJNPQRTUWX", 3),
}


def _nric_valid(nric: str) -> bool:
    if len(nric) != 9:
        return False
    first = nric[0].upper()
    if first not in _NRIC_TABLES:
        return False
    digits = nric[1:8]
    if not digits.isdigit():
        return False
    check = nric[8].upper()
    weights = (2, 7, 6, 5, 4, 3, 2)
    total = sum(int(d) * w for d, w in zip(digits, weights))
    table, offset = _NRIC_TABLES[first]
    expected = table[(total + offset) % 11]
    return expected == check


class SgNricRecognizer(EntityRecognizer):
    def __init__(self) -> None:
        super().__init__(supported_entities=["SG_NRIC"], name="SgNricRecognizer")

    def load(self) -> None:  # pragma: no cover - required by base class
        return None

    def analyze(self, text: str, entities, nlp_artifacts: NlpArtifacts | None = None):
        import re
        pattern = re.compile(r"\b[STFGM]\d{7}[A-Z]\b")
        results: list[RecognizerResult] = []
        for m in pattern.finditer(text):
            if _nric_valid(m.group(0)):
                results.append(
                    RecognizerResult(
                        entity_type="SG_NRIC",
                        start=m.start(),
                        end=m.end(),
                        score=0.95,
                    )
                )
        return results


_SG_MOBILE = Pattern(name="sg_mobile", regex=r"\b[89]\d{3}\s?\d{4}\b", score=0.6)


class SgMobileRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=[_SG_MOBILE],
            context=["mobile", "phone", "hp", "contact", "tel"],
        )


_SG_POSTAL = Pattern(name="sg_postal", regex=r"\bSingapore\s+\d{6}\b|\b\d{6}\b(?=\s*(?:Singapore|$))", score=0.5)


class SgPostalRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity="LOCATION",
            patterns=[_SG_POSTAL],
            context=["singapore", "postal", "address"],
        )


_ETH_ADDR = Pattern(name="eth_address", regex=r"\b0x[a-fA-F0-9]{40}\b", score=0.85)
_SOL_ADDR = Pattern(name="sol_address", regex=r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])", score=0.3)


class CryptoWalletRecognizer(PatternRecognizer):
    """Extra crypto formats beyond Presidio's built-in BTC."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="CRYPTO",
            patterns=[_ETH_ADDR, _SOL_ADDR],
            context=["wallet", "address", "eth", "ethereum", "solana", "sol"],
        )


# Common Chinese surnames in Chinese characters (simplified + traditional).
_ZH_SURNAMES = (
    "李王张刘陈杨黄赵吴周徐孙马胡朱郭何高林郑谢罗梁宋唐许韩冯邓曹彭曾肖田董袁潘"
    "于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方邹熊白孟秦邱"
    "侯江尹薛闫段雷龙黎史陶贺顾毛郝龚邵万钱严覃武戴莫洪萧许邱庄佘"
    # Traditional-script variants
    "陳張劉楊趙吳徐孫郭鄭謝羅梁許韓馮鄧曹彭曾蕭田董袁潘蔣蔡呂任沈姚盧姜崔鐘譚陸"
    "範廖賈夏韋鄒熊孟秦邱侯閻雷龍黎陶賀顧龔鄒萬錢嚴覃戴莫洪蕭許邱莊佘"
)

_ZH_NAME_RE = re.compile(
    r"(?<![^\s一-鿿])"  # not preceded by a non-space CJK char
    r"[" + _ZH_SURNAMES + r"]"
    r"[一-鿿]{1,2}"
    r"(?![一-鿿])"       # not followed by more CJK (avoids mid-word hits)
)


class ChineseCharNameRecognizer(EntityRecognizer):
    """Detects Chinese-character personal names (surname + 1-2 given-name chars)."""

    def __init__(self) -> None:
        super().__init__(supported_entities=["PERSON"], name="ChineseCharNameRecognizer")

    def load(self) -> None:  # pragma: no cover
        return None

    def analyze(self, text: str, entities, nlp_artifacts: NlpArtifacts | None = None):
        results: list[RecognizerResult] = []
        for m in _ZH_NAME_RE.finditer(text):
            results.append(
                RecognizerResult(entity_type="PERSON", start=m.start(), end=m.end(), score=0.75)
            )
        return results


# Romanized Chinese surnames common in Singapore / Malaysia / Taiwan / HK.
_ROM_SURNAMES = (
    "Ang|Aw|Bay|Beh|Chai|Chan|Chen|Chia|Chin|Choo|Chong|Chow|Chu|Chua|Chew|"
    "Fong|Foo|Gan|Goh|Han|Heng|Ho|Hoe|Huang|Hung|Khoo|Ko|Kok|Kong|Koh|Koo|"
    "Ku|Kwek|Kwok|Lai|Lam|Lau|Lee|Leong|Lim|Lin|Liu|Loh|Low|Mah|Mak|Mok|Neo|"
    "Ng|Ong|Pan|Pang|Phua|Png|Poon|Quah|Quek|See|Seah|Seow|Sim|Sng|Soh|Sum|"
    "Sun|Tan|Tang|Tay|Teo|Teng|Thio|Tng|Toh|Tsai|Tsang|Tse|Wang|Wee|Wong|Woo|Wu|"
    "Yang|Yap|Yee|Yeo|Yim|Yiu|Yong|Yuen"
)

_ROM_NAME_PATTERN = Pattern(
    name="romanized_chinese_name",
    # Surname followed by 1-2 capitalized given-name words (e.g. "Tan Wei Ming")
    regex=r"\b(?:" + _ROM_SURNAMES + r")\s+[A-Z][a-z]{1,14}(?:\s+[A-Z][a-z]{1,14})?\b",
    score=0.65,
)


class RomanizedChineseNameRecognizer(PatternRecognizer):
    """Detects romanized Chinese names (common surnames + capitalized given name)."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PERSON",
            patterns=[_ROM_NAME_PATTERN],
            context=["name", "mr", "mrs", "ms", "miss", "dr", "account", "holder", "payee"],
        )


def all_custom():
    return [
        SgNricRecognizer(),
        SgMobileRecognizer(),
        SgPostalRecognizer(),
        CryptoWalletRecognizer(),
        ChineseCharNameRecognizer(),
        RomanizedChineseNameRecognizer(),
    ]
