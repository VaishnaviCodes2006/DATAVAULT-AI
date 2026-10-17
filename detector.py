"""Sensitive-data detection: regex/context rules plus optional Presidio/spaCy for names."""
import re
from dataclasses import dataclass

@dataclass(frozen=True)
class Span:
    start: int
    end: int
    category: str
    source: str

def _luhn(digits: str) -> bool:
    d = [int(c) for c in digits][::-1]
    return len(d) >= 13 and (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0

# (category, compiled regex, capture group used as the span, validator)
_R = lambda p, f=0: re.compile(p, f)
RULES = [
    ("EMAIL", _R(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"), 0, None),
    ("PHONE", _R(r"(?<![\w-])(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w-])"), 0, None),
    ("PHONE", _R(r"(?<![\w-])\+\d{1,3}[\s.-]?\d{8,12}(?!\d)"), 0, None),
    ("PHONE", _R(r"(?:phone|mobile|tel|call|contact)\D{0,15}(\+?\d[\d\s.-]{8,14}\d)", re.I), 1, None),
    ("ACCOUNT_ID", _R(r"(?:account|acct|a/c)(?:\s*(?:number|no\.?|num|#|id))?\s*[:#-]?\s*(\d{6,18})(?!\d)", re.I), 1, None),
    ("CREDIT_CARD", _R(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), 0, lambda s: _luhn(re.sub(r"\D", "", s))),
    ("SSN", _R(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 0, None),
    ("SECRET", _R(r"AKIA[0-9A-Z]{16}"), 0, None),
    ("SECRET", _R(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"), 0, None),
    ("SECRET", _R(r"gh[pousr]_[A-Za-z0-9]{20,}"), 0, None),
    ("SECRET", _R(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0, None),
    ("SECRET", _R(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0, None),
    ("SECRET", _R(r"bearer\s+([A-Za-z0-9._~+/=-]{16,})", re.I), 1, None),
    ("SECRET", _R(r"(?:password|passwd|pwd|secret|api[_ -]?key|access[_ -]?token|token)\s*(?:is|[:=])\s*[\"']?(\S{4,})", re.I), 1, None),
    # Name cues (used when Presidio/spaCy is unavailable; Presidio adds general NER)
    ("PERSON", _R(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)"), 1, None),
    ("PERSON", _R(r"(?i:\bname\s*(?:is|:))\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})"), 1, None),
    ("PERSON", _R(r"(?i:\b(?:record|customer|client|employee|patient|user|from|contact)\b)\s*:?\s+([A-Z][a-z]+\s[A-Z][a-z]+)\b"), 1, None),
]

_presidio = None
def _load_presidio():
    global _presidio
    if _presidio is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            _presidio = AnalyzerEngine()
        except Exception:
            _presidio = False
    return _presidio

def nlp_available() -> bool:
    return bool(_load_presidio())

def detect(text: str) -> list[Span]:
    spans = []
    for cat, rx, grp, validate in RULES:
        for m in rx.finditer(text):
            if validate and not validate(m.group(0)):
                continue
            spans.append(Span(m.start(grp), m.end(grp), cat, "rule"))
    engine = _load_presidio()
    if engine:
        for r in engine.analyze(text=text, language="en", entities=["PERSON"]):
            if r.score >= 0.6:
                spans.append(Span(r.start, r.end, "PERSON", "nlp"))
    return merge(spans)

_PRIORITY = {"SECRET": 0, "SSN": 1, "CREDIT_CARD": 2, "ACCOUNT_ID": 3, "EMAIL": 4, "PHONE": 5, "PERSON": 6}

def merge(spans: list[Span]) -> list[Span]:
    """Resolve overlaps: higher-priority category wins, then the longer span."""
    ordered = sorted(spans, key=lambda s: (_PRIORITY.get(s.category, 9), -(s.end - s.start), s.start))
    kept: list[Span] = []
    for s in ordered:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)
