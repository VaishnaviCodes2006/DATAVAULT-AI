from detector import Span

def mask(text: str, spans: list[Span], labels: dict[str, str]) -> str:
    """Replace non-overlapping spans right-to-left so earlier offsets stay valid."""
    out = text
    for s in sorted(spans, key=lambda s: s.start, reverse=True):
        out = out[:s.start] + labels.get(s.category, "[REDACTED]") + out[s.end:]
    return out
