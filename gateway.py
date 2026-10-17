"""detect -> decide -> protect -> forward -> audit. The only path to the connector."""
import time, uuid
from detector import detect
from sanitizer import mask
from policy import decide

class Gateway:
    def __init__(self, cfg, audit, connector):
        self.cfg, self.audit, self.connector = cfg, audit, connector
        self.labels = {k: v["label"] for k, v in cfg["categories"].items()}

    def process(self, text: str, principal: str, role: str, destination: str) -> dict:
        t0, event_id = time.perf_counter(), str(uuid.uuid4())
        try:
            if len(text) > self.cfg["max_input_chars"]:
                raise ValueError("input too large")
            spans = detect(text)
            d = decide(text, spans, destination, role, self.cfg)
        except Exception:   # fail closed: nothing is forwarded if inspection fails
            spans, d = [], type("D", (), {"action": "block", "sensitivity": "unknown", "categories": ["INSPECTION_ERROR"],
                                          "reasons": ["inspection failed; request blocked (fail-closed)"]})()
        sanitized = ai = None
        forwarded = False
        if d.action in ("allow", "mask"):
            sanitized = mask(text, spans, self.labels) if d.action == "mask" else text
            ai = self.connector.send(sanitized, approved=True)
            forwarded = True
        ms = (time.perf_counter() - t0) * 1000
        self.audit.record(event_id, principal, role, destination, d.categories, d.sensitivity, d.action, ms, forwarded)
        return {"event_id": event_id, "action": d.action, "sensitivity": d.sensitivity, "reasons": d.reasons,
                "findings": [{"category": s.category, "start": s.start, "end": s.end, "source": s.source} for s in spans],
                "sanitized_text": sanitized, "ai_response": ai, "forwarded": forwarded, "latency_ms": round(ms, 2)}
