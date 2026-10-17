"""Measure detection quality and latency on data/synthetic_samples.json (category-level, per sample)."""
import json, statistics, sys, time
from pathlib import Path
from detector import detect, nlp_available
from audit import Audit
from connector import MockAIConnector
from gateway import Gateway
from policy import load_config

data = json.loads(Path(__file__).with_name("data").joinpath("synthetic_samples.json").read_text())
gw = Gateway(load_config(), Audit(":memory:"), MockAIConnector())
tp = fp = fn = neg_total = neg_flagged = action_ok = 0
lat = []
for ex in data:
    t0 = time.perf_counter()
    got = {s.category for s in detect(ex["text"])}
    lat.append((time.perf_counter() - t0) * 1000)
    want = set(ex["entities"])
    tp += len(got & want); fp += len(got - want); fn += len(want - got)
    if not want:
        neg_total += 1; neg_flagged += bool(got)
    action_ok += gw.process(ex["text"], "eval", "user", "approved_ai")["action"] == ex["action"]
p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0
print(json.dumps({"samples": len(data), "nlp_engine": "presidio" if nlp_available() else "rules-only",
    "precision": round(p, 3), "recall": round(r, 3), "f1": round(2 * p * r / (p + r), 3) if p + r else 0,
    "false_positive_rate_on_clean_samples": round(neg_flagged / neg_total, 3),
    "policy_action_accuracy": round(action_ok / len(data), 3),
    "detect_latency_ms_median": round(statistics.median(lat), 3), "detect_latency_ms_max": round(max(lat), 3)}, indent=2))
