import re
from dataclasses import dataclass, field
from pathlib import Path
import yaml
from detector import Span

_ORDER = {"allow": 0, "mask": 1, "require_authorization": 2, "block": 3}
_LEVEL = {"none": 0, "low": 1, "medium": 2, "high": 3, "restricted": 4}

def load_config(path: str | None = None) -> dict:
    p = Path(path or Path(__file__).with_name("config.yaml"))
    return yaml.safe_load(p.read_text())

@dataclass
class Decision:
    action: str
    sensitivity: str
    categories: list[str]
    reasons: list[str] = field(default_factory=list)

def decide(text: str, spans: list[Span], destination: str, role: str, cfg: dict) -> Decision:
    cats = sorted({s.category for s in spans})
    action, level, reasons = "allow", "none", []

    def raise_to(a, why):
        nonlocal action
        reasons.append(why)
        if _ORDER[a] > _ORDER[action]:
            action = a

    dest = cfg["destinations"].get(destination)
    if dest is None:
        raise_to("block", "destination is not approved")
    elif role not in dest["allowed_roles"]:
        raise_to("require_authorization", f"role '{role}' is not permitted for this destination")

    for c in cats:
        rule = cfg["categories"].get(c, {"action": "block", "sensitivity": "high"})
        raise_to(rule["action"], f"{c} detected")
        if _LEVEL[rule["sensitivity"]] > _LEVEL[level]:
            level = rule["sensitivity"]

    upper = text.upper()
    if any(m in upper for m in cfg.get("restricted_markers", [])):
        level = "restricted"
        if role == "user":
            raise_to("require_authorization", "restricted document needs analyst/admin authorization")
        else:
            reasons.append("restricted document marker present")
    return Decision(action, level, cats, reasons)
