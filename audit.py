"""Minimal audit store: metadata only. Original prompts are never written."""
import json, os, sqlite3, threading
from datetime import datetime, timezone

class Audit:
    def __init__(self, path: str):
        self.path, self.lock = path, threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS events(
            id TEXT PRIMARY KEY, ts TEXT, principal TEXT, role TEXT, destination TEXT,
            categories TEXT, sensitivity TEXT, action TEXT, latency_ms REAL, forwarded INTEGER)""")
        self.db.commit()
        try: os.chmod(path, 0o600)
        except OSError: pass

    def record(self, event_id, principal, role, destination, categories, sensitivity, action, latency_ms, forwarded):
        with self.lock:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
                (event_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), principal, role,
                 destination, json.dumps(categories), sensitivity, action, round(latency_ms, 2), int(forwarded)))
            self.db.commit()

    def recent(self, limit: int = 50):
        with self.lock:
            rows = self.db.execute("SELECT * FROM events ORDER BY ts DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        keys = ["event_id", "timestamp", "principal", "role", "destination", "categories", "sensitivity", "action", "latency_ms", "forwarded"]
        return [{**dict(zip(keys, r)), "categories": json.loads(r[5]), "forwarded": bool(r[9])} for r in rows]

    def metrics(self):
        with self.lock:
            total, avg = self.db.execute("SELECT COUNT(*), COALESCE(AVG(latency_ms),0) FROM events").fetchone()
            actions = dict(self.db.execute("SELECT action, COUNT(*) FROM events GROUP BY action").fetchall())
            cats: dict[str, int] = {}
            for (c,) in self.db.execute("SELECT categories FROM events"):
                for k in json.loads(c): cats[k] = cats.get(k, 0) + 1
        return {"total": total, "avg_latency_ms": round(avg, 2), "actions": actions, "categories": cats}
