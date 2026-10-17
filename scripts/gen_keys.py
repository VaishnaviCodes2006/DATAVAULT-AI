"""Create .env with random API keys (file mode 600). Keys are printed once."""
import os, secrets, stat
from pathlib import Path
p = Path(__file__).resolve().parent.parent / ".env"
if p.exists():
    raise SystemExit(".env already exists; delete it to rotate keys.")
keys = {r: secrets.token_urlsafe(32) for r in ("admin", "analyst", "user")}
p.write_text("DATAVAULT_KEYS=" + ",".join(f"{r}1:{r}:{k}" for r, k in keys.items()) + "\n")
os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
print("Wrote .env (mode 600). Store these keys now; they are not shown again:")
for r, k in keys.items(): print(f"  {r:8s} {k}")
