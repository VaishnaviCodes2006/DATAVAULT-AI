# DataVault AI (prototype)

Security gateway that detects, classifies, masks or blocks sensitive data before it reaches a downstream AI service.
Flow: **detect → decide → protect → forward → audit**. Built from the Team HyperByte design document.

## Run
```bash
./run.sh      # creates .venv, generates API keys into .env (mode 600), serves on 127.0.0.1:8443
# open http://127.0.0.1:8443 and paste a key printed by scripts/gen_keys.py
```
Docker (multi-arch, including linux/s390x on LinuxONE):
```bash
docker build -t datavault-ai .
docker run -p 127.0.0.1:8443:8443 -e DATAVAULT_KEYS='alice:admin:<24+ char key>' -v dv_data:/app/data datavault-ai
```
Tests and measurements: `pip install -r requirements-dev.txt && pytest && python evaluate.py`

## API (all except /healthz need header `X-API-Key`)
| Endpoint | Roles | Purpose |
|---|---|---|
| POST /v1/inspect `{text, destination}` | user, analyst, admin | run the gateway |
| GET /v1/events, /v1/metrics | analyst, admin | audit metadata only |
| GET /healthz | none | status and active NER engine |

## Security controls implemented
Hashed API keys with constant-time comparison and role checks; failed-auth and per-key rate limits; 64 KB body and 20,000 character caps; strict input validation; fail-closed on inspection errors; unknown destinations blocked; audit stores metadata only (tests check secrets never appear in the DB or connector); no docs/OpenAPI endpoints, no CORS; CSP, nosniff, no-store headers; dashboard never uses innerHTML; non-root container; localhost binding by default.
**Before real use:** terminate TLS (certs in `certs/server.crt|key`, or a proxy), integrate your identity provider, run threat testing.

## LinuxONE (s390x) notes
Required packages are pure Python or ship s390x wheels (FastAPI, uvicorn without uvloop, pydantic, PyYAML, SQLite). The dashboard is plain HTML/JS served by the gateway because Streamlit depends on pyarrow, which may lack s390x wheels. Presidio/spaCy (`requirements-nlp.txt`) is optional; `/healthz` reports `rules-only` when absent. **Not yet run on IBM LinuxONE**: treat as "proposed" until tested there.

## Known limits
Rules-only mode finds names only with cues ("Dr. X", "customer: X Y"); obfuscated values ("john [at] example.com", encoded text) are not caught; rate limits are in-memory per process; the evaluation set is small and written alongside the rules, so its scores are optimistic.
