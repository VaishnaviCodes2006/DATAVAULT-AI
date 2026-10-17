import pytest
from fastapi.testclient import TestClient
from api import create_app
K = {"u": "u" * 30, "a": "a" * 30, "m": "m" * 30}
RAW = f"u1:user:{K['u']},a1:analyst:{K['a']},m1:admin:{K['m']}"

@pytest.fixture
def app(tmp_path): return create_app(RAW, str(tmp_path / "t.db"))
@pytest.fixture
def c(app): return TestClient(app)
H = lambda k: {"X-API-Key": K[k]}

def test_auth_required(c):
    assert c.post("/v1/inspect", json={"text": "hi"}).status_code == 401
    assert c.post("/v1/inspect", json={"text": "hi"}, headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.get("/v1/events").status_code == 401
def test_roles(c):
    assert c.get("/v1/events", headers=H("u")).status_code == 403
    assert c.get("/v1/events", headers=H("a")).status_code == 200
def test_blocked_never_reaches_connector_or_audit(app, c):
    secret = "sk-FAKEFAKEFAKEFAKE12345678"
    r = c.post("/v1/inspect", json={"text": f"api_key={secret}"}, headers=H("u")).json()
    assert r["action"] == "block" and r["sanitized_text"] is None and not r["forwarded"]
    assert app.state.connector.received == []
    assert secret not in str(app.state.audit.recent())
    assert secret not in str(c.get("/v1/events", headers=H("a")).json())
def test_masked_payload_clean(app, c):
    r = c.post("/v1/inspect", json={"text": "mail john@example.com"}, headers=H("u")).json()
    assert r["action"] == "mask" and "john@example.com" not in str(app.state.connector.received)
def test_input_limits(c):
    assert c.post("/v1/inspect", json={"text": "x" * 20001}, headers=H("u")).status_code in (413, 422)
    assert c.post("/v1/inspect", json={"text": ""}, headers=H("u")).status_code == 422
    assert c.post("/v1/inspect", json={"text": "hi", "destination": "../etc"}, headers=H("u")).status_code == 422
def test_fail_closed(app, c, monkeypatch):
    import gateway
    monkeypatch.setattr(gateway, "detect", lambda t: 1 / 0)
    r = c.post("/v1/inspect", json={"text": "hello"}, headers=H("u")).json()
    assert r["action"] == "block" and app.state.connector.received == []
def test_headers_and_no_docs(c):
    r = c.get("/healthz")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert c.get("/docs").status_code in (404, 405) or c.get("/docs").status_code == 404
def test_bruteforce_throttled(c):
    codes = [c.post("/v1/inspect", json={"text": "hi"}, headers={"X-API-Key": f"bad{i}"}).status_code for i in range(14)]
    assert 429 in codes
def test_weak_keys_rejected():
    with pytest.raises(ValueError): create_app("x:user:short", ":memory:")
