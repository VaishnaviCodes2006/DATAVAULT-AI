from detector import detect
from policy import decide, load_config
C = load_config()
def d(text, dest="approved_ai", role="user"): return decide(text, detect(text), dest, role, C).action
def test_branches():
    assert d("hello there") == "allow"
    assert d("mail a@b.co") == "mask"
    assert d("token: abcd1234fake") == "block"
    assert d("hello", dest="nowhere") == "block"
    assert d("hello", dest="restricted_ai", role="user") == "require_authorization"
    assert d("hello", dest="restricted_ai", role="admin") == "allow"
    assert d("TOP SECRET plan") == "require_authorization"
    assert d("TOP SECRET plan", role="analyst") == "allow"
def test_block_beats_mask():
    assert d("a@b.co token: abcd1234fake") == "block"
