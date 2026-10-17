from detector import detect
from sanitizer import mask
from policy import load_config
L = {k: v["label"] for k, v in load_config()["categories"].items()}
def test_masking_removes_values_and_keeps_rest():
    t = "Hi Dr. Priya Sharma, mail priya@example.com now."
    out = mask(t, detect(t), L)
    assert out == "Hi Dr. [PERSON], mail [EMAIL] now."
def test_unicode_offsets():
    t = "héllo 🙂 a@b.co ok"
    assert mask(t, detect(t), L) == "héllo 🙂 [EMAIL] ok"
