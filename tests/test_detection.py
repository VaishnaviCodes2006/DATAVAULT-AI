from detector import detect
cats = lambda t: {s.category for s in detect(t)}

def test_example_record():
    assert cats("customer record: John Smith, john@example.com, account number 123456789.") == {"PERSON", "EMAIL", "ACCOUNT_ID"}
def test_bare_digits_are_not_accounts():
    assert cats("Order 123456789 shipped") == set()
def test_secrets():
    assert "SECRET" in cats("API_KEY = sk-FAKEFAKEFAKEFAKE12345678")
    assert "SECRET" in cats("PASSWORD: hunter2fake")   # casing
def test_luhn():
    assert cats("4111 1111 1111 1111") == {"CREDIT_CARD"}
    assert cats("4111 1111 1111 1112") == set()
def test_long_input_and_empty_ok():
    assert detect("a " * 9000) == []
def test_overlap_resolution():
    assert [s.category for s in detect("password: john@example.com")] == ["SECRET"]
