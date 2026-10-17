"""Mock downstream AI service. It only accepts text the gateway has approved."""
class MockAIConnector:
    def __init__(self):
        self.received: list[str] = []   # kept in memory so tests can prove nothing raw arrives

    def send(self, sanitized_text: str, approved: bool) -> str:
        if not approved:
            raise PermissionError("connector refuses unapproved content")
        self.received.append(sanitized_text)
        return f"[mock AI] Received {len(sanitized_text)} characters of approved text."
