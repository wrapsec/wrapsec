import os


class TraceId:
    PREFIX = "req"

    def __init__(self, value: str | None = None):
        if value:
            self._value = value
        else:
            self._value = f"{self.PREFIX}_{self._generate_ulid()}"

    @staticmethod
    def _generate_ulid() -> str:
        """
        Generate a ULID-based identifier.
        Lexicographically sortable by time — better for DB indexing
        and audit log ordering than random hex.
        Falls back to random hex if python-ulid not installed.
        """
        try:
            from ulid import ULID
            return str(ULID()).lower()
        except ImportError:
            # Fallback — random hex (maintains backward compatibility)
            import uuid
            return uuid.uuid4().hex[:8]

    @property
    def value(self) -> str:
        return self._value

    @classmethod
    def generate(cls) -> "TraceId":
        return cls()

    @classmethod
    def from_string(cls, value: str) -> "TraceId":
        if not value.startswith(cls.PREFIX + "_"):
            raise ValueError(f"Invalid trace_id format: {value}")
        return cls(value)

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"TraceId('{self._value}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TraceId):
            return self._value == other._value
        return False

    def __hash__(self) -> int:
        return hash(self._value)