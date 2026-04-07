import uuid


class TraceId:
    PREFIX = "req"

    def __init__(self, value: str | None = None):
        if value:
            self._value = value
        else:
            self._value = f"{self.PREFIX}_{uuid.uuid4().hex[:8]}"

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