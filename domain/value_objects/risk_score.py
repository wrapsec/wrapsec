class RiskScore:
    MIN = 0.0
    MAX = 1.0

    def __init__(self, value: float):
        if not isinstance(value, (int, float)):
            raise TypeError(f"RiskScore must be a float, got {type(value)}")
        if not self.MIN <= value <= self.MAX:
            raise ValueError(
                f"RiskScore must be between {self.MIN} and {self.MAX}, got {value}"
            )
        self._value = round(float(value), 4)

    @property
    def value(self) -> float:
        return self._value

    @classmethod
    def zero(cls) -> "RiskScore":
        return cls(0.0)

    @classmethod
    def max(cls) -> "RiskScore":
        return cls(1.0)

    def is_above(self, threshold: float) -> bool:
        return self._value >= threshold

    def __float__(self) -> float:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __repr__(self) -> str:
        return f"RiskScore({self._value})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RiskScore):
            return self._value == other._value
        if isinstance(other, float):
            return self._value == other
        return False

    def __lt__(self, other: "RiskScore") -> bool:
        return self._value < other._value

    def __le__(self, other: "RiskScore") -> bool:
        return self._value <= other._value

    def __gt__(self, other: "RiskScore") -> bool:
        return self._value > other._value

    def __ge__(self, other: "RiskScore") -> bool:
        return self._value >= other._value