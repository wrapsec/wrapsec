from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class MLPrediction:
    label:      str
    confidence: float
    all_scores: dict[str, float]


class BaseMLModel(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Model name."""

    @abstractmethod
    def predict(self, text: str) -> MLPrediction:
        """Run prediction — must never raise."""

    @abstractmethod
    def is_ready(self) -> bool:
        """Returns True if model is loaded and ready."""