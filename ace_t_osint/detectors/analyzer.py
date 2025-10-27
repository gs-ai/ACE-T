from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List

from .rules_engine import RuleMatch, RulesEngine
from ..utils.sentiment import SentimentAnalyzer


@dataclass
class DetectionResult:
    rule: RuleMatch
    entities: Dict[str, List[str]]
    sentiment: str


class Detector:
    def __init__(
        self,
        rules_engine: RulesEngine,
        entities: Dict[str, List[str]],
        sentiment: SentimentAnalyzer,
    ) -> None:
        self.rules_engine = rules_engine
        self.entities = entities
        self.sentiment = sentiment

    def detect(self, text: str) -> Iterable[DetectionResult]:
        matches = list(self.rules_engine.evaluate(text))
        if not matches:
            return []
        extracted = {key: self._extract(values, text) for key, values in self.entities.items()}
        sentiment = self.sentiment.analyse(text)
        results = [DetectionResult(rule=match, entities=extracted, sentiment=sentiment) for match in matches]
        return results

    @staticmethod
    def _extract(patterns: List[str], text: str) -> List[str]:
        found: List[str] = []
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                found.extend(regex.findall(text))
            except re.error:
                if pattern.lower() in text.lower():
                    found.append(pattern)
        return list(dict.fromkeys(found))


__all__ = ["Detector", "DetectionResult"]
