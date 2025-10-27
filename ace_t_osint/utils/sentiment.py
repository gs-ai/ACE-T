from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Dict

logger = logging.getLogger(__name__)


class SentimentAnalyzer:
    def __init__(self, lexicon_path: str, model_path: str | None = None) -> None:
        self.lexicon = self._load_lexicon(lexicon_path)
        self.model_path = model_path
        if model_path and not os.path.exists(model_path):
            logger.warning("sentiment-model-missing", extra={"path": model_path})

    @staticmethod
    def _load_lexicon(path: str) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        if not os.path.exists(path):
            return mapping
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    sentiment, word = line.split(":", 1)
                    mapping[word.lower()] = sentiment
                except ValueError:
                    continue
        return mapping

    def analyse(self, text: str) -> str:
        tokens = [token.lower() for token in text.split()]
        counts = Counter(self.lexicon.get(token, "neutral") for token in tokens if token in self.lexicon)
        if not counts:
            return "neu"
        positive = counts.get("positive", 0)
        negative = counts.get("negative", 0)
        if positive > negative:
            return "pos"
        if negative > positive:
            return "neg"
        return "neu"


__all__ = ["SentimentAnalyzer"]
