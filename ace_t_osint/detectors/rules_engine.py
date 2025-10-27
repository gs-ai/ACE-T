from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..utils.html import normalize_whitespace


@dataclass
class RuleMatch:
    rule_id: str
    matched_text: str
    context: List[str]
    tags: List[str]
    classification: str


class RulesEngine:
    def __init__(self, rules_path: str | Path) -> None:
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict]:
        with self.rules_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data.get("rules", [])

    @staticmethod
    def _window(lines: List[str], index: int, context: int) -> List[str]:
        start = max(0, index - context)
        end = min(len(lines), index + context + 1)
        return lines[start:end]

    def evaluate(self, text: str) -> Iterable[RuleMatch]:
        normalized = normalize_whitespace(text)
        lines = normalized.split(" ")
        for rule in self.rules:
            include_terms = [term.lower() for term in rule.get("include", [])]
            exclude_terms = [term.lower() for term in rule.get("exclude", [])]
            regex_patterns = [re.compile(pat, re.IGNORECASE) for pat in rule.get("regex", [])]
            window = rule.get("window", 200)
            context = rule.get("context", 2)
            content_lower = normalized.lower()

            if include_terms and not any(term in content_lower for term in include_terms):
                continue
            if exclude_terms and any(term in content_lower for term in exclude_terms):
                continue
            regex_match_text = None
            for pattern in regex_patterns:
                match = pattern.search(normalized)
                if match:
                    regex_match_text = match.group(0)
                    break
            if regex_patterns and not regex_match_text:
                continue

            proximity = rule.get("proximity")
            if proximity:
                terms = [t.lower() for t in proximity.get("terms", [])]
                distance = proximity.get("distance", 10)
                tokens = normalized.lower().split()
                indices = {term: [] for term in terms}
                for idx, token in enumerate(tokens):
                    if token in indices:
                        indices[token].append(idx)
                if not all(indices.values()):
                    continue
                valid = False
                for positions in zip(*indices.values()):
                    if max(positions) - min(positions) <= distance:
                        valid = True
                        break
                if not valid:
                    continue

            matched_text = regex_match_text or " ".join(lines[: min(len(lines), window)])
            yield RuleMatch(
                rule_id=rule.get("id", "unknown"),
                matched_text=matched_text,
                context=self._window(lines, 0, context),
                tags=rule.get("tags", []),
                classification=rule.get("classification", "public"),
            )


__all__ = ["RulesEngine", "RuleMatch"]
