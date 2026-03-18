from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator


@dataclass
class SchemaRegistry:
    base_dir: Path
    schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    validators: Dict[str, Draft202012Validator] = field(default_factory=dict)

    def register(self, name: str, path: Path) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(payload)
        self.schemas[name] = payload
        self.validators[name] = Draft202012Validator(payload)

    def validator(self, name: str) -> Draft202012Validator:
        if name not in self.validators:
            raise KeyError(f"Schema not registered: {name}")
        return self.validators[name]

    def intel_object_validator(self, name: str) -> Draft202012Validator:
        if name not in self.schemas:
            raise KeyError(f"Schema not registered: {name}")
        schema = self.schemas[name]
        obj_schema = {
            "$schema": schema.get("$schema"),
            "$id": schema.get("$id"),
            "$defs": schema.get("$defs"),
            "$ref": "#/$defs/IntelObject",
        }
        Draft202012Validator.check_schema(obj_schema)
        return Draft202012Validator(obj_schema)


def load_default_registry() -> SchemaRegistry:
    root = Path(__file__).resolve().parents[1]
    registry = SchemaRegistry(root)
    intel_path = root / "schemas" / "acet_intel.schema.json"
    if not intel_path.exists():
        raise FileNotFoundError(f"Missing schema file: {intel_path}")
    registry.register("intel_bundle", intel_path)
    return registry


DEFAULT_REGISTRY = load_default_registry()
