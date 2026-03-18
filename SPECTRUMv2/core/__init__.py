from __future__ import annotations

__all__ = ["DEFAULT_REGISTRY", "SchemaRegistry", "load_default_registry"]


def __getattr__(name: str):
    if name in {"DEFAULT_REGISTRY", "SchemaRegistry", "load_default_registry"}:
        from .schema_registry import DEFAULT_REGISTRY, SchemaRegistry, load_default_registry

        values = {
            "DEFAULT_REGISTRY": DEFAULT_REGISTRY,
            "SchemaRegistry": SchemaRegistry,
            "load_default_registry": load_default_registry,
        }
        return values[name]
    raise AttributeError(f"module 'core' has no attribute {name!r}")
