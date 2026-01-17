from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from .legacy_adapter import (
    alert_to_artifact,
    ioc_to_artifact,
    ioc_to_signal,
    target_to_signal,
)

__all__ = [
    "alert_to_artifact",
    "ioc_to_artifact",
    "ioc_to_signal",
    "target_to_signal",
]
