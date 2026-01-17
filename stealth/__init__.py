"""
Stealth/OPSEC controls.

Expose Tor enforcement, monitoring, shutdown, and socket guards from a single
namespace so callers do not reach into legacy modules.
"""
from ace_t_osint.utils.tor_enforcer import (
    get_tor_enforcer,
    TorEnforcer,
    TorNotReadyError,
    TorEnforcerError,
)
from ace_t_osint.utils.monitoring import (
    get_monitoring_system,
    setup_structured_logging,
    trace_operation,
    monitor_performance,
)
from ace_t_osint.system.shutdown_manager import install_shutdown_manager
from ace_t_osint.system.watchdog import start_watchdog, initiate_shutdown

__all__ = [
    "get_tor_enforcer",
    "TorEnforcer",
    "TorNotReadyError",
    "TorEnforcerError",
    "get_monitoring_system",
    "setup_structured_logging",
    "trace_operation",
    "monitor_performance",
    "install_shutdown_manager",
    "start_watchdog",
    "initiate_shutdown",
]
