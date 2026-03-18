from __future__ import annotations
import asyncio
import logging
import os
from typing import Dict, Any
import signal

from .bus import EventBus
from .store import Store

from .agents.rss_ingest import RSSIngestAgent
from .agents.file_watch import FileWatchAgent
from .agents.normalize import NormalizeAgent
from .agents.ioc_extract import IOCExtractAgent
from .agents.llm_enrich import LLMEnrichAgent
from .agents.graph_writer import GraphWriterAgent
from .agents.timeline_writer import TimelineWriterAgent

def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml
    except Exception as e:
        raise RuntimeError("Missing dependency: pyyaml. Install: pip install pyyaml") from e
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def _setup_logging(level: str):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

async def main(config_path: str = "agents/config.yaml"):
    cfg = _load_yaml(config_path)
    _setup_logging(cfg.get("runtime", {}).get("log_level", "INFO"))
    log = logging.getLogger("agents.run")

    bus = EventBus(max_queue=int(cfg.get("bus", {}).get("max_queue", 5000)))
    store = Store(sqlite_path=cfg.get("storage", {}).get("sqlite_path", "db/osint.db"))

    # Instantiate agents
    rss = RSSIngestAgent(bus, store, cfg)
    files = FileWatchAgent(bus, store, cfg)
    norm = NormalizeAgent(bus, store, cfg)
    ioc = IOCExtractAgent(bus, store, cfg)
    llm = LLMEnrichAgent(bus, store, cfg)
    graph = GraphWriterAgent(bus, store, cfg)
    timeline = TimelineWriterAgent(bus, store, cfg)

    # Subscribe consumers
    bus.subscribe("raw.", norm.handle)
    bus.subscribe("norm.", ioc.handle)
    bus.subscribe("norm.", llm.handle)
    bus.subscribe("norm.", graph.handle)
    bus.subscribe("ioc.", graph.handle)
    bus.subscribe("enrich.", graph.handle)
    bus.subscribe("norm.", timeline.handle)
    bus.subscribe("ioc.", timeline.handle)
    bus.subscribe("enrich.", timeline.handle)

    # Graceful stop
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _stop(*_):
        bus.stop()
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    # Ensure required dirs
    os.makedirs(cfg.get("storage", {}).get("artifacts_dir", "data"), exist_ok=True)
    os.makedirs(cfg.get("storage", {}).get("quarantine_dir", "data/quarantine"), exist_ok=True)
    os.makedirs("data/intel_drops", exist_ok=True)
    log.info("Agent framework online")
    log.info("Artifacts dir: %s", cfg.get("storage", {}).get("artifacts_dir", "data"))
    log.info("SQLite: %s", cfg.get("storage", {}).get("sqlite_path", "db/osint.db"))

    # Start producers + bus
    producers = [
        asyncio.create_task(rss.start()),
        asyncio.create_task(files.start()),
    ]
    bus_task = asyncio.create_task(bus.run(max_inflight=int(cfg.get("runtime", {}).get("max_inflight_tasks", 200))))

    await stop_event.wait()

    # shutdown grace
    grace = int(cfg.get("runtime", {}).get("shutdown_grace_seconds", 10))
    try:
        await asyncio.wait_for(asyncio.gather(*producers, return_exceptions=True), timeout=grace)
    except asyncio.TimeoutError:
        pass
    try:
        await asyncio.wait_for(bus_task, timeout=grace)
    except asyncio.TimeoutError:
        pass

if __name__ == "__main__":
    asyncio.run(main())
