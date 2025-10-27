from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import yaml


from .detectors.analyzer import Detector
from .detectors.entities_loader import EntityLoader
from .detectors.rules_engine import RulesEngine
from .parsers import ParsedItem
from .parsers import archive_org, chans, crtsh, ghostbin, github, nitter, pastebin, reddit, rentry, telegram
from .scheduler.loop import SchedulerLoop
from .utils.checkpoint import SeenStore
from .utils.hashing import sha256_hash, simhash
from .utils.http import FetchResult, HttpClientFactory
from .utils.html import sanitize_html
from .utils.sentiment import SentimentAnalyzer
from .utils.time import format_ts
from .utils.geoparse import lookup_geo
from .writers.jsonl_writer import JSONLWriter
from .writers.sqlite_writer import SQLiteWriter


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "time": dt.datetime.utcfromtimestamp(record.created).isoformat(timespec="seconds") + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        for key, value in record.__dict__.items():
            if key in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
            }:
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = JsonFormatter()
    file_handler = logging.FileHandler(log_dir / "osint.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = []
    root.addHandler(file_handler)
    root.addHandler(console_handler)


def load_config(config_path: Path) -> Dict:
    text = config_path.read_text(encoding="utf-8")
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse config: {exc}") from exc


@dataclass
class HtmlPage:
    url: str
    content: str
    bytes_in: int
    latency_ms: float
    from_cache: bool = False
    via_fixture: bool = False


class DetectorManager:
    def __init__(self, config: Dict, reload_interval: int | None) -> None:
        self._config = config
        self._reload_interval = reload_interval
        self._detector: Detector | None = None
        self._mtimes: Dict[str, float] = {}
        self._last_check = 0.0
        self._lock: asyncio.Lock | None = None

    @staticmethod
    def _watch_targets() -> Sequence[Path]:
        base = Path(__file__).parent
        entities_dir = base / "entities"
        files = [base / "triggers" / "triggers.json", entities_dir / "sentiment_lexicon.txt"]
        files.extend(entities_dir.glob("*.yml"))
        return files

    def _snapshot(self) -> Dict[str, float]:
        snapshot: Dict[str, float] = {}
        for path in self._watch_targets():
            if path.exists():
                snapshot[str(path)] = path.stat().st_mtime
        return snapshot

    async def get_detector(self) -> Detector:
        lock = self._ensure_lock()
        async with lock:
            now = time.time()
            if self._detector is None:
                self._detector = build_detector(self._config)
                self._mtimes = self._snapshot()
                self._last_check = now
                return self._detector
            if not self._reload_interval:
                return self._detector
            if now - self._last_check < self._reload_interval:
                return self._detector
            self._last_check = now
            snapshot = self._snapshot()
            if snapshot != self._mtimes:
                self._detector = build_detector(self._config)
                self._mtimes = snapshot
                logging.getLogger(__name__).info(
                    "detector-reloaded",
                    extra={"files": list(snapshot.keys())},
                )
            return self._detector

    async def force_reload(self) -> Detector:
        lock = self._ensure_lock()
        async with lock:
            self._detector = build_detector(self._config)
            self._mtimes = self._snapshot()
            self._last_check = time.time()
            return self._detector

    def _ensure_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock


def build_detector(config: Dict) -> Detector:
    rules_path = Path(__file__).parent / "triggers" / "triggers.json"
    rules_engine = RulesEngine(rules_path)
    entities_dir = Path(__file__).parent / "entities"
    entities = EntityLoader(entities_dir).load()
    sentiment_lex = entities_dir / "sentiment_lexicon.txt"
    sentiment_model = config.get("sentiment_model_path")
    sentiment = SentimentAnalyzer(str(sentiment_lex), sentiment_model)
    return Detector(rules_engine, entities, sentiment)


def parser_for_source(source: str):
    mapping = {
        "pastebin": lambda html: pastebin.parse_archive(html),
        "ghostbin": lambda html: ghostbin.parse_public(html),
        "rentry": lambda html, url="https://rentry.org": rentry.parse_page(html, url),
        "reddit": lambda html: reddit.parse_listing(html),
        "chans": lambda html, base="https://boards.4channel.org": chans.parse_catalog(html, base),
        "telegram": lambda html, base="https://t.me": telegram.parse_channel(html, base),
        "twitter": lambda html, base="https://nitter.net": nitter.parse_timeline(html, base),
        "archive_org": lambda html, base="https://web.archive.org": archive_org.parse_wayback(html, base),
        "github": lambda html, base="https://github.com": github.parse_repo(html, base),
        "crtsh": lambda html: crtsh.parse_results(html),
    }
    return mapping.get(source)


def _fixture_directories(config: Dict) -> Sequence[Path]:
    directories: List[Path] = []
    fixture_dir = config.get("fixture_dir")
    if fixture_dir:
        directories.append(Path(fixture_dir))
    directories.append(Path(__file__).parent / "fixtures")
    directories.append(Path("tests/fixtures"))
    return directories


async def collect_html(config: Dict, source: str, http_client: HttpClientFactory) -> tuple[List[HtmlPage], int]:
    source_cfg = (config.get("sources", {}) or {}).get(source, {})
    urls = source_cfg.get("urls", [])
    html_responses: List[HtmlPage] = []
    errors = 0
    if urls:
        for url in urls:
            try:
                fetch: FetchResult = await http_client.fetch_text(url, source)
                html_responses.append(
                    HtmlPage(
                        url=url,
                        content=fetch.text,
                        bytes_in=fetch.bytes_in,
                        latency_ms=fetch.latency_ms,
                        from_cache=fetch.from_cache,
                    )
                )
            except Exception as exc:  # pylint: disable=broad-except
                logging.getLogger(__name__).warning(
                    "fetch-error", extra={"source": source, "url": url, "error": str(exc)}
                )
                errors += 1
    if not html_responses:
        for directory in _fixture_directories(config):
            fixture = directory / source / "sample.html"
            if fixture.exists():
                content = fixture.read_text(encoding="utf-8")
                html_responses.append(
                    HtmlPage(
                        url=str(fixture),
                        content=content,
                        bytes_in=len(content.encode("utf-8")),
                        latency_ms=0.0,
                        via_fixture=True,
                    )
                )
                break
        else:
            placeholder = f"<html><body>No data available for source {source}</body></html>"
            html_responses.append(
                HtmlPage(
                    url=f"fixture://{source}",
                    content=placeholder,
                    bytes_in=len(placeholder.encode("utf-8")),
                    latency_ms=0.0,
                    via_fixture=True,
                )
            )
    return html_responses, errors


def build_alert(parsed: ParsedItem, detection: Dict) -> Dict:
    timestamp = format_ts()
    geo_info = lookup_geo(parsed.content)
    entities = detection["entities"]
    rule = detection["rule"]
    return {
        "geo_info": geo_info,
        "source_url": parsed.url,
        "detected_at": timestamp,
        "first_seen": timestamp,
        "last_seen": timestamp,
        "entities": {
            "orgs": entities.get("orgs", []),
            "persons": entities.get("persons", []),
            "keywords": entities.get("keywords", []),
        },
        "threat_analysis": {
            "summary": rule.matched_text,
            "risk_vector": ",".join(rule.tags) or "unknown",
            "related_terms": list({*entities.get("keywords", []), *rule.tags}),
        },
        "trend_velocity": {
            "pct_increase": detection.get("trend", {}).get("pct_increase", 0.0),
            "prev_volume": detection.get("trend", {}).get("prev_volume", 0),
            "curr_volume": detection.get("trend", {}).get("curr_volume", 1),
        },
        "sentiment": detection["sentiment"],
        "tags": rule.tags,
        "classification": rule.classification,
        "source_name": parsed.source,
        "content_hash": detection["content_hash"],
        "content_excerpt": parsed.content[:500],
        "simhash": detection["simhash"],
    }


async def run_sources(
    config: Dict,
    sources: Iterable[str],
    once: bool,
    from_checkpoint: bool,
    since: str | None,
    reload_interval: int | None = None,
) -> None:
    detector_manager = DetectorManager(config, reload_interval)
    http_client = HttpClientFactory(config)
    sqlite_writer = SQLiteWriter("data/osint.db")
    jsonl_writer = JSONLWriter(config.get("alert_output_dir", "data/alerts"))
    seen_store = SeenStore(config.get("checkpoint_dir", "data/checkpoints"))
    logger = logging.getLogger(__name__)
    since_dt = None
    if since:
        try:
            since_dt = dt.datetime.fromisoformat(since)
        except ValueError:
            logger.warning("invalid-since", extra={"value": since})

    async def process(source: str) -> None:
        parser = parser_for_source(source)
        if not parser:
            logger.info("unknown-source", extra={"source": source})
            return
        if from_checkpoint:
            logger.info("resuming-from-checkpoint", extra={"source": source})
        html_pages, fetch_errors = await collect_html(config, source, http_client)
        metrics = {
            "source": source,
            "started_at": format_ts(),
            "fetched": len(html_pages),
            "alerts": 0,
            "dedup": 0,
            "bytes_in": 0,
            "errors": fetch_errors,
            "cache_hits": 0,
            "fixtures_used": 0,
            "avg_latency_ms": 0.0,
        }
        seen_hashes = seen_store.load(source)
        previous_metrics = sqlite_writer.fetch_last_run_metrics(source)
        prev_volume = previous_metrics.get("alerts", 0)
        latency_total = 0.0
        latency_samples = 0
        for page in html_pages:
            metrics["bytes_in"] += page.bytes_in
            if page.from_cache:
                metrics["cache_hits"] += 1
            if page.via_fixture:
                metrics["fixtures_used"] += 1
            if page.latency_ms:
                latency_total += page.latency_ms
                latency_samples += 1
            detector = await detector_manager.get_detector()
            for item in parser(page.content):
                if since_dt and item.published_at:
                    try:
                        published = dt.datetime.fromisoformat(item.published_at)
                        if published < since_dt:
                            continue
                    except ValueError:
                        pass
                content_text = sanitize_html(item.content)
                hash_value = sha256_hash(content_text)
                simhash_value = simhash(content_text)
                if hash_value in seen_hashes:
                    metrics["dedup"] += 1
                    continue
                seen_store.add(source, hash_value)
                seen_hashes.add(hash_value)
                detections = detector.detect(content_text)
                for detection in detections:
                    alert_payload = build_alert(
                        item,
                        {
                            "entities": detection.entities,
                            "rule": detection.rule,
                            "sentiment": detection.sentiment,
                            "content_hash": hash_value,
                            "simhash": simhash_value,
                            "trend": {
                                "prev_volume": prev_volume,
                                "curr_volume": prev_volume + 1,
                                "pct_increase": ((prev_volume + 1 - max(prev_volume, 1)) / max(prev_volume, 1)) * 100 if prev_volume else 100.0,
                            },
                        },
                    )
                    sqlite_writer.write_alert(alert_payload)
                    sqlite_writer.update_seen(source, hash_value)
                    jsonl_writer.write_alert(alert_payload)
                    metrics["alerts"] += 1
                    prev_volume += 1
        if latency_samples:
            metrics["avg_latency_ms"] = round(latency_total / latency_samples, 2)
        metrics["finished_at"] = format_ts()
        sqlite_writer.record_run(source, "ok", metrics)
        logger.info("source-run", extra=metrics)

    jobs = {source: lambda s=source: process(s) for source in sources}
    if once:
        await asyncio.gather(*(job() for job in jobs.values()))
    else:
        scheduler = SchedulerLoop({source: config.get("scrape_interval_seconds", {}).get(source, 300) for source in sources})
        await scheduler.run_forever(jobs)
    await http_client.close()
    sqlite_writer.close()


def run_command(args: argparse.Namespace) -> None:
    config_path = Path(__file__).parent / "config.yml"
    config = load_config(config_path)
    setup_logging(Path(config.get("logs_dir", "logs")))
    available_sources = {
        "pastebin",
        "ghostbin",
        "rentry",
        "reddit",
        "chans",
        "telegram",
        "twitter",
        "archive_org",
        "github",
        "crtsh",
    }
    if args.sources == "all":
        selected = available_sources
    else:
        selected = {source.strip() for source in args.sources.split(",") if source.strip()}
    invalid = selected - available_sources
    if invalid:
        raise SystemExit(f"Unknown sources: {', '.join(sorted(invalid))}")
    once = args.once or not args.loop
    reload_interval = args.reload_interval
    if reload_interval is None:
        reload_interval = (config.get("reload") or {}).get("interval_seconds")
    asyncio.run(
        run_sources(
            config,
            sorted(selected),
            once=once,
            from_checkpoint=args.from_checkpoint,
            since=args.since,
            reload_interval=reload_interval,
        )
    )


def validate_command(_: argparse.Namespace) -> None:
    config_path = Path(__file__).parent / "config.yml"
    config = load_config(config_path)
    print(yaml.safe_dump(config, sort_keys=False))


def reindex_command(_: argparse.Namespace) -> None:
    writer = SQLiteWriter("data/osint.db")
    for idx in writer.conn.execute("SELECT name FROM sqlite_master WHERE type='index'"):
        print(f"Index: {idx[0]}")
    writer.close()


def vacuum_command(_: argparse.Namespace) -> None:
    writer = SQLiteWriter("data/osint.db")
    writer.conn.execute("VACUUM")
    writer.close()
    print("Vacuum complete")


def reload_command(_: argparse.Namespace) -> None:
    config_path = Path(__file__).parent / "config.yml"
    config = load_config(config_path)
    manager = DetectorManager(config, reload_interval=0)
    asyncio.run(manager.force_reload())
    print("Detector packs reloaded")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ACE-T OSINT monitoring CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Execute sources")
    run_parser.add_option = run_parser.add_argument
    run_parser.add_option("--sources", default="all", help="Comma separated list of sources or 'all'")
    run_parser.add_option("--once", action="store_true", help="Run a single iteration")
    run_parser.add_option("--loop", action="store_true", help="Continuously loop")
    run_parser.add_option("--from-checkpoint", action="store_true", dest="from_checkpoint", help="Resume from checkpoint")
    run_parser.add_option("--since", default=None, help="Historical seed date (YYYY-MM-DD)")
    run_parser.add_option("--reload-interval", type=int, default=None, help="Seconds between detector reload checks")
    run_parser.set_defaults(func=run_command)

    validate_parser = subparsers.add_parser("validate", help="Print configuration")
    validate_parser.set_defaults(func=validate_command)

    reindex_parser = subparsers.add_parser("reindex", help="List SQLite indexes")
    reindex_parser.set_defaults(func=reindex_command)

    vacuum_parser = subparsers.add_parser("vacuum", help="Vacuum SQLite database")
    vacuum_parser.set_defaults(func=vacuum_command)

    reload_parser = subparsers.add_parser("reload", help="Reload triggers and entity packs")
    reload_parser.set_defaults(func=reload_command)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
