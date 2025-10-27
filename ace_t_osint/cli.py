from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import logging
from pathlib import Path
from typing import Dict, Iterable, List

import yaml


from .detectors.analyzer import Detector
from .detectors.entities_loader import EntityLoader
from .detectors.rules_engine import RulesEngine
from .parsers import ParsedItem
from .parsers import archive_org, chans, crtsh, ghostbin, github, nitter, pastebin, reddit, rentry, telegram
from .scheduler.loop import SchedulerLoop
from .utils.checkpoint import SeenStore
from .utils.hashing import sha256_hash, simhash
from .utils.http import HttpClientFactory
from .utils.html import sanitize_html
from .utils.sentiment import SentimentAnalyzer
from .utils.time import format_ts
from .utils.geoparse import lookup_geo
from .writers.jsonl_writer import JSONLWriter
from .writers.sqlite_writer import SQLiteWriter


LOG_FORMAT = "%(message)s"


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_dir / "osint.log")
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = []
    root.addHandler(handler)


def load_config(config_path: Path) -> Dict:
    text = config_path.read_text(encoding="utf-8")
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse config: {exc}") from exc


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


async def collect_html(config: Dict, source: str, http_client: HttpClientFactory) -> List[str]:
    source_cfg = (config.get("sources", {}) or {}).get(source, {})
    urls = source_cfg.get("urls", [])
    html_responses: List[str] = []
    if urls and http_client.network_available():
        for url in urls:
            try:
                html = await http_client.fetch_text(url, source)
                html_responses.append(html)
            except Exception as exc:  # pylint: disable=broad-except
                logging.getLogger(__name__).warning("fetch-error", extra={"source": source, "url": url, "error": str(exc)})
    if not html_responses:
        fixture = Path("tests/fixtures") / source / "sample.html"
        if fixture.exists():
            html_responses.append(fixture.read_text(encoding="utf-8"))
        else:
            html_responses.append("<html><body>No data available for source {}</body></html>".format(source))
    return html_responses


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
) -> None:
    detector = build_detector(config)
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
        html_pages = await collect_html(config, source, http_client)
        metrics = {
            "source": source,
            "started_at": format_ts(),
            "fetched": len(html_pages),
            "alerts": 0,
            "dedup": 0,
        }
        seen_hashes = seen_store.load(source)
        previous_metrics = sqlite_writer.fetch_last_run_metrics(source)
        prev_volume = previous_metrics.get("alerts", 0)
        for html in html_pages:
            for item in parser(html):
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
        metrics["finished_at"] = format_ts()
        sqlite_writer.record_run(source, "ok", metrics)

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
    asyncio.run(run_sources(config, sorted(selected), once=once, from_checkpoint=args.from_checkpoint, since=args.since))


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
    run_parser.set_defaults(func=run_command)

    validate_parser = subparsers.add_parser("validate", help="Print configuration")
    validate_parser.set_defaults(func=validate_command)

    reindex_parser = subparsers.add_parser("reindex", help="List SQLite indexes")
    reindex_parser.set_defaults(func=reindex_command)

    vacuum_parser = subparsers.add_parser("vacuum", help="Vacuum SQLite database")
    vacuum_parser.set_defaults(func=vacuum_command)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
