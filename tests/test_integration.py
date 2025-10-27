import asyncio
import json
from pathlib import Path

from ace_t_osint.cli import run_sources, load_config


def test_run_once_creates_alerts(tmp_path, monkeypatch):
    config_path = Path("ace_t_osint/config.yml")
    config = load_config(config_path)
    config["alert_output_dir"] = tmp_path.as_posix()
    config["checkpoint_dir"] = (tmp_path / "checkpoints").as_posix()
    config["logs_dir"] = tmp_path.as_posix()

    asyncio.run(run_sources(config, ["pastebin"], once=True, from_checkpoint=False, since=None))

    jsonl_files = list(tmp_path.rglob("alerts.jsonl"))
    assert jsonl_files
    content = jsonl_files[0].read_text(encoding="utf-8").strip()
    assert content
    alert = json.loads(content.splitlines()[0])
    assert alert["source_name"] == "pastebin"
