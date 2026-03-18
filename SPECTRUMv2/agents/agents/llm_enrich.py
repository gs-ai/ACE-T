from __future__ import annotations
from typing import Any, Dict
from ..base import Agent
from ..schemas import Event
from ..llm import OllamaLLM

SYSTEM = """You are an intelligence extraction engine.
You convert raw intel snippets into a strict JSON object with fields:
- entities: [{type, value}]
- topics: [string]
- indicators: {ransomware_group, malware_family, vuln_id, cve_list[]}
- geo: {countries[], regions[], cities[]}
- confidence: 0..1
If unknown, use empty arrays/strings and confidence <= 0.4.
"""

class LLMEnrichAgent(Agent):
    name = "llm_enrich"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ocfg = self.cfg.get("ollama", {})
        self.enabled = bool(ocfg.get("enabled", False))
        self.llm = OllamaLLM(
            binary=ocfg.get("binary", "ollama"),
            model=ocfg.get("model", "qwen2.5-coder:7b"),
            max_tokens=int(ocfg.get("max_tokens", 800)),
            temperature=float(ocfg.get("temperature", 0.2)),
        )

    async def handle(self, ev: Event) -> None:
        if not self.enabled:
            return
        if ev.type != "norm.intel":
            return

        user = {
            "title": ev.payload.get("title",""),
            "url": ev.payload.get("url",""),
            "summary": ev.payload.get("summary","")[:3500],
            "source": ev.payload.get("source","")
        }
        prompt = (
            "Extract entities/topics/indicators/geo from this intel.\n"
            f"INTEL_JSON:\n{user}\n"
        )
        out = self.llm.generate_json(system=SYSTEM, user=prompt)
        if not out or not isinstance(out, dict):
            return

        ev2 = Event(
            type="enrich.llm",
            source=ev.source,
            payload={"enrichment": out, "intel": ev.payload},
            parent_id=ev.event_id,
            tags=["enrich","llm"]
        )
        await self.emit(ev2)
