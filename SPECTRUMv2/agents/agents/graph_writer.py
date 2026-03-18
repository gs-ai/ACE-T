from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os
import math
from ..base import Agent
from ..schemas import Event
from ..artifacts import atomic_write_json, now_iso_utc

def _load_json(path: str, default):
    try:
        import json
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        return default
    return default

def _safe_id(s: str) -> str:
    # stable, filesystem/graph safe id
    import base64
    raw = s.encode("utf-8", errors="ignore")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

class GraphWriterAgent(Agent):
    name = "graph_writer"

    async def handle(self, ev: Event) -> None:
        if ev.type not in ("norm.intel", "ioc.extracted", "enrich.llm"):
            return

        out_cfg = self.cfg.get("outputs", {})
        artifacts_dir = self.cfg.get("storage", {}).get("artifacts_dir", "data")
        intel_path = out_cfg.get("intel_bundle_json_path", os.path.join(artifacts_dir, "intel_bundle.json"))
        graph_path = out_cfg.get("graph_json_path", os.path.join(artifacts_dir, "graph_3d.json"))

        bundle = _load_json(intel_path, default={"timestamp_utc": now_iso_utc(), "items": []})
        if not isinstance(bundle, dict):
            bundle = {"timestamp_utc": now_iso_utc(), "items": []}
        if "items" not in bundle or not isinstance(bundle.get("items"), list):
            bundle["items"] = []
        bundle["timestamp_utc"] = now_iso_utc()

        bundle["items"].append({
            "event_id": ev.event_id,
            "type": ev.type,
            "source": ev.source,
            "ts_utc": ev.ts_utc,
            "payload": ev.payload,
            "parent_id": ev.parent_id,
            "tags": ev.tags,
        })
        # keep bounded
        if len(bundle["items"]) > 5000:
            bundle["items"] = bundle["items"][-5000:]

        atomic_write_json(intel_path, bundle)

        if not out_cfg.get("write_graph_json", True):
            return

        # Minimal graph merge strategy:
        # - Create/refresh nodes for intel items and IOCs
        # - Create edges intel->ioc, intel->enrichment markers
        g = _load_json(graph_path, default={"nodes": [], "links": []})
        nodes = {n.get("id"): n for n in g.get("nodes", []) if n.get("id")}
        links = {(l.get("source"), l.get("target"), l.get("type","")): l for l in g.get("links", [])}

        def upsert_node(n: Dict[str, Any]):
            nodes[n["id"]] = {**nodes.get(n["id"], {}), **n}

        def upsert_link(src: str, dst: str, typ: str, meta: Dict[str, Any]):
            k = (src, dst, typ)
            links[k] = {**links.get(k, {"source": src, "target": dst, "type": typ}), **meta}

        if ev.type == "norm.intel":
            intel = ev.payload
            nid = _safe_id(intel.get("url") or intel.get("title") or ev.event_id)
            upsert_node({
                "id": nid,
                "label": intel.get("title","")[:120],
                "source": intel.get("source",""),
                "kind": intel.get("kind","intel"),
                "url": intel.get("url",""),
                "first_observed": intel.get("published","") or "",
                "last_observed": now_iso_utc(),
            })

        if ev.type == "ioc.extracted":
            intel = ev.payload.get("intel", {})
            intel_id = _safe_id(intel.get("url") or intel.get("title") or ev.parent_id or ev.event_id)
            upsert_node({
                "id": intel_id,
                "label": intel.get("title","")[:120],
                "source": intel.get("source",""),
                "kind": intel.get("kind","intel"),
                "url": intel.get("url",""),
                "last_observed": now_iso_utc(),
            })
            iocs = ev.payload.get("iocs", {})
            for typ, vals in iocs.items():
                for v in vals:
                    ioc_id = _safe_id(f"ioc:{typ}:{v}")
                    upsert_node({
                        "id": ioc_id,
                        "label": v[:120],
                        "source": "IOC",
                        "kind": f"ioc:{typ}",
                        "value": v,
                        "last_observed": now_iso_utc(),
                    })
                    upsert_link(intel_id, ioc_id, "intel_has_ioc", {"weight": 1})

        if ev.type == "enrich.llm":
            intel = ev.payload.get("intel", {})
            intel_id = _safe_id(intel.get("url") or intel.get("title") or ev.parent_id or ev.event_id)
            upsert_node({
                "id": intel_id,
                "label": intel.get("title","")[:120],
                "source": intel.get("source",""),
                "kind": intel.get("kind","intel"),
                "url": intel.get("url",""),
                "last_observed": now_iso_utc(),
            })
            enrich = ev.payload.get("enrichment", {})
            ents = enrich.get("entities", []) or []
            for e in ents:
                t = (e.get("type") or "entity").strip().lower()
                v = (e.get("value") or "").strip()
                if not v:
                    continue
                eid = _safe_id(f"ent:{t}:{v}")
                upsert_node({
                    "id": eid,
                    "label": v[:120],
                    "source": "ENRICH",
                    "kind": f"entity:{t}",
                    "value": v,
                    "last_observed": now_iso_utc(),
                })
                upsert_link(intel_id, eid, "intel_mentions", {"weight": 1})

        g["nodes"] = list(nodes.values())
        g["links"] = list(links.values())
        atomic_write_json(graph_path, g)
