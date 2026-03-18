## What’s currently making SPECTRUMv2 look “soft” instead of sharp

### 1) Your edge thickness is mostly placebo (browser limitation)

You’re using `THREE.LineBasicMaterial` and setting `material.linewidth = thickness` in `createEdgeLine()` . In WebGL, line width is effectively locked to 1 on most platforms, so edges alias and look thin, broken, and “fuzzy” no matter what thickness you set.

### 2) Pixel ratio is capped to 1.5

Renderer is doing:

```js
this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, pixelRatioCap));
```

with `CONFIG.performance.maxPixelRatio = 1.5` . On a modern display (especially retina), 1.5 will visually soften everything, including text overlays, nodes, and lines.

### 3) Nodes are intentionally “always on top” which flattens depth cues

Your node shader meshes run with `depthWrite=false` and `depthTest=false` . That makes them pop, but it also removes crisp occlusion cues, so the scene can feel smeared in dense regions.

### 4) Layout is doing collision safety, but not edge clearance against non-connected nodes

You have a solid grid-based separation pass in `applyLayoutSafety()`  and edge jitter midpoints in `createEdgeLine()` , but you are not enforcing “no connector crosses a node unless it connects” at render-time. So visually: edges will still appear to slice through spheres.

---

## Make the graph look sharper now (drop-in patches)

### Patch A: Raise fidelity and correct color pipeline

Edit `gui/ace_t_spectrum_3d.html` renderer setup block .

Replace your renderer init with this:

```js
// Renderer setup
this.renderer = new THREE.WebGLRenderer({
  canvas: document.getElementById('three-canvas'),
  antialias: true,
  alpha: false,
  powerPreference: 'high-performance',
  preserveDrawingBuffer: false,
  stencil: false,
  depth: true
});

this.renderer.setSize(window.innerWidth, window.innerHeight);

// Sharper output: allow higher cap, clamp to sane range
const pixelRatioCap = (CONFIG.performance && CONFIG.performance.maxPixelRatio)
  ? CONFIG.performance.maxPixelRatio
  : window.devicePixelRatio;

this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, Math.max(2.0, pixelRatioCap)));

// Correct modern three.js output
this.renderer.outputColorSpace = THREE.SRGBColorSpace;
this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
this.renderer.toneMappingExposure = 1.05;

// Optional: shadows often blur perception in dense graphs, keep but tighten
this.renderer.shadowMap.enabled = true;
this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;
```

Then change your config cap in `CONFIG.performance` from 1.5 to 2.5:

```js
performance: {
  maxPixelRatio: 2.5,
  maxEdgesPerNode: 6
},
```

This alone will make everything look more “etched” .

---

### Patch B: Replace WebGL lines with screen-space thick lines (crisp edges)

You need `Line2` / `LineMaterial` / `LineGeometry` (three.js examples) to get real thickness and anti-aliasing behavior.

#### 1) Add these vendor modules

Drop these files into:

* `gui/three/vendor/lines/Line2.js`
* `gui/three/vendor/lines/LineMaterial.js`
* `gui/three/vendor/lines/LineGeometry.js`
* `gui/three/vendor/lines/LineSegments2.js` (optional)

(Grab them from the same three.js revision you’re using, REVISION 160 .)

#### 2) Import them in `ace_t_spectrum_3d.html`

Near your other imports:

```html
<script type="module">
import * as THREE from './three/vendor/three.module.js';
import { OrbitControls } from './three/vendor/OrbitControls.js';
import { Line2 } from './three/vendor/lines/Line2.js';
import { LineMaterial } from './three/vendor/lines/LineMaterial.js';
import { LineGeometry } from './three/vendor/lines/LineGeometry.js';
```

#### 3) Replace `createEdgeLine(edge)` with a Line2 implementation

This keeps your current curve midpoint logic  but makes it sharp:

```js
createEdgeLine(edge) {
  const sourceNode = this.nodesById[edge.source];
  const targetNode = this.nodesById[edge.target];
  if (!sourceNode || !targetNode) return null;

  const rawWeight = typeof edge.weight === 'number' ? edge.weight : 1;
  const clampedWeight = Math.max(1, Math.min(5, Math.round(rawWeight)));

  let curveOffset = typeof edge.curve_offset === 'number' ? edge.curve_offset : 0;
  if (!curveOffset) {
    const seed = (this.hashScalar(edge.id || `${edge.source}-${edge.target}`) - 0.5);
    curveOffset = seed * 16;
  }

  const mid = new THREE.Vector3(
    (sourceNode.x + targetNode.x) / 2,
    (sourceNode.y + targetNode.y) / 2,
    (sourceNode.z + targetNode.z) / 2
  );

  if (curveOffset !== 0) {
    const dir = this.hashDirection(edge.id || `${edge.source}-${edge.target}`);
    mid.addScaledVector(dir, curveOffset);
  }

  const positions = [
    sourceNode.x, sourceNode.y, sourceNode.z,
    mid.x, mid.y, mid.z,
    targetNode.x, targetNode.y, targetNode.z
  ];

  const edgeColor = this.getEdgeColor(sourceNode, targetNode);

  const typeStyle = {
    SAME_GROUP: { opacity: 0.42, width: 1.6 },
    TIME_CLUSTER: { opacity: 0.52, width: 1.9 },
    DOMAIN_PATTERN_MATCH: { opacity: 0.70, width: 2.6 },
    GROUP_SECTOR_OVERLAP: { opacity: 0.48, width: 1.8 },
    GROUP_COUNTRY_OVERLAP: { opacity: 0.40, width: 1.6 },
    CROSS_GROUP_SECTOR: { opacity: 0.32, width: 1.4 }
  };
  const style = typeStyle[edge.type] || { opacity: 0.30, width: 1.3 };

  const geo = new LineGeometry();
  geo.setPositions(positions);

  const mat = new LineMaterial({
    color: edgeColor,
    transparent: true,
    opacity: this.clampValue(style.opacity, 0.16, 0.85),
    linewidth: this.clampValue(style.width, 1.0, 3.0), // in pixels
    depthWrite: false,
    depthTest: true
  });

  // critical: set resolution so linewidth works correctly
  mat.resolution.set(window.innerWidth, window.innerHeight);

  const line = new Line2(geo, mat);
  line.computeLineDistances();
  line.renderOrder = 1;

  line.userData = {
    sourceId: edge.source,
    targetId: edge.target,
    weight: clampedWeight,
    curveOffset,
    curveDir: curveOffset ? this.hashDirection(edge.id || `${edge.source}-${edge.target}`) : null,
    baseOpacity: mat.opacity
  };

  return line;
}
```

Also update your resize handler to keep edge widths correct:

```js
window.addEventListener('resize', () => {
  this.camera.aspect = window.innerWidth / window.innerHeight;
  this.camera.updateProjectionMatrix();
  this.renderer.setSize(window.innerWidth, window.innerHeight);

  // keep LineMaterial linewidth stable
  this.edgeLines.forEach(l => {
    if (l.material && l.material.resolution) {
      l.material.resolution.set(window.innerWidth, window.innerHeight);
    }
  });
});
```

Result: edges become crisp and truly thick, which is the biggest “sharpness” win in your whole stack.

---

### Patch C: Keep node pop, but restore depth cues for clarity

Right now nodes are “always in front” (`depthTest=false`) .

Change node material behavior to:

* `depthTest=true`
* `depthWrite=false`

That keeps blending and glow, but gives the scene real occlusion so it reads sharper.

Where you set:

```js
mesh.material.depthTest = false;
```

change to:

```js
mesh.material.depthTest = true;
mesh.material.depthWrite = false;
```

Do the same for your instanced node materials in `createVisualization()` .

---

## Maintain “connector light up” and “node pulse” on click

You already have selection machinery and per-edge base opacity tracking (`baseOpacity`)  and a click handler wired in `setupEventListeners()` .

To ensure nothing breaks when switching to Line2:

* keep storing `line.userData.baseOpacity`
* in your selection highlight routine, update `line.material.opacity` (Line2 still supports it)
* do not mutate `material.color` object reference, set via `line.material.color.setHex(...)` or `set(...)`

If you paste your current `updateSelectionHighlight()` I can wire it exactly, but you can do this safely without seeing it:

```js
// When selected:
// - edges connected to selected node: opacity = min(1, baseOpacity * 2.8)
// - others: opacity = baseOpacity * 0.25

const boost = 2.8;
const dim = 0.25;

this.edgeLines.forEach(line => {
  const ud = line.userData || {};
  const base = ud.baseOpacity ?? 0.3;
  const hit = (ud.sourceId === selectedId || ud.targetId === selectedId);
  line.material.opacity = hit ? Math.min(1.0, base * boost) : base * dim;
  line.material.needsUpdate = true;
});
```

Node pulse: you already have shader uniforms and a base scale (`baseScale`) stored . Keep that logic untouched.

---

## Regen the data-to-graph algorithm (deterministic, higher signal, fewer junk edges)

Your Python build currently:

* creates nodes
* calls `create_spectrum_edges(nodes)`
* then prunes for render using `_build_render_edges(max_edges_per_node=6)`

That means your “truth graph” can be extremely dense, and the viewer just hides most of it, which reduces clarity and makes layout/physics work harder.

### Replace with: “Edge scoring + hard budgets” at build time

Implement `create_spectrum_edges_v2()` that:

* generates only meaningful candidates
* scores them
* applies per-node and per-type budgets
* outputs a smaller truth graph that renders clean

Drop-in module: `graph_copy/edge_engine_v2.py`

```python
# graph_copy/edge_engine_v2.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple
import math
import hashlib
from datetime import datetime

def _norm(s: Any) -> str:
    return str(s or "").strip().lower()

def _stable_id(*parts: str) -> str:
    h = hashlib.sha1("||".join(parts).encode("utf-8", "ignore")).hexdigest()
    return h[:24]

def _parse_time(v: Any) -> float | None:
    if not v:
        return None
    s = str(v).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None

def _get_time(node: Dict[str, Any]) -> float | None:
    for k in ("last_observed", "first_observed", "posted_at", "timestamp", "discovered"):
        t = _parse_time(node.get(k) or node.get("metadata", {}).get(k))
        if t:
            return t
    return None

def _tokens(node: Dict[str, Any]) -> Dict[str, str]:
    md = node.get("metadata", {}) or {}
    return {
        "group": _norm(node.get("group") or md.get("group") or md.get("actor") or md.get("ransomware_group")),
        "victim": _norm(node.get("affected") or md.get("victim") or md.get("victim_name") or md.get("organization")),
        "domain": _norm(md.get("domain") or md.get("hostname")),
        "ip": _norm(md.get("ip") or md.get("ip_address")),
        "country": _norm(node.get("country") or md.get("country")),
        "sector": _norm(node.get("sector") or md.get("sector") or md.get("industry")),
        "cve": _norm(md.get("cve") or md.get("cve_id")),
        "hash": _norm(md.get("sha256") or md.get("hash")),
        "source": _norm(node.get("source")),
    }

@dataclass
class Edge:
    id: str
    source: str
    target: str
    type: str
    weight: float
    curve_offset: float | None = None

def create_spectrum_edges_v2(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Index by entity keys for fast candidate generation
    by_group: Dict[str, List[int]] = {}
    by_victim: Dict[str, List[int]] = {}
    by_domain: Dict[str, List[int]] = {}
    by_ip: Dict[str, List[int]] = {}
    by_cve: Dict[str, List[int]] = {}
    by_hash: Dict[str, List[int]] = {}

    tok = []
    times = []
    for i, n in enumerate(nodes):
        t = _tokens(n)
        tok.append(t)
        times.append(_get_time(n))
        if t["group"]: by_group.setdefault(t["group"], []).append(i)
        if t["victim"]: by_victim.setdefault(t["victim"], []).append(i)
        if t["domain"]: by_domain.setdefault(t["domain"], []).append(i)
        if t["ip"]: by_ip.setdefault(t["ip"], []).append(i)
        if t["cve"]: by_cve.setdefault(t["cve"], []).append(i)
        if t["hash"]: by_hash.setdefault(t["hash"], []).append(i)

    def time_weight(i: int, j: int) -> float:
        a, b = times[i], times[j]
        if not a or not b:
            return 0.15
        dt = abs(a - b)
        # 0..14 days maps to 1.0..0.2
        days = dt / 86400.0
        return max(0.2, 1.0 - (days / 14.0))

    def add_edges_for_bucket(index_map: Dict[str, List[int]], etype: str, base: float) -> List[Tuple[int,int,str,float]]:
        out = []
        for k, idxs in index_map.items():
            if len(idxs) < 2:
                continue
            # pair within bucket (cap pair explosion)
            idxs_sorted = idxs[:200]  # hard cap per key
            for a_pos in range(len(idxs_sorted)):
                ia = idxs_sorted[a_pos]
                for b_pos in range(a_pos + 1, len(idxs_sorted)):
                    ib = idxs_sorted[b_pos]
                    tw = time_weight(ia, ib)
                    score = base * (0.55 + 0.45 * tw)
                    out.append((ia, ib, etype, score))
        return out

    candidates: List[Tuple[int,int,str,float]] = []
    candidates += add_edges_for_bucket(by_group,  "SAME_GROUP", 1.00)
    candidates += add_edges_for_bucket(by_victim, "SAME_VICTIM", 0.95)
    candidates += add_edges_for_bucket(by_domain, "SAME_DOMAIN", 0.85)
    candidates += add_edges_for_bucket(by_ip,     "SAME_IP",     0.85)
    candidates += add_edges_for_bucket(by_cve,    "SAME_CVE",    0.75)
    candidates += add_edges_for_bucket(by_hash,   "SAME_HASH",   0.90)

    # Soft boosts for cross-source confirmations
    def cross_source_boost(i: int, j: int) -> float:
        return 1.12 if tok[i]["source"] and tok[j]["source"] and tok[i]["source"] != tok[j]["source"] else 1.0

    # Budgeting: per-node max edges, per-type max edges
    per_node_cap = 10
    per_type_cap = {
        "SAME_GROUP": 4,
        "SAME_VICTIM": 4,
        "SAME_DOMAIN": 3,
        "SAME_IP": 3,
        "SAME_CVE": 2,
        "SAME_HASH": 2
    }

    # Rank all candidates globally
    scored = []
    for ia, ib, et, s in candidates:
        s2 = s * cross_source_boost(ia, ib)
        scored.append((s2, ia, ib, et))
    scored.sort(reverse=True, key=lambda x: x[0])

    node_degree = [0] * len(nodes)
    node_type_degree = [{k: 0 for k in per_type_cap.keys()} for _ in nodes]
    chosen: List[Edge] = []
    seen_pairs = set()

    for s, ia, ib, et in scored:
        if node_degree[ia] >= per_node_cap or node_degree[ib] >= per_node_cap:
            continue
        if node_type_degree[ia][et] >= per_type_cap[et] or node_type_degree[ib][et] >= per_type_cap[et]:
            continue

        a_id = nodes[ia].get("id")
        b_id = nodes[ib].get("id")
        if not a_id or not b_id:
            continue
        pair_key = (a_id, b_id, et) if a_id < b_id else (b_id, a_id, et)
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        eid = _stable_id(et, a_id, b_id)
        chosen.append(Edge(id=eid, source=a_id, target=b_id, type=et, weight=round(1.0 + 4.0 * min(1.0, s), 2)))
        node_degree[ia] += 1
        node_degree[ib] += 1
        node_type_degree[ia][et] += 1
        node_type_degree[ib][et] += 1

    return [e.__dict__ for e in chosen]
```

Then in your build script, swap:

```python
edges = create_spectrum_edges(nodes)
```

with:

```python
from graph_copy.edge_engine_v2 import create_spectrum_edges_v2
edges = create_spectrum_edges_v2(nodes)
```

Why this improves sharpness: fewer but stronger edges means less visual haze and less physics jitter. Your viewer currently computes adjacency and render edges from a limited set anyway , so you might as well generate a cleaner graph upstream.

---

## Convert ingestion to “agents” and make new sources drop-in

Right now everything funnels through `load_all_raw_records()` and a monolithic builder loop . Replace that with a local agent bus that is:

* modular (each source is a plugin)
* schedulable
* deterministic
* easy to add by dropping a file

### Directory layout (add this)

```
graph_copy/
  agents/
    __init__.py
    bus.py
    base.py
    orchestrator.py
    registry.py
  sources/
    __init__.py
    ransomware_live.py
    threatfox.py
    urlhaus.py
  normalize/
    contract.py
    normalize.py
  edge_engine_v2.py
  build_graph_v3.py
```

### Agent base + registry

`graph_copy/agents/base.py`

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Protocol

@dataclass
class SourceResult:
    source: str
    records: List[Dict[str, Any]]
    meta: Dict[str, Any]

class SourceAgent(Protocol):
    name: str
    def fetch(self) -> SourceResult: ...
```

`graph_copy/agents/registry.py`

```python
from __future__ import annotations
from typing import Dict, Type
from .base import SourceAgent

_REG: Dict[str, SourceAgent] = {}

def register(agent: SourceAgent) -> None:
    _REG[agent.name] = agent

def all_agents() -> Dict[str, SourceAgent]:
    return dict(_REG)
```

### Orchestrator (runs all agents, normalizes, builds graph)

`graph_copy/agents/orchestrator.py`

```python
from __future__ import annotations
from typing import Any, Dict, List
from .registry import all_agents
from ..normalize.normalize import normalize_record_to_node
from ..edge_engine_v2 import create_spectrum_edges_v2

def run_once(active: List[str] | None = None) -> Dict[str, Any]:
    agents = all_agents()
    if active:
        agents = {k:v for k,v in agents.items() if k in set(active)}

    raw = []
    meta = {"sources": []}
    for name, agent in agents.items():
        res = agent.fetch()
        meta["sources"].append({"name": name, **res.meta})
        for r in res.records:
            r["source"] = r.get("source") or res.source
            raw.append(r)

    nodes = []
    for r in raw:
        n = normalize_record_to_node(r)
        if n:
            nodes.append(n)

    edges = create_spectrum_edges_v2(nodes)
    return {"nodes": nodes, "edges": edges, "metadata": meta}
```

### Normalization contract

`graph_copy/normalize/normalize.py`

```python
from __future__ import annotations
from typing import Any, Dict
import hashlib
import math

def _stable_id(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:24]

def normalize_record_to_node(r: Dict[str, Any]) -> Dict[str, Any] | None:
    # Minimal contract: id, label, source, x,y,z exist
    src = r.get("source", "unknown")
    label = r.get("label") or r.get("victim") or r.get("victim_name") or r.get("title") or "unknown"
    seed = f"{src}::{label}::{r.get('group','')}"
    nid = _stable_id(seed)

    # deterministic initial placement (viewer physics will refine)
    h = int(hashlib.sha1(nid.encode()).hexdigest()[:8], 16)
    a = (h % 360) * (math.pi / 180.0)
    rad = 120 + ((h >> 3) % 180)
    z = (((h >> 5) % 200) - 100)

    node = {
        "id": nid,
        "label": label,
        "source": src,
        "group": r.get("group") or "",
        "affected": r.get("victim") or r.get("victim_name") or "",
        "sector": r.get("sector") or "",
        "country": r.get("country") or "",
        "x": round(rad * math.cos(a), 3),
        "y": round(rad * math.sin(a), 3),
        "z": round(z, 3),
        "metadata": r
    }
    return node
```

### Example source agent (ThreatFox)

`graph_copy/sources/threatfox.py`

```python
from __future__ import annotations
import requests
from typing import Any, Dict, List
from ..agents.base import SourceResult
from ..agents.registry import register

class ThreatFoxAgent:
    name = "threatfox"

    def fetch(self) -> SourceResult:
        url = "https://threatfox.abuse.ch/export/json/recent/"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        records: List[Dict[str, Any]] = []
        for _, items in data.items():
            if not isinstance(items, list):
                continue
            for it in items:
                records.append({
                    "source": "ThreatFox",
                    "label": it.get("ioc") or it.get("indicator") or "ioc",
                    "ip": it.get("ioc") if it.get("ioc_type") == "ip:port" else "",
                    "domain": it.get("ioc") if "domain" in str(it.get("ioc_type","")) else "",
                    "malware": it.get("malware") or "",
                    "tags": it.get("tags") or [],
                    "first_observed": it.get("first_seen") or "",
                    "last_observed": it.get("last_seen") or "",
                    "raw": it
                })

        return SourceResult(
            source="ThreatFox",
            records=records,
            meta={"count": len(records), "url": url}
        )

register(ThreatFoxAgent())
```

### Build runner

`graph_copy/build_graph_v3.py`

```python
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from agents.orchestrator import run_once

BASE_DIR = Path(__file__).resolve().parent

def build_graph():
    graph = run_once()
    graph["metadata"]["generated_at"] = datetime.utcnow().isoformat() + "Z"

    (BASE_DIR / "graph_3d.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")
    (BASE_DIR / "graph_3d_render.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")

if __name__ == "__main__":
    build_graph()
```

This architecture makes sources drop-in: any file that imports `register()` and calls it becomes active.

---

## “Drop a prompt into VS Code” module generator (fast source creation)

Create `graph_copy/tools/new_source_prompt.txt` and paste this into VS Code whenever you want a new source. It produces a complete adapter you only edit in 3 places.

**VS Code prompt template:**

```
Create a new Python file at graph_copy/sources/<source_key>.py.

Requirements:
- Implement a class named <SourceKeyTitle>Agent with:
  - name = "<source_key>"
  - fetch() -> SourceResult
- Use requests.get with timeout=30 and raise_for_status
- Convert raw items into flat records with fields: source, label, group, victim/victim_name, domain, ip, country, sector, first_observed, last_observed, raw
- At the bottom, register(<SourceKeyTitle>Agent()).
- No extra dependencies beyond requests.

Also:
- Ensure records are list[dict]
- Meta includes: count, url
- SourceResult.source is a human readable source label
```

Replace `<source_key>` and `<SourceKeyTitle>` and you are done.

---

## One more visual win: enforce “no connector crosses a node unless connected”

You already have `layoutSafety.edgeClearance`, `edgePush`, `edgeBendStrength`, and sampling controls in CONFIG , but your current `applyLayoutSafety()` is primarily node-node separation .

The clean way to do this without heavy geometry math is:

* sample each edge polyline (you already define `maxEdgeSamples`)
* for each sample point, query nearby nodes via the same grid
* if a node is within clearance distance and is not the edge’s source/target, push that node away along the local normal

If you paste the remainder of your `applyLayoutSafety()` function (it’s truncated in the export at the edge of the snippet), I’ll wire the exact patch into your current structure. Based on what’s already in config, you designed for this but did not fully activate it yet .

---

## Summary of what you should do first (highest impact order)

1. Switch edges to `Line2` for real thickness and crispness (Patch B). This is the biggest upgrade.
2. Raise pixel ratio cap to 2.5 and set modern color pipeline (Patch A).
3. Turn node `depthTest` back on, keep `depthWrite` off (Patch C).
4. Swap in `create_spectrum_edges_v2()` to reduce haze and improve signal.
5. Move ingestion to agent registry so new sources are drop-in.

If you want, I can output a single consolidated “apply these diffs” patch block for the exact files in your tree, but everything above is already formatted to paste directly into the matching modules shown in your export .
