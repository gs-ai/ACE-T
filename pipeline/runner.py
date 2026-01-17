from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from core.schema_registry import DEFAULT_REGISTRY
from core.scoring import build_band_index, score_objects
from export.bundle import build_bundle
from export.graph import write_graph
from export.timeline import write_timeline
from pipeline.handlers import (
    collect_stage,
    extract_stage,
    resolve_stage,
    track_stage,
    validate_stage,
)
from pipeline.validation import validate_objects


class PipelineRunner:
    def __init__(self, pipeline_path: Path, seed: Dict[str, Any], output_root: Path) -> None:
        self.pipeline_path = pipeline_path
        self.seed = seed
        self.output_root = output_root
        self.pipeline = self._load_pipeline()
        self.registry = DEFAULT_REGISTRY
        self.intel_object_validator = self.registry.intel_object_validator("intel_bundle")

    def _load_pipeline(self) -> Dict[str, Any]:
        if not self.pipeline_path.exists():
            raise FileNotFoundError(f"Pipeline not found: {self.pipeline_path}")
        return json.loads(self.pipeline_path.read_text(encoding="utf-8"))

    def run(self) -> Dict[str, Any]:
        context: Dict[str, Any] = {"seed": self.seed}
        retention_days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
        handlers = {
            "validate": lambda stage, inputs: validate_stage(stage, inputs),
            "collect": lambda stage, inputs: collect_stage(stage, inputs, retention_days),
            "extract": lambda stage, inputs: extract_stage(stage, inputs),
            "resolve": lambda stage, inputs: resolve_stage(stage, inputs),
            "track": lambda stage, inputs: track_stage(stage, inputs),
        }
        for stage in self.pipeline.get("stages", []):
            stage_id = stage.get("id", "stage")
            stage_type = stage.get("type")
            inputs = {name: context.get(name) for name in stage.get("inputs", [])}
            outputs: Dict[str, Any] = {}

            if stage_type in handlers:
                outputs = handlers[stage_type](stage, inputs)
            elif stage_type == "score":
                merged: List[Dict[str, Any]] = []
                for value in inputs.values():
                    if isinstance(value, list):
                        merged.extend(value)
                artifacts = []
                for name, value in context.items():
                    if name.startswith("artifacts") and isinstance(value, list):
                        artifacts.extend(value)
                band_lookup = build_band_index(merged + artifacts)
                scored = score_objects(merged, stage.get("scoring") or {}, band_lookup)
                outputs = {"scored_objects": scored}
            elif stage_type == "build":
                scored = inputs.get("scored_objects") or []
                graph_objects = [o for o in scored if o.get("type") in {"entity", "edge", "cluster"}]
                timeline_objects = [o for o in scored if o.get("type") == "event"]
                outputs = {"graph_objects": graph_objects, "timeline_objects": timeline_objects}
            elif stage_type == "export":
                graph_objects = inputs.get("graph_objects") or []
                timeline_objects = inputs.get("timeline_objects") or []
                graph_objects, _ = validate_objects(graph_objects, self.intel_object_validator, f"{stage_id}_graph")
                timeline_objects, _ = validate_objects(timeline_objects, self.intel_object_validator, f"{stage_id}_timeline")
                artifacts = []
                for name, value in inputs.items():
                    if name.startswith("artifacts") and isinstance(value, list):
                        artifacts.extend(value)
                all_objects = list(graph_objects) + list(timeline_objects) + list(artifacts)
                run_id = os.getenv("ACE_T_RUN_ID") or "ace-t-pipeline"
                bundle = build_bundle(
                    case_id=self.seed.get("case_id", "case"),
                    objects=all_objects,
                    producer="ace-t",
                    run_id=run_id,
                    version=self.pipeline.get("version", "1.0.0"),
                    toolchain=[self.pipeline.get("pipeline_id", "ace-t")],
                )
                outputs = {"intel_bundle": bundle, "exports": []}
                try:
                    self.registry.validator("intel_bundle").validate(bundle)
                except Exception as exc:
                    print(f"[pipeline] bundle validation failed: {exc}")
                    bundle = None
                    outputs["intel_bundle"] = None
                for exporter in stage.get("exporters", []):
                    path = Path(exporter.get("path"))
                    if not path.is_absolute():
                        path = self.output_root / path
                    name = exporter.get("name")
                    if name == "bundle_json":
                        if bundle is None:
                            continue
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
                        outputs["exports"].append({"name": name, "path": str(path)})
                    elif name == "graph_json":
                        write_graph(path, graph_objects)
                        outputs["exports"].append({"name": name, "path": str(path)})
                    elif name == "timeline_json":
                        write_timeline(path, timeline_objects)
                        outputs["exports"].append({"name": name, "path": str(path)})
                    elif name == "artifact_manifest":
                        manifest = list(artifacts)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                        outputs["exports"].append({"name": name, "path": str(path)})
            else:
                raise ValueError(f"Unknown stage type: {stage_type}")

            for output_name, payload in outputs.items():
                if isinstance(payload, list):
                    if payload and isinstance(payload[0], dict) and "type" in payload[0]:
                        valid, _invalid = validate_objects(payload, self.intel_object_validator, stage_id)
                        context[output_name] = valid
                    else:
                        context[output_name] = payload
                else:
                    context[output_name] = payload

        return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ACE-T OSINT spectrum pipeline.")
    parser.add_argument(
        "--pipeline",
        default=str(Path(__file__).resolve().parents[1] / "pipeline" / "acet_osint_spectrum.pipeline.json"),
        help="Path to pipeline JSON",
    )
    parser.add_argument("--seed", required=True, help="Path to seed JSON file")
    parser.add_argument(
        "--output-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Output root for export paths",
    )
    args = parser.parse_args()
    seed = json.loads(Path(args.seed).read_text(encoding="utf-8"))
    runner = PipelineRunner(Path(args.pipeline), seed, Path(args.output_root))
    runner.run()


if __name__ == "__main__":
    main()
