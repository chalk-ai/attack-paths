"""Condense results/recorded_run.json into the data behind the demo page (results/page_data.json).

uv run python export_page_data.py
"""

from __future__ import annotations

import json
from pathlib import Path

from attack_paths.estate import ALERT_KINDS, ALERTS, CUSTOM_TARGET_LABELS, NODES
from attack_paths.features import MONITOR_AT, PRIORITIZE_AT

HERE = Path(__file__).resolve().parent
SCORE_TERMS = (
    "proximity",
    "exposure_score",
    "credential_score",
    "privilege_score",
    "severity_score",
    "breadth_score",
)


def main() -> None:
    run = json.loads((HERE / "results" / "recorded_run.json").read_text())
    by_id = {r["alert_id"]: r for r in run["runs"]}
    page = {
        "recordedAt": run["recorded_at"],
        "branch": run["branch"],
        "thresholds": {"prioritize": PRIORITIZE_AT, "monitor": MONITOR_AT},
        "kinds": list(ALERT_KINDS),
        "customTargets": [
            {"id": n.id, "name": n.name, "label": n.label, "env": n.env}
            for n in NODES
            if n.label in CUSTOM_TARGET_LABELS
        ],
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "kind": a.kind,
                "severity": a.severity,
                "source": a.source,
                "tags": list(a.tags),
                "result": {
                    "features": {
                        k: v
                        for k, v in by_id[a.id]["features"].items()
                        if k not in ("title", "kind", "severity", "source")
                    },
                    "queryMs": by_id[a.id]["query_ms"],
                    "queryId": by_id[a.id]["query_id"],
                },
            }
            for a in ALERTS
        ],
        "scoreTerms": list(SCORE_TERMS),
    }
    out = HERE / "results" / "page_data.json"
    out.write_text(json.dumps(page, indent=1))
    print(f"wrote {out}: {len(page['alerts'])} alerts")


if __name__ == "__main__":
    main()
