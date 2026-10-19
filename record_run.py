#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12,<3.14"
# dependencies = ["chalkpy[runtime]==2.155.2", "requests>=2.32,<3"]
# ///
"""Triage every catalog alert with a Chalk online query, check it, and save the responses.

Each graph feature is compared with reference.py, and each verdict with the expected one, so a
change to the estate, the Cypher or the scoring shows up here. The saved responses are the
recorded run the demo page falls back to when the live API is unreachable.

    ./record_run.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from chalk.client import ChalkClient

import reference
from attack_paths.estate import ALERTS
from attack_paths.outputs import JSON_FEATURES, OUTPUTS

EXPECTED = {
    "ALR-1041": "prioritize",
    "ALR-1042": "dismiss",
    "ALR-1043": "prioritize",
    "ALR-1044": "dismiss",
    "ALR-1045": "monitor",
    "ALR-1046": "monitor",
    "ALR-1047": "prioritize",
    "ALR-1048": "prioritize",
}


def main() -> None:
    client = ChalkClient(branch="attack-paths")

    records = []
    failures = 0
    for alert in ALERTS:
        t0 = time.perf_counter()
        result = client.query(
            input={"security_alert.id": alert.id},
            output=OUTPUTS,
            query_name="attack-paths-record",
        )
        ms = (time.perf_counter() - t0) * 1000
        if result.errors:
            raise SystemExit(f"{alert.id}: {result.errors}")
        values = {k.split(".", 1)[1]: v for k, v in result.to_dict().items()}
        for key in JSON_FEATURES:
            values[key] = json.loads(values[key])
        ref = reference.features(alert.target_id)
        diffs = {k: (values[k], v) for k, v in ref.items() if values[k] != v}
        if values["triage"] != EXPECTED[alert.id]:
            diffs["triage"] = (values["triage"], EXPECTED[alert.id])
        failures += bool(diffs)
        query_id = getattr(result.meta, "query_id", None) if result.meta else None
        print(
            f"{alert.id} {values['triage']:<10} risk={values['risk_score']:.2f} {ms:6.0f} ms "
            f"{'OK' if not diffs else diffs} {query_id}"
        )
        records.append(
            {
                "alert_id": alert.id,
                "features": values,
                "query_ms": round(ms, 1),
                "query_id": query_id,
            }
        )

    out = HERE / "results" / "recorded_run.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "branch": 'attack-paths',
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "runs": records,
            },
            indent=1,
            default=str,
        )
    )
    print(f"wrote {out}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
