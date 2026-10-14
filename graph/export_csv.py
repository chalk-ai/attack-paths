"""Write the estate as CSVs for `neo4j-admin database import`.

uv run python -m graph.export_csv
"""

from __future__ import annotations

import csv
from pathlib import Path

from attack_paths.estate import ATTACK_EDGES, EDGES, NODES

HERE = Path(__file__).resolve().parent


def main() -> None:
    with open(HERE / "nodes.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "id:ID",
                "name",
                "env",
                "crown_jewel:boolean",
                "privileged:boolean",
                "note",
                ":LABEL",
            ]
        )
        for n in NODES:
            w.writerow(
                [
                    n.id,
                    n.name,
                    n.env,
                    str(n.crown_jewel).lower(),
                    str(n.privileged).lower(),
                    n.note,
                    f"Asset;{n.label}",
                ]
            )
    with open(HERE / "rels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([":START_ID", ":END_ID", ":TYPE", "detail"])
        for e in EDGES:
            if e.type not in ATTACK_EDGES:
                raise ValueError(f"{e.type} is not an attack edge")
            w.writerow([e.src, e.dst, e.type, e.detail])
    print(f"wrote {len(NODES)} nodes and {len(EDGES)} relationships")


if __name__ == "__main__":
    main()
