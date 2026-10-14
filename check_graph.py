"""Check the Cypher features against the plain-Python reference for every alert.

ATTACK_GRAPH_URL=http://localhost:7474 uv run python check_graph.py
"""

from __future__ import annotations

import sys

import reference
from attack_paths.estate import ALERTS
from attack_paths.graph import attack_surface

KEYS = (
    "min_hops_to_crown_jewel",
    "crown_jewels_reachable",
    "path_count",
    "blast_radius",
    "secrets_reachable",
    "privileged_roles_reachable",
    "internet_hops",
)

bad = 0
for a in ALERTS:
    s = attack_surface(a.target_id)
    ref = reference.features(a.target_id)
    got = {k: getattr(s, k) for k in KEYS}
    diff = {k: (got[k], ref[k]) for k in KEYS if got[k] != ref[k]}
    bad += bool(diff)
    print(
        a.id,
        "OK" if not diff else f"MISMATCH {diff}",
        f"{s.graph_ms:.0f} ms",
        "path:",
        " -> ".join(s.attack_path["nodes"]) or "-",
        f"| drawn {len(s.neighborhood['nodes'])} nodes / {len(s.neighborhood['edges'])} edges",
    )
sys.exit(1 if bad else 0)
