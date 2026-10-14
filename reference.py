"""A plain-Python reference for the graph features, used to check what the Cypher resolver returns.

uv run python reference.py
"""

from __future__ import annotations

import json
from collections import deque

from attack_paths.estate import ALERTS, EDGES, NODES_BY_ID

MAX_HOPS = 6

ADJ: dict[str, list[str]] = {}
for e in EDGES:
    ADJ.setdefault(e.src, []).append(e.dst)


def bfs(start: str, max_hops: int) -> dict[str, int]:
    dist = {start: 0}
    q = deque([start])
    while q:
        n = q.popleft()
        if dist[n] == max_hops:
            continue
        for m in ADJ.get(n, []):
            if m not in dist:
                dist[m] = dist[n] + 1
                q.append(m)
    return dist


def simple_paths_to_crown(start: str) -> int:
    count = 0

    def walk(n: str, seen: set[str], depth: int) -> None:
        nonlocal count
        if depth > 0 and NODES_BY_ID[n].crown_jewel:
            count += 1
        if depth == MAX_HOPS:
            return
        for m in ADJ.get(n, []):
            if m not in seen:
                walk(m, seen | {m}, depth + 1)

    walk(start, {start}, 0)
    return count


def features(target: str) -> dict[str, object]:
    dist = bfs(target, MAX_HOPS)
    reach = {n: d for n, d in dist.items() if n != target}
    crown = sorted((d, n) for n, d in reach.items() if NODES_BY_ID[n].crown_jewel)
    exposure = bfs("internet", MAX_HOPS).get(target)
    return {
        "min_hops_to_crown_jewel": crown[0][0] if crown else None,
        "crown_jewels_reachable": len(crown),
        "path_count": simple_paths_to_crown(target),
        "blast_radius": len(reach),
        "secrets_reachable": sum(1 for n in reach if NODES_BY_ID[n].label == "Secret"),
        "privileged_roles_reachable": sum(
            1 for n in reach if NODES_BY_ID[n].privileged
        ),
        "internet_hops": exposure,
    }


if __name__ == "__main__":
    for a in ALERTS:
        print(a.id, a.kind, a.target_id, a.severity, json.dumps(features(a.target_id)))
