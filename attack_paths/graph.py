"""Attack-path queries against the graph database, over Neo4j's HTTP transaction API.

Every asset is an `:Asset` node with a second label for its kind, and every relationship is a
move an attacker can make (see `estate.ATTACK_EDGES`), so the queries can follow any edge type.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

import requests

MAX_HOPS = 6

_EDGES = "EXPOSES|ROUTES_TO|CAN_REACH|RUNS_AS|AUTHENTICATES_AS|CAN_ASSUME|CAN_READ|GRANTS|ADMIN_OF|CONTAINS"

# Shortest path from the alerted asset to each crown jewel it can reach.
CROWN_PATHS = f"""
MATCH (a:Asset {{id: $id}}), (c:Asset {{crown_jewel: true}})
WHERE a <> c
MATCH p = shortestPath((a)-[:{_EDGES}*1..{MAX_HOPS}]->(c))
RETURN c.id AS crown, length(p) AS hops,
       [n IN nodes(p) | n.id] AS ids,
       [r IN relationships(p) | [type(r), coalesce(r.detail, '')]] AS rels
ORDER BY hops, crown
"""

# Every distinct way to a crown jewel within the hop limit, not only the shortest.
PATH_COUNT = f"""
MATCH p = (:Asset {{id: $id}})-[:{_EDGES}*1..{MAX_HOPS}]->(:Asset {{crown_jewel: true}})
RETURN count(p) AS paths
"""

# Everything the asset can reach: its blast radius.
BLAST = f"""
MATCH (:Asset {{id: $id}})-[:{_EDGES}*1..{MAX_HOPS}]->(n:Asset)
RETURN count(DISTINCT n) AS reach,
       count(DISTINCT CASE WHEN n:Secret THEN n END) AS secrets,
       count(DISTINCT CASE WHEN n.privileged THEN n END) AS privileged
"""

# How an attacker on the internet gets to the asset, if they can.
ENTRY = f"""
MATCH (i:Internet), (a:Asset {{id: $id}})
WHERE i <> a
MATCH p = shortestPath((i)-[:{_EDGES}*1..{MAX_HOPS}]->(a))
RETURN length(p) AS hops,
       [n IN nodes(p) | n.id] AS ids,
       [r IN relationships(p) | [type(r), coalesce(r.detail, '')]] AS rels
"""

# The asset's immediate surroundings, drawn around the paths for context.
NEIGHBORS = f"""
MATCH p = (:Asset {{id: $id}})-[:{_EDGES}*1..2]->(:Asset)
UNWIND relationships(p) AS r
RETURN DISTINCT startNode(r).id AS src, endNode(r).id AS dst, type(r) AS type,
       coalesce(r.detail, '') AS detail
"""

NODE_DETAILS = """
MATCH (n:Asset) WHERE n.id IN $ids
RETURN n.id AS id, n.name AS name, [l IN labels(n) WHERE l <> 'Asset'][0] AS label,
       n.env AS env, coalesce(n.crown_jewel, false) AS crown_jewel,
       coalesce(n.privileged, false) AS privileged, coalesce(n.note, '') AS note
"""


@dataclass(frozen=True)
class AttackSurface:
    min_hops_to_crown_jewel: int | None
    crown_jewels_reachable: int
    path_count: int
    blast_radius: int
    secrets_reachable: int
    privileged_roles_reachable: int
    internet_hops: int | None
    attack_path: dict
    entry_path: dict
    neighborhood: dict
    graph_ms: float


def _graph_url() -> str:
    """The graph database's in-cluster URL: the ATTACK_GRAPH_URL secret, else graph_location.py.

    A running server reads Chalk secrets when it starts, so the module covers a server that started
    before the secret was set. It holds an environment-specific host, so it is gitignored.
    """
    url = os.environ.get("ATTACK_GRAPH_URL", "")
    if not url:
        try:
            from attack_paths.graph_location import GRAPH_URL as url
        except ImportError:
            url = ""
    if not url:
        raise RuntimeError(
            "set ATTACK_GRAPH_URL or write attack_paths/graph_location.py"
        )
    return url.rstrip("/")


def _run(statements: list[tuple[str, dict]]) -> list[list[dict]]:
    body = {
        "statements": [
            {"statement": s, "parameters": p, "resultDataContents": ["row"]}
            for s, p in statements
        ]
    }
    resp = requests.post(f"{_graph_url()}/db/neo4j/tx/commit", json=body, timeout=10)
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("errors"):
        raise RuntimeError(f"graph query failed: {payload['errors'][0]}")
    out: list[list[dict]] = []
    for result in payload["results"]:
        cols = result["columns"]
        out.append([dict(zip(cols, row["row"])) for row in result["data"]])
    return out


def _path(ids: list[str], rels: list[list[str]]) -> dict:
    return {
        "nodes": ids,
        "edges": [
            {"src": ids[i], "dst": ids[i + 1], "type": t, "detail": d}
            for i, (t, d) in enumerate(rels)
        ],
    }


def attack_surface(asset_id: str) -> AttackSurface:
    t0 = time.perf_counter()
    params = {"id": asset_id}
    crown, count, blast, entry, neighbors = _run(
        [
            (CROWN_PATHS, params),
            (PATH_COUNT, params),
            (BLAST, params),
            (ENTRY, params),
            (NEIGHBORS, params),
        ]
    )

    edges: dict[tuple[str, str, str], dict] = {}
    on_path: set[tuple[str, str]] = set()
    for row in crown:
        p = _path(row["ids"], row["rels"])
        for e in p["edges"]:
            edges[(e["src"], e["dst"], e["type"])] = e
            on_path.add((e["src"], e["dst"]))
    entry_path = (
        _path(entry[0]["ids"], entry[0]["rels"])
        if entry
        else {"nodes": [], "edges": []}
    )
    for e in entry_path["edges"]:
        edges[(e["src"], e["dst"], e["type"])] = e
    for row in neighbors:
        edges.setdefault((row["src"], row["dst"], row["type"]), dict(row))

    ids = sorted(
        {asset_id}
        | {e["src"] for e in edges.values()}
        | {e["dst"] for e in edges.values()}
    )
    (details,) = _run([(NODE_DETAILS, {"ids": ids})])
    nearest = crown[0] if crown else None
    graph_ms = (time.perf_counter() - t0) * 1000

    return AttackSurface(
        min_hops_to_crown_jewel=nearest["hops"] if nearest else None,
        crown_jewels_reachable=len(crown),
        path_count=count[0]["paths"] if count else 0,
        blast_radius=blast[0]["reach"] if blast else 0,
        secrets_reachable=blast[0]["secrets"] if blast else 0,
        privileged_roles_reachable=blast[0]["privileged"] if blast else 0,
        internet_hops=entry[0]["hops"] if entry else None,
        attack_path=_path(nearest["ids"], nearest["rels"])
        if nearest
        else {"nodes": [], "edges": []},
        entry_path=entry_path,
        neighborhood={
            "nodes": details,
            "edges": [
                {**e, "crown_path": (e["src"], e["dst"]) in on_path}
                for e in edges.values()
            ],
        },
        graph_ms=graph_ms,
    )


def dumps(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
