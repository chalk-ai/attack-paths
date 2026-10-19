#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12,<3.14"
# dependencies = ["chalkcompute>=2.13.8"]
# ///
"""Deploy the graph database (Neo4j, read-only) as a ScalingGroup.

The container bulk-imports graph/nodes.csv and graph/rels.csv on first start, then serves the
estate read-only. Its route requires a Chalk token, so the only unauthenticated callers are
workloads inside the environment's cluster, such as the resolvers:

    ./deploy_graph.py
    chalk secret set ATTACK_GRAPH_URL=http://sg-<scaling group id>.ns-<environment id>.svc.cluster.local:7474

A server that was already running when the secret was set does not see it until it restarts. In
that case write the URL to attack_paths/graph_location.py as `GRAPH_URL = "..."` (gitignored), and
deploy from a directory where it is not ignored.

Credentials for the deploy come from your existing `chalk login` (or the CHALK_* env vars).
"""

from __future__ import annotations

import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> None:
    from chalkcompute import Image, ReadinessProbe, ScalingGroup

    image = (
        Image.base("neo4j:5.26-community")
        .add_local_file(
            str(HERE / "graph" / "nodes.csv"), "/seed/nodes.csv", strategy="copy"
        )
        .add_local_file(
            str(HERE / "graph" / "rels.csv"), "/seed/rels.csv", strategy="copy"
        )
        .add_local_file(
            str(HERE / "graph" / "start.sh"),
            "/seed/start.sh",
            mode=0o755,
            strategy="copy",
        )
    )
    sg = ScalingGroup(
        image=image,
        name='attack-paths-graph',
        cpu="1",
        memory="2Gi",
        env={
            "NEO4J_AUTH": "none",
            "NEO4J_server_databases_default__to__read__only": "true",
            "NEO4J_server_memory_heap_initial__size": "512m",
            "NEO4J_server_memory_heap_max__size": "512m",
            "NEO4J_server_memory_pagecache_size": "128m",
        },
        entrypoint=["/seed/start.sh"],
        port=7474,
        authenticated=True,
        readiness_probe=ReadinessProbe.http("/"),
        min_replicas=1,
        max_replicas=1,
    )
    t0 = time.monotonic()
    try:
        sg.deploy(build_timeout=1800.0, ready_timeout=900.0)
    finally:
        print(f"deploy returned after {time.monotonic() - t0:.0f}s")
    print("web_url:", sg.web_url)
    print("scaling group id:", sg.id if hasattr(sg, "id") else "?")


if __name__ == "__main__":
    main()
