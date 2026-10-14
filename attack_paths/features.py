"""Features for triaging a security alert by where an attacker could go from it.

The alert names an asset. `resolvers.attack_surface` asks the graph database which crown jewels
are reachable from that asset, how far away the nearest one is, how much of the estate it can
touch, and whether the internet can reach the asset at all. The risk score and the verdict are
native Chalk expressions over those graph features, so the triage logic is visible and versioned
with the rest of the feature code.
"""

from __future__ import annotations

import chalk.functions as F
from chalk.features import _, features

PRIORITIZE_AT = 0.6
MONITOR_AT = 0.3


@features
class SecurityAlert:
    id: str

    # From the alert source (a SIEM table in production; a fixed catalog in this demo).
    title: str
    kind: str
    target_id: str
    target_name: str
    target_label: str
    severity: str
    source: str

    # From the graph database, via a Python resolver running Cypher.
    min_hops_to_crown_jewel: int | None
    crown_jewels_reachable: int
    path_count: int
    blast_radius: int
    secrets_reachable: int
    privileged_roles_reachable: int
    internet_hops: int | None
    attack_path: str  # JSON: the shortest path to the nearest crown jewel
    entry_path: str  # JSON: the shortest path from the internet to the asset
    neighborhood: str  # JSON: the subgraph the page draws
    graph_ms: float

    # Each term is one reason to care, so a verdict can be explained term by term.
    proximity: float = F.greatest(
        0.0, 0.8 - 0.12 * F.coalesce(_.min_hops_to_crown_jewel, 99)
    )
    exposure_score: float = F.if_then_else(
        F.coalesce(_.internet_hops, 99) <= 2, 0.15, 0.0
    )
    credential_score: float = F.if_then_else(_.kind == "leaked_credential", 0.15, 0.0)
    privilege_score: float = F.if_then_else(_.privileged_roles_reachable > 0, 0.05, 0.0)
    severity_score: float = F.if_then_else(
        _.severity == "high",
        0.1,
        F.if_then_else(_.severity == "medium", 0.05, 0.0),
    )
    breadth_score: float = F.if_then_else(_.path_count >= 3, 0.05, 0.0)

    risk_score: float = F.least(
        1.0,
        _.proximity
        + _.exposure_score
        + _.credential_score
        + _.privilege_score
        + _.severity_score
        + _.breadth_score,
    )
    triage: str = F.if_then_else(
        _.risk_score >= PRIORITIZE_AT,
        "prioritize",
        F.if_then_else(_.risk_score >= MONITOR_AT, "monitor", "dismiss"),
    )
