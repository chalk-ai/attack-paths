"""Resolvers: the alert source and the graph database.

`get_alert` stands in for a SQL resolver over a SIEM's alert table. `attack_surface` is the
interesting one: a plain Python resolver that runs Cypher against the graph database for every
alert Chalk is asked about, and returns the graph features the triage expressions score.
"""

from __future__ import annotations

from chalk import online
from chalk.features import Features

from attack_paths.estate import NODES_BY_ID, resolve_alert
from attack_paths.features import SecurityAlert
from attack_paths.graph import attack_surface as query_graph
from attack_paths.graph import dumps


@online
def get_alert(
    id: SecurityAlert.id,
) -> Features[
    SecurityAlert.title,
    SecurityAlert.kind,
    SecurityAlert.target_id,
    SecurityAlert.target_name,
    SecurityAlert.target_label,
    SecurityAlert.severity,
    SecurityAlert.source,
]:
    alert = resolve_alert(id)
    if alert is None:
        raise ValueError(f"unknown alert {id!r}")
    target = NODES_BY_ID[alert.target_id]
    return SecurityAlert(
        title=alert.title,
        kind=alert.kind,
        target_id=alert.target_id,
        target_name=target.name,
        target_label=target.label,
        severity=alert.severity,
        source=alert.source,
    )


@online
def attack_surface(
    target: SecurityAlert.target_id,
) -> Features[
    SecurityAlert.min_hops_to_crown_jewel,
    SecurityAlert.crown_jewels_reachable,
    SecurityAlert.path_count,
    SecurityAlert.blast_radius,
    SecurityAlert.secrets_reachable,
    SecurityAlert.privileged_roles_reachable,
    SecurityAlert.internet_hops,
    SecurityAlert.attack_path,
    SecurityAlert.entry_path,
    SecurityAlert.neighborhood,
    SecurityAlert.graph_ms,
]:
    s = query_graph(target)
    return SecurityAlert(
        min_hops_to_crown_jewel=s.min_hops_to_crown_jewel,
        crown_jewels_reachable=s.crown_jewels_reachable,
        path_count=s.path_count,
        blast_radius=s.blast_radius,
        secrets_reachable=s.secrets_reachable,
        privileged_roles_reachable=s.privileged_roles_reachable,
        internet_hops=s.internet_hops,
        attack_path=dumps(s.attack_path),
        entry_path=dumps(s.entry_path),
        neighborhood=dumps(s.neighborhood),
        graph_ms=s.graph_ms,
    )
