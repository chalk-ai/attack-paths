"""The features the demo page shows, shared by the live API and the recorder."""

from __future__ import annotations

from attack_paths.features import SecurityAlert

JSON_FEATURES = ("attack_path", "entry_path", "neighborhood")

OUTPUTS = [
    SecurityAlert.title,
    SecurityAlert.kind,
    SecurityAlert.target_id,
    SecurityAlert.target_name,
    SecurityAlert.target_label,
    SecurityAlert.severity,
    SecurityAlert.source,
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
    SecurityAlert.proximity,
    SecurityAlert.exposure_score,
    SecurityAlert.credential_score,
    SecurityAlert.privilege_score,
    SecurityAlert.severity_score,
    SecurityAlert.breadth_score,
    SecurityAlert.risk_score,
    SecurityAlert.triage,
]
