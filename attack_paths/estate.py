"""Kestrel Pay's cloud estate and its security alerts. Everything here is fictional.

The estate is a directed graph whose edges point the way an attacker moves: from the internet to a
load balancer, from a compromised workload to the role it runs as, from a role to the secrets and
data it can read, and so on. `graph/export_csv.py` writes it out for the graph database, and the
alert catalog stands in for a SIEM table.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Node:
    id: str
    label: str  # Internet, LoadBalancer, VM, Container, AccessKey, Role, Secret, DataStore, Account
    name: str
    env: str
    crown_jewel: bool = False
    privileged: bool = False
    note: str = ""


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    type: str
    detail: str = ""


@dataclass(frozen=True)
class AlertSpec:
    id: str
    title: str
    kind: str  # suspicious_process, leaked_credential, exposed_service, brute_force, anomalous_access
    target_id: str
    severity: str  # low, medium, high: the detection rule's own severity, before any graph context
    source: str
    tags: tuple[str, ...] = field(default_factory=tuple)


# Edges an attacker can traverse; `export_csv.py` writes only these, so every edge in the graph is
# one of them.
ATTACK_EDGES = (
    "EXPOSES",  # internet -> a public endpoint
    "ROUTES_TO",  # load balancer -> backend workload
    "CAN_REACH",  # workload -> workload, over an allowed network port
    "RUNS_AS",  # workload -> the IAM role it holds
    "AUTHENTICATES_AS",  # access key -> the role it signs in as
    "CAN_ASSUME",  # role -> role it may assume
    "CAN_READ",  # role -> secret or data store
    "GRANTS",  # secret -> the role or data store its credentials open
    "ADMIN_OF",  # role -> account it administers
    "CONTAINS",  # account -> crown-jewel store inside it
)

NODES: tuple[Node, ...] = (
    Node("internet", "Internet", "Internet", "public"),
    # Accounts
    Node("acct-prod", "Account", "kestrel-prod", "prod"),
    Node("acct-staging", "Account", "kestrel-staging", "staging"),
    Node("acct-ci", "Account", "kestrel-ci", "ci"),
    Node("acct-dev", "Account", "kestrel-dev", "dev"),
    # Public entry points
    Node("lb-checkout", "LoadBalancer", "checkout-public-lb", "prod"),
    Node("lb-partner-api", "LoadBalancer", "partner-api-lb", "prod"),
    # Workloads
    Node("vm-checkout-01", "VM", "checkout-web-01", "prod"),
    Node("vm-checkout-02", "VM", "checkout-web-02", "prod"),
    Node("vm-bastion", "VM", "bastion-01", "prod", note="SSH from the internet"),
    Node("vm-ci-runner", "VM", "ci-runner-03", "ci"),
    Node(
        "vm-ds-sandbox",
        "VM",
        "ds-sandbox-17",
        "dev",
        note="Public Jupyter for data science",
    ),
    Node("ctr-ledger", "Container", "ledger-svc", "prod"),
    Node("ctr-partner-gw", "Container", "partner-gateway", "prod"),
    Node("ctr-reports", "Container", "reports-worker", "prod"),
    Node(
        "ctr-k8s-dash",
        "Container",
        "k8s-dashboard",
        "staging",
        note="Exposed by mistake",
    ),
    Node("ctr-metrics", "Container", "metrics-agent", "prod"),
    # Access keys
    Node("key-ci-deployer", "AccessKey", "AKIA…DEPLOY (ci-deployer)", "ci"),
    Node("key-analytics-intern", "AccessKey", "AKIA…INTERN (analytics-intern)", "dev"),
    # Roles
    Node("role-checkout-web", "Role", "checkout-web-instance", "prod"),
    Node("role-ledger", "Role", "ledger-service", "prod"),
    Node("role-partner-gw", "Role", "partner-gateway", "prod"),
    Node("role-reports", "Role", "reports-exporter", "prod"),
    Node("role-metrics", "Role", "metrics-agent", "prod"),
    Node("role-ci-runner", "Role", "ci-runner-instance", "ci"),
    Node("role-ci-deployer", "Role", "ci-deployer", "ci"),
    Node("role-prod-deploy", "Role", "prod-deploy", "prod", privileged=True),
    Node("role-ds-sandbox", "Role", "ds-sandbox", "dev"),
    Node("role-analytics-ro", "Role", "analytics-readonly", "dev"),
    Node("role-staging-admin", "Role", "staging-admin", "staging", privileged=True),
    Node("role-observability", "Role", "shared-observability", "prod"),
    # Secrets
    Node("sec-ledger-db", "Secret", "ledger-db-credentials", "prod"),
    Node("sec-redis", "Secret", "checkout-redis-password", "prod"),
    Node("sec-partner-hmac", "Secret", "partner-hmac-keys", "prod"),
    Node("sec-staging-db", "Secret", "staging-orders-db", "staging"),
    Node("sec-replica-ro", "Secret", "ledger-replica-readonly", "prod"),
    # Data stores
    Node(
        "db-ledger", "DataStore", "payments-ledger (Postgres)", "prod", crown_jewel=True
    ),
    Node(
        "bkt-customer-pii",
        "DataStore",
        "customer-kyc-documents (bucket)",
        "prod",
        crown_jewel=True,
    ),
    Node(
        "db-ledger-replica",
        "DataStore",
        "ledger-replica (Postgres)",
        "prod",
        crown_jewel=True,
    ),
    Node("cache-checkout", "DataStore", "checkout-sessions (Redis)", "prod"),
    Node("db-staging-orders", "DataStore", "staging-orders (Postgres)", "staging"),
    Node("bkt-dev-scratch", "DataStore", "ds-scratch (bucket)", "dev"),
    Node("bkt-marketing", "DataStore", "marketing-assets (bucket)", "dev"),
    Node("bkt-metrics", "DataStore", "metrics-archive (bucket)", "prod"),
)

EDGES: tuple[Edge, ...] = (
    # Internet exposure
    Edge("internet", "lb-checkout", "EXPOSES", "443"),
    Edge("internet", "lb-partner-api", "EXPOSES", "443"),
    Edge("internet", "vm-bastion", "EXPOSES", "22"),
    Edge("internet", "vm-ds-sandbox", "EXPOSES", "8888"),
    Edge("internet", "ctr-k8s-dash", "EXPOSES", "8443"),
    Edge("lb-checkout", "vm-checkout-01", "ROUTES_TO", "443"),
    Edge("lb-checkout", "vm-checkout-02", "ROUTES_TO", "443"),
    Edge("lb-partner-api", "ctr-partner-gw", "ROUTES_TO", "443"),
    # Network reachability inside the estate
    Edge("vm-checkout-01", "ctr-ledger", "CAN_REACH", "8080"),
    Edge("vm-checkout-02", "ctr-ledger", "CAN_REACH", "8080"),
    Edge("vm-checkout-01", "cache-checkout", "CAN_REACH", "6379"),
    Edge("ctr-partner-gw", "ctr-ledger", "CAN_REACH", "8080"),
    Edge("vm-bastion", "vm-ci-runner", "CAN_REACH", "22"),
    Edge("vm-bastion", "vm-checkout-02", "CAN_REACH", "22"),
    Edge("ctr-reports", "ctr-metrics", "CAN_REACH", "9100"),
    # Workload identities
    Edge("vm-checkout-01", "role-checkout-web", "RUNS_AS"),
    Edge("vm-checkout-02", "role-checkout-web", "RUNS_AS"),
    Edge("ctr-ledger", "role-ledger", "RUNS_AS"),
    Edge("ctr-partner-gw", "role-partner-gw", "RUNS_AS"),
    Edge("ctr-reports", "role-reports", "RUNS_AS"),
    Edge("ctr-metrics", "role-metrics", "RUNS_AS"),
    Edge("vm-ci-runner", "role-ci-runner", "RUNS_AS"),
    Edge("vm-ds-sandbox", "role-ds-sandbox", "RUNS_AS"),
    Edge("ctr-k8s-dash", "role-staging-admin", "RUNS_AS"),
    # Access keys
    Edge("key-ci-deployer", "role-ci-deployer", "AUTHENTICATES_AS"),
    Edge("key-analytics-intern", "role-analytics-ro", "AUTHENTICATES_AS"),
    # Role chaining
    Edge("role-ci-runner", "role-ci-deployer", "CAN_ASSUME"),
    Edge("role-ci-deployer", "role-prod-deploy", "CAN_ASSUME"),
    Edge("role-staging-admin", "role-observability", "CAN_ASSUME"),
    Edge("role-metrics", "role-observability", "CAN_ASSUME"),
    # What each role can read
    Edge("role-checkout-web", "sec-ledger-db", "CAN_READ", "secrets:GetSecretValue"),
    Edge("role-checkout-web", "sec-redis", "CAN_READ", "secrets:GetSecretValue"),
    Edge("role-ledger", "db-ledger", "CAN_READ", "rds-db:connect"),
    Edge("role-partner-gw", "sec-partner-hmac", "CAN_READ", "secrets:GetSecretValue"),
    Edge("role-reports", "bkt-customer-pii", "CAN_READ", "s3:GetObject"),
    Edge("role-metrics", "bkt-metrics", "CAN_READ", "s3:PutObject"),
    Edge("role-ds-sandbox", "bkt-dev-scratch", "CAN_READ", "s3:*"),
    Edge("role-analytics-ro", "bkt-marketing", "CAN_READ", "s3:GetObject"),
    Edge("role-analytics-ro", "bkt-dev-scratch", "CAN_READ", "s3:GetObject"),
    Edge("role-staging-admin", "sec-staging-db", "CAN_READ", "secrets:GetSecretValue"),
    Edge("role-observability", "sec-replica-ro", "CAN_READ", "secrets:GetSecretValue"),
    Edge("role-observability", "bkt-metrics", "CAN_READ", "s3:GetObject"),
    # What each secret opens
    Edge("sec-ledger-db", "db-ledger", "GRANTS", "postgres login"),
    Edge("sec-redis", "cache-checkout", "GRANTS", "redis AUTH"),
    Edge("sec-staging-db", "db-staging-orders", "GRANTS", "postgres login"),
    Edge("sec-replica-ro", "db-ledger-replica", "GRANTS", "postgres login"),
    # Account administration
    Edge("role-prod-deploy", "acct-prod", "ADMIN_OF", "AdministratorAccess"),
    Edge("role-staging-admin", "acct-staging", "ADMIN_OF", "AdministratorAccess"),
    Edge("acct-prod", "db-ledger", "CONTAINS"),
    Edge("acct-prod", "bkt-customer-pii", "CONTAINS"),
)

# Pairs on purpose: the same detection on two assets, which the graph context tells apart.
ALERTS: tuple[AlertSpec, ...] = (
    AlertSpec(
        "ALR-1041",
        "Crypto-miner process on checkout-web-01",
        "suspicious_process",
        "vm-checkout-01",
        "medium",
        "EDR",
        ("xmrig", "outbound to mining pool"),
    ),
    AlertSpec(
        "ALR-1042",
        "Crypto-miner process on ds-sandbox-17",
        "suspicious_process",
        "vm-ds-sandbox",
        "medium",
        "EDR",
        ("xmrig", "outbound to mining pool"),
    ),
    AlertSpec(
        "ALR-1043",
        "ci-deployer access key found in a public repository",
        "leaked_credential",
        "key-ci-deployer",
        "high",
        "Secret scanning",
        ("committed to GitHub", "key active"),
    ),
    AlertSpec(
        "ALR-1044",
        "analytics-intern access key found in a public gist",
        "leaked_credential",
        "key-analytics-intern",
        "high",
        "Secret scanning",
        ("pasted in a gist", "key active"),
    ),
    AlertSpec(
        "ALR-1045",
        "Kubernetes dashboard reachable from the internet",
        "exposed_service",
        "ctr-k8s-dash",
        "medium",
        "Attack surface scan",
        ("no auth proxy", "staging cluster"),
    ),
    AlertSpec(
        "ALR-1046",
        "SSH brute force against bastion-01",
        "brute_force",
        "vm-bastion",
        "low",
        "Network IDS",
        ("4,200 failed logins", "no success"),
    ),
    AlertSpec(
        "ALR-1047",
        "Unusual bulk export by reports-worker",
        "anomalous_access",
        "ctr-reports",
        "medium",
        "Cloud audit log",
        ("12x normal object reads",),
    ),
    AlertSpec(
        "ALR-1048",
        "Malicious npm package installed in partner-gateway",
        "suspicious_process",
        "ctr-partner-gw",
        "high",
        "Container runtime",
        ("typosquatted dependency",),
    ),
)

NODES_BY_ID = {n.id: n for n in NODES}
ALERTS_BY_ID = {a.id: a for a in ALERTS}

# Visitors can also raise a custom alert against any asset an attacker could land on.
ALERT_KINDS = (
    "suspicious_process",
    "leaked_credential",
    "exposed_service",
    "brute_force",
    "anomalous_access",
)
CUSTOM_TARGET_LABELS = ("VM", "Container", "AccessKey", "LoadBalancer")
CUSTOM_PREFIX = "custom"


def custom_alert_id(target_id: str, kind: str) -> str:
    return f"{CUSTOM_PREFIX}:{target_id}:{kind}"


def resolve_alert(alert_id: str) -> AlertSpec | None:
    """The catalog alert, or a custom one encoded as `custom:<asset id>:<kind>`."""
    if alert_id in ALERTS_BY_ID:
        return ALERTS_BY_ID[alert_id]
    parts = alert_id.split(":")
    if len(parts) != 3 or parts[0] != CUSTOM_PREFIX:
        return None
    _, target_id, kind = parts
    node = NODES_BY_ID.get(target_id)
    if (
        node is None
        or node.label not in CUSTOM_TARGET_LABELS
        or kind not in ALERT_KINDS
    ):
        return None
    return AlertSpec(
        alert_id,
        f"{kind.replace('_', ' ').capitalize()} on {node.name}",
        kind,
        target_id,
        "medium",
        "Custom",
    )
