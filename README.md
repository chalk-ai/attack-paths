# Attack-path triage with a graph resolver

Triage security alerts by where an attacker could go next. A Chalk Python resolver queries a graph
database of the estate for lateral movement from the alerted asset to its crown jewels, and native
Chalk expressions turn that reach into a verdict: prioritize, monitor or dismiss, with the attack
path as evidence.

Kestrel Pay, its cloud estate and its alerts are fictional. The alerts come in pairs on purpose:
the same detection on two assets, which only the graph tells apart. A crypto-miner on
`checkout-web-01` is three hops from the payments ledger and reachable from the internet; the same
miner on `ds-sandbox-17` reaches nothing that matters.

## How it works

```
alert id ─▶ get_alert ─▶ target asset ─▶ attack_surface (Python resolver) ──Cypher──▶ Neo4j
                                              │ shortest path to each crown jewel
                                              │ number of routes, blast radius
                                              └ route in from the internet
           proximity + exposure + credential + privilege + severity + breadth
           ─▶ risk_score ─▶ triage          (native Chalk expressions)
```

- **The graph.** Every asset is an `:Asset` node with a second label for its kind (VM, Container,
  AccessKey, Role, Secret, DataStore, …). Every relationship is a move an attacker can make:
  `EXPOSES`, `ROUTES_TO`, `CAN_REACH`, `RUNS_AS`, `AUTHENTICATES_AS`, `CAN_ASSUME`, `CAN_READ`,
  `GRANTS`, `ADMIN_OF` and `CONTAINS`, so the queries can follow any edge.
- **The resolver.** `attack_surface` sends one batched request to Neo4j's HTTP API: the shortest
  path to each crown jewel within 6 hops, the number of distinct routes, everything in reach (blast
  radius, secrets, privileged roles), and the shortest route in from the internet. It also returns
  the subgraph the demo page draws.
- **The score.** Each term is one reason to care, so a verdict can be explained term by term:
  `0.8 − 0.12 × hops` to the nearest crown jewel, plus 0.15 if the internet is within 2 hops, 0.15
  for a leaked credential, 0.05 for a reachable privileged role, up to 0.1 for the detection's
  severity, and 0.05 for 3 or more routes. Monitor at 0.3, prioritize at 0.6.

On the eight catalog alerts, the Cypher features match a plain-Python reference (`reference.py`)
exactly, and the verdicts are 4 prioritize, 2 monitor and 2 dismiss.

## Files

| File | Role |
| --- | --- |
| `attack_paths/estate.py` | The fictional estate (nodes and attack edges) and the alert catalog |
| `attack_paths/features.py` | `SecurityAlert`: alert fields, graph features and the scoring expressions |
| `attack_paths/resolvers.py` | `get_alert` (stand-in for a SIEM table) and `attack_surface` (the graph resolver) |
| `attack_paths/graph.py` | The Cypher queries and the Neo4j HTTP client |
| `graph/` | `export_csv.py` writes the estate for `neo4j-admin import`; `start.sh` loads it read-only |
| `deploy_graph.py` | Deploys Neo4j as a Chalk ScalingGroup, reachable only inside the cluster |
| `reference.py`, `check_graph.py` | A plain-Python reference for the graph features, and a check against it |
| `record_run.py` | Triages every catalog alert with Chalk, checks it, and saves the responses |
| `server.py`, `deploy_api.py` | The live API behind the demo page, deployed as a ScalingGroup |
| `results/` | The recorded run and the data behind the demo page |

## Run it

You need [`uv`](https://docs.astral.sh/uv/), the Chalk CLI and a Chalk environment.

```bash
./deploy_graph.py                                   # Neo4j with the estate, read-only
chalk secret set ATTACK_GRAPH_URL=http://sg-<scaling group id>.ns-<environment id>.svc.cluster.local:7474
chalk apply --branch attack-paths                   # features, resolvers and scoring
chalk query --branch attack-paths --in security_alert.id=ALR-1041 \
  --out security_alert.triage --out security_alert.risk_score --out security_alert.attack_path
./record_run.py --branch attack-paths               # all eight alerts, checked against reference.py
```

The graph's route requires a Chalk token, and Neo4j runs with auth off but read-only, so the
resolvers reach it over the cluster network and nothing else can write to it. A server that was
already running when you set `ATTACK_GRAPH_URL` does not see the secret until it restarts; see
`deploy_graph.py` for the workaround.

To check the Cypher locally:

```bash
python -m graph.export_csv
docker run -d -p 7474:7474 -e NEO4J_AUTH=none -v "$PWD/graph:/seed" \
  --entrypoint /seed/start.sh neo4j:5.26-community
ATTACK_GRAPH_URL=http://localhost:7474 uv run --with requests python check_graph.py
```

## The live API

`server.py` answers `GET /api/triage?alert=ALR-1041`, or `?target=<asset id>&kind=<alert kind>`
for a custom alert, with a Chalk online query on the branch, and `GET /api/alerts` with the
catalog. It uses a service token that can only run online queries; see `deploy_api.py` for how to
create it, store it as a Chalk secret, and deploy the API as a ScalingGroup. It allows 20 triages a
minute per visitor and 4 concurrent queries, and browsers may call it only from Chalk's own
origins and localhost.

## License

Apache-2.0.

## Local authentication

The SDK reads credentials, API host, and the selected environment from your existing
`chalk login` in `~/.chalk.yml`, including project-scoped and default logins.
For unattended runs, `CHALK_CLIENT_ID` and `CHALK_CLIENT_SECRET` remain supported. Where available, `--env-id`
overrides the target environment; otherwise the SDK uses your login or environment settings.
