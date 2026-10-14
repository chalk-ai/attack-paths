"""The live API behind the attack-paths demo page.

    GET /api/alerts                              the alert catalog and the assets a custom alert can target
    GET /api/triage?alert=ALR-1041               triage one catalog alert with a Chalk online query
    GET /api/triage?target=vm-bastion&kind=...   triage a custom alert raised against any asset
    GET /healthz

The Chalk credentials are a service token that can only run online queries. Requests are capped per
client and in total, because the page is public.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

import uvicorn
from chalk.client import ChalkClient
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from attack_paths.estate import (
    ALERT_KINDS,
    ALERTS,
    CUSTOM_TARGET_LABELS,
    NODES,
    custom_alert_id,
    resolve_alert,
)
from attack_paths.features import SecurityAlert
from attack_paths.outputs import JSON_FEATURES, OUTPUTS

PER_CLIENT_PER_MIN = 20
MAX_CONCURRENT = 4
# An idle branch server sleeps; one cheap query every few minutes keeps visitor queries fast.
KEEPALIVE_S = int(os.environ.get("AP_KEEPALIVE_S", "240"))

client = ChalkClient(
    client_id=os.environ["AP_CHALK_CLIENT_ID"],
    client_secret=os.environ["AP_CHALK_CLIENT_SECRET"],
    api_server=os.environ["AP_CHALK_API_SERVER"],
    environment=os.environ["AP_CHALK_ENVIRONMENT_ID"],
    branch=os.environ["AP_CHALK_BRANCH"],
)
gate = asyncio.Semaphore(MAX_CONCURRENT)
recent: dict[str, deque[float]] = defaultdict(deque)


def triage(alert_id: str) -> dict:
    t0 = time.perf_counter()
    result = client.query(
        input={SecurityAlert.id: alert_id},
        output=OUTPUTS,
        query_name="attack-paths-demo",
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    if result.errors:
        raise HTTPException(502, "; ".join(str(e.message) for e in result.errors)[:300])
    values = {k.split(".", 1)[1]: v for k, v in result.to_dict().items()}
    for key in JSON_FEATURES:
        values[key] = json.loads(values[key])
    meta = result.meta
    return {
        "alert_id": alert_id,
        "features": values,
        "query_ms": round(elapsed_ms, 1),
        "query_id": getattr(meta, "query_id", None) if meta else None,
    }


async def keep_branch_warm() -> None:
    while True:
        try:
            await asyncio.to_thread(triage, ALERTS[0].id)
        except Exception as e:  # noqa: BLE001 - any failure must not end the keepalive loop
            print(f"keepalive failed: {e}", flush=True)
        await asyncio.sleep(KEEPALIVE_S)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(keep_branch_warm()) if KEEPALIVE_S > 0 else None
    yield
    if task is not None:
        task.cancel()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://(chalk\.ai|[a-z0-9-]+\.chalk\.dev|[a-z0-9-]+\.vercel\.app)|http://localhost:\d+",
    allow_methods=["GET"],
)


def _rate_limit(request: Request) -> None:
    ip = request.headers.get(
        "x-forwarded-for", request.client.host if request.client else "?"
    ).split(",")[0]
    now = time.monotonic()
    q = recent[ip]
    while q and q[0] < now - 60:
        q.popleft()
    if len(q) >= PER_CLIENT_PER_MIN:
        raise HTTPException(429, "slow down: 20 triages a minute per visitor")
    q.append(now)


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.get("/api/alerts")
async def alerts() -> dict:
    return {
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "kind": a.kind,
                "target_id": a.target_id,
                "severity": a.severity,
                "source": a.source,
                "tags": list(a.tags),
            }
            for a in ALERTS
        ],
        "custom_targets": [
            {"id": n.id, "name": n.name, "label": n.label, "env": n.env}
            for n in NODES
            if n.label in CUSTOM_TARGET_LABELS
        ],
        "kinds": list(ALERT_KINDS),
    }


@app.get("/api/triage")
async def triage_endpoint(
    request: Request,
    alert: str | None = None,
    target: str | None = None,
    kind: str | None = None,
) -> dict:
    alert_id = alert if alert else custom_alert_id(target or "", kind or "")
    if resolve_alert(alert_id) is None:
        raise HTTPException(400, "unknown alert, asset or alert kind")
    _rate_limit(request)
    async with gate:
        return await asyncio.to_thread(triage, alert_id)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
