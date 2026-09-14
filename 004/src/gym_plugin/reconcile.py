"""Create one managed incident case, preserving existing investigation work."""

from __future__ import annotations

from typing import Any

from gymctl import tracecat
from gymctl.http import ClientLike

from .alert import source_case


REFERENCE_KEYS = (
    "gym_id", "alert_id", "rule_id", "event_id", "source_sha256", "source_ordinal",
    "normalization_version", "event_object_url", "source_object_url", "manifest_object_url",
)


def managed_cases(client: ClientLike, workspace_id: str) -> list[dict[str, Any]]:
    """Inspect every page so older cases cannot cause duplicate creation."""
    rows: list[dict[str, Any]] = []
    cursors: set[str] = set()
    params: dict[str, Any] = {"limit": 100, "include_payload": "true"}
    while True:
        payload = tracecat.request_json(
            client, "GET", f"/workspaces/{workspace_id}/cases", params=params,
        )
        items = tracecat.paginated_items(payload, "case list")
        rows.extend(
            row for row in items
            if isinstance(row.get("payload"), dict) and row["payload"].get("gym_id") == "004"
        )
        if not payload.get("has_more"):
            return rows
        cursor = payload.get("next_cursor")
        if not isinstance(cursor, str) or not cursor or cursor in cursors:
            raise tracecat.TracecatError("case pagination did not provide a new cursor")
        cursors.add(cursor)
        params = {**params, "cursor": cursor}


def verify_case(case: dict[str, Any], desired: dict[str, Any]) -> None:
    if not case.get("id"):
        raise tracecat.TracecatError("managed case is missing its id")
    actual = case.get("payload") or {}
    drift = [key for key in REFERENCE_KEYS if actual.get(key) != desired["payload"][key]]
    if drift:
        raise tracecat.TracecatError(
            "managed case evidence references differ: " + ", ".join(drift)
            + "; review the case payload or evidence configuration before reconciling"
        )


def find_case(client: ClientLike, workspace_id: str, desired: dict[str, Any]) -> dict[str, Any] | None:
    rows = managed_cases(client, workspace_id)
    if not rows:
        return None
    if len(rows) != 1 or rows[0]["payload"].get("alert_id") != desired["payload"]["alert_id"]:
        raise tracecat.TracecatError("expected one Gym 004 case for the derived alert; review existing managed cases")
    case = tracecat.request_json(
        client, "GET", f"/workspaces/{workspace_id}/cases/{rows[0]['id']}",
    )
    verify_case(case, desired)
    return case


def reconcile_case(client: ClientLike, workspace_id: str) -> dict[str, Any]:
    desired = source_case()
    existing = find_case(client, workspace_id, desired)
    if existing is not None:
        print(f"[gym-004] Preserved existing incident case: {existing['id']}", flush=True)
        return existing
    tracecat.request_json(
        client, "POST", f"/workspaces/{workspace_id}/cases", body=desired, expected=(201,),
    )
    final = find_case(client, workspace_id, desired)
    if final is None:
        raise tracecat.TracecatError("created GroundLink case was not returned by the API")
    print(f"[gym-004] Created incident case: {final['id']}", flush=True)
    return final


def status(client: ClientLike, email: str | None = None, password: str | None = None) -> dict[str, Any]:
    workspace_id = tracecat.login(client, email, password)
    case = find_case(client, workspace_id, source_case())
    if case is None:
        raise tracecat.TracecatError("GroundLink case is missing; run just up or just reconcile")
    print(f"[gym-004] Incident case READY: {case['id']}; evidence references verified.", flush=True)
    return case


def main(*, read_only: bool = False) -> int:
    with tracecat.client() as client:
        if read_only:
            status(client)
        else:
            workspace_id = tracecat.login(client)
            reconcile_case(client, workspace_id)
    return 0
