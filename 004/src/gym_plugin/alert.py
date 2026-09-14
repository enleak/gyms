"""Derive one investigation entry point from checksum-locked CloudTrail data."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any
from urllib.parse import unquote

from . import config
from .dataset import EVENTS_KEY, MANIFEST_KEY, NORMALIZATION_VERSION, SOURCE_KEY, validate_corpus


RULE_ID = "gym-004-cloudtrail-groundlink-caller-trust-v1"
ROLE_NAME_PREFIX = "groundlink-"


def caller_role_trust(record: dict[str, Any]) -> list[str]:
    """Find a GroundLink role update that explicitly trusts the calling role."""
    if (
        record["eventSource"] != "iam.amazonaws.com"
        or record["eventName"] != "UpdateAssumeRolePolicy"
        or record.get("errorCode")
    ):
        return []
    request = record.get("requestParameters") or {}
    role_name = request.get("roleName", "")
    if not isinstance(role_name, str) or not role_name.startswith(ROLE_NAME_PREFIX):
        return []
    issuer = ((record.get("userIdentity") or {}).get("sessionContext") or {}).get("sessionIssuer") or {}
    caller_role = issuer.get("arn")
    if not isinstance(caller_role, str) or ":role/" not in caller_role:
        return []
    policy = request.get("policyDocument")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            policy = json.loads(unquote(policy))
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    principals: set[str] = set()
    for statement in statements:
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        actions = statement.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if "sts:AssumeRole" not in actions:
            continue
        principal = statement.get("Principal")
        aws = principal.get("AWS", []) if isinstance(principal, dict) else []
        aws = [aws] if isinstance(aws, str) else aws
        if caller_role in aws:
            principals.add(caller_role)
    return sorted(principals)


def evidence_settings() -> tuple[str, str]:
    configured = config.parse_env()
    bucket = os.environ.get("GROUNDLINK_BUCKET", configured.get("GROUNDLINK_BUCKET", "groundlink"))
    endpoint = os.environ.get("GROUNDLINK_ENDPOINT", configured.get("GROUNDLINK_ENDPOINT", "minio:9000"))
    return bucket, f"http://{endpoint}/{bucket}"


def source_case() -> dict[str, Any]:
    source, records = validate_corpus()
    matches = [
        (record, ordinal, principals)
        for ordinal, record in enumerate(records, start=1)
        if (principals := caller_role_trust(record))
    ]
    if not matches:
        raise ValueError("GroundLink corpus has no event matching the caller-role trust rule")
    record, ordinal, principals = min(matches, key=lambda item: (item[0]["eventTime"], item[0]["eventID"]))
    bucket, base = evidence_settings()
    role = record["requestParameters"]["roleName"]
    event_id = record["eventID"]
    identity_arn = record["userIdentity"]["arn"]
    return {
        "summary": f"GroundLink: suspicious IAM trust-policy update for {role}",
        "description": (
            "Gym-derived CloudTrail detection; this is not an upstream GuardDuty finding.\n\n"
            f"At {record['eventTime']}, {identity_arn} successfully called UpdateAssumeRolePolicy "
            f"for {role}. The submitted policy allows sts:AssumeRole to "
            f"the calling IAM role, {', '.join(principals)}, without conditions. "
            "The previous trust policy is not provided by this event.\n\n"
            "Determine whether the change was authorized, follow relevant role/session and "
            "resource relationships, assess impact, and recommend containment from the evidence.\n\n"
            f"Evidence URL: {base}/{EVENTS_KEY}\n"
            f"Original corpus: {base}/{SOURCE_KEY}\n"
            f"Manifest: {base}/{MANIFEST_KEY}\n"
            f"Starting event ID: {event_id}\n"
            f"Source SHA-256: {hashlib.sha256(source).hexdigest()}\n"
            f"Source ordinal: {ordinal} (1-based Records array index)\n\n"
            "Dataset caveats: access keys are redacted, source IPs are identical, and recorded "
            "calls succeeded. Correlate identities and resources rather than access keys or IPs. "
            "This lab uses captured evidence and does not execute actions against AWS."
        ),
        "status": "new",
        "priority": "high",
        "severity": "medium",
        "payload": {
            "gym_id": "004",
            "alert_id": f"{RULE_ID}:{event_id}",
            "rule_id": RULE_ID,
            "detection_source": "gym-derived-cloudtrail",
            "event_id": event_id,
            "event_time": record["eventTime"],
            "event_source": record["eventSource"],
            "event_name": record["eventName"],
            "aws_region": record.get("awsRegion"),
            "identity_arn": identity_arn,
            "role_name": role,
            "trusted_principals": principals,
            "monitored_role_name_prefix": ROLE_NAME_PREFIX,
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "source_ordinal": ordinal,
            "normalization_version": NORMALIZATION_VERSION,
            "evidence_bucket": bucket,
            "event_object_url": f"{base}/{EVENTS_KEY}",
            "source_object_url": f"{base}/{SOURCE_KEY}",
            "manifest_object_url": f"{base}/{MANIFEST_KEY}",
        },
    }


def main() -> int:
    target = config.ROOT / "artifacts/alert-case.json"
    desired = source_case()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(desired, indent=2, sort_keys=True) + "\n")
    print(f"[gym-004] Prepared one derived alert/case: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
