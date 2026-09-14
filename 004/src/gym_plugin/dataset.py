"""Validate GroundLink evidence and seed reproducible objects into MinIO."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from . import config


NORMALIZATION_VERSION = "cloudtrail-query-v1"
SOURCE_KEY = "gym-004/source/groundlink.json.gz"
EVENTS_KEY = "gym-004/normalized/cloudtrail-v1.jsonl.gz"
MANIFEST_KEY = "gym-004/manifest.json"
POLICY_SID = "Gym004ReadEvidence"


def corpus_path() -> Path:
    # Compose uses the host path as a bind source; its seed process gets the
    # separate, fixed container path instead.
    value = os.environ.get("GROUNDLINK_CORPUS")
    if value is None:
        value = config.parse_env().get(
            "GROUNDLINK_CORPUS", config.load_lock()["artifacts"]["groundlink"]["path"]
        )
    path = Path(value).expanduser()
    return path if path.is_absolute() else config.ROOT / path


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def validate_corpus(path: Path | None = None) -> tuple[bytes, list[dict[str, Any]]]:
    path = path or corpus_path()
    expected = config.load_lock()["artifacts"]["groundlink"]
    if not path.is_file():
        raise ValueError(f"GroundLink corpus missing: {path}; see assets/README.md")
    source = path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if digest != expected["sha256"]:
        raise ValueError(f"GroundLink corpus checksum mismatch: {digest}")
    with gzip.GzipFile(fileobj=io.BytesIO(source)) as stream:
        decoded = stream.read(10 * 1024 * 1024 + 1)
    if len(decoded) > 10 * 1024 * 1024:
        raise ValueError("GroundLink decoded corpus exceeds 10 MiB")
    envelope = json.loads(decoded)
    if not isinstance(envelope, dict) or not isinstance(envelope.get("Records"), list):
        raise ValueError("GroundLink corpus must contain a native CloudTrail Records array")
    records = envelope["Records"]
    if len(records) != expected["record_count"]:
        raise ValueError(f"GroundLink record count mismatch: {len(records)}")
    event_ids: set[str] = set()
    for ordinal, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"CloudTrail record {ordinal} must be an object")
        for key in ("eventID", "eventTime", "eventSource", "eventName"):
            if not isinstance(record.get(key), str) or not record[key]:
                raise ValueError(f"CloudTrail record {ordinal} has invalid {key}")
        uuid.UUID(record["eventID"])
        if record["eventID"] in event_ids:
            raise ValueError(f"duplicate CloudTrail eventID at record {ordinal}")
        event_ids.add(record["eventID"])
        if not isinstance(record.get("userIdentity"), dict):
            raise ValueError(f"CloudTrail record {ordinal} has no identity")
        for key in ("requestParameters", "responseElements"):
            if record.get(key) is not None and not isinstance(record[key], dict):
                raise ValueError(f"CloudTrail record {ordinal} has invalid {key}")
    return source, records


def normalize_record(record: dict[str, Any], ordinal: int, source_sha256: str) -> dict[str, Any]:
    identity = record["userIdentity"]
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    request = record.get("requestParameters") or {}
    response = record.get("responseElements") or {}
    assumed = response.get("assumedRoleUser") or {}
    arn = identity.get("arn")
    policy = request.get("policyDocument")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            policy = json.loads(unquote(policy))
    return {
        "event_id": record["eventID"],
        "event_time": record["eventTime"],
        "event_source": record["eventSource"],
        "event_name": record["eventName"],
        "aws_region": record.get("awsRegion"),
        "source_ip": record.get("sourceIPAddress"),
        "identity_type": identity.get("type"),
        "identity_arn": arn,
        "principal_id": identity.get("principalId"),
        "session_name": arn.rsplit("/", 1)[-1] if isinstance(arn, str) else None,
        "session_issuer_arn": issuer.get("arn"),
        "assumed_role_arn": assumed.get("arn"),
        "assumed_role_id": assumed.get("assumedRoleId"),
        "role_arn": request.get("roleArn"),
        "role_name": request.get("roleName"),
        "role_session_name": request.get("roleSessionName"),
        "policy_document": canonical_json(policy) if policy is not None else None,
        "group_id": request.get("groupId"),
        "ip_permissions": canonical_json(request["ipPermissions"]) if "ipPermissions" in request else None,
        "ssm_target": request.get("target"),
        "ssm_session_id": response.get("sessionId"),
        "bucket_name": request.get("bucketName"),
        "object_key": request.get("key"),
        "object_prefix": request.get("prefix"),
        "version_id": request.get("versionId"),
        "request_parameters": canonical_json(record.get("requestParameters")),
        "response_elements": canonical_json(record.get("responseElements")),
        "raw_event": canonical_json(record),
        "source_sha256": source_sha256,
        "source_ordinal": ordinal,
        "normalization_version": NORMALIZATION_VERSION,
    }


def prepare_objects(path: Path | None = None) -> dict[str, bytes]:
    source, records = validate_corpus(path)
    source_sha = hashlib.sha256(source).hexdigest()
    rows = [normalize_record(record, ordinal, source_sha) for ordinal, record in enumerate(records, start=1)]
    jsonl = "".join(canonical_json(row) + "\n" for row in rows).encode()
    stream = io.BytesIO()
    # Explicit filename and mtime make bytes independent of path and clock.
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0, compresslevel=9) as target:
        target.write(jsonl)
    events = stream.getvalue()
    manifest = {
        "gym_id": "004",
        "normalization_version": NORMALIZATION_VERSION,
        "record_count": len(rows),
        "source": {"key": SOURCE_KEY, "sha256": source_sha, "bytes": len(source)},
        "events": {"key": EVENTS_KEY, "sha256": hashlib.sha256(events).hexdigest(), "bytes": len(events)},
        "citation": "event_id + source_sha256 + source_ordinal (1-based Records array index)",
    }
    return {SOURCE_KEY: source, EVENTS_KEY: events, MANIFEST_KEY: (canonical_json(manifest) + "\n").encode()}


def client_from_env():
    # Dependencies come from the existing, pinned Tracecat image.
    from minio import Minio

    return Minio(
        os.environ.get("GROUNDLINK_ENDPOINT", "minio:9000"),
        access_key=os.environ["MINIO_ROOT_USER"],
        secret_key=os.environ["MINIO_ROOT_PASSWORD"],
        secure=False,
    )


def read_object(client, bucket: str, key: str) -> bytes | None:
    from minio.error import S3Error

    try:
        response = client.get_object(bucket, key)
    except S3Error as exc:
        if exc.code in ("NoSuchKey", "NoSuchObject"):
            return None
        raise
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def ensure_read_policy(client, bucket: str, keys: list[str]) -> None:
    from minio.error import S3Error

    try:
        policy = json.loads(client.get_bucket_policy(bucket))
    except S3Error as exc:
        if exc.code != "NoSuchBucketPolicy":
            raise
        policy = {"Version": "2012-10-17", "Statement": []}
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    statement = {
        "Sid": POLICY_SID,
        "Effect": "Allow",
        "Principal": {"AWS": ["*"]},
        "Action": ["s3:GetObject"],
        "Resource": [f"arn:aws:s3:::{bucket}/{key}" for key in sorted(keys)],
    }
    desired = {**policy, "Statement": [s for s in statements if s.get("Sid") != POLICY_SID] + [statement]}
    if desired != policy:
        client.set_bucket_policy(bucket, canonical_json(desired))


def verify_objects(client, bucket: str, objects: dict[str, bytes]) -> None:
    for key, expected in objects.items():
        observed = read_object(client, bucket, key)
        if observed != expected:
            raise ValueError(f"seeded GroundLink object mismatch: {key}")


def seed(client=None) -> dict[str, Any]:
    # Complete validation and normalization before touching MinIO.
    objects = prepare_objects()
    client = client_from_env() if client is None else client
    bucket = os.environ.get("GROUNDLINK_BUCKET", "groundlink")
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    uploaded = 0
    for key, data in objects.items():
        if read_object(client, bucket, key) == data:
            continue
        content_type = "application/gzip" if key.endswith(".gz") else "application/json"
        client.put_object(
            bucket, key, io.BytesIO(data), len(data), content_type=content_type,
            metadata={"sha256": hashlib.sha256(data).hexdigest()},
        )
        uploaded += 1
    ensure_read_policy(client, bucket, list(objects))
    verify_objects(client, bucket, objects)
    result = {
        "bucket": bucket, "objects": len(objects),
        "records": json.loads(objects[MANIFEST_KEY])["record_count"],
        "uploaded": uploaded, "unchanged": len(objects) - uploaded,
    }
    print(f"[dataset-seed] READY: {canonical_json(result)}", flush=True)
    return result


def main() -> int:
    seed()
    return 0


def audit() -> int:
    """Read back all owned objects without uploading or changing policies."""
    objects = prepare_objects()
    verify_objects(client_from_env(), os.environ.get("GROUNDLINK_BUCKET", "groundlink"), objects)
    print("[dataset-audit] Original corpus, normalized records and manifest match their expected bytes.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="write deterministic evidence locally without Docker")
    args = parser.parse_args()
    if args.prepare:
        objects = prepare_objects()
        output = config.ROOT / "artifacts/evidence"
        for key, data in objects.items():
            path = output / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print(f"[dataset-prepare] Wrote {len(objects)} objects under {output}")
    else:
        main()
