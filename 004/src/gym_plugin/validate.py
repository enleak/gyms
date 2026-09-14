"""Repository integrity and optional non-destructive Compose checks."""

from __future__ import annotations

import ast
import hashlib
import json
import shutil

from . import config
from .dataset import EVENTS_KEY, MANIFEST_KEY, NORMALIZATION_VERSION, SOURCE_KEY, prepare_objects
from .alert import ROLE_NAME_PREFIX, RULE_ID, source_case


def validate() -> None:
    lock = config.load_lock()
    if lock["schema_version"] != 2 or lock["gym"]["id"] != "004":
        raise ValueError("Gym 004 lock schema or identity mismatch")
    if lock["gym"]["compose_project"] != config.PROJECT:
        raise ValueError("Compose project identity mismatch")
    if lock["images"]["local"]["control"]["input_sha256"] != config.image_input_hash():
        raise ValueError("control image input hash drifted; refresh Gym 004 lock metadata")
    platform = config.load_platform_lock()
    for filename, key in (("docker-compose.yml", "compose_sha256"), ("Caddyfile", "caddyfile_sha256")):
        path = config.REPO_ROOT / "upstream/tracecat" / filename
        if hashlib.sha256(path.read_bytes()).hexdigest() != platform["tracecat"][key]:
            raise ValueError(f"shared Tracecat checksum mismatch: {filename}")
    for path in (config.ROOT / "src").rglob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
    scenario = json.loads((config.ROOT / "benchmark/scenario.json").read_text())
    if scenario["gym_id"] != "004" or scenario["implementation_stage"] != "incident-case":
        raise ValueError("scenario identity mismatch")
    objects = prepare_objects()
    if scenario["evidence"]["normalization_version"] != NORMALIZATION_VERSION:
        raise ValueError("scenario normalization version drifted")
    for field, key in (
        ("source_object_key", SOURCE_KEY), ("query_object_key", EVENTS_KEY),
        ("manifest_object_key", MANIFEST_KEY),
    ):
        if scenario["evidence"][field] != key:
            raise ValueError(f"scenario evidence key drifted: {field}")
    print(f"[gym-004] Evidence validated: {len(objects)} deterministic objects, 211 records.")
    desired = source_case()
    if scenario["case_entry_point"]["rule_id"] != RULE_ID or scenario["case_entry_point"]["case_count"] != 1:
        raise ValueError("scenario case entry point drifted")
    if scenario["case_entry_point"]["role_name_prefix"] != ROLE_NAME_PREFIX:
        raise ValueError("scenario monitored role prefix drifted")
    if desired["payload"]["source_sha256"] != json.loads(objects[MANIFEST_KEY])["source"]["sha256"]:
        raise ValueError("derived alert refers to a different corpus")
    print("[gym-004] Derived alert validated against the source corpus.")
    if (config.ROOT / "benchmark/evals").exists():
        raise ValueError("Gym 004 does not include evaluation or grading components")
    print("[gym-004] Repository integrity passed.")
    if shutil.which("docker") is None:
        print("[gym-004] Docker unavailable; Compose and live platform checks were not run.")
        return
    merged = config.run_compose("--profile", "bootstrap", "config", "--format", "json", capture=True)
    services = json.loads(merged.stdout)["services"]
    mount = services["dataset-seed"]["volumes"]
    if len(mount) != 1 or not mount[0].get("read_only") or mount[0].get("bind", {}).get("create_host_path") is not False:
        raise ValueError("corpus must have exactly one read-only bind mount with create_host_path disabled")
    if mount[0]["target"] != "/run/gym-data/groundlink.json.gz":
        raise ValueError("corpus container mount path drifted")
    if services["dataset-seed"]["environment"]["GROUNDLINK_CORPUS"] != mount[0]["target"]:
        raise ValueError("dataset seed process reads a different path from its mounted corpus")
    if services["dataset-seed"]["image"] != config.local_image():
        raise ValueError("dataset seed image is not the deterministic control image")
    if services["gym-reconciler"]["volumes"] != mount:
        raise ValueError("case reconciler must read the same immutable corpus as the dataset seed")
    if services["gym-reconciler"]["environment"]["GROUNDLINK_CORPUS"] != mount[0]["target"]:
        raise ValueError("case reconciler corpus path drifted")
    if services["minio"].get("ports"):
        raise ValueError("MinIO must remain on the private Docker network")
    probe = config.run_compose("ps", "--quiet", "api", check=False, capture=True)
    if probe.returncode != 0:
        print("[gym-004] Docker daemon unavailable; live platform checks were not run.")
        return
    if probe.stdout.strip():
        from .host import HEALTH_SERVICES
        from gymctl import lifecycle

        for service in HEALTH_SERVICES:
            container = lifecycle.container_id(config.run_compose, service)
            if not container:
                raise ValueError(f"running platform is missing {service}")
            state = lifecycle.run(
                config.ROOT,
                ["docker", "inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", container],
                capture=True,
            ).stdout.strip()
            if state != "running healthy":
                raise ValueError(f"{service} is not healthy: {state}")
        print("[gym-004] Live platform health checks passed.")
        config.run_compose(
            "--profile", "bootstrap", "run", "--rm", "--no-deps", "--pull", "never",
            "gym-reconciler", "internal-test-api",
        )
    minio = config.run_compose("ps", "--quiet", "minio", check=False, capture=True)
    if minio.stdout.strip():
        config.run_compose(
            "--profile", "bootstrap", "run", "--rm", "--no-deps", "--pull", "never",
            "dataset-seed", "internal-reconcile", "status",
        )
