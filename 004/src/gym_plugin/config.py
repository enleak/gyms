"""Gym 004 identity and deterministic control-image metadata."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from gymctl import compose
from gymctl.definition import GymDefinition


ROOT = Path(os.environ.get("GYM_ROOT", Path(__file__).resolve().parents[2])).resolve()
REPO_ROOT = ROOT.parent
DEFINITION = GymDefinition(
    gym_id="004",
    root=ROOT,
    compose_project="tracecat-gym-004",
    volume_suffixes=(
        "core-db", "temporal-db", "minio-data", "redis-data", "sandbox-cache",
    ),
    host_port=48080,
    prefer_gym_upstream_images=True,
)
PROJECT = DEFINITION.compose_project


def load_lock() -> dict:
    return DEFINITION.load_lock()


def load_platform_lock() -> dict:
    return DEFINITION.load_platform_lock()


def parse_env(path: Path | None = None) -> dict[str, str]:
    return compose.parse_env(DEFINITION, path)


def upstream_image(name: str) -> str:
    return compose.upstream_image(DEFINITION, name)


def image_input_hash(component: str = "control") -> str:
    if component != "control":
        raise ValueError(f"unknown image component: {component}")
    paths = list((ROOT / "src").rglob("*.py"))
    paths += [p for p in (ROOT / "benchmark").rglob("*") if p.is_file()]
    paths += list((REPO_ROOT / "src/gymctl").rglob("*.py"))
    paths += [ROOT / "images/control/Dockerfile", REPO_ROOT / "platform.lock.json"]
    digest = hashlib.sha256()
    for path in sorted(p for p in paths if "__pycache__" not in p.parts):
        digest.update(path.relative_to(REPO_ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    lock = load_lock()
    local = lock["images"]["local"]["control"]
    normalized = {
        **lock,
        "images": {
            **lock["images"],
            "local": {"control": {k: v for k, v in local.items() if k != "input_sha256"}},
        },
    }
    digest.update(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode())
    return digest.hexdigest()


def local_image(component: str = "control") -> str:
    return f"{load_lock()['images']['local']['control']['repository']}:{image_input_hash(component)[:16]}"


def compose_environment() -> dict[str, str]:
    from .dataset import corpus_path

    environment = compose.compose_environment(DEFINITION, {"GYM_CONTROL_IMAGE": local_image()})
    environment["GROUNDLINK_CORPUS"] = str(corpus_path().resolve())
    return environment


def compose_args(*args: str) -> list[str]:
    return compose.compose_args(DEFINITION, *args)


def run_compose(*args: str, check: bool = True, capture: bool = False):
    import subprocess

    return subprocess.run(
        compose_args(*args), cwd=ROOT, env=compose_environment(),
        check=check, text=True, capture_output=capture,
    )
