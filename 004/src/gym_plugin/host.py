"""Standard-library host lifecycle for Gym 004's shared Tracecat services."""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import socket

from gymctl import lifecycle

from . import config


HEALTH_SERVICES = ("api", "litellm", "postgres_db", "temporal", "minio", "redis")


def log(message: str) -> None:
    print(f"[gym-004] {message}", flush=True)


def init() -> None:
    target = config.ROOT / ".env"
    if target.exists():
        target.chmod(0o600)
        log("Existing .env retained; credentials were not rotated.")
        return
    replacements = {
        "TRACECAT__DB_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        **{key: secrets.token_hex(32) for key in (
            "TRACECAT__SERVICE_KEY", "TRACECAT__SIGNING_SECRET", "USER_AUTH_SECRET",
            "TRACECAT__POSTGRES_PASSWORD", "TEMPORAL__POSTGRES_PASSWORD", "MINIO_ROOT_PASSWORD",
        )},
        "TRACEcat_TENANT_PASSWORD": secrets.token_urlsafe(24),
        "TRACEcat_SUPERADMIN_PASSWORD": secrets.token_urlsafe(24),
    }
    lifecycle.write_env(config.DEFINITION, replacements)
    log("Created .env with random credentials and mode 0600.")


def doctor() -> None:
    from .dataset import validate_corpus

    validate_corpus()
    missing = [name for name in ("docker",) if shutil.which(name) is None]
    if missing:
        raise lifecycle.LifecycleError(f"required commands are missing: {', '.join(missing)}")
    lifecycle.run(config.ROOT, ["docker", "info"], capture=True)
    lifecycle.run(config.ROOT, ["docker", "buildx", "version"], capture=True)
    # Compose !override requires 2.24.4 or newer; config validates support.
    config.run_compose("config", "--quiet")
    rows = lifecycle.run(
        config.ROOT,
        ["docker", "ps", "--filter", f"publish={config.DEFINITION.host_port}", "--format", "{{.ID}}"],
        capture=True,
    ).stdout.split()
    for container in rows:
        owner = lifecycle.run(
            config.ROOT,
            ["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project"}}', container],
            capture=True,
        ).stdout.strip()
        if owner != config.PROJECT:
            raise lifecycle.LifecycleError(f"port 48080 belongs to Docker project {owner or 'unknown'}")
    if not rows:
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", config.DEFINITION.host_port)) == 0:
                raise lifecycle.LifecycleError("host port 48080 is occupied")
    log("Evidence, Docker and Compose checks passed.")


def build(*, force: bool = False) -> None:
    digest = config.image_input_hash()
    platform = config.load_platform_lock()
    revision = lifecycle.run(config.ROOT, ["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    lifecycle.build_image(
        config.DEFINITION,
        image=config.local_image(),
        dockerfile=config.ROOT / "images/control/Dockerfile",
        context=config.ROOT,
        input_digest=digest,
        build_contexts={"gymctl": config.REPO_ROOT / "src/gymctl"},
        build_args={
            "TRACECAT_IMAGE": config.upstream_image("tracecat"),
            "TRACECAT_VERSION": platform["tracecat"]["tag"],
            "GYM_COMPONENT_VERSION": config.load_lock()["gym"]["component_version"],
            "GYM_INPUT_SHA": digest,
            "GYM_REVISION": revision,
        },
        force=force,
    )


def up() -> None:
    init()
    doctor()
    build()
    config.run_compose("up", "--detach")
    lifecycle.run_bootstrap(config.DEFINITION, config.run_compose, "dataset-seed", timeout=600)
    lifecycle.run_bootstrap(config.DEFINITION, config.run_compose, "tracecat-seed", timeout=600)
    bootstrap_case()
    log("Platform, evidence and incident case initialized. Automated investigation is a subsequent stage.")
    info()


def reconcile() -> None:
    """Re-seed evidence and ensure one incident case, preserving existing work."""
    from .dataset import validate_corpus

    validate_corpus()
    build()
    lifecycle.wait_runtime_health(
        config.DEFINITION, config.run_compose, ("api", "minio"), timeout=600,
        on_change=lambda states: log(f"waiting for case setup services: {states}"),
    )
    lifecycle.run_bootstrap(config.DEFINITION, config.run_compose, "dataset-seed", timeout=600)
    lifecycle.run_bootstrap(config.DEFINITION, config.run_compose, "tracecat-seed", timeout=600)
    bootstrap_case()
    log("Evidence and incident case reconciled; existing investigation work retained.")


def bootstrap_case() -> None:
    # Bootstrap containers use --no-deps; explicitly wait for the API before
    # making case requests, including after a VM/platform restart.
    lifecycle.wait_runtime_health(
        config.DEFINITION, config.run_compose, ("api", "minio"), timeout=600,
        on_change=lambda states: log(f"waiting for incident case services: {states}"),
    )
    lifecycle.run_bootstrap(config.DEFINITION, config.run_compose, "gym-reconciler", timeout=600)


def wait() -> None:
    if not lifecycle.container_id(config.run_compose, "tracecat-seed"):
        raise lifecycle.LifecycleError("platform bootstrap has not run; run just up")
    lifecycle.wait_exit(config.DEFINITION, config.run_compose, "tracecat-seed", timeout=600)
    lifecycle.wait_exit(config.DEFINITION, config.run_compose, "dataset-seed", timeout=600)
    lifecycle.wait_exit(config.DEFINITION, config.run_compose, "gym-reconciler", timeout=600)
    lifecycle.wait_runtime_health(
        config.DEFINITION, config.run_compose, HEALTH_SERVICES, timeout=600,
        on_change=lambda states: log(f"waiting for platform health: {states}"),
    )
    status()
    log("Platform, evidence and incident case are ready; automated investigation is not implemented yet.")


def info() -> None:
    env = config.parse_env()
    if not env:
        raise lifecycle.LifecycleError(".env is missing; run just init")
    print(f"Tracecat UI: http://127.0.0.1:{config.DEFINITION.host_port}")
    print(f"  Tenant: {env['TRACEcat_TENANT_EMAIL']} / {env['TRACEcat_TENANT_PASSWORD']}")
    print(f"  Superadmin: {env['TRACEcat_SUPERADMIN_EMAIL']} / {env['TRACEcat_SUPERADMIN_PASSWORD']}")


def status() -> None:
    config.run_compose("--profile", "bootstrap", "ps", "--all")
    if not lifecycle.container_id(config.run_compose, "api"):
        raise lifecycle.LifecycleError("Gym 004 is not running")
    from gymctl.http import Client
    from . import reconcile as state

    env = config.parse_env()
    with Client(base_url=env["PUBLIC_API_URL"], timeout=120) as client:
        state.status(client, env["TRACEcat_TENANT_EMAIL"], env["TRACEcat_TENANT_PASSWORD"])
    log("Implementation stage: incident case; analyst preset and workflows are not implemented yet.")


def logs(service: str | None) -> None:
    args = ["--profile", "bootstrap", "logs", "--follow", "--tail", "200"]
    config.run_compose(*args, *([service] if service else []))


def down() -> None:
    config.run_compose("--profile", "bootstrap", "down", "--remove-orphans")
    log("Stopped; volumes and credentials retained.")


def reset(confirm: str | None) -> None:
    if confirm != "artifacts-captured":
        raise lifecycle.LifecycleError("reset deletes Gym 004 volumes; use just reset CONFIRM=artifacts-captured")
    config.run_compose("--profile", "bootstrap", "down", "--volumes", "--remove-orphans")
    log("Removed Gym 004 service volumes; operator-supplied evidence and host artifacts retained.")
