"""Bind the shared command surface to Gym 004's incident-case stage."""

from __future__ import annotations


def dispatch(args):
    if args.command == "internal-seed-dataset":
        from .dataset import main

        return main()
    if args.command == "internal-reconcile" and args.mode == "status":
        from .dataset import audit

        return audit()
    if args.command in ("internal-reconcile", "internal-test-api"):
        from .reconcile import main

        return main(read_only=args.command == "internal-test-api")
    if args.command == "seed":
        from gymctl.seed import main

        return main()
    if args.command == "check":
        from .validate import validate

        validate()
        return 0
    if args.command in ("check-upstreams", "update-upstreams"):
        from gymctl.update_upstreams import check_upstreams, update_upstreams

        (check_upstreams if args.command == "check-upstreams" else update_upstreams)()
        return 0

    from . import host

    if args.command == "build":
        if args.components and args.components != ["control"]:
            raise ValueError("Gym 004 builds only the control image")
        host.build(force=args.force)
    elif args.command == "logs":
        host.logs(args.service)
    elif args.command == "reset":
        host.reset(args.confirm)
    elif args.command == "clean-restart":
        host.reset(args.confirm)
        host.up()
    elif args.command == "restart":
        host.down()
        host.up()
    elif args.command in ("init", "doctor", "up", "wait", "info", "status", "down", "reconcile"):
        getattr(host, args.command)()
    else:
        raise ValueError(f"Gym 004 does not support {args.command} at the incident-case stage")
    return 0
