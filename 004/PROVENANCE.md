# Provenance

| Path | Classification | Notes |
|---|---|---|
| `../upstream/tracecat/` | `upstream-verbatim` | Shared Compose and Caddy snapshot pinned in `../platform.lock.json`. |
| `assets/groundlink.json.gz` | `user-supplied` | Original CloudTrail corpus from BTV GroundLink, contributed by DEF CON Cloud Village. SHA-256 locked; artifact not committed. Redistribution terms not established. |
| `artifacts/evidence/`, MinIO `gym-004/normalized/` | `generated-derived` | Deterministic query projection preserves complete events, adds uniform query fields and source references; generated data not committed. |
| MinIO `gym-004/source/` | `upstream-verbatim` | Exact operator-supplied source bytes, uploaded only after checksum validation. |
| `benchmark/scenario.json` | `gym-owned` | Investigation scope and implementation status; contains no CTF questions or answers. |
| `artifacts/alert-case.json`, Tracecat case | `generated-derived` | Locally authored detection selects one observed trust-policy event and links to the evidence. Generated payload not committed; not an upstream GuardDuty finding. |
| `src/gym_plugin/`, `images/`, `compose.override.yml`, `Justfile` | `gym-owned` | Gym 004 configuration and lifecycle; follows Gym 002's shared-platform integration patterns. |
| `../src/gymctl/`, `../compose/`, `../config/` | `gym-owned-shared` | Existing platform, bootstrap, and lifecycle helpers reused without modification. |
| `gym.lock.json` MinIO image | `official-registry-mirror` | Quay serves the exact SHA-256 already pinned by the shared platform. Gym 004 uses this official mirror because Docker Hub refused the pinned pull; shared platform pins remain unchanged. |

Scenario reference: [GroundLink Intrusion: Ten Techniques](https://ctf.blueteamvillage.org/challenges/groundlink-intrusion),
case `IR-GL10`, contributed by DEF CON Cloud Village to Blue Team Village.
Observed source image identity is recorded in `gym.lock.json` for provenance,
not as a runtime image dependency. Normalization version is `cloudtrail-query-v1`;
gzip output uses fixed filename/mtime metadata and canonical JSON serialization.
MinIO's [official Compose example](https://github.com/minio/minio/blob/master/docs/orchestration/docker-compose/docker-compose.yaml)
identifies `quay.io/minio/minio` as its image registry. The mirror changes
registry location, not the pinned image digest or release.

This gym uses captured evidence. It does not deploy AWS resources, execute
the attack, or perform real containment. Upstream challenge questions,
scoring, workbench, and branding assets are not redistributed.
