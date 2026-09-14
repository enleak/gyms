# Gym 004 — GroundLink cloud intrusion

Implementation status: **evidence loading**. Gym 004 defines the shared
Tracecat/MinIO platform and loads checksum-locked CloudTrail evidence into
MinIO. The incident case and analyst/workflow reconciliation are subsequent
stages. This is not yet a runnable GroundLink analyst investigation.

The planned investigation starts with suspicious IAM trust-policy activity and
follows identity and resource relationships through recorded AWS CloudTrail
evidence. The data path will be:

`GroundLink corpus → MinIO → DuckDB queries → Tracecat case findings`

Gym 002 is the architectural reference because it already uses MinIO and
DuckDB for recorded-evidence investigations. Gym 004 reuses the shared
`gymctl` runtime and pinned platform. It has no CTF questions, flags, grader,
evaluation runner, external enrichment requirement, or embedding/memory loop.

## Platform setup

Prerequisites: Python 3.11+, Docker with Buildx and Compose 2.24.4+, Git, and `just`.
On macOS, Docker Desktop must be running, or the Docker CLI must point to a
running Linux VM daemon such as Colima.

Gym 004 uses the official Quay MinIO mirror with the same image digest as the
shared platform, because Docker Hub refused that pinned pull during setup.

```sh
cd 004
just init
```

Place the operator-supplied corpus at `assets/groundlink.json.gz`, or set
`GROUNDLINK_CORPUS` in `.env`; see [assets/README.md](assets/README.md). Then:

```sh
just prepare-evidence
just check
just doctor
just up
just wait
just info
```

Open Tracecat at <http://127.0.0.1:48080>. `just info` displays generated local
login credentials. Startup creates local users and seeds the original corpus,
query projection, and manifest. There is no GroundLink case or analyst preset
yet. Model configuration will be required when that stage is added.

`just check` validates repository integrity and the corpus and, when Docker is
available, checks the merged Compose configuration and an already-running
platform. If MinIO is running, a temporary audit container reads back the
three evidence objects without uploading or changing policies. The check
does not start platform services, reset state, or trigger an investigation.
Without Docker, it explicitly reports skipped Compose/live checks. The same commands can be run
without `just` as `PYTHONPATH=../src:src python3 -m gymctl <command>`.

`just down` retains service volumes. Full deletion requires the existing
explicit command convention: `just reset CONFIRM=artifacts-captured`.
Host evidence, artifacts, and `.env` are retained.

## Evidence storage and queries

All evidence objects are in the configured `GROUNDLINK_BUCKET` (default
`groundlink`) under the Gym 004-owned prefix:

| Object key | Contents |
|---|---|
| `gym-004/source/groundlink.json.gz` | Unchanged original CloudTrail envelope |
| `gym-004/normalized/cloudtrail-v1.jsonl.gz` | 211 queryable rows with full original events and stable source references |
| `gym-004/manifest.json` | Normalization version, record count, object sizes and SHA-256 hashes |

Seeding compares actual bytes, skips unchanged objects, repairs changed owned
objects, and leaves unrelated objects and bucket-policy statements in place.
Anonymous reads are enabled for these exact three keys on the private Docker
network so DuckDB can access them. MinIO has no published host port.

Example query for the existing DuckDB action:

```sql
SELECT event_id, event_time, identity_arn, role_name, policy_document
FROM read_json_auto(
  'http://minio:9000/groundlink/gym-004/normalized/cloudtrail-v1.jsonl.gz',
  format='newline_delimited'
)
WHERE event_name = 'UpdateAssumeRolePolicy'
ORDER BY event_time;
```

Use the configured bucket if it differs from `groundlink`. Cite `event_id`
together with `source_sha256` and `source_ordinal`, which is the 1-based index
in the original `Records` array. `raw_event`, `request_parameters`, and
`response_elements` retain their complete original JSON as strings; query
them with DuckDB JSON functions when a field is not flattened.

Re-seed an already-running MinIO service with `just reconcile`. The
normalization is byte-reproducible and does not rewrite the source file.

Evidence loading was verified against live MinIO with the pinned control image:
`just build`, `just doctor`, `just reconcile`, and `just check` passed. The
actual `core.duckdb.execute_sql` action read all 211 unique events over the
Docker network, including three valid trust-policy documents, three SSM
sessions, and eight version-specific object reads. Repeated seeding skipped
all three unchanged objects, and the read-only audit verified their exact bytes.

## Next implementation stages

1. Create one case from a locally derived suspicious trust-policy-change alert.
2. Publish the analyst preset and intake/investigation workflows.
3. Verify the complete investigation, case findings, duplicate intake, reconciliation, restart, and scenario reset.

See [assets/README.md](assets/README.md) and [PROVENANCE.md](PROVENANCE.md)
for the evidence source and reuse boundary.
