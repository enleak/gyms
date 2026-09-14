# Gym 004 — GroundLink cloud intrusion

Implementation status: **incident case**. Gym 004 loads checksum-locked
CloudTrail evidence into MinIO and creates one native Tracecat incident case
from a locally derived suspicious trust-policy alert. Analyst presets and
automated investigation workflows are subsequent stages.

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

Allow 8 GiB of RAM for the Docker VM when running the full shared platform.
The 4 GiB VM used for initial evidence checks showed API restarts during
full-platform bootstrap.

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
just prepare-case
just check
just doctor
just up
just wait
just info
```

Open Tracecat at <http://127.0.0.1:48080>. `just info` displays generated local
login credentials. Startup creates local users, seeds the original corpus,
query projection, and manifest, and creates the GroundLink case in the tenant
workspace. Open **Cases** to investigate it manually. No model credentials are
required for case setup; model configuration will be needed for automation.

`just check` validates repository integrity and the corpus and, when Docker is
available, checks the merged Compose configuration and an already-running
platform. If MinIO is running, a temporary audit container reads back the
three evidence objects without uploading or changing policies. It also verifies
the case's evidence references when the full platform is running. The check
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

Reconcile evidence and the incident case on an already-running Tracecat
platform with `just reconcile`. The
normalization is byte-reproducible and does not rewrite the source file.

Evidence loading was verified against live MinIO with the pinned control image:
`just build`, `just doctor`, `just reconcile`, and `just check` passed. The
actual `core.duckdb.execute_sql` action read all 211 unique events over the
Docker network, including three valid trust-policy documents, three SSM
sessions, and eight version-specific object reads. Repeated seeding skipped
all three unchanged objects, and the read-only audit verified their exact bytes.

## Incident case

`just prepare-case` derives the case payload locally and writes the ignored
`artifacts/alert-case.json` for review. The rule selects the earliest successful
`UpdateAssumeRolePolicy` for a `groundlink-` role whose submitted policy
explicitly allows `sts:AssumeRole` to the calling IAM role without conditions. This is
an investigation lead, not proof of unauthorized access or a comparison with
the previous policy. Other trust-policy updates remain in the corpus for
comparison; the rule does not select the account-root trust look-alikes.

`just up` and `just reconcile` create one case with a stable rule/event-based
alert ID, the observed caller and target role, native event citation, and the
three evidence URLs. The full corpus remains available for investigation.
Existing case descriptions, status, comments, and analyst work are preserved;
reconciliation neither patches nor deletes an existing case. It checks every
case-list page and reports duplicate managed cases or changed evidence references
for review. Run reconciliation serially; concurrent first-time creation is not
an atomic upsert. Analyst presets and intake/investigation workflows are not
installed or invoked at this stage.

`just test` runs authored alert/case contract tests without Docker or the
operator-supplied corpus. They verify setup behavior rather than analyst answers.

Live verification confirmed case creation, exact source citations, and retention
of the same case, edited description/status, and a comment across repeated
setup. The selected lead also has a subsequent matching role assumption in
the corpus. Platform startup, readiness, and read-only case/evidence audits passed.

## Next implementation stages

1. Publish the analyst preset and intake/investigation workflows.
2. Verify the complete investigation, case findings, duplicate intake, reconciliation, restart, and scenario reset.

See [assets/README.md](assets/README.md) and [PROVENANCE.md](PROVENANCE.md)
for the evidence source and reuse boundary.
