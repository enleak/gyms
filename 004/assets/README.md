# GroundLink evidence input

Evidence is operator-supplied. Obtain the native CloudTrail `.json.gz` corpus
from the official Blue Team Village GroundLink challenge package:

`ghcr.io/blueteamvillage/challenge-024`

Copy only its CloudTrail corpus to `assets/groundlink.json.gz`, or configure
`GROUNDLINK_CORPUS` in `.env`. The original filename and verified SHA-256 are
recorded in `../gym.lock.json`.

The original dataset is not committed or included in the control image.
Redistribution terms have not been established. Questions, flags, upstream
workbench files, and logos are not inputs to this gym.

`just prepare-evidence` validates and generates the three storage objects under
the ignored `artifacts/evidence/` directory without Docker. `just up` validates
the source and seeds those same objects into MinIO. `just reconcile` rechecks
and repairs the objects on an already-running Tracecat platform, then ensures
the derived incident case exists. `just prepare-case` writes the ignored local
case payload for review without contacting Tracecat.

MinIO stores the unchanged original corpus, normalized gzip JSONL, and a
manifest of their checksums under its `gym-004/` prefix. The native event ID,
source SHA-256, and 1-based position in the original `Records` array provide
citations. Complete original events, request parameters, and response elements
remain available in JSON string columns in the normalized records.
