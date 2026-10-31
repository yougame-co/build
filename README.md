# yougame-co/build

Public build workflows for YouGame test builds. Public repos run GitHub's standard runners for free, so builds of
public sources happen here instead of on our own machines.

## What may live here

- Workflows, build scripts, and a manifest of upstream repositories pinned by commit. Sources are fetched at build time.
- Nothing else. No game code or assets.

## What must never be here or on these runners

- ROMs, disc images, DOL/ELF/ISO/RVZ/GCM files, BIOS files, console or title keys, or anything extracted from them.
- A project that needs the player's own copy of a game to *build* builds on the player's machine, not here.
- Secrets of any kind. Workflows here take no secrets.
- Compiled objects in `actions/cache`. Pull requests from forks can restore the base branch's caches.

## Artifacts are always encrypted

Any signed-in GitHub user can download a public repository's Actions artifacts during their retention period. So every
workflow here encrypts its output to the public key in `keys/` (age) before uploading it. Only YouGame's promoter
holds the private key. Job logs and SHA-256 sums can stay plain. The key is placed by YouGame security; until it is,
workflows here must not upload build outputs.

## Takedowns

A notice against an entry takes that entry down within 24 hours.

## Rules for workflows

- Triggers: `workflow_dispatch`, `workflow_call`, and scheduled maintenance (`schedule`), never `pull_request_target`.
- `permissions:` least privilege (`contents: read` unless a job needs more).
- Only GitHub-owned actions (`actions/*`), pinned to full commit SHAs. `timeout-minutes` on every job.
- Builds attest their outputs (GitHub artifact attestation) so YouGame can check an upload came from a run here.

## Agent test boxes

See [docs/test-boxes.md](docs/test-boxes.md) for Azure VM lifecycle workflows, access, cleanup and costs.
