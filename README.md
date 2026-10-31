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

## Crowd builds

`crowd-build.yml` accepts a repository manifest through `workflow_dispatch` only.
Its build job has only `contents: read`: it validates the
manifest, fetches the pinned public source, runs the recipe, and encrypts the zip
with age to `keys/artifacts.age.pub` from this repository at the workflow commit.
It uploads only `build.zip.age` for the attest job (one-day retention). A separate
attest job runs no source or recipe code and never decrypts: it derives the manifest
from its own checkout at the workflow commit, cross-checks its digest against the
build job's digest, and attests both the ciphertext and manifest in one GitHub build
provenance statement. Its final artifact contains only
`build.zip.age`, `build.zip.age.sha256` and the validated `manifest.json`
(seven-day retention). Every uploaded build output is encrypted.

To add a recipe, follow [scripts/recipes/README.md](scripts/recipes/README.md),
add a manifest pinned to a full source commit and run the offline tests with
`python3 -I -m unittest discover -s tests -p 'test_*.py'`. The self-test's all-zero source SHA
must be replaced with the merged fixture commit before dispatch. On the promoter
Mac, use the run ID and attempt from which you downloaded
`crowd-encrypted-<run-id>-<run-attempt>`. Obtain that attempt's conclusion with:

```sh
gh run view <run-id> --repo yougame-co/build --attempt <run-attempt> --json conclusion --jq .conclusion
```

Then run:

```sh
python3 -I scripts/promoter_verify.py <artifact-folder> <expected-manifest> <age-private-key-path> \
  --run-id <run-id> --run-attempt <run-attempt> --run-conclusion <conclusion>
```

The verifier refuses any conclusion except `success`. It checks the ciphertext
checksum and verifies provenance from this workflow on `main` using `gh`. It parses
the verified statement and requires the SHA-256 digests of both downloaded files
in that same statement, with a SLSA invocation ID exactly matching
`https://github.com/yougame-co/build/actions/runs/<run-id>/attempts/<run-attempt>`.
It then checks the canonical manifest against the expected manifest and its digest
before decrypting into a new empty temporary directory. A binding or run mismatch
fails at `attestation`; an expected-manifest mismatch fails at `manifest`. Neither
decrypts. Only success prints `VERIFIED`
with the plaintext zip path and its SHA-256; failures remove the temporary directory;
delete that temporary directory when finished. It never extracts or publishes files.

## Rules for workflows

- Triggers: `workflow_dispatch` and scheduled maintenance (`schedule`), never `pull_request_target`.
- `permissions:` least privilege (`contents: read` unless a job needs more).
- Only GitHub-owned actions (`actions/*`), pinned to full commit SHAs. `timeout-minutes` on every job.
- Builds attest their outputs (GitHub artifact attestation) so YouGame can check an upload came from a run here.

## Agent test boxes

See [docs/test-boxes.md](docs/test-boxes.md) for Azure VM lifecycle workflows, access, cleanup and costs.
