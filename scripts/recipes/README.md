# Crowd build recipes

A recipe is `scripts/recipes/<name>.sh`, invoked with `bash` and two positional
arguments: `SRC`, the freshly fetched source directory, and `OUT`, an empty
output directory. Both paths are absolute. Write only distributable build
outputs to `OUT`; the workflow packs regular files into a deterministic zip.
Recipes run on GitHub-hosted Linux only. They must not need game files or data,
and must not download anything except what the recipe documents here. Recipes
have no secrets, environment approvals or attestation privileges.

Add a script with a name matching `^[a-z0-9][a-z0-9-]{0,40}$` and a manifest in
`manifests/*.json` with exactly `recipe`, `repo` (a public GitHub HTTPS URL), and
`sha` (a full lowercase commit SHA). Pin and review any documented downloads.
Run `python3 -I scripts/crowd_manifest.py manifests/<name>.json` and the offline
tests before requesting review. Only trusted workflow refs should be dispatched.

## selftest

Compiles `tests/fixtures/selftest/hello.c` from this public repository using
`cc`. No additional downloads and no game data. Replace the manifest's all-zero
SHA with the merged commit containing the fixture before dispatching it.

## melee-unlocked-linux — NOT YET

Waits for melee-native's source-only Linux path. Today `tools/build_linux.py`
reads the player's `main.dol`, which can never run here. No recipe or manifest
for this build may be added until it builds without player game files.
