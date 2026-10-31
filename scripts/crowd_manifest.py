#!/usr/bin/env python3
"""Validate a repository manifest before fetching or executing any source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RECIPE = re.compile(r'[a-z0-9][a-z0-9-]{0,40}', re.ASCII)
REPO = re.compile(r'https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+', re.ASCII)
SHA = re.compile(r'[0-9a-f]{40}', re.ASCII)


class ValidationError(ValueError):
    """A fixed diagnostic safe to include in workflow logs."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError('duplicate manifest key')
        result[key] = value
    return result


def canonical_manifest(raw, recipes=ROOT / 'scripts/recipes'):
    """Return validated canonical JSON bytes, without a trailing newline."""
    data = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or set(data) != {'recipe', 'repo', 'sha'}:
        raise ValidationError('manifest must have exactly recipe, repo and sha')
    for name, pattern in (('recipe', RECIPE), ('repo', REPO), ('sha', SHA)):
        if not isinstance(data[name], str) or not pattern.fullmatch(data[name]):
            raise ValidationError('invalid ' + name)
    recipe = recipes / (data['recipe'] + '.sh')
    if recipe.is_symlink() or not recipe.is_file():
        raise ValidationError('recipe does not exist as a regular script')
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def manifest_path(value):
    if not re.fullmatch(r'manifests/[A-Za-z0-9][A-Za-z0-9._-]*\.json', value):
        raise ValidationError('manifest path must be manifests/<name>.json')
    path = ROOT / value
    if path.is_symlink() or path.resolve().parent != ROOT / 'manifests':
        raise ValidationError('manifest must stay in manifests/')
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', help='manifests/<name>.json in this repository')
    args = parser.parse_args(argv)
    try:
        canonical = canonical_manifest(manifest_path(args.manifest).read_bytes())
        data = json.loads(canonical)
        digest = hashlib.sha256(canonical).hexdigest()
        outputs = {'manifest': canonical.decode('utf-8'), 'manifest_digest': digest, **data}
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
                for key, value in outputs.items():
                    output.write(f'{key}={value}\n')
        print(canonical.decode('utf-8'))
        print('manifest sha256: ' + digest)
        return 0
    except ValidationError as error:
        reason = str(error)
    except (json.JSONDecodeError, UnicodeError):
        reason = 'invalid JSON or UTF-8'
    except OSError:
        reason = 'cannot read manifest or write outputs'
    # Never echo supplied paths or raw JSON parser diagnostics into workflow logs.
    print('manifest validation failed: ' + reason, file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
