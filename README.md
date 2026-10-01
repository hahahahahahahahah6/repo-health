# repo-health

The last thing you check before you hit publish. The stuff you always forget.

## The classics

- **"oops I committed .env"** — your API key is now in git history forever, and revoking it is the easy part; explaining it in the incident channel is not.
- **"oops, no license"** — you wrote a great README, got 200 stars, and your code legally belongs to no one.
- **"oops, it's 400MB"** — three people committed their datasets to `data/` and `git clone` now takes longer than onboarding.
- **"oops, vendor lock-in"** — a three-file "zero-dependency" utility that quietly `import requests`, `import click`, and `import dotenv`.

`repo-health` is the 60-second gate that catches these before your repo goes public, not after.

## Install

```bash
git clone https://github.com/hahahahahahahahah6/repo-health
cd repo-health
python3 repo_health.py
```

(Not on PyPI — the `repo-health` name there belongs to an unrelated project.
Run it straight from source — it's a single file with no dependencies:)

```bash
python3 repo_health.py
```

## Usage

```bash
python3 repo_health.py [path]       # defaults to current directory
python3 repo_health.py . --json     # machine-readable report
```

### Example

```
$ python3 repo_health.py .
repo-health 0.1.0 — /home/hao/projects/agent-guard

[✓ PASS] license       LICENSE
[✓ PASS] readme        README.md
[! WARN] gitignore     no .gitignore found
[✗ FAIL] secrets       1 suspicious file(s): .env
[! WARN] fat-files     1 file(s) over 1MB: assets/demo.mp4 (12.4MB)
[✓ PASS] todos         7 TODO/FIXME/XXX/HACK markers
[! WARN] stdlib-only   third-party imports: requests

summary: 3 pass / 3 warn / 1 fail
```

Exit code `0` means no check failed; `1` means at least one FAIL (missing LICENSE, missing README, or a secret-like filename).

### The checks

| Check | Rule | Severity |
|---|---|---|
| `license` | `LICENSE` / `LICENCE` / `COPYING` exists | FAIL |
| `readme` | `README.*` exists | FAIL |
| `gitignore` | `.gitignore` exists | WARN |
| `secrets` | filenames matching `.env`, `*.pem`, `*.key`, `id_rsa*`, `*secret*` (names only — contents are never printed) | FAIL |
| `fat-files` | files over 1MB, top 5 listed (`.git` excluded) | WARN |
| `todos` | count of `TODO`/`FIXME`/`XXX`/`HACK` in text files (null-byte sniffed); >20 is a pile-up | WARN |
| `stdlib-only` | Python files importing anything outside `sys.stdlib_module_names` and local/relative modules | WARN |

## Differentiation

`repo-health` is **not a security scanner**. Tools like `gitleaks` and `trufflehog` do entropy analysis, history scanning, and 100+ secret detectors — use them if that's what you need.

This is a **60-second hygiene gate for the ship-it pipeline**: the last command you run before `git push` to a public repo, or the first command you run in CI on a new project. Seven checks, zero configuration, zero dependencies, instant answer.

The `stdlib-only` check is the differentiator for the zero-dependency discipline: if your project's whole pitch is "no dependencies," `repo-health` enforces it at the door. Any `import` that isn't in the standard library or local gets named, so a stray `import requests` in a "stdlib-only" project fails the gate before your README lies about it.

## License

MIT — see [LICENSE](LICENSE).
