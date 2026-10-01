"""Smoke tests for repo-health: each builds a fixture repo in a tmp dir."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

CLI = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "repo_health.py"))


def run_cli(path, *extra):
    return subprocess.run(
        [sys.executable, CLI, path, *extra],
        capture_output=True,
        text=True,
    )


def make_repo(files):
    """files: {relpath: content or bytes}. Returns the tmp dir path."""
    d = tempfile.mkdtemp()
    for rel, content in files.items():
        full = os.path.join(d, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(full, mode) as f:
            f.write(content)
    return d


HEALTHY = {
    "LICENSE": "MIT\n",
    "README.md": "# healthy\n",
    ".gitignore": "*.pyc\n",
    "main.py": "import os\nimport sys\nprint('hi')\n",
}


def make_git_repo(files, gitignore=""):
    """Like make_repo, but a real git repo with files committed."""
    d = make_repo(files)
    subprocess.run(["git", "init"], cwd=d, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"],
                   cwd=d, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"],
                   cwd=d, check=True, capture_output=True)
    if gitignore:
        with open(os.path.join(d, ".gitignore"), "w") as f:
            f.write(gitignore)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "init"],
                   cwd=d, check=True, capture_output=True)
    return d


GIT = shutil.which("git")
needs_git = unittest.skipIf(GIT is None, "git binary not available")


class TestRepoHealth(unittest.TestCase):
    def test_missing_license_and_readme_exit_1(self):
        d = make_repo({".gitignore": "*.pyc\n", "main.py": "x = 1\n"})
        r = run_cli(d)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAIL", r.stdout)
        self.assertIn("license", r.stdout)
        self.assertIn("readme", r.stdout)

    def test_healthy_repo_exit_0(self):
        d = make_repo(HEALTHY)
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("FAIL", r.stdout)

    def test_env_file_flagged_as_fail(self):
        d = make_repo(dict(HEALTHY, **{".env": "API_KEY=supersecret\n"}))
        r = run_cli(d)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAIL", r.stdout)
        # secret name flagged, contents never printed
        self.assertIn(".env", r.stdout)
        self.assertNotIn("supersecret", r.stdout)

    def test_pem_and_id_rsa_flagged(self):
        d = make_repo(dict(HEALTHY, **{"deploy.pem": b"\x00fake", "id_rsa": "keydata\n"}))
        r = run_cli(d)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("deploy.pem", r.stdout)
        self.assertIn("id_rsa", r.stdout)

    def test_fat_file_flagged_warn(self):
        d = make_repo(dict(HEALTHY, **{"data.bin": b"x" * (2 * 1024 * 1024)}))
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)  # warn only
        self.assertIn("WARN", r.stdout)
        self.assertIn("data.bin", r.stdout)

    def test_third_party_import_flagged(self):
        d = make_repo(
            dict(HEALTHY, **{"app.py": "import os\nimport requests\nfrom flask import Flask\n"})
        )
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("WARN", r.stdout)
        self.assertIn("requests", r.stdout)
        self.assertIn("flask", r.stdout)
        stdlib_line = next(l for l in r.stdout.splitlines() if "stdlib-only" in l)
        self.assertNotIn(", os", stdlib_line)
        self.assertNotIn("imports: os", stdlib_line)

    def test_local_import_not_flagged(self):
        d = make_repo(
            dict(HEALTHY, **{"app.py": "import os\nimport utils\n", "utils.py": "import json\n"})
        )
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("third-party imports", r.stdout)

    def test_todo_pileup_warn(self):
        d = make_repo(
            dict(HEALTHY, **{"a.py": "".join("# TODO fix this\n" for _ in range(25))})
        )
        r = run_cli(d)
        self.assertIn("WARN", r.stdout)
        self.assertIn("25", r.stdout)

    def test_missing_gitignore_warn(self):
        d = make_repo(
            {"LICENSE": "MIT\n", "README.md": "# x\n", "main.py": "import os\n"}
        )
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("WARN", r.stdout)
        self.assertIn("gitignore", r.stdout)

    def test_git_dir_skipped(self):
        d = make_repo(dict(HEALTHY, **{".git/objects/secret.env": "K=v\n", ".git/hooks/x.pem": b"\x00"}))
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("secret.env", r.stdout)

    def test_json_valid_and_structured(self):
        d = make_repo(HEALTHY)
        r = run_cli(d, "--json")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        payload = json.loads(r.stdout)
        self.assertIn("checks", payload)
        self.assertEqual(len(payload["checks"]), 7)
        statuses = {c["check"]: c["status"] for c in payload["checks"]}
        self.assertEqual(statuses["license"], "PASS")
        self.assertEqual(statuses["stdlib-only"], "PASS")

    def test_no_python_files_stdlib_skip(self):
        d = make_repo({"LICENSE": "MIT\n", "README.md": "# x\n", ".gitignore": "*.pyc\n"})
        r = run_cli(d)
        self.assertIn("SKIP", r.stdout)

    def test_default_path_is_cwd(self):
        d = make_repo(HEALTHY)
        r = subprocess.run(
            [sys.executable, CLI],
            capture_output=True,
            text=True,
            cwd=d,
        )
        self.assertEqual(r.returncode, 0, r.stdout)


@needs_git
class TestGitAware(unittest.TestCase):
    """File discovery via `git ls-files`: .gitignore must be respected."""

    def test_gitignored_env_not_flagged(self):
        d = make_git_repo(
            dict(HEALTHY, **{".env": "API_KEY=supersecret\n"}),
            gitignore=".env\n",
        )
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("FAIL", r.stdout)

    def test_tracked_env_still_flagged(self):
        # A .env that is actually committed is the real danger: still FAIL.
        d = make_git_repo(dict(HEALTHY, **{".env": "API_KEY=x\n"}))
        r = run_cli(d)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(".env", r.stdout)

    def test_secrets_py_not_flagged_by_name(self):
        d = make_git_repo(
            dict(HEALTHY, **{"secrets.py": "import secrets\ntoken = secrets.token_hex(8)\n"})
        )
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("secrets.py", r.stdout)

    def test_secret_named_non_source_still_flagged(self):
        d = make_git_repo(dict(HEALTHY, **{"client_secret.json": "{}\n"}))
        r = run_cli(d)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("client_secret.json", r.stdout)

    def test_venv_imports_not_counted(self):
        d = make_git_repo(
            dict(HEALTHY, **{".venv/lib/pkg.py": "import requests\n"}),
            gitignore=".venv/\n",
        )
        r = run_cli(d)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("third-party imports", r.stdout)

    def test_stdlib_names_available(self):
        sys.path.insert(0, os.path.dirname(CLI))
        import repo_health
        self.assertTrue(len(repo_health.STDLIB_MODULE_NAMES) > 50)
        for mod in ("os", "sys", "json", "re", "secrets"):
            self.assertIn(mod, repo_health.STDLIB_MODULE_NAMES)


if __name__ == "__main__":
    unittest.main()
