import json
from pathlib import Path
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sec_review import __version__


def tracked_runtime_resources() -> set[str]:
    manifest = json.loads((ROOT / "config/resource-manifest.json").read_text())
    return {entry["path"] for entry in manifest["resources"]}


class DistributionTests(unittest.TestCase):
    def test_source_exclusions_apply_to_tracked_and_manifest_declared_candidates(self):
        import sec_review_build
        forbidden = ['.envrc', 'credentials-prod.json', 'reports/report.json', 'capture.raw.json',
                     'credentials.txt', 'examples/other/credentials.txt',
                     'examples/vulnerable/credentials.txt',
                     'examples/vulnerable/Credentials-test.txt',
                     'examples/credentials-backup/data.txt']
        allowed = ['examples/vulnerable/synthetic-token-fixture.txt', 'sec_review/app.py']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for relative in forbidden + allowed:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic fixture')
            manifest = root / sec_review_build.SOURCE_MANIFEST
            manifest.parent.mkdir()
            manifest.write_text(json.dumps({'schema_version': '1.0', 'files': forbidden + allowed}))
            for tracked in (forbidden + allowed, []):
                with self.subTest(tracked=bool(tracked)), mock.patch.object(sec_review_build, 'ROOT', root), \
                     mock.patch.object(sec_review_build, '_git_ls_files', return_value=tracked):
                    paths = sec_review_build._source_files()
                    self.assertEqual({path.relative_to(root).as_posix() for path in paths}, set(allowed))

    def test_source_manifest_and_sdist_never_include_credentials_named_paths(self):
        import sec_review_build

        declared = json.loads((ROOT / sec_review_build.SOURCE_MANIFEST).read_text())['files']
        self.assertFalse(any(
            part.casefold().startswith('credentials')
            for relative in declared for part in Path(relative).parts
        ))
        with tempfile.TemporaryDirectory() as directory:
            sdist = Path(directory) / sec_review_build.build_sdist(directory)
            with tarfile.open(sdist, 'r:gz') as archive:
                entries = archive.getnames()
        self.assertFalse(any(
            part.casefold().startswith('credentials')
            for entry in entries for part in Path(entry).parts
        ))

    def test_ci_archive_inspection_rejects_every_credentials_named_path(self):
        workflow = (ROOT / '.github/workflows/verify.yml').read_text()
        self.assertNotIn('allowed_credentials', workflow)
        self.assertIn(
            "if any(part.casefold().startswith('credentials') for part in parts):",
            workflow,
        )

    def test_doctor_help_separates_scanner_diagnostics_from_corporate_readiness(self):
        from sec_review.cli import parser
        help_text = ' '.join(parser().format_help().split())
        self.assertIn('scanner diagnostics', help_text)
        self.assertIn('does not establish corporate readiness', help_text)
        self.assertNotIn('Claude is optional', help_text)

    def project_metadata(self):
        return tomllib.loads((ROOT / "pyproject.toml").read_text())

    def test_release_version_is_2_4_1(self):
        self.assertEqual(__version__, "2.4.1")

    def test_pypi_metadata_has_current_install_instructions(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / sec_review_build.build_wheel(directory)
            with zipfile.ZipFile(wheel) as archive:
                metadata = archive.read("commitscope-2.4.1.dist-info/METADATA").decode()

        self.assertIn("Name: commitscope\n", metadata)
        self.assertIn("Version: 2.4.1\n", metadata)
        self.assertIn("pipx install commitscope==2.4.1", metadata)
        self.assertIn("pipx install commitscope\n", metadata)
        self.assertNotIn("No public `v2.4.0` tag", metadata)

    def test_project_metadata_and_console_entrypoint(self):
        metadata = self.project_metadata()

        self.assertEqual(metadata["build-system"]["requires"], [])
        self.assertEqual(metadata["build-system"]["build-backend"], "sec_review_build")
        self.assertEqual(metadata["build-system"]["backend-path"], ["."])
        self.assertEqual(metadata["project"]["name"], "commitscope")
        self.assertEqual(metadata["project"]["requires-python"], ">=3.11,<3.15")
        self.assertEqual(metadata["project"]["dependencies"], [])
        self.assertEqual(metadata["project"]["license"], "MIT")
        self.assertNotIn(
            "License :: OSI Approved :: MIT License",
            metadata["project"]["classifiers"],
        )
        self.assertEqual(metadata["project"]["scripts"]["commitscope"], "sec_review.cli:main")
        self.assertEqual(
            metadata["tool"]["commitscope-build"]["dynamic"]["version"]["attr"],
            "sec_review.__version__",
        )

    def test_every_tracked_runtime_resource_is_declared_as_wheel_data(self):
        metadata = self.project_metadata()
        data_files = metadata["tool"]["commitscope-build"]["data-files"]
        declared = {
            item
            for destination, values in data_files.items()
            if destination.startswith("share/commitscope/")
            for item in values
        }

        self.assertEqual(
            declared,
            tracked_runtime_resources() | {"config/resource-manifest.json"},
        )

    def test_wheel_data_destinations_preserve_relative_layout(self):
        metadata = self.project_metadata()
        data_files = {
            destination: set(resources)
            for destination, resources in metadata["tool"]["commitscope-build"]["data-files"].items()
        }
        expected_destinations = {
            "share/commitscope/config": {
                resource
                for resource in tracked_runtime_resources() | {"config/resource-manifest.json"}
                if resource.startswith("config/")
            },
            "share/commitscope/prompts": {
                resource for resource in tracked_runtime_resources() if resource.startswith("prompts/")
            },
            "share/commitscope/examples": {
                resource
                for resource in tracked_runtime_resources()
                if Path(resource).parent == Path("examples")
            },
            "share/commitscope/examples/fixed": {
                resource
                for resource in tracked_runtime_resources()
                if resource.startswith("examples/fixed/")
            },
            "share/commitscope/examples/vulnerable": {
                resource
                for resource in tracked_runtime_resources()
                if resource.startswith("examples/vulnerable/")
            },
            "share/commitscope/examples/ai-acceptance/idor/vulnerable": {
                "examples/ai-acceptance/idor/vulnerable/app.py"
            },
            "share/commitscope/examples/ai-acceptance/idor/fixed": {
                "examples/ai-acceptance/idor/fixed/app.py"
            },
            "share/commitscope/examples/ai-acceptance/eval/vulnerable": {
                "examples/ai-acceptance/eval/vulnerable/app.py"
            },
            "share/commitscope/examples/ai-acceptance/eval/fixed": {
                "examples/ai-acceptance/eval/fixed/app.py"
            },
            "share/commitscope/examples/ai-acceptance/shell/vulnerable": {
                "examples/ai-acceptance/shell/vulnerable/app.py"
            },
            "share/commitscope/examples/ai-acceptance/shell/fixed": {
                "examples/ai-acceptance/shell/fixed/app.py"
            },
            "share/commitscope/scripts": {"scripts/ai_acceptance.py"},
            "share/commitscope/tests": {
                "tests/test_ai_acceptance.py",
                "tests/test_demo_app.py",
            },
        }

        self.assertEqual(data_files, expected_destinations)

    def test_in_tree_build_backend_creates_wheel_and_sdist_without_external_build_package(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            wheel = dist / sec_review_build.build_wheel(str(dist))
            sdist = dist / sec_review_build.build_sdist(str(dist))

            self.assertEqual(wheel.name, "commitscope-2.4.1-py3-none-any.whl")
            self.assertEqual(sdist.name, "commitscope-2.4.1.tar.gz")
            self.assertTrue(wheel.is_file())
            self.assertTrue(sdist.is_file())

            with zipfile.ZipFile(wheel) as archive:
                wheel_entries = set(archive.namelist())
            self.assertIn("sec_review/cli.py", wheel_entries)
            self.assertIn(
                "commitscope-2.4.1.data/data/share/commitscope/config/tools.lock.json",
                wheel_entries,
            )
            self.assertIn("commitscope-2.4.1.dist-info/RECORD", wheel_entries)
            self.assertFalse(any("/.tools/" in entry or "/.runs/" in entry for entry in wheel_entries))

            with tarfile.open(sdist, "r:gz") as archive:
                sdist_entries = set(archive.getnames())
            self.assertIn("commitscope-2.4.1/pyproject.toml", sdist_entries)
            self.assertIn("commitscope-2.4.1/sec_review_build.py", sdist_entries)
            self.assertIn("commitscope-2.4.1/config/tools.lock.json", sdist_entries)
            for relative in (
                "examples/ai-acceptance/idor/vulnerable/app.py",
                "examples/ai-acceptance/idor/fixed/app.py",
                "examples/ai-acceptance/eval/vulnerable/app.py",
                "examples/ai-acceptance/eval/fixed/app.py",
                "examples/ai-acceptance/shell/vulnerable/app.py",
                "examples/ai-acceptance/shell/fixed/app.py",
                "scripts/ai_acceptance.py",
                "tests/test_ai_acceptance.py",
            ):
                self.assertIn("commitscope-2.4.1/" + relative, sdist_entries)
            blocked = (
                "/.git/",
                "/.idea/",
                "/.runs/",
                "/.tools/",
                "/.worktrees/",
                "/raw/",
            )
            self.assertFalse(any(any(part in entry for part in blocked) for entry in sdist_entries))
            self.assertFalse(any(entry.startswith("/") or "/../" in entry or entry.endswith(".raw.json") for entry in sdist_entries))

    def test_prepared_metadata_matches_wheel_dist_info_except_record(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata_root = root / "metadata"
            dist = root / "dist"
            dist_info = sec_review_build.prepare_metadata_for_build_wheel(str(metadata_root))
            wheel = dist / sec_review_build.build_wheel(str(dist), metadata_directory=str(metadata_root))

            prepared = {}
            for path in (metadata_root / dist_info).rglob("*"):
                if path.is_file():
                    prepared[path.relative_to(metadata_root / dist_info).as_posix()] = path.read_bytes()

            with zipfile.ZipFile(wheel) as archive:
                wheel_metadata = {
                    name.split("/", 1)[1]: archive.read(name)
                    for name in archive.namelist()
                    if name.startswith(dist_info + "/") and not name.endswith("/RECORD")
                }

            self.assertEqual(wheel_metadata, prepared)

    def test_build_backend_rejects_symlinked_source_files(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone = root / "clone"
            shutil.copytree(ROOT, clone, symlinks=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            secret = root / "outside-secret.txt"
            secret.write_text("must not be packaged")
            target = clone / "sec_review" / "symlink_secret.py"
            target.symlink_to(secret)

            script = (
                "from pathlib import Path; import sys; sys.path.insert(0, str(Path.cwd())); "
                "import sec_review_build; "
                "sec_review_build.build_wheel(str(Path('dist')))"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", script],
                cwd=clone,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing symbolic-link build input", result.stderr + result.stdout)

    def test_build_backend_rejects_symlinked_metadata_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone = root / "clone"
            shutil.copytree(ROOT, clone, symlinks=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            secret = root / "outside-readme.md"
            secret.write_text("must not be packaged as metadata")
            readme = clone / "README.md"
            readme.unlink()
            readme.symlink_to(secret)

            script = (
                "from pathlib import Path; import sys; sys.path.insert(0, str(Path.cwd())); "
                "import sec_review_build; "
                "sec_review_build.build_wheel(str(Path('dist')))"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", script],
                cwd=clone,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing symbolic-link build input", result.stderr + result.stdout)

    def test_build_backend_files_are_tracked_for_git_url_installs(self):
        for relative in ("sec_review_build.py", "scripts/build_dist.py"):
            result = subprocess.run(
                ["git", "ls-files", "--error-unmatch", relative],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_sdist_installs_in_clean_venv_without_index_or_build_dependencies(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "dist"
            sdist = dist / sec_review_build.build_sdist(str(dist))
            venv = root / "venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
            python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            commitscope = venv / ("Scripts/commitscope.exe" if os.name == "nt" else "bin/commitscope")
            env = os.environ.copy()
            env["PIP_NO_INDEX"] = "1"
            env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
            subprocess.run(
                [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(sdist)],
                cwd=root,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            cli = subprocess.run(
                [str(commitscope), "--version"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            module = subprocess.run(
                [str(python), "-m", "sec_review", "--version"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(cli.stdout.strip(), "2.4.1")
            self.assertEqual(module.stdout.strip(), "2.4.1")

    def test_sdist_no_git_fallback_uses_exact_manifest_and_rejects_allowlisted_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean"
            shutil.copytree(ROOT, clean, symlinks=True, ignore=shutil.ignore_patterns(".git", "__pycache__"))

            forbidden = (
                ".env", ".env.production", "credentials.json",
                "reports/raw/semgrep.json", ".runs/old/report.json",
                ".tools/bin/gitleaks", ".idea/workspace.xml", "scratch.tmp",
            )
            for relative in forbidden:
                path = clean / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("FORBIDDEN")

            script = (
                "from pathlib import Path; import json, sys, tarfile; sys.path.insert(0, str(Path.cwd())); "
                "import sec_review_build; "
                "path = Path('dist') / sec_review_build.build_sdist('dist'); "
                "entries = tarfile.open(path, 'r:gz').getnames(); "
                "prefix = 'commitscope-2.4.1/'; "
                "declared = json.loads(Path('config/sdist-manifest.json').read_text())['files']; "
                "assert all(entries.count(prefix + item) == 1 for item in declared); "
                "assert not any(prefix + item in entries for item in " + repr(forbidden) + ")"
            )
            complete = subprocess.run(
                [sys.executable, "-I", "-c", script],
                cwd=clean,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(complete.returncode, 0, complete.stderr + complete.stdout)

            secret = root / "outside-secret.txt"
            secret.write_text("must not be packaged")
            target = clean / "sec_review" / "cli.py"
            target.unlink()
            target.symlink_to(secret)
            rejected = subprocess.run(
                [sys.executable, "-I", "-c", script],
                cwd=clean,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Refusing symbolic-link build input", rejected.stderr + rejected.stdout)

    def test_sdist_manifest_rejects_del_character_in_existing_path(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            unsafe = "unsafe\x7fname"
            (root / unsafe).write_text("content")
            manifest = root / "config/sdist-manifest.json"
            manifest.parent.mkdir()
            manifest.write_text(json.dumps({"schema_version": "1.0", "files": [unsafe]}))

            with mock.patch.object(sec_review_build, "ROOT", root):
                with self.assertRaises(RuntimeError):
                    sec_review_build._manifest_source_files()

    def test_module_entrypoint_returns_cli_status(self):
        with mock.patch("sec_review.cli.main", return_value=7):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_module("sec_review", run_name="__main__")
        self.assertEqual(stopped.exception.code, 7)
