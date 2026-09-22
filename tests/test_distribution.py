from pathlib import Path
import os
import runpy
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
RESOURCE_ROOTS = ("config", "prompts", "examples")

from sec_review import __version__


def tracked_runtime_resources() -> set[str]:
    listing = subprocess.run(
        ["git", "ls-files", *RESOURCE_ROOTS, "tests/test_demo_app.py"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return {
        line
        for line in listing.stdout.splitlines()
        if line.startswith(RESOURCE_ROOTS) or line == "tests/test_demo_app.py"
    }


class DistributionTests(unittest.TestCase):
    def project_metadata(self):
        return tomllib.loads((ROOT / "pyproject.toml").read_text())

    def test_release_version_is_2_3_0(self):
        self.assertEqual(__version__, "2.3.0")

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

        self.assertEqual(declared, tracked_runtime_resources())

    def test_wheel_data_destinations_preserve_relative_layout(self):
        metadata = self.project_metadata()
        data_files = {
            destination: set(resources)
            for destination, resources in metadata["tool"]["commitscope-build"]["data-files"].items()
        }
        expected_destinations = {
            "share/commitscope/config": {
                resource for resource in tracked_runtime_resources() if resource.startswith("config/")
            },
            "share/commitscope/prompts": {
                resource for resource in tracked_runtime_resources() if resource.startswith("prompts/")
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
            "share/commitscope/tests": {"tests/test_demo_app.py"},
        }

        self.assertEqual(data_files, expected_destinations)

    def test_in_tree_build_backend_creates_wheel_and_sdist_without_external_build_package(self):
        import sec_review_build

        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            wheel = dist / sec_review_build.build_wheel(str(dist))
            sdist = dist / sec_review_build.build_sdist(str(dist))

            self.assertEqual(wheel.name, "commitscope-2.3.0-py3-none-any.whl")
            self.assertEqual(sdist.name, "commitscope-2.3.0.tar.gz")
            self.assertTrue(wheel.is_file())
            self.assertTrue(sdist.is_file())

            with zipfile.ZipFile(wheel) as archive:
                wheel_entries = set(archive.namelist())
            self.assertIn("sec_review/cli.py", wheel_entries)
            self.assertIn(
                "commitscope-2.3.0.data/data/share/commitscope/config/tools.lock.json",
                wheel_entries,
            )
            self.assertIn("commitscope-2.3.0.dist-info/RECORD", wheel_entries)
            self.assertFalse(any("/.tools/" in entry or "/.runs/" in entry for entry in wheel_entries))

            with tarfile.open(sdist, "r:gz") as archive:
                sdist_entries = set(archive.getnames())
            self.assertIn("commitscope-2.3.0/pyproject.toml", sdist_entries)
            self.assertIn("commitscope-2.3.0/sec_review_build.py", sdist_entries)
            self.assertIn("commitscope-2.3.0/config/tools.lock.json", sdist_entries)
            self.assertFalse(any("/.tools/" in entry or "/.runs/" in entry for entry in sdist_entries))

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
            self.assertEqual(cli.stdout.strip(), "2.3.0")
            self.assertEqual(module.stdout.strip(), "2.3.0")

    def test_module_entrypoint_returns_cli_status(self):
        with mock.patch("sec_review.cli.main", return_value=7):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_module("sec_review", run_name="__main__")
        self.assertEqual(stopped.exception.code, 7)
