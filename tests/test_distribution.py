from pathlib import Path
import runpy
import subprocess
import sys
import tomllib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RESOURCE_ROOTS = ("config", "prompts", "examples")


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

    def test_project_metadata_and_console_entrypoint(self):
        metadata = self.project_metadata()

        self.assertEqual(metadata["build-system"]["requires"], ["setuptools==80.9.0"])
        self.assertEqual(metadata["build-system"]["build-backend"], "setuptools.build_meta")
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
            metadata["tool"]["setuptools"]["dynamic"]["version"]["attr"],
            "sec_review.__version__",
        )

    def test_every_tracked_runtime_resource_is_declared_as_wheel_data(self):
        metadata = self.project_metadata()
        data_files = metadata["tool"]["setuptools"]["data-files"]
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
            for destination, resources in metadata["tool"]["setuptools"]["data-files"].items()
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

    def test_module_entrypoint_returns_cli_status(self):
        with mock.patch("sec_review.cli.main", return_value=7):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_module("sec_review", run_name="__main__")
        self.assertEqual(stopped.exception.code, 7)
