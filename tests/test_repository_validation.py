from __future__ import annotations

import importlib.util
import re
import subprocess
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
_VALIDATOR_PATH = ROOT / "scripts" / "validate-repository.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_repository", _VALIDATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LockInventoryTests(unittest.TestCase):
    expected: ClassVar[dict[str, str]] = {
        "pyyaml-6.0.3-cp311-cp311-macosx_11_0_arm64.whl": "652cb6edd41e718550aad172851962662ff2681490a8a711af6a4d288dd96824",  # noqa: E501
        "pyyaml-6.0.3-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": "b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d",  # noqa: E501
        "pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl": "fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0",  # noqa: E501
        "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",  # noqa: E501
        "pyyaml-6.0.3-cp313-cp313-macosx_11_0_arm64.whl": "2283a07e2c21a2aa78d9c4442724ec1eb15f5e42a723b99cb3d822d48f5f7ad1",  # noqa: E501
        "pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": "0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6",  # noqa: E501
        "pyyaml-6.0.3-cp314-cp314-macosx_11_0_arm64.whl": "34d5fcd24b8445fadc33f9cf348c1047101756fd760b4dacb5c3e99755703310",  # noqa: E501
        "pyyaml-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": "c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5",  # noqa: E501
        "pyyaml-6.0.3.tar.gz": "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f",  # noqa: E501
        "ruff-0.16.3-py3-none-macosx_11_0_arm64.whl": "e2ed719e14aa64d895c2ee922594a90a43c861a93f0575a95ff8c47cdbd13eb9",  # noqa: E501
        "ruff-0.16.3-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": "294b95c4ae0cda9388525c2047778aa758d6b8d4bb876fd4e9eaa3ebc92343eb",  # noqa: E501
        "ruff-0.16.3.tar.gz": "e76d33a347661a84b5be6d043d0347fdc745dfdcf825a8f4fed64b5e26eebdf2",  # noqa: E501
    }

    def _inventory(self, name: str) -> dict[str, str]:
        text = (ROOT / name).read_text(encoding="utf-8")
        inventory = dict(
            re.findall(r"^# artifact: (\S+) sha256:([0-9a-f]{64})$", text, re.M)
        )
        if name == "requirements-dev.lock":
            inventory = {**self._inventory("requirements-runtime.lock"), **inventory}
        return inventory

    def test_runtime_lock_is_exact_reviewed_pyyaml_inventory(self):
        inventory = self._inventory("requirements-runtime.lock")
        expected = {
            key: value
            for key, value in self.expected.items()
            if key.startswith("pyyaml-")
        }
        self.assertEqual(inventory, expected)
        text = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
        self.assertIn("PyYAML==6.0.3", text)
        self.assertNotRegex(text, r"PyYAML\s*==\s*(?!6\.0\.3)")
        self.assertNotIn("cp310", text)
        self.assertNotIn("win_", text)

    def test_developer_lock_is_exact_reviewed_ruff_inventory_and_runtime_include(self):
        inventory = self._inventory("requirements-dev.lock")
        self.assertEqual(inventory, self.expected)
        text = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
        self.assertIn("-r requirements-runtime.lock", text)
        self.assertIn("ruff==0.16.3", text)
        self.assertNotIn("cp310", text)
        self.assertNotIn("win_", text)

    def test_compatibility_requirement_files_include_separate_locks(self):
        self.assertEqual(
            (ROOT / "requirements.txt").read_text(encoding="utf-8").strip(),
            "-r requirements-runtime.lock",
        )
        self.assertEqual(
            (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").strip(),
            "-r requirements-dev.lock",
        )


class CanonicalValidatorTests(unittest.TestCase):
    def test_unexpected_argv_is_rejected_before_subprocess_or_repository_reads(self):
        validator = _load_validator()
        with (
            patch.object(validator.subprocess, "run") as run,
            patch.object(validator.Path, "read_text") as read_text,
        ):
            self.assertEqual(validator.main(["--install"]), 2)
        run.assert_not_called()
        read_text.assert_not_called()

    def test_empty_argv_runs_each_fixed_check_once(self):
        validator = _load_validator()
        calls: list[tuple[str, ...]] = []

        def run(argv, **kwargs):
            del kwargs
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, "", "")

        with patch.object(validator.subprocess, "run", side_effect=run):
            self.assertEqual(validator.main([]), 0)
        self.assertEqual(len(calls), len(set(calls)))
        self.assertTrue(
            any("validate-catalogs.py" in item for call in calls for item in call)
        )
        self.assertTrue(
            any(
                "unittest" in item and "discover" in call
                for call in calls
                for item in call
            )
        )
        self.assertTrue(
            any("git" in item and "diff" in call for call in calls for item in call)
        )
        self.assertTrue(
            any("git" in item and "status" in call for call in calls for item in call)
        )


class BootstrapContractTests(unittest.TestCase):
    def test_bootstrap_is_fixed_argv_and_validates_python_before_venv(self):
        text = (ROOT / "scripts" / "bootstrap-developer.sh").read_text(encoding="utf-8")
        self.assertIn('[ "$#" -eq 0 ]', text)
        self.assertIn("3.11", text)
        self.assertIn("3.14", text)
        self.assertIn(
            "python -m pip install --require-hashes --requirement requirements-dev.lock",  # noqa: E501
            text,
        )
        self.assertLess(
            text.index("python3 --version"), text.index("python3 -m venv .venv")
        )
        self.assertNotIn("curl", text.lower())
        self.assertNotIn("wget", text.lower())


if __name__ == "__main__":
    unittest.main()
