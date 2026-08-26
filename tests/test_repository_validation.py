from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import tempfile
import unittest
from collections import Counter
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
        "ruff-0.16.3-py3-none-macosx_11_0_arm64.whl": "e2ed719e14aa64d895c2ee922594a90a43c861a93f0575a95ff8c47cdbd13eb9",  # noqa: E501
        "ruff-0.16.3-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": "294b95c4ae0cda9388525c2047778aa758d6b8d4bb876fd4e9eaa3ebc92343eb",  # noqa: E501
    }
    expected_markers: ClassVar[dict[str, str]] = {
        "pyyaml-6.0.3-cp311-cp311-macosx_11_0_arm64.whl": 'implementation_name == "cpython" and python_version == "3.11" and platform_system == "Darwin" and platform_machine == "arm64"',  # noqa: E501
        "pyyaml-6.0.3-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": 'implementation_name == "cpython" and python_version == "3.11" and platform_system == "Linux" and platform_machine == "x86_64"',  # noqa: E501
        "pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl": 'implementation_name == "cpython" and python_version == "3.12" and platform_system == "Darwin" and platform_machine == "arm64"',  # noqa: E501
        "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": 'implementation_name == "cpython" and python_version == "3.12" and platform_system == "Linux" and platform_machine == "x86_64"',  # noqa: E501
        "pyyaml-6.0.3-cp313-cp313-macosx_11_0_arm64.whl": 'implementation_name == "cpython" and python_version == "3.13" and platform_system == "Darwin" and platform_machine == "arm64"',  # noqa: E501
        "pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": 'implementation_name == "cpython" and python_version == "3.13" and platform_system == "Linux" and platform_machine == "x86_64"',  # noqa: E501
        "pyyaml-6.0.3-cp314-cp314-macosx_11_0_arm64.whl": 'implementation_name == "cpython" and python_version == "3.14" and platform_system == "Darwin" and platform_machine == "arm64"',  # noqa: E501
        "pyyaml-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl": 'implementation_name == "cpython" and python_version == "3.14" and platform_system == "Linux" and platform_machine == "x86_64"',  # noqa: E501
        "ruff-0.16.3-py3-none-macosx_11_0_arm64.whl": 'implementation_name == "cpython" and python_version >= "3.11" and python_version < "3.15" and platform_system == "Darwin" and platform_machine == "arm64"',  # noqa: E501
        "ruff-0.16.3-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": 'implementation_name == "cpython" and python_version >= "3.11" and python_version < "3.15" and platform_system == "Linux" and platform_machine == "x86_64"',  # noqa: E501
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
        self.assertNotIn(".tar.gz", text)

    def test_comments_are_independently_associated_with_exact_marked_requirements(self):
        for name in ("requirements-runtime.lock", "requirements-dev.lock"):
            text = (ROOT / name).read_text(encoding="utf-8")
            lines = text.splitlines()
            expected_for_file = {
                key: value
                for key, value in self.expected.items()
                if (name == "requirements-runtime.lock") == key.startswith("pyyaml-")
            }
            seen: dict[str, tuple[str, str]] = {}
            for index, line in enumerate(lines):
                match = re.fullmatch(r"# artifact: (\S+) sha256:([0-9a-f]{64})", line)
                if match is None:
                    continue
                artifact, digest = match.groups()
                self.assertNotIn(artifact, seen)
                self.assertIn(artifact, self.expected)
                self.assertIn(artifact, self.expected_markers)
                requirement = lines[index + 1]
                hash_line = lines[index + 2].strip()
                self.assertTrue(
                    requirement.startswith(("PyYAML==6.0.3 ;", "ruff==0.16.3 ;"))
                )
                self.assertTrue(requirement.endswith("\\"))
                self.assertEqual(hash_line, f"--hash=sha256:{digest}")
                marker = requirement.split(" ; ", 1)[1][:-1].strip()
                self.assertEqual(marker, self.expected_markers[artifact])
                seen[artifact] = (marker, digest)
            self.assertEqual(set(seen), set(expected_for_file))
            self.assertEqual(
                {key: value[1] for key, value in seen.items()},
                {key: self.expected[key] for key in expected_for_file},
            )
            package_lines = [
                line for line in lines if line.startswith(("PyYAML", "ruff"))
            ]
            self.assertEqual(
                package_lines,
                [
                    f"{'PyYAML' if key.startswith('pyyaml-') else 'ruff'}=="
                    f"{'6.0.3' if key.startswith('pyyaml-') else '0.16.3'} ; "
                    f"{self.expected_markers[key]} \\"
                    for key in expected_for_file
                ],
            )
            self.assertEqual(
                re.findall(r"^    --hash=sha256:([0-9a-f]{64})$", text, re.M),
                [self.expected[key] for key in expected_for_file],
            )

    def test_developer_lock_is_exact_reviewed_ruff_inventory_and_runtime_include(self):
        inventory = self._inventory("requirements-dev.lock")
        self.assertEqual(inventory, self.expected)
        text = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
        self.assertIn("-r requirements-runtime.lock", text)
        self.assertIn("ruff==0.16.3", text)
        self.assertNotIn("cp310", text)
        self.assertNotIn("win_", text)

    def test_independent_inventory_rejects_reviewed_lock_mutations(self):
        text = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
        expected = {
            key: value
            for key, value in self.expected.items()
            if key.startswith("pyyaml-")
        }

        def assert_exact(candidate: str) -> None:
            lines = candidate.splitlines()
            allowed_headers = {
                "# Reviewed from https://pypi.org/pypi/PyYAML/6.0.3/json.",
                "# Install only with: python -m pip install --require-hashes "
                "--requirement requirements-runtime.lock",
            }
            comments = re.findall(
                r"^# artifact: (\S+) sha256:([0-9a-f]{64})$", candidate, re.M
            )
            self.assertEqual(dict(comments), expected)
            self.assertEqual(len(comments), len(expected))
            for index, line in enumerate(lines):
                match = re.fullmatch(r"# artifact: (\S+) sha256:([0-9a-f]{64})", line)
                if match is None:
                    continue
                artifact, digest = match.groups()
                requirement = lines[index + 1]
                self.assertEqual(
                    requirement,
                    f"PyYAML==6.0.3 ; {self.expected_markers[artifact]} \\",
                )
                self.assertEqual(lines[index + 2], f"    --hash=sha256:{digest}")
            self.assertEqual(
                [line for line in lines if line.startswith("PyYAML")],
                [
                    f"PyYAML==6.0.3 ; {self.expected_markers[key]} \\"
                    for key in expected
                ],
            )
            self.assertEqual(
                re.findall(r"^    --hash=sha256:([0-9a-f]{64})$", candidate, re.M),
                list(expected.values()),
            )
            allowed_lines = allowed_headers | {
                f"# artifact: {key} sha256:{value}" for key, value in expected.items()
            }
            allowed_lines |= {
                f"PyYAML==6.0.3 ; {self.expected_markers[key]} \\" for key in expected
            }
            allowed_lines |= {
                f"    --hash=sha256:{value}" for value in expected.values()
            }
            for line in lines:
                self.assertIn(line, allowed_lines)

        assert_exact(text)
        mutations = (
            text.replace(next(iter(expected.values())), "0" * 64, 1),
            text + "\n# artifact: pyyaml-extra.whl sha256:" + "0" * 64 + "\n",
            text.replace("PyYAML==6.0.3", "PyYAML==6.0.2", 1),
            text.replace(
                'platform_machine == "arm64"', 'platform_machine == "x86_64"', 1
            ),
            text.replace(
                "    --hash=sha256:", "    # missing hash\n    --hash=sha256:", 1
            ),
            text + "\nPyYAML==6.0.3\n",
            text + "\n    --hash=sha256:" + "0" * 64 + "\n",
            text + "\nPyYAML>=6.0\n",
            text + "\nrequests==1.0\n",
            text + "\n--no-index\n",
            text + "\n-r requirements-runtime.lock\n",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation[-80:]):
                with self.assertRaises(AssertionError):
                    assert_exact(mutation)

    def test_compatibility_requirement_files_include_separate_locks(self):
        self.assertEqual(
            (ROOT / "requirements.txt").read_text(encoding="utf-8").strip(),
            "-r requirements-runtime.lock",
        )
        self.assertEqual(
            (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").strip(),
            "-r requirements-dev.lock",
        )

    def test_developer_lock_rejects_every_unrecognized_semantic_line(self):
        text = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
        expected_artifacts = {
            key: value
            for key, value in self.expected.items()
            if key.startswith("ruff-")
        }
        allowed = [
            "# Reviewed from https://pypi.org/pypi/ruff/0.16.3/json; "
            "runtime is included below.",
            "# Install only with: python -m pip install --require-hashes "
            "--requirement requirements-dev.lock",
            "-r requirements-runtime.lock",
        ]
        for key, value in expected_artifacts.items():
            allowed.extend(
                (
                    f"# artifact: {key} sha256:{value}",
                    f"ruff==0.16.3 ; {self.expected_markers[key]} \\",
                    f"    --hash=sha256:{value}",
                )
            )
        self.assertEqual(Counter(text.splitlines()), Counter(allowed))
        for mutation in (
            text + "\nrequests==1.0\n",
            text + "\n--no-index\n",
            text + "\n-r requirements-runtime.lock\n",
            text.replace(allowed[3], allowed[3] + "\n" + allowed[3], 1),
        ):
            with self.subTest(mutation=mutation[-80:]):
                self.assertNotEqual(Counter(mutation.splitlines()), Counter(allowed))


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
            return validator._result(0)

        tools = tuple(
            Path(item)
            for item in ("/usr/bin/python3", "/usr/bin/ruff", "/bin/sh", "/usr/bin/git")
        )
        with (
            patch.object(validator, "_fixed_tools", return_value=tools),
            patch.object(validator, "_backend_gate", return_value=(0, "", "")),
            patch.object(validator, "_run", side_effect=run),
        ):
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
        self.assertFalse(
            any(
                "tests.test_validation_backend" in item
                for call in calls
                for item in call
            )
        )
        self.assertTrue(all(Path(call[0]).is_absolute() for call in calls))

    def test_system_interpreter_configuration_is_backend_gate_only(self):
        validator = _load_validator()
        ordinary_environments: list[dict[str, str]] = []
        backend_environments: list[dict[str, str]] = []

        def run(_argv, **kwargs):
            ordinary_environments.append(kwargs["env"])
            return validator._result(0)

        def backend(_repo_root, *, env):
            backend_environments.append(env)
            return validator._result(0)

        tools = tuple(
            Path(item)
            for item in ("/usr/bin/python3", "/usr/bin/ruff", "/bin/sh", "/usr/bin/git")
        )
        with (
            patch.dict(
                validator.os.environ,
                {"VALIDATION_SYSTEM_PYTHON": "/reviewed/system/python"},
                clear=False,
            ),
            patch.object(validator, "_fixed_tools", return_value=tools),
            patch.object(validator, "_backend_gate", side_effect=backend),
            patch.object(validator, "_run", side_effect=run),
        ):
            self.assertEqual(validator.main([]), 0)
        self.assertTrue(ordinary_environments)
        self.assertTrue(
            all("VALIDATION_SYSTEM_PYTHON" not in env for env in ordinary_environments)
        )
        self.assertEqual(
            backend_environments[0]["VALIDATION_SYSTEM_PYTHON"],
            "/reviewed/system/python",
        )

    def test_fixed_tools_reject_symlinked_executable(self):
        validator = _load_validator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            target.chmod(0o700)
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                validator._fixed_executable(link, label="test", root_owned=False)

    def test_fixed_candidate_skips_unsafe_first_and_fails_without_safe_fallback(self):
        validator = _load_validator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            target.chmod(0o700)
            link = root / "link"
            link.symlink_to(target)
            selected = validator._fixed_candidate(
                (link, target), label="test", root_owned=False
            )
            self.assertEqual(selected, target)
            with self.assertRaises(OSError):
                validator._fixed_candidate((link,), label="test", root_owned=False)
            directory = root / "directory"
            directory.mkdir()
            with self.assertRaises(OSError):
                validator._fixed_candidate((directory,), label="test", root_owned=False)

    def test_fixed_tool_failure_has_safe_diagnostic_label(self):
        validator = _load_validator()
        with (
            patch.object(
                validator, "_fixed_tools", side_effect=OSError("private secret")
            ),
            patch("builtins.print") as printed,
        ):
            self.assertEqual(validator.main([]), 1)
        message = str(printed.call_args)
        self.assertIn("fixed tool gate", message)
        self.assertIn("status=blocked", message)
        self.assertNotIn("private secret", message)
        self.assertNotIn("private validation environment", message)

    def test_failed_check_diagnostics_are_bounded_and_secret_free(self):
        validator = _load_validator()
        tools = tuple(
            Path(item)
            for item in ("/usr/bin/python3", "/usr/bin/ruff", "/bin/sh", "/usr/bin/git")
        )
        with (
            patch.object(validator, "_fixed_tools", return_value=tools),
            patch.object(
                validator,
                "_run",
                return_value=(7, "PRIVATE stdout secret", "PRIVATE stderr secret"),
            ),
            patch("builtins.print") as printed,
        ):
            self.assertEqual(validator.main([]), 1)
        message = str(printed.call_args)
        self.assertIn("status=exit-7", message)
        self.assertIn("stdout-sha256=", message)
        self.assertIn("stderr-sha256=", message)
        self.assertIn("stdout-bytes=", message)
        self.assertIn("stderr-bytes=", message)
        self.assertNotIn("PRIVATE", message)
        self.assertNotIn("/Users/pawel", message)

    def test_unit_failure_diagnostic_keeps_only_safe_identifiers_and_reasons(self):
        validator = _load_validator()
        stderr = """\
FAIL: test_safe (tests.test_safe.SafeTests)
----------------------------------------------------------------------
Traceback (most recent call last):
AssertionError: API_KEY=super-secret\nhttps://example.invalid/token
ERROR: test_broken (tests.test_broken.BrokenTests)
----------------------------------------------------------------------
ValueError: /Users/private/checkout/prompt.txt
"""
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=stderr)
        )

        self.assertIn(
            "unit-failures=FAIL:test_safe (tests.test_safe.SafeTests),"
            "ERROR:test_broken (tests.test_broken.BrokenTests)",
            diagnostic,
        )
        self.assertIn("unit-reasons=assertion,exception", diagnostic)
        for field in (
            "stdout-bytes=",
            "stdout-sha256=",
            "stderr-bytes=",
            "stderr-sha256=",
        ):
            self.assertIn(field, diagnostic)
        for secret in (
            "API_KEY=super-secret",
            "https://example.invalid/token",
            "/Users/private/checkout/prompt.txt",
            "most recent call",
        ):
            self.assertNotIn(secret, diagnostic)

    def test_unit_parser_accepts_real_python_314_failure_error_and_subtest(
        self,
    ):
        validator = _load_validator()
        # Captured from Python 3.14 unittest TextTestRunner output.  The
        # traceback/source lines are intentionally included to prove the
        # parser does not need to inspect arbitrary test output.
        stderr = """\
testCamelCase (__main__.T.testCamelCase) ... ERROR
test_plain (__main__.T.test_plain) ... FAIL
test_sub (__main__.T.test_sub) ...
  test_sub (__main__.T.test_sub) (case=0) ... FAIL

======================================================================
ERROR: testCamelCase (__main__.T.testCamelCase)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "<string>", line 4, in testCamelCase
    def testCamelCase(self): 1/0
ZeroDivisionError: division by zero

======================================================================
FAIL: test_plain (__main__.T.test_plain)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "<string>", line 3, in test_plain
    def test_plain(self): self.fail("x")
AssertionError: x

======================================================================
FAIL: test_sub (__main__.T.test_sub) (case=0)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "<string>", line 7, in test_sub
    with self.subTest(case=i): self.fail("x")
AssertionError: x
"""
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=stderr)
        )

        self.assertIn(
            "unit-failures=ERROR:testCamelCase (__main__.T.testCamelCase),"
            "FAIL:test_plain (__main__.T.test_plain),"
            "FAIL:test_sub (__main__.T.test_sub)",
            diagnostic,
        )
        self.assertNotIn("(case=0)", diagnostic)
        self.assertIn("unit-reasons=exception,assertion", diagnostic)

    def test_unit_parser_accepts_real_exact_test_method_identifier(self):
        validator = _load_validator()
        # Captured from Python 3.14 unittest output for def test(self).
        stderr = """\
======================================================================
FAIL: test (__main__.T.test)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "<string>", line 2, in test
AssertionError: x
"""
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=stderr)
        )

        self.assertIn("unit-failures=FAIL:test (__main__.T.test)", diagnostic)

    def test_unit_parser_ignores_nested_subtest_suffix_and_secret(self):
        validator = _load_validator()
        # Captured from Python 3.14 unittest output for a nested subTest value.
        stderr = """\
======================================================================
FAIL: test_sub (__main__.T.test_sub) (case='x (secret)')
----------------------------------------------------------------------
Traceback (most recent call last):
  File "<string>", line 4, in test_sub
AssertionError: x
"""
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=stderr)
        )

        self.assertIn("unit-failures=FAIL:test_sub (__main__.T.test_sub)", diagnostic)
        self.assertIn("unit-reasons=assertion", diagnostic)
        self.assertNotIn("case=", diagnostic)
        self.assertNotIn("x (secret)", diagnostic)
        self.assertNotIn("SECRET", diagnostic)

    def test_unit_failure_parser_rejects_malicious_headers_reasons_and_controls(self):
        validator = _load_validator()
        stderr = (
            "FAIL: test_safe (tests.test_safe.SafeTests)\n"
            "FAIL: test_suffix (__main__.T) "
            "(API_KEY=secret https://evil.invalid/token /private/prompt)\n"
            "FAIL: test_scope_secret (SECRET)\n"
            "FAIL: test_scope_dots (pkg..SECRET.)\n"
            "FAIL: test_control (__main__.T.test_control) (case=\x00)\n"
            "FAIL: test_unicode (__main__.T.test_unicode) (case=é)\n"
            "FAIL: SECRET (pkg.C)\n"
            "ERROR: helper (pkg.C)\n"
            "FAIL: test_evil; API_KEY=secret (tests.test_evil.Evil)\n"
            "ERROR: test_path (../../private)\n"
            "AssertionError: prompt=do-not-share\x00\x1b[31m\n"
            "not a unittest report\n"
        )
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=stderr)
        )

        self.assertIn(
            "unit-failures=FAIL:test_safe (tests.test_safe.SafeTests)", diagnostic
        )
        self.assertNotIn("test_evil", diagnostic)
        self.assertNotIn("test_path", diagnostic)
        self.assertNotIn("test_scope_secret", diagnostic)
        self.assertNotIn("test_scope_dots", diagnostic)
        self.assertNotIn("test_control", diagnostic)
        self.assertNotIn("test_unicode", diagnostic)
        self.assertNotIn("SECRET", diagnostic)
        self.assertNotIn("helper", diagnostic)
        self.assertNotIn("API_KEY", diagnostic)
        self.assertNotIn("https://evil.invalid/token", diagnostic)
        self.assertNotIn("/private/prompt", diagnostic)
        self.assertNotIn("prompt=do-not-share", diagnostic)
        self.assertNotRegex(diagnostic, r"[\x00-\x1f\x7f]")

    def test_unit_parser_rejects_secret_and_malformed_dotted_scopes(self):
        validator = _load_validator()
        stderr = "FAIL: test_safe (SECRET)\nFAIL: test_safe (pkg..SECRET.)\n"
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=stderr)
        )

        self.assertNotIn("unit-failures=", diagnostic)
        self.assertNotIn("SECRET", diagnostic)

    def test_unit_failure_parser_is_bounded_and_malformed_output_is_omitted(self):
        validator = _load_validator()
        headers = "\n".join(
            f"FAIL: test_{index:03d} (tests.test_many.Case)" for index in range(40)
        )
        diagnostic = validator._diagnostic(
            "unit test discovery", "exit-1", validator._result(1, stderr=headers)
        )
        self.assertLessEqual(diagnostic.count("unit-failures="), 1)
        failure_field = diagnostic.split("unit-failures=", 1)[1].split("; ", 1)[0]
        self.assertLessEqual(
            len(failure_field.split(",")), validator._UNIT_DIAGNOSTIC_MAX_ITEMS
        )
        self.assertLessEqual(
            max(map(len, failure_field.split(","))),
            validator._UNIT_DIAGNOSTIC_MAX_ITEM_LENGTH,
        )

        malformed = validator._diagnostic(
            "unit test discovery",
            "exit-1",
            validator._result(1, stderr="FAIL: \x00 arbitrary output SECRET"),
        )
        self.assertNotIn("unit-failures=", malformed)
        self.assertNotIn("arbitrary output", malformed)
        self.assertNotIn("SECRET", malformed)

    def test_non_unit_failure_diagnostic_remains_hash_only(self):
        validator = _load_validator()
        diagnostic = validator._diagnostic(
            "Ruff check",
            "exit-1",
            validator._result(
                1,
                stdout="FAIL: test_safe (tests.test_safe.SafeTests)",
                stderr="AssertionError: SECRET /private/path",
            ),
        )
        self.assertNotIn("unit-failures=", diagnostic)
        self.assertNotIn("unit-reasons=", diagnostic)
        self.assertNotIn("test_safe", diagnostic)
        self.assertNotIn("SECRET", diagnostic)

    def test_failure_fingerprints_distinguish_secret_free_failures(self):
        validator = _load_validator()
        tools = tuple(
            Path(item)
            for item in ("/usr/bin/python3", "/usr/bin/ruff", "/bin/sh", "/usr/bin/git")
        )
        messages = []
        for stdout, stderr in (
            ("first SECRET", "stderr-a"),
            ("second SECRET", "stderr-b"),
        ):
            with (
                patch.object(validator, "_fixed_tools", return_value=tools),
                patch.object(validator, "_run", return_value=(9, stdout, stderr)),
                patch("builtins.print") as printed,
            ):
                self.assertEqual(validator.main([]), 1)
            message = str(printed.call_args)
            self.assertNotIn("SECRET", message)
            messages.append(message)
        self.assertNotEqual(messages[0], messages[1])

    def test_direct_check_capture_is_capped_and_hashes_full_stream_bytes(self):
        validator = _load_validator()
        payload_size = validator._CAPTURE_LIMIT * 4
        command = (
            str(Path("/usr/bin/python3")),
            "-c",
            f"import sys; sys.stdout.buffer.write(b'o' * {payload_size}); "
            f"sys.stderr.buffer.write(b'e' * {payload_size})",
        )
        result = validator._run(command, env=dict(os.environ), cwd=ROOT)
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(result.stdout.text.encode()), validator._CAPTURE_LIMIT)
        self.assertLessEqual(len(result.stderr.text.encode()), validator._CAPTURE_LIMIT)
        self.assertEqual(result.stdout.byte_count, payload_size)
        self.assertEqual(result.stderr.byte_count, payload_size)
        self.assertEqual(len(result.stdout.sha256), 64)
        self.assertEqual(len(result.stderr.sha256), 64)
        self.assertNotIn("o" * (validator._CAPTURE_LIMIT + 1), result.stdout.text)

    def test_eof_waits_for_successful_child_instead_of_false_timeout(self):
        validator = _load_validator()

        class FakeStream:
            def __init__(self, descriptor):
                self.descriptor = descriptor
                self.closed = False

            def fileno(self):
                return self.descriptor

            def close(self):
                self.closed = True

        class FakeKey:
            def __init__(self, fileobj, data):
                self.fileobj = fileobj
                self.data = data

        class FakeSelector:
            def __init__(self):
                self.keys = {}

            def register(self, fileobj, _events, data):
                self.keys[fileobj.fileno()] = FakeKey(fileobj, data)

            def unregister(self, fileobj):
                del self.keys[fileobj.fileno()]

            def get_map(self):
                return self.keys

            def select(self, _timeout):
                return [
                    (key, validator.selectors.EVENT_READ) for key in self.keys.values()
                ]

            def close(self):
                pass

        class FakeProcess:
            def __init__(self):
                self.stdout = FakeStream(11)
                self.stderr = FakeStream(12)
                self.returncode = None
                self.wait_calls = []
                self.kill_calls = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.wait_calls.append(timeout)
                self.returncode = 0
                return self.returncode

            def kill(self):
                self.kill_calls += 1

        process = FakeProcess()
        with (
            patch.object(validator.subprocess, "Popen", return_value=process),
            patch.object(
                validator.selectors, "DefaultSelector", return_value=FakeSelector()
            ),
            patch.object(validator.os, "read", side_effect=lambda _fd, _size: b""),
        ):
            result = validator._run(("/usr/bin/true",), env={}, cwd=ROOT)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(process.kill_calls, 0)
        self.assertEqual(len(process.wait_calls), 1)

    def test_direct_check_timeout_kills_child_and_returns_bounded_result(self):
        validator = _load_validator()
        command = (
            "/usr/bin/python3",
            "-c",
            "import time; print('timeout marker'); time.sleep(10)",
        )
        with patch.object(validator, "_DIRECT_CHECK_TIMEOUT", 0.01):
            result = validator._run(command, env=dict(os.environ), cwd=ROOT)
        self.assertEqual(result.returncode, 124)
        self.assertLessEqual(len(result.stdout.text.encode()), validator._CAPTURE_LIMIT)

    def test_backend_probe_command_passes_real_prevalidation(self):
        validator = _load_validator()
        from scripts.validation_isolation.backend import validate_command_argv

        command = (
            str(Path("/usr/bin/python3").resolve()),
            "-c",
            validator._BACKEND_PROBE,
        )
        self.assertNotIn("/etc/hosts", validator._BACKEND_PROBE)
        self.assertEqual(validate_command_argv(command, ROOT), command)

    def test_validator_environment_is_private_and_sanitized(self):
        validator = _load_validator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "validation"
            root.mkdir(mode=0o700)
            environment = validator._environment(root)
            for key in (
                "HOME",
                "TMPDIR",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "PYTHONPYCACHEPREFIX",
                "RUFF_CACHE_DIR",
            ):
                value = Path(environment[key])
                self.assertTrue(value.is_relative_to(root))
                self.assertEqual(value.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                environment["PATH"].split(os.pathsep)[1:], ["/usr/bin", "/bin"]
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
        self.assertIn("sys.implementation.name ==", text)
        self.assertLess(text.index("python3 -c"), text.index("python3 -m venv"))
        self.assertIn("--copies", text)
        self.assertIn('os.lstat(".venv/bin/python")', text)
        self.assertNotIn("curl", text.lower())
        self.assertNotIn("wget", text.lower())


class BootstrapBehaviorTests(unittest.TestCase):
    def _fake_python(self, root: Path, mode: str) -> tuple[Path, Path]:
        bin_dir = root / "bin"
        bin_dir.mkdir()
        log = root / "python.log"
        fake = bin_dir / "python3"
        fake.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> {log}\n"
            'if [ "$1" = "-c" ]; then\n'
            f"  test {mode!r} = valid\n"
            "  exit $?\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return bin_dir, log

    def test_any_preexisting_venv_entry_is_rejected_before_python_execution(self):
        for kind in ("directory", "file", "fifo", "dangling-symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                entry = root / ".venv"
                if kind == "directory":
                    entry.mkdir()
                elif kind == "file":
                    entry.write_text("hostile", encoding="utf-8")
                elif kind == "fifo":
                    os.mkfifo(entry)
                else:
                    entry.symlink_to(root / "missing")
                fake_bin, log = self._fake_python(root, "valid")
                result = subprocess.run(  # noqa: S603
                    [str(ROOT / "scripts" / "bootstrap-developer.sh")],
                    cwd=root,
                    env={"PATH": f"{fake_bin}:/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(log.exists())

    def test_non_cpython_and_unsupported_versions_are_rejected_before_creation(self):
        for mode in ("pypy", "3.10"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fake_bin, _ = self._fake_python(root, mode)
                result = subprocess.run(  # noqa: S603
                    [str(ROOT / "scripts" / "bootstrap-developer.sh")],
                    cwd=root,
                    env={"PATH": f"{fake_bin}:/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / ".venv").exists())

    def test_bootstrap_uses_copies_and_rejects_interpreter_symlinks(self):
        text = (ROOT / "scripts" / "bootstrap-developer.sh").read_text(encoding="utf-8")
        self.assertIn("--copies", text)
        self.assertIn("not stat.S_ISLNK(interpreter.st_mode)", text)
        self.assertIn("exec .venv/bin/python", text)


if __name__ == "__main__":
    unittest.main()
