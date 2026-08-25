import io
import unittest

from subagents_configs.diagnostics import (
    Diagnostic,
    DiagnosticCode,
    SafeContext,
    emit_diagnostic,
    render_diagnostic,
)


class DiagnosticRendererTests(unittest.TestCase):
    def test_rendering_is_typed_and_canonical(self):
        diagnostic = Diagnostic(
            DiagnosticCode.MANAGED_CONFLICT,
            SafeContext(
                targets=("opencode", "codex", "codex"),
                homes=("/private/raw/codex", "/private/raw/opencode"),
                operation="install",
                phase="preflight",
                status="conflict",
            ),
        )

        rendered = render_diagnostic(diagnostic)

        self.assertEqual(
            rendered,
            "error: code=MANAGED_CONFLICT targets=codex,opencode "
            "homes=home-1,home-2 operation=install phase=preflight "
            "status=conflict\n",
        )
        self.assertNotIn("/private/raw", rendered)

    def test_unknown_context_values_are_fixed_labels(self):
        rendered = render_diagnostic(
            Diagnostic(
                DiagnosticCode.OUTPUT_FAILED,
                SafeContext(
                    targets=("../../attacker", "codex\nSECRET"),
                    homes=("/private/raw/secret",),
                    operation="install\nTOKEN=leak",
                    phase="phase\nPAYLOAD",
                    status="status\nPRIVATE",
                ),
            )
        )

        self.assertEqual(
            rendered,
            "error: code=OUTPUT_FAILED targets=unknown "
            "homes=home-1 operation=unknown phase=unknown status=unknown\n",
        )
        for value in (
            "attacker",
            "SECRET",
            "/private/raw/secret",
            "TOKEN",
            "PAYLOAD",
            "PRIVATE",
        ):
            self.assertNotIn(value, rendered)

    def test_emit_diagnostic_never_accepts_or_renders_exception_data(self):
        output = io.StringIO()

        written = emit_diagnostic(
            output,
            DiagnosticCode.VALIDATION_BLOCKED,
            ("claude-code", "codex"),
            ("/home/raw", "/srv/raw"),
            "install",
            "validation",
            "blocked",
        )

        self.assertTrue(written)
        self.assertEqual(
            output.getvalue(),
            "error: code=VALIDATION_BLOCKED targets=codex,claude-code "
            "homes=home-1,home-2 operation=install phase=validation "
            "status=blocked\n",
        )


if __name__ == "__main__":
    unittest.main()
