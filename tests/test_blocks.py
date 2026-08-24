import hashlib
import unittest

from subagents_configs.models import ManagedBlock


class ManagedBlockTests(unittest.TestCase):
    def test_render_is_deterministic_and_hashes_complete_block(self):
        from subagents_configs.blocks import render_managed_block

        block = render_managed_block("routing-codex", b"route = true")
        expected = (
            b"# BEGIN SUBAGENTS_CONFIGS routing-codex\n"
            b"route = true\n"
            b"# END SUBAGENTS_CONFIGS routing-codex\n"
        )
        self.assertEqual(block.begin_marker, b"# BEGIN SUBAGENTS_CONFIGS routing-codex")
        self.assertEqual(block.end_marker, b"# END SUBAGENTS_CONFIGS routing-codex")
        self.assertEqual(block.content, b"route = true\n")
        self.assertEqual(block.sha256, hashlib.sha256(expected).hexdigest())

    def test_insert_replace_and_remove_preserve_surrounding_bytes(self):
        from subagents_configs.blocks import (
            insert_or_replace_block,
            remove_exact_block,
            render_managed_block,
        )

        block = render_managed_block("routing-codex", b"one")
        original = (
            b"before\n"
            + block.begin_marker
            + b"\nold\n"
            + block.end_marker
            + b"\nafter"
        )
        replaced = insert_or_replace_block(original, block)
        self.assertEqual(replaced, b"before\n" + block_bytes(block) + b"after")
        removed, changed = remove_exact_block(replaced, block)
        self.assertEqual((removed, changed), (b"before\nafter", True))
        unresolved, changed = remove_exact_block(
            replaced.replace(b"one", b"two"), block
        )
        self.assertEqual(
            (unresolved, changed), (replaced.replace(b"one", b"two"), False)
        )
        missing, changed = remove_exact_block(b"surrounding bytes", block)
        self.assertEqual((missing, changed), (b"surrounding bytes", False))

    def test_parser_rejects_duplicate_nested_unbalanced_and_ambiguous_markers(self):
        from subagents_configs.blocks import (
            insert_or_replace_block,
            render_managed_block,
        )

        block = render_managed_block("routing-codex", b"body")
        cases = (
            block_bytes(block) + block_bytes(block),
            block.begin_marker
            + b"\n"
            + block.begin_marker
            + b"\nbody\n"
            + block.end_marker,
            block.begin_marker + b"\nbody\n",
            block.begin_marker + b"\nbody\n# END SUBAGENTS_CONFIGS routing-opencode\n",
            block.begin_marker + b" extra\nbody\n" + block.end_marker,
        )
        for original in cases:
            with self.assertRaises(ValueError):
                insert_or_replace_block(original, block)

    def test_unknown_ids_and_marker_injection_are_rejected(self):
        from subagents_configs.blocks import render_managed_block

        with self.assertRaises(ValueError):
            render_managed_block("unknown", b"body")
        with self.assertRaises(ValueError):
            render_managed_block(
                "routing-codex", b"body\n# END SUBAGENTS_CONFIGS routing-codex"
            )

    def test_forged_blocks_reject_bare_near_and_substring_markers(self):
        from subagents_configs.blocks import (
            insert_or_replace_block,
            render_managed_block,
        )

        begin = b"# BEGIN SUBAGENTS_CONFIGS routing-codex"
        end = b"# END SUBAGENTS_CONFIGS routing-codex"
        for body in (
            b"# BEGIN SUBAGENTS_CONFIGS",
            b"# BEGIN SUBAGENTS_CONFIGS ",
            b"prefix # BEGIN SUBAGENTS_CONFIGS routing-codex",
        ):
            rendered = begin + b"\n" + body + b"\n" + end + b"\n"
            forged = ManagedBlock(
                "routing-codex",
                begin,
                end,
                body + b"\n",
                hashlib.sha256(rendered).hexdigest(),
            )
            with self.assertRaises(ValueError):
                insert_or_replace_block(b"", forged)
        with self.assertRaises(ValueError):
            render_managed_block("routing-codex", b"body\r\n")

    def test_render_rejects_ambiguous_eof_and_crlf_block_boundaries(self):
        from subagents_configs.blocks import remove_exact_block, render_managed_block

        with self.assertRaises(ValueError):
            render_managed_block("routing-codex", b"body\r")
        block = render_managed_block("routing-codex", b"body")
        forged = ManagedBlock(
            block.block_id,
            block.begin_marker,
            block.end_marker,
            block.content[:-1],
            block.sha256,
        )
        with self.assertRaises(ValueError):
            remove_exact_block(block_bytes(block), forged)
        with self.assertRaises(ValueError):
            remove_exact_block(block_bytes(block).replace(b"\n", b"\r\n"), block)

    def test_original_managed_end_marker_at_eof_requires_final_lf(self):
        from subagents_configs.blocks import (
            insert_or_replace_block,
            remove_exact_block,
            render_managed_block,
        )

        block = render_managed_block("routing-codex", b"body")
        eof_block = block_bytes(block).removesuffix(b"\n")
        for operation in (
            lambda: insert_or_replace_block(eof_block, block),
            lambda: remove_exact_block(eof_block, block),
        ):
            with self.assertRaises(ValueError):
                operation()


def block_bytes(block):
    return block.begin_marker + b"\n" + block.content + block.end_marker + b"\n"


if __name__ == "__main__":
    unittest.main()
