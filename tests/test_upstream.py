"""Workflow regression tests using only temporary local Git repositories."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "upstream.py"
SPEC = importlib.util.spec_from_file_location("upstream", SCRIPT)
upstream = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upstream)


def git(directory, *arguments):
    return subprocess.run(
        ["git", "-c", "user.name=Workflow Test", "-c", "user.email=test@example.invalid",
         "-c", "core.autocrlf=false", *arguments], cwd=directory, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.decode().strip()


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.origin = self.base / "origin"
        self.origin.mkdir()
        git(self.origin, "init")
        (self.origin / "base.txt").write_bytes(("first\noriginal\nlast\n").encode())
        (self.origin / "README.md").write_bytes(("Upstream guide\n").encode())
        (self.origin / ".gitignore").write_bytes((".env\n").encode())
        git(self.origin, "add", ".")
        git(self.origin, "commit", "-m", "Pinned upstream")
        self.pin = git(self.origin, "rev-parse", "HEAD")
        self.root = self.base / "project"
        self.root.mkdir()
        self.checkout = self.base / "checkout"
        git(self.root, "clone", str(self.origin), str(self.checkout))
        (self.checkout / "base.txt").write_bytes(("first\nproject change\nlast\n").encode())
        self.added = self.checkout / "tools" / "run.sh"
        self.added.parent.mkdir()
        self.added.write_bytes(("#!/bin/sh\necho project\n").encode())
        self.added.chmod(0o755)
        self.data = {"repository": str(self.origin), "commit": self.pin,
                     "patch": "patches/upstream.patch", "modified_files": ["base.txt"],
                     "added_files": ["tools/run.sh"]}
        self.save_manifest()
        self.assert_run(0, "export")

    def save_manifest(self):
        (self.root / "upstream.json").write_bytes((json.dumps(self.data)).encode())

    def assert_run(self, expected, *arguments, include_checkout=True):
        output = io.StringIO()
        arguments = list(arguments)
        if include_checkout and "--checkout" not in arguments:
            arguments.extend(["--checkout", str(self.checkout)])
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                result = upstream.main(arguments, root=self.root)
            except SystemExit as error:
                result = error.code
        self.assertEqual(expected, result, output.getvalue())
        return output.getvalue()

    def fresh_checkout(self):
        target = self.base / "rebuilt"
        self.assert_run(0, "prepare", "--checkout", str(target))
        return target

    def test_fresh_prepare_roundtrip_and_repeat(self):
        target = self.fresh_checkout()
        self.assertEqual(self.pin, git(target, "rev-parse", "HEAD"))
        self.assertEqual("true", git(target, "rev-parse", "--is-shallow-repository"))
        self.assertEqual((self.checkout / "base.txt").read_bytes(), (target / "base.txt").read_bytes())
        self.assertEqual(self.added.read_bytes(), (target / "tools/run.sh").read_bytes())
        self.assertTrue((target / "tools/run.sh").stat().st_mode & 0o111)
        self.assertIn("Already prepared", self.assert_run(0, "prepare", "--checkout", str(target)))
        self.assert_run(0, "export", "--check", "--checkout", str(target))
        self.assertEqual("", git(target, "diff", "--cached", "--name-only"))

    def test_checkout_path_must_be_explicit(self):
        for action in ("prepare", "export"):
            with self.subTest(action=action):
                self.assertIn("--checkout", self.assert_run(2, action, include_checkout=False))
        self.assertFalse((self.root / "holmesgpt").exists())

    def test_checkout_cannot_be_inside_project(self):
        targets = [self.root, self.root / "holmesgpt"]
        link = self.base / "project-link"
        try:
            link.symlink_to(self.root, target_is_directory=True)
            targets.append(link / "nested")
        except OSError:  # Windows without the symlink privilege
            pass
        for action in ("prepare", "export"):
            for target in targets:
                with self.subTest(action=action, target=target):
                    self.assertIn("outside the Blacksite repository", self.assert_run(
                        1, action, "--checkout", str(target)))
        self.assertFalse((self.root / ".git").exists())
        self.assertFalse((self.root / "holmesgpt").exists())
        self.assertFalse((self.root / "nested").exists())

    def test_prepared_checkout_has_no_push_destination(self):
        target = self.fresh_checkout()
        self.assertEqual("", git(target, "remote"))
        self.assertEqual("nothing", git(target, "config", "--local", "push.default"))
        self.assertNotEqual(0, upstream.git(target, "push", check=False).returncode)

    def test_prepare_removes_matching_upstream_origin(self):
        self.assertEqual(str(self.origin), git(self.checkout, "remote", "get-url", "origin"))
        self.assert_run(0, "prepare")
        self.assertEqual("", git(self.checkout, "remote"))
        self.assertEqual("nothing", git(self.checkout, "config", "--local", "push.default"))
        self.assertNotEqual(0, upstream.git(self.checkout, "push", check=False).returncode)

    def test_prepare_preserves_unexpected_remotes_and_checkout(self):
        target = self.base / "unexpected"
        git(self.root, "clone", str(self.origin), str(target))
        for arguments in (("remote", "set-url", "origin", "https://example.invalid/other.git"),
                          ("remote", "add", "other", str(self.origin))):
            with self.subTest(arguments=arguments):
                git(target, *arguments)
                before = (target / ".git/config").read_bytes()
                self.assertIn("unexpected Git remotes", self.assert_run(
                    1, "prepare", "--checkout", str(target)))
                self.assertEqual(before, (target / ".git/config").read_bytes())
                self.assertEqual("first\noriginal\nlast\n", (target / "base.txt").read_text(encoding="utf-8"))
                self.assertFalse((target / "tools/run.sh").exists())
                git(target, "remote", "set-url", "origin", str(self.origin))

    def test_prepare_preserves_unrelated_local_changes(self):
        (self.checkout / ".gitignore").write_bytes((".env\nlocal-only\n").encode())
        self.assert_run(0, "prepare")
        self.assertEqual(".env\nlocal-only\n", (self.checkout / ".gitignore").read_text(encoding="utf-8"))

    def test_divergent_overlay_refused_before_patch_changes(self):
        target = self.base / "clean"
        git(self.root, "clone", str(self.origin), str(target))
        (target / "tools").mkdir()
        (target / "tools/run.sh").write_bytes(("local work").encode())
        self.assertIn("Local overlay differs", self.assert_run(1, "prepare", "--checkout", str(target)))
        self.assertEqual("first\noriginal\nlast\n", (target / "base.txt").read_text(encoding="utf-8"))

    def test_unknown_tracked_and_untracked_changes_refused(self):
        patch = (self.root / self.data["patch"]).read_bytes()
        (self.checkout / "private.txt").write_bytes(("unreviewed").encode())
        (self.checkout / ".gitignore").write_bytes((".env\nlocal-only\n").encode())
        output = self.assert_run(1, "export")
        self.assertIn("private.txt", output)
        self.assertIn(".gitignore", output)
        self.assertEqual(patch, (self.root / self.data["patch"]).read_bytes())

    @unittest.skipIf(os.name == "nt", "Windows has no executable bit or unprivileged symlinks")
    def test_check_detects_stale_patch_content_and_executable_mode(self):
        (self.checkout / "base.txt").write_bytes(("new patch\n").encode())
        self.added.chmod(0o644)
        output = self.assert_run(1, "export", "--check")
        self.assertIn("patches/upstream.patch", output)
        self.assertIn("overlay/tools/run.sh", output)
        self.assert_run(0, "export")
        self.assert_run(0, "export", "--check")
        self.assertFalse((self.root / "overlay/tools/run.sh").stat().st_mode & 0o111)

    def test_empty_patch_and_ignored_local_file(self):
        git(self.checkout, "restore", "base.txt")
        (self.checkout / ".env").write_bytes(("local secret").encode())
        self.assert_run(0, "export")
        self.assertEqual(b"", (self.root / self.data["patch"]).read_bytes())
        target = self.fresh_checkout()
        self.assertFalse((target / ".env").exists())
        self.assert_run(0, "export", "--check", "--checkout", str(target))

    def test_local_only_docs_preserved_without_publication_or_requirement(self):
        self.data["local_only_files"] = ["README.md", "docs/local.md"]
        self.save_manifest()
        (self.checkout / "README.md").write_bytes(("Local guide edits\n").encode())
        local = self.checkout / "docs/local.md"
        local.parent.mkdir()
        local.write_bytes(("Local notes\n").encode())
        retained = self.root / "overlay/docs/local.md"
        retained.parent.mkdir()
        retained.write_bytes(("Previously exported notes\n").encode())

        self.assert_run(0, "export")
        self.assert_run(0, "export", "--check")
        self.assert_run(0, "prepare")
        self.assertEqual("Local guide edits\n", (self.checkout / "README.md").read_text(encoding="utf-8"))
        self.assertEqual("Local notes\n", local.read_text(encoding="utf-8"))
        self.assertEqual("Previously exported notes\n", retained.read_text(encoding="utf-8"))
        self.assertNotIn("README.md", (self.root / self.data["patch"]).read_text(encoding="utf-8"))

        retained.unlink()  # A public clone has no local-only overlay files.
        target = self.fresh_checkout()
        self.assertEqual("Upstream guide\n", (target / "README.md").read_text(encoding="utf-8"))
        self.assertFalse((target / "docs/local.md").exists())
        self.assert_run(0, "export", "--check", "--checkout", str(target))

    def test_local_only_manifest_paths_must_be_safe_and_disjoint(self):
        for paths, message in [
            (["base.txt"], "overlapping paths"),
            (["../private.md"], "Unsafe manifest path"),
            ("docs/local.md", "local_only_files list"),
        ]:
            with self.subTest(paths=paths):
                self.data["local_only_files"] = paths
                self.save_manifest()
                self.assertIn(message, self.assert_run(1, "export"))

    @unittest.skipIf(os.name == "nt", "Windows has no executable bit or unprivileged symlinks")
    def test_local_only_symlinks_refused(self):
        self.data["local_only_files"] = ["local.md"]
        self.save_manifest()
        (self.checkout / "local.md").symlink_to(self.checkout / "README.md")
        self.assertIn("Symlinks", self.assert_run(1, "export"))

    @unittest.skipIf(os.name == "nt", "Windows has no executable bit or unprivileged symlinks")
    def test_unlisted_overlay_and_symlinks_refused(self):
        extra = self.root / "overlay/private.txt"
        extra.write_bytes(("unlisted").encode())
        self.assertIn("Unlisted overlay", self.assert_run(1, "export", "--check"))
        extra.unlink()
        extra.symlink_to(self.checkout / "base.txt")
        self.assertIn("Symlinks", self.assert_run(1, "prepare"))
        extra.unlink()
        self.added.unlink()
        self.added.symlink_to(self.checkout / "base.txt")
        self.assertIn("Symlinks", self.assert_run(1, "export"))

    def test_wrong_head_refused(self):
        git(self.checkout, "add", "base.txt")
        git(self.checkout, "commit", "-m", "Unexpected new commit")
        self.assertIn("expected pinned commit", self.assert_run(1, "export"))
        self.assertIn("expected pinned commit", self.assert_run(1, "prepare"))

    def test_untracked_file_cannot_be_classified_as_modified(self):
        self.data["modified_files"].append("tools/run.sh")
        self.data["added_files"] = []
        self.save_manifest()
        self.assertIn("wrong added/modified classification", self.assert_run(1, "export", "--check"))

    def test_upstream_file_cannot_be_classified_as_added(self):
        self.data["modified_files"] = []
        self.data["added_files"].append("base.txt")
        self.save_manifest()
        self.assertIn("wrong added/modified classification", self.assert_run(1, "export"))

    def test_manifest_path_cannot_escape(self):
        self.data["added_files"].append("../private.txt")
        self.save_manifest()
        self.assertIn("Unsafe manifest path", self.assert_run(1, "export"))


if __name__ == "__main__":
    unittest.main()
