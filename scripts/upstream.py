#!/usr/bin/env python3
"""Rebuild or export Blacksite's explicit overlay on a pinned HolmesGPT checkout."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile


class WorkflowError(Exception):
    pass


def git(checkout, *arguments, check=True):
    result = subprocess.run(
        ["git", "-c", "core.filemode=true", "-c", "core.autocrlf=false", *arguments],
        cwd=checkout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise WorkflowError(f"git {arguments[0]} failed: {detail}")
    return result


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise WorkflowError(f"Invalid manifest path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(
        part in ("..", ".git") for part in path.parts
    ) or value == ".":
        raise WorkflowError(f"Unsafe manifest path: {value!r}")
    return value


def safe_path(base, relative):
    """Reject symlinks, including symlinked parent directories, before file access."""
    path = base
    components = PurePosixPath(relative).parts
    for index, component in enumerate(components):
        path = path / component
        if path.is_symlink():
            raise WorkflowError(f"Symlinks are not supported: {path}")
        if index < len(components) - 1 and path.exists() and not path.is_dir():
            raise WorkflowError(f"Expected a parent directory: {path}")
    return path


def manifest(root):
    with (root / "upstream.json").open() as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise WorkflowError("upstream.json must contain an object")
    if not isinstance(data.get("repository"), str) or not data["repository"]:
        raise WorkflowError("upstream.json requires a repository URL")
    if not isinstance(data.get("commit"), str) or not re.fullmatch(
        r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?", data["commit"]
    ):
        raise WorkflowError("upstream.json requires a full pinned commit SHA")
    data["commit"] = data["commit"].lower()
    data["patch"] = relative_path(data.get("patch"))
    all_paths = []
    for key in ("modified_files", "added_files"):
        if not isinstance(data.get(key), list):
            raise WorkflowError(f"upstream.json requires a {key} list")
        data[key] = sorted(relative_path(path) for path in data[key])
        all_paths.extend(data[key])
    if len(set(all_paths)) != len(all_paths):
        raise WorkflowError("Manifest file lists contain duplicate or overlapping paths")
    return data


def overlay_files(root, expected, require_all):
    overlay = safe_path(root, "overlay")
    actual = set()
    if overlay.exists():
        if not overlay.is_dir():
            raise WorkflowError(f"Expected a directory: {overlay}")
        for directory, directories, files in os.walk(overlay, followlinks=False):
            for name in directories + files:
                path = Path(directory) / name
                if path.is_symlink():
                    raise WorkflowError(f"Symlinks are not supported: {path}")
            for name in files:
                path = Path(directory) / name
                if not path.is_file():
                    raise WorkflowError(f"Expected a regular file: {path}")
                actual.add(path.relative_to(overlay).as_posix())
    extra = actual - set(expected)
    missing = set(expected) - actual if require_all else set()
    if extra or missing:
        problems = []
        if extra:
            problems.append("Unlisted overlay files: " + ", ".join(sorted(extra)))
        if missing:
            problems.append("Missing overlay files: " + ", ".join(sorted(missing)))
        raise WorkflowError("\n".join(problems))
    return overlay


def verify_checkout(checkout, pin):
    if not checkout.is_dir():
        raise WorkflowError(f"Checkout does not exist: {checkout}; run prepare first")
    top = git(checkout, "rev-parse", "--show-toplevel").stdout.decode().strip()
    if Path(top).resolve() != checkout.resolve():
        raise WorkflowError(f"Checkout must be a Git repository root: {checkout}")
    head = git(checkout, "rev-parse", "HEAD").stdout.decode().strip()
    if head != pin:
        raise WorkflowError(f"Checkout HEAD is {head}; expected pinned commit {pin}. No changes made.")


def verify_manifest_paths(checkout, data):
    pinned = {}
    for record in git(checkout, "ls-tree", "-r", "-z", data["commit"]).stdout.split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            pinned[name.decode("utf-8", "surrogateescape")] = metadata.split()[0]
    regular = {name for name, mode in pinned.items() if mode in (b"100644", b"100755")}
    invalid = (set(data["modified_files"]) - regular) | (set(data["added_files"]) & pinned.keys())
    if invalid:
        raise WorkflowError("Manifest paths have the wrong added/modified classification: "
                            + ", ".join(sorted(invalid)))
    for name in data["modified_files"]:
        safe_path(checkout, name)


def same_file(left, right):
    return (
        right.is_file()
        and left.read_bytes() == right.read_bytes()
        and bool(left.stat().st_mode & 0o111) == bool(right.stat().st_mode & 0o111)
    )


def write_file(destination, content, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".blacksite-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def copy_file(source, destination):
    write_file(destination, source.read_bytes(), 0o755 if source.stat().st_mode & 0o111 else 0o644)


def validate_patch(root, patch, allowed):
    if not patch.is_file():
        raise WorkflowError(f"Patch file is missing: {patch}")
    if not patch.stat().st_size:
        return
    result = git(root, "apply", "--numstat", "-z", str(patch))
    names = {record.split(b"\t", 2)[2].decode("utf-8", "surrogateescape")
             for record in result.stdout.split(b"\0") if record}
    unknown = names - set(allowed)
    if unknown:
        raise WorkflowError("Patch contains unlisted paths: " + ", ".join(sorted(unknown)))


def prepare(root, checkout, data):
    overlay = overlay_files(root, data["added_files"], require_all=True)
    patch = safe_path(root, data["patch"])
    validate_patch(root, patch, data["modified_files"])
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        git(root, "init", "--", str(checkout))
        git(checkout, "remote", "add", "origin", data["repository"])
        git(checkout, "fetch", "--depth=1", "origin", data["commit"])
        git(checkout, "checkout", "--detach", data["commit"])
    verify_checkout(checkout, data["commit"])
    verify_manifest_paths(checkout, data)

    copies = []
    for name in data["added_files"]:
        source = safe_path(overlay, name)
        destination = safe_path(checkout, name)
        if destination.exists():
            if not same_file(source, destination):
                raise WorkflowError(f"Local overlay differs: {name}. Export or save your changes first.")
        else:
            copies.append((source, destination))

    apply_patch = False
    if patch.stat().st_size:
        if git(checkout, "apply", "--reverse", "--check", str(patch), check=False).returncode:
            result = git(checkout, "apply", "--check", str(patch), check=False)
            if result.returncode:
                raise WorkflowError("Patch neither applies cleanly nor is already applied. "
                                    "Local changes were preserved.\n" + result.stderr.decode(errors="replace").strip())
            apply_patch = True
    if apply_patch:
        git(checkout, "apply", "--whitespace=nowarn", str(patch))
    for source, destination in copies:
        copy_file(source, destination)
    print(f"Prepared {checkout} at {data['commit']}" if apply_patch or copies else
          f"Already prepared: {checkout}")


def export(root, checkout, data, check):
    verify_checkout(checkout, data["commit"])
    verify_manifest_paths(checkout, data)
    allowed = set(data["modified_files"] + data["added_files"])
    changed = git(checkout, "diff", "--no-renames", "--name-only", "-z", data["commit"], "--").stdout
    untracked = git(checkout, "ls-files", "--others", "--exclude-standard", "-z").stdout
    unknown = {name.decode("utf-8", "surrogateescape") for name in
               (changed + untracked).split(b"\0") if name} - allowed
    if unknown:
        raise WorkflowError("Unlisted checkout changes; review and explicitly add approved paths to "
                            "upstream.json before exporting:\n  " + "\n  ".join(sorted(unknown)))

    overlay = overlay_files(root, data["added_files"], require_all=False)
    sources = []
    for name in data["added_files"]:
        source = safe_path(checkout, name)
        destination = safe_path(overlay, name)
        if not source.is_file():
            raise WorkflowError(f"Added file is missing or is not a regular file: {name}")
        if destination.exists() and not destination.is_file():
            raise WorkflowError(f"Expected a regular overlay file: {destination}")
        sources.append((source, destination))
    patch = safe_path(root, data["patch"])
    if patch.exists() and not patch.is_file():
        raise WorkflowError(f"Expected a patch file: {patch}")
    diff = git(checkout, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-renames",
               "--no-textconv", "--no-color", "--src-prefix=a/", "--dst-prefix=b/", "--unified=3",
               "--diff-algorithm=myers", "--no-indent-heuristic", data["commit"], "--",
               *data["modified_files"]).stdout if data["modified_files"] else b""
    stale = [data["patch"]] if not patch.is_file() or patch.read_bytes() != diff else []
    stale.extend("overlay/" + destination.relative_to(overlay).as_posix()
                 for source, destination in sources if not same_file(source, destination))
    if check:
        if stale:
            raise WorkflowError("Published files are stale; run export:\n  " + "\n  ".join(stale))
        print("Published patch and overlay match the checkout.")
        return
    if data["patch"] in stale:
        write_file(patch, diff)
    for source, destination in sources:
        if not same_file(source, destination):
            copy_file(source, destination)
    print(f"Exported {len(data['modified_files'])} patch paths and {len(sources)} overlay files.")


def main(argv=None, root=None):
    root = Path(root).resolve() if root is not None else Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "export"):
        command = commands.add_parser(action)
        command.add_argument("--checkout", type=Path, default=root / "holmesgpt",
                             help="HolmesGPT Git root (default: ./holmesgpt)")
        if action == "export":
            command.add_argument("--check", action="store_true", help="Fail if published files differ")
    arguments = parser.parse_args(argv)
    try:
        data = manifest(root)
        checkout = arguments.checkout.absolute()
        if checkout.is_symlink():
            raise WorkflowError(f"Checkout cannot be a symlink: {checkout}")
        if arguments.action == "prepare":
            prepare(root, checkout, data)
        else:
            export(root, checkout, data, arguments.check)
    except (WorkflowError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
