"""USB mode: evidence arrives on a removable drive and the solution leaves on it.

A developer copies logs, configs, and command output from the failing server into a
``blacksite`` folder on a USB stick, microSD card, or external drive::

    <drive>/blacksite/
        api-502/                 one folder per incident
            incident.txt         optional: first line is the title, the rest the description
            nginx/error.log ...  anything else is evidence; .zip and .tar(.gz) are unpacked
            SOLUTION-20260927-2114/   written back by Blacksite on export

If ``blacksite/`` has no subfolders, the folder itself is one incident. Blacksite only
reads drives that carry this folder, never runs anything from them, and works on a copy
in a private sandbox, so the drive can be pulled at any time. After export the sandbox
is deleted.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import string
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from ._fs import replace
from .config import UsbSettings
from .evidence.store import ARTIFACTS_DIR, INCIDENT_FILE

SOURCE_FILE = "source.json"
SOLUTION_PREFIX = "SOLUTION-"
NOTE_FILES = {"incident.txt", "incident.md", "incident.json", "readme.txt", "readme.md"}
# Folders and files operating systems put on removable media; never evidence.
_SYSTEM_NAMES = {"system volume information", "$recycle.bin", "recycler", "lost+found", "found.000",
                 "desktop.ini", "thumbs.db", "autorun.inf"}
_ARCHIVES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
_CHUNK = 1 << 20


class UsbError(ValueError):
    """A drive or bundle problem the developer can act on."""


@dataclass(frozen=True)
class Drive:
    path: Path
    name: str   # the volume name, stable across insertions
    label: str  # for display; on Windows it includes the drive letter


@dataclass(frozen=True)
class Bundle:
    drive: Drive
    path: Path
    name: str
    relative: str  # path under the drive root, POSIX style, to find it again after reinsertion
    fingerprint: str
    solved: bool


# Drives ------------------------------------------------------------------------------

def list_drives(roots: tuple[str, ...] = ()) -> list[Drive]:
    """Mounted drives other than the system disk.

    With ``roots``, every subdirectory of each root counts as a drive (used for custom
    mount points and tests). Otherwise this platform's usual mount locations are used.
    """
    if roots:
        return _drives_under(Path(root) for root in roots)
    if sys.platform == "win32":
        return _windows_drives()
    if sys.platform == "darwin":
        return [drive for drive in _drives_under([Path("/Volumes")]) if not _is_system_volume(drive.path)]
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    parents = [Path("/media") / user, Path("/run/media") / user, Path("/media"), Path("/mnt")]
    return [drive for drive in _drives_under(parents) if os.path.ismount(drive.path)]


def _drives_under(parents: Any) -> list[Drive]:
    drives, seen = [], set()
    for parent in parents:
        try:
            children = sorted(parent.iterdir())
        except OSError:
            continue
        for child in children:
            try:
                if child.is_dir() and not child.name.startswith(".") and child.resolve() not in seen:
                    seen.add(child.resolve())
                    drives.append(Drive(child, child.name, child.name))
            except OSError:
                continue
    return drives


def _is_system_volume(path: Path) -> bool:
    try:
        return path.resolve() == Path("/").resolve() or os.path.samefile(path, "/")
    except OSError:
        return True


def _windows_drives() -> list[Drive]:  # pragma: no cover - exercised on Windows CI
    import ctypes

    kernel32 = ctypes.windll.kernel32
    system = os.environ.get("SYSTEMDRIVE", "C:").upper().rstrip("\\")
    mask = kernel32.GetLogicalDrives()
    drives = []
    for index, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << index) or f"{letter}:" == system:
            continue
        root = f"{letter}:\\"
        # 2 removable (USB sticks, SD cards), 3 fixed (USB hard drives report as fixed).
        if kernel32.GetDriveTypeW(root) not in (2, 3):
            continue
        name = ctypes.create_unicode_buffer(261)
        ok = kernel32.GetVolumeInformationW(root, name, 261, None, None, None, None, 0)
        if not ok:
            continue  # no medium in the reader
        volume = name.value or "Drive"
        drives.append(Drive(Path(root), volume, f"{volume} ({letter}:)"))
    return drives


# Bundles -----------------------------------------------------------------------------

def find_bundles(drive: Drive, marker: str) -> list[Bundle]:
    """Incident folders under the drive's marker folder (matched case-insensitively)."""
    try:
        root = next((entry for entry in drive.path.iterdir()
                     if entry.name.lower() == marker.lower() and entry.is_dir() and not entry.is_symlink()), None)
    except OSError:
        return []
    if root is None:
        return []
    try:
        folders = sorted(entry for entry in root.iterdir() if entry.is_dir() and not entry.is_symlink()
                         and not _ignored(entry.name) and not entry.name.upper().startswith(SOLUTION_PREFIX))
    except OSError:
        return []
    candidates = folders or [root]
    bundles = []
    for path in candidates:
        files = list(_evidence_files(path))
        if not files:
            continue
        stats = [(file, file.stat()) for file in files]
        digest = hashlib.sha256()
        for file, info in stats:
            digest.update(f"{file.relative_to(path).as_posix()}\0{info.st_size}\0{int(info.st_mtime)}\n".encode())
        newest = max(info.st_mtime for _, info in stats)
        solved = any(entry.is_dir() and entry.name.upper().startswith(SOLUTION_PREFIX) and entry.stat().st_mtime >= newest
                     for entry in path.iterdir())
        name = path.name if path != root else drive.label
        relative = path.relative_to(drive.path).as_posix()
        bundles.append(Bundle(drive, path, name, relative, digest.hexdigest()[:16], solved))
    return bundles


def _ignored(name: str) -> bool:
    lower = name.lower()
    return name.startswith((".", "._", "~$")) or lower in _SYSTEM_NAMES


def _evidence_files(root: Path) -> Iterator[Path]:
    """Regular files under ``root``, skipping symlinks, hidden files, and earlier solutions."""
    for current, dirs, files in os.walk(root, followlinks=False):
        here = Path(current)
        dirs[:] = sorted(name for name in dirs if not _ignored(name) and not name.upper().startswith(SOLUTION_PREFIX)
                         and not (here / name).is_symlink())
        for name in sorted(files):
            path = here / name
            if _ignored(name) or path.is_symlink() or not path.is_file():
                continue
            yield path


# Import ------------------------------------------------------------------------------

@dataclass
class _Budget:
    bytes_left: int
    files_left: int
    skipped: list[str]

    def take(self, size: int, label: str) -> bool:
        if self.files_left <= 0 or size > self.bytes_left:
            self.skipped.append(label)
            return False
        self.files_left -= 1
        self.bytes_left -= size
        return True


def import_bundle(bundle: Bundle, sandbox_root: Path, settings: UsbSettings) -> Path:
    """Copy a bundle into a new private sandbox incident and return its directory."""
    sandbox_root.mkdir(parents=True, exist_ok=True)
    _private(sandbox_root)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "-", bundle.name.lower()).strip("-")[:40] or "incident"
    target = sandbox_root / f"usb-{stamp}-{slug}"
    suffix = 1
    while target.exists():  # two drives can carry same-named folders
        suffix += 1
        target = sandbox_root / f"usb-{stamp}-{slug}-{suffix}"
    artifacts = target / ARTIFACTS_DIR
    artifacts.mkdir(parents=True)
    _private(target)
    budget = _Budget(settings.max_bytes, settings.max_files, [])
    copied: list[dict[str, Any]] = []
    notes: dict[str, str] = {}
    try:
        for source in _evidence_files(bundle.path):
            relative = source.relative_to(bundle.path)
            if len(relative.parts) == 1 and relative.name.lower() in NOTE_FILES:
                notes[relative.name.lower()] = source.read_text(encoding="utf-8", errors="replace")[:20_000]
                continue
            destination = artifacts.joinpath(*_safe_parts(relative.parts))
            if source.name.lower().endswith(_ARCHIVES):
                copied += _extract(source, destination.parent / _archive_stem(destination.name), artifacts,
                                   budget, relative.as_posix())
                continue
            if budget.take(source.stat().st_size, relative.as_posix()):
                copied.append({"path": destination.relative_to(artifacts).as_posix(), **_copy(source, destination)})
    except OSError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise UsbError(f"Could not read the drive: {exc}. Reinsert it and try again.") from None
    if not copied:
        shutil.rmtree(target, ignore_errors=True)
        raise UsbError(f"{bundle.relative} has no readable evidence files")

    title, description = _describe(notes, bundle.name)
    (target / INCIDENT_FILE).write_text(json.dumps(
        {"id": target.name, "title": title, "description": description}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    source = {
        "kind": "usb",
        "drive_name": bundle.drive.name,
        "drive_label": bundle.drive.label,
        "drive_path": str(bundle.drive.path),
        "bundle": bundle.relative,
        "fingerprint": bundle.fingerprint,
        "imported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": copied,
        "skipped": budget.skipped,
        "exported_to": None,
    }
    write_source(target, source)
    return target


def read_source(incident: Path) -> dict[str, Any] | None:
    try:
        data = json.loads((incident / SOURCE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("kind") == "usb" else None


def write_source(incident: Path, data: dict[str, Any]) -> None:
    tmp = incident / f".{SOURCE_FILE}.tmp"
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    replace(tmp, incident / SOURCE_FILE)


def locate_bundle(source: dict[str, Any], roots: tuple[str, ...] = ()) -> Path | None:
    """Where the incident's folder is now, if its drive is plugged in (letters can change)."""
    for drive in list_drives(roots):
        if drive.name == source.get("drive_name") or str(drive.path) == source.get("drive_path"):
            path = drive.path.joinpath(*PurePosixPath(source["bundle"]).parts)
            if path.is_dir():
                return path
    return None


def _describe(notes: dict[str, str], fallback: str) -> tuple[str, str]:
    if "incident.json" in notes:
        with contextlib.suppress(ValueError):
            data = json.loads(notes["incident.json"])
            if isinstance(data, dict) and data.get("title"):
                return str(data["title"])[:200], str(data.get("description", ""))[:5000]
    for name in ("incident.txt", "incident.md", "readme.txt", "readme.md"):
        text = notes.get(name, "").strip()
        if text:
            first, _, rest = text.partition("\n")
            return first.lstrip("# ").strip()[:200] or fallback, rest.strip()[:5000]
    return fallback, ""


def _copy(source: Path, destination: Path) -> dict[str, Any]:
    """Copy bytes while hashing; keep the modification time (year-less syslog relies on it)."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as reader, destination.open("wb") as writer:
        while chunk := reader.read(_CHUNK):
            digest.update(chunk)
            writer.write(chunk)
            size += len(chunk)
    shutil.copystat(source, destination, follow_symlinks=False)
    os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
    return {"bytes": size, "sha256": digest.hexdigest()}


def _extract(archive: Path, destination: Path, artifacts: Path, budget: _Budget,
             label: str) -> list[dict[str, Any]]:
    """Unpack an archive's regular files; entries escaping the folder are skipped (zip slip)."""
    copied: list[dict[str, Any]] = []
    try:
        if archive.name.lower().endswith(".zip"):
            with zipfile.ZipFile(archive) as bundle:
                for info in bundle.infolist():
                    parts = _member_parts(info.filename)
                    if info.is_dir() or not parts or info.flag_bits & 0x1:  # encrypted members are skipped
                        continue
                    if not budget.take(info.file_size, f"{label}!{info.filename}"):
                        continue
                    target = destination.joinpath(*parts)
                    with bundle.open(info) as reader:
                        copied.append({"path": target.relative_to(artifacts).as_posix(),
                                       **_write_limited(reader, target, info.file_size)})
        else:
            with tarfile.open(archive) as bundle:
                for member in bundle.getmembers():
                    parts = _member_parts(member.name)
                    if not member.isfile() or not parts:
                        continue  # links, devices, and directories are never created
                    if not budget.take(member.size, f"{label}!{member.name}"):
                        continue
                    reader = bundle.extractfile(member)
                    if reader is None:
                        continue
                    target = destination.joinpath(*parts)
                    with reader:
                        copied.append({"path": target.relative_to(artifacts).as_posix(),
                                       **_write_limited(reader, target, member.size)})
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        budget.skipped.append(f"{label} (unreadable archive: {exc})")
    return copied


def _write_limited(reader: Any, target: Path, declared: int) -> dict[str, Any]:
    """Write at most the declared size, so a lying header cannot fill the disk."""
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    with target.open("wb") as writer:
        while size < declared and (chunk := reader.read(min(_CHUNK, declared - size))):
            digest.update(chunk)
            writer.write(chunk)
            size += len(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}


def _member_parts(name: str) -> list[str]:
    """Safe path parts for an archive member, or [] when it would escape its folder."""
    parts = [part for part in re.split(r"[\\/]+", name) if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts) or re.match(r"^[A-Za-z]:", parts[0]):
        return []
    if any(_ignored(part) for part in parts):
        return []
    return _safe_parts(parts)


def _safe_parts(parts: Any) -> list[str]:
    """Names valid on Windows, macOS, and Linux file systems."""
    return [re.sub(r'[<>:"|?*\x00-\x1f]', "_", part).rstrip(" .") or "_" for part in parts]


def _archive_stem(name: str) -> str:
    lower = name.lower()
    for suffix in sorted(_ARCHIVES, key=len, reverse=True):
        if lower.endswith(suffix):
            return name[: -len(suffix)] or "archive"
    return name


def _private(path: Path) -> None:
    """Owner-only access where the platform supports it (POSIX)."""
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IRWXU)


# Export and wipe ---------------------------------------------------------------------

def write_solution(bundle_path: Path, files: dict[str, str]) -> Path:
    """Write the solution folder next to the evidence, flushed to the drive before returning."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = bundle_path / f"{SOLUTION_PREFIX}{stamp}"
    staging = bundle_path / f".{SOLUTION_PREFIX}{stamp}-{os.getpid()}.tmp"
    try:
        staging.mkdir()
        for name, content in files.items():
            path = staging / name
            with path.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        replace(staging, target)
        _fsync_directory(bundle_path)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise UsbError(f"Could not write to the drive: {exc}. Check that it is not read-only or full.") from None
    return target


def _fsync_directory(path: Path) -> None:
    """Flush the directory entry too, where the OS allows it (not on Windows)."""
    if os.name == "nt":
        return
    with contextlib.suppress(OSError):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def wipe(incident: Path) -> None:
    """Delete a sandbox incident: evidence, index, conversation, and guide.

    Files are overwritten with zeros first. On SSDs and flash that is best effort (wear
    levelling may keep old blocks), so the workstation should use full-disk encryption.
    """
    for current, _, files in os.walk(incident):
        for name in files:
            path = Path(current) / name
            with contextlib.suppress(OSError):
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
                size = path.stat().st_size
                with path.open("r+b") as stream:
                    zeros = bytes(min(size, _CHUNK))
                    written = 0
                    while written < size:
                        stream.write(zeros[: min(len(zeros), size - written)])
                        written += min(len(zeros), size - written)
                    stream.flush()
                    os.fsync(stream.fileno())

    def retry_writable(function: Any, path: str, *_: Any) -> None:
        os.chmod(path, stat.S_IRWXU)
        function(path)

    if sys.version_info >= (3, 12):
        shutil.rmtree(incident, onexc=retry_writable)
    else:  # pragma: no cover
        shutil.rmtree(incident, onerror=retry_writable)
