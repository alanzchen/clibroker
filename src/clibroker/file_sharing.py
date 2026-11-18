"""Safe file sharing for configured tool host directories."""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import hashlib
import logging
import os
import shutil
import stat
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Literal
from urllib.parse import quote

from .config import Config

ShareAccess = Literal["read", "read_write"]
logger = logging.getLogger("clibroker.file_sharing")
_MAX_LIST_ENTRIES = 10_000
_DEFAULT_INLINE_READ_BYTES = 1_048_576


class FileShareError(Exception):
    """Base class for file sharing errors."""

    status_code = 400


class FileShareNotFound(FileShareError):
    """Raised when a tool, share, or path does not exist."""

    status_code = 404


class FileShareForbidden(FileShareError):
    """Raised when the caller is not authorized for a share or path."""

    status_code = 403


class FileShareConflict(FileShareError):
    """Raised when an operation conflicts with existing filesystem state."""

    status_code = 409


class FileShareTooLarge(FileShareError):
    """Raised when a file exceeds the configured sharing byte limit."""

    status_code = 413


@dataclass(frozen=True)
class ResolvedFileShare:
    """A share root after applying defaults and explicit config."""

    tool_name: str
    name: str
    root: Path
    access: ShareAccess
    max_file_bytes: int
    max_inline_read_bytes: int | None = None


class FileShareService:
    """Resolves shares, checks RBAC, and performs safe file operations."""

    def __init__(self, config: Config) -> None:
        self._tool_allow_rules: dict[str, set[str]] = {}
        self._shares: dict[str, dict[str, ResolvedFileShare]] = {}

        for tool_name, tool_cfg in config.tools.items():
            self._tool_allow_rules[tool_name] = {
                rule.id for rule in tool_cfg.rules if rule.effect == "allow"
            }

            tool_shares: dict[str, ResolvedFileShare] = {}
            sharing_cfg = tool_cfg.file_sharing
            if (
                sharing_cfg.expose_working_dir
                and tool_cfg.working_dir
                and Path(tool_cfg.working_dir).is_absolute()
            ):
                tool_shares["working_dir"] = ResolvedFileShare(
                    tool_name=tool_name,
                    name="working_dir",
                    root=Path(tool_cfg.working_dir).resolve(strict=False),
                    access="read",
                    max_file_bytes=sharing_cfg.max_file_bytes,
                    max_inline_read_bytes=sharing_cfg.max_inline_read_bytes,
                )

            for share in sharing_cfg.shares:
                tool_shares[share.name] = ResolvedFileShare(
                    tool_name=tool_name,
                    name=share.name,
                    root=Path(share.path).resolve(strict=False),
                    access=share.access,
                    max_file_bytes=sharing_cfg.max_file_bytes,
                    max_inline_read_bytes=sharing_cfg.max_inline_read_bytes,
                )

            self._shares[tool_name] = tool_shares

    def tool_has_access(
        self,
        tool_name: str,
        allowed_rules: set[str] | list[str] | None,
    ) -> bool:
        """Return whether allowed rule IDs grant file access to a tool."""

        if tool_name not in self._tool_allow_rules:
            return False
        if allowed_rules is None:
            return True
        return bool(self._tool_allow_rules[tool_name] & set(allowed_rules))

    def get_client_shares(
        self,
        tool_name: str,
        allowed_rules: set[str] | list[str] | None,
    ) -> list[dict[str, str]]:
        """Return token-scoped share descriptors safe for client discovery."""

        if not self.tool_has_access(tool_name, allowed_rules):
            return []
        return [
            {
                "name": share.name,
                "access": share.access,
                "url": self.url_for(share.tool_name, share.name, "."),
            }
            for share in self._shares.get(tool_name, {}).values()
        ]

    def get_share(
        self,
        tool_name: str,
        share_name: str,
        allowed_rules: set[str] | list[str] | None,
    ) -> ResolvedFileShare:
        """Return an authorized share or raise a typed error."""

        if tool_name not in self._shares:
            raise FileShareNotFound(f"Unknown tool '{tool_name}'")
        if not self.tool_has_access(tool_name, allowed_rules):
            raise FileShareForbidden(
                f"Not authorized for file shares on tool '{tool_name}'"
            )

        try:
            return self._shares[tool_name][share_name]
        except KeyError as exc:
            raise FileShareNotFound(
                f"Unknown file share '{share_name}' for tool '{tool_name}'"
            ) from exc

    def url_for(self, tool_name: str, share_name: str, path: str) -> str:
        """Build a relative authenticated file URL with no embedded secrets."""

        base = f"/files/{quote(tool_name, safe='')}/{quote(share_name, safe='')}"
        normalized = _normalize_client_path(path)[1]
        if normalized == ".":
            return base
        return f"{base}/{quote(normalized, safe='/')}"

    def list_dir(
        self,
        share: ResolvedFileShare,
        path: str = ".",
        *,
        recursive: bool = False,
    ) -> dict[str, Any]:
        root, candidate, resolved, rel_path = self._existing_path(share, path)
        if not resolved.is_dir():
            raise FileShareError(f"Path '{rel_path}' is not a directory")

        entries = []
        truncated = False
        for entry in self._iter_entries(root, resolved, recursive=recursive):
            if len(entries) >= _MAX_LIST_ENTRIES:
                truncated = True
                break
            try:
                entries.append(self._metadata(share, root, entry))
            except (FileShareError, OSError):
                continue

        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "path": rel_path,
            "url": self.url_for(share.tool_name, share.name, rel_path),
            "recursive": recursive,
            "truncated": truncated,
            "max_entries": _MAX_LIST_ENTRIES,
            "entries": entries,
        }

    def stat_path(self, share: ResolvedFileShare, path: str = ".") -> dict[str, Any]:
        root, candidate, resolved, rel_path = self._existing_path(share, path)
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "entry": self._metadata(share, root, candidate, resolved=resolved),
            "path": rel_path,
        }

    def open_for_download(
        self,
        share: ResolvedFileShare,
        path: str = ".",
    ) -> tuple[BinaryIO | None, str, os.stat_result]:
        """Open and validate the actual object; callers must close returned files."""
        root, _, resolved, rel_path = self._existing_path(share, path)
        with self._open_contained_path(root, resolved, rel_path) as (fd, snapshot):
            if stat.S_ISDIR(snapshot.st_mode):
                return None, rel_path, snapshot
            if not stat.S_ISREG(snapshot.st_mode):
                raise FileShareError(f"Path '{rel_path}' is not a file or directory")
            if _exceeds_file_limit(snapshot.st_size, share.max_file_bytes):
                raise FileShareTooLarge(
                    f"File '{rel_path}' exceeds max_file_bytes ({share.max_file_bytes})"
                )
            return os.fdopen(os.dup(fd), "rb"), rel_path, snapshot

    def prepare_artifact_dir(
        self,
        share: ResolvedFileShare,
        path: str,
    ) -> tuple[Path, str]:
        """Create and return a safe server-side artifact directory."""

        root = self._resolved_root(share)
        parts, rel_path = _normalize_client_path(path)
        if rel_path == ".":
            raise FileShareError("Artifact directory must not be the share root")

        candidate = root.joinpath(*parts)
        resolved = candidate.resolve(strict=False)
        if not _is_relative_to(resolved, root):
            raise FileShareForbidden("Path escapes the file share root")
        if resolved == root:
            raise FileShareError("Artifact directory must not be the share root")
        with self._directory_fd(root, resolved.parent, create=True) as parent_fd:
            with self._os_errors("create artifact directory", rel_path):
                os.mkdir(resolved.name, dir_fd=parent_fd)
        return resolved, rel_path

    def artifact_metadata(
        self,
        share: ResolvedFileShare,
        path: str,
        *,
        recursive: bool = False,
    ) -> list[dict[str, Any]]:
        """Return metadata for files under an artifact directory."""

        root, _candidate, resolved, _rel_path = self._existing_path(share, path)
        if not resolved.is_dir():
            raise FileShareError("Artifact path is not a directory")

        artifacts: list[dict[str, Any]] = []
        for entry in self._iter_entries(root, resolved, recursive=recursive):
            canonical = self._checked_resolve(entry, root)
            metadata = self._metadata(share, root, entry, resolved=canonical)
            if metadata["type"] != "file":
                continue
            with self._open_regular_file(root, canonical, metadata["path"]) as (
                stream,
                snapshot,
            ):
                if _exceeds_file_limit(snapshot.st_size, share.max_file_bytes):
                    continue
                digest = hashlib.sha256()
                remaining = snapshot.st_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise FileShareConflict(
                            "Artifact changed while being collected"
                        )
                    digest.update(chunk)
                    remaining -= len(chunk)
                current = os.fstat(stream.fileno())
                if (current.st_size, current.st_mtime_ns) != (
                    snapshot.st_size,
                    snapshot.st_mtime_ns,
                ):
                    raise FileShareConflict("Artifact changed while being collected")
                metadata = self._metadata_from_stat(share, metadata["path"], snapshot)
                metadata["sha256"] = digest.hexdigest()
                artifacts.append(metadata)

        artifacts.sort(key=lambda item: item["path"])
        return artifacts

    def read_file(
        self,
        share: ResolvedFileShare,
        path: str,
        *,
        encoding: str = "auto",
    ) -> dict[str, Any]:
        root, _candidate, resolved, rel_path = self._existing_path(share, path)
        data = self._read_contained_bytes(share, root, resolved, rel_path)
        size = len(data)
        if encoding == "auto":
            try:
                content = data.decode("utf-8")
                response_encoding = "utf-8"
            except UnicodeDecodeError:
                content = base64.b64encode(data).decode("ascii")
                response_encoding = "base64"
        elif encoding == "utf-8":
            content = data.decode("utf-8")
            response_encoding = "utf-8"
        elif encoding == "base64":
            content = base64.b64encode(data).decode("ascii")
            response_encoding = "base64"
        else:
            raise FileShareError("encoding must be one of: auto, utf-8, base64")

        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "path": rel_path,
            "encoding": response_encoding,
            "size": size,
            "content": content,
            "download_url": self.url_for(share.tool_name, share.name, rel_path),
        }

    def _read_contained_bytes(
        self,
        share: ResolvedFileShare,
        root: Path,
        resolved: Path,
        rel_path: str,
    ) -> bytes:
        """Use the same pinned descriptor boundary as downloads and hashing."""
        read_limit, limit_name = _inline_read_limit(share)
        with self._open_regular_file(root, resolved, rel_path) as (stream, snapshot):
            if snapshot.st_size > read_limit:
                raise FileShareTooLarge(
                    f"File '{rel_path}' exceeds {limit_name} ({read_limit})"
                )
            data = stream.read(read_limit + 1)
        if len(data) > read_limit:
            raise FileShareTooLarge(
                f"File '{rel_path}' exceeds {limit_name} ({read_limit})"
            )
        return data

    def write_file(
        self,
        share: ResolvedFileShare,
        path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        overwrite: bool = True,
    ) -> dict[str, Any]:
        self._require_write(share)
        data = self._decode_content(content, encoding)
        if _exceeds_file_limit(len(data), share.max_file_bytes):
            raise FileShareTooLarge(
                f"Write exceeds max_file_bytes ({share.max_file_bytes})"
            )
        root, candidate, rel_path = self._destination_path(share, path)
        if rel_path == ".":
            raise FileShareError("Cannot write to the share root")

        # Preserve supported in-share symlinks, but never reopen a checked
        # pathname. Only the canonical parent descriptor reaches the OS call.
        if candidate.exists() or candidate.is_symlink():
            if not overwrite:
                raise FileShareConflict(f"Path '{rel_path}' already exists")
            target = self._checked_resolve(candidate, root)
            if target.is_dir():
                raise FileShareConflict(f"Path '{rel_path}' is a directory")
        else:
            target = self._checked_existing_dir(candidate.parent, root) / candidate.name

        with self._directory_fd(root, target.parent) as parent_fd:
            temporary = f".clibroker-{uuid.uuid4().hex}.tmp"
            with self._os_errors("write", rel_path):
                try:
                    existing = os.stat(
                        target.name, dir_fd=parent_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    existing = None
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o666,
                    dir_fd=parent_fd,
                )
                try:
                    with os.fdopen(fd, "wb") as stream:
                        if existing is not None and stat.S_ISREG(existing.st_mode):
                            os.fchmod(stream.fileno(), stat.S_IMODE(existing.st_mode))
                        stream.write(data)
                        stream.flush()
                        snapshot = os.fstat(stream.fileno())
                    if overwrite:
                        os.replace(
                            temporary,
                            target.name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                        )
                    else:
                        _rename_noreplace(parent_fd, temporary, parent_fd, target.name)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "entry": self._metadata_from_stat(share, rel_path, snapshot),
        }

    def mkdir(
        self,
        share: ResolvedFileShare,
        path: str,
        *,
        parents: bool = True,
    ) -> dict[str, Any]:
        self._require_write(share)
        root, candidate, rel_path = self._destination_path(share, path)
        target = candidate.resolve(strict=False)
        if not _is_relative_to(target, root):
            raise FileShareForbidden("Path escapes the file share root")
        if parents:
            with self._directory_fd(root, target, create=True) as fd:
                snapshot = os.fstat(fd)
        elif target == root:
            with self._directory_fd(root, root) as fd:
                snapshot = os.fstat(fd)
        else:
            with self._directory_fd(root, target.parent) as parent_fd:
                with self._os_errors("create directory", rel_path):
                    try:
                        os.mkdir(target.name, dir_fd=parent_fd)
                    except FileExistsError:
                        pass
                    fd = os.open(target.name, _directory_flags(), dir_fd=parent_fd)
                    try:
                        snapshot = os.fstat(fd)
                    finally:
                        os.close(fd)
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "entry": self._metadata_from_stat(share, rel_path, snapshot),
        }

    def move(
        self,
        share: ResolvedFileShare,
        source_path: str,
        destination_path: str,
        *,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        self._require_write(share)
        root, source, _, source_rel = self._existing_path(share, source_path)
        _, destination, destination_rel = self._destination_path(
            share, destination_path
        )
        if source_rel == "." or destination_rel == ".":
            raise FileShareError("Cannot move the share root or move to it")
        source_parent = self._checked_existing_dir(source.parent, root)
        destination_parent = self._checked_existing_dir(destination.parent, root)
        # An existing destination symlink outside the share remains forbidden.
        if destination.exists() or destination.is_symlink():
            self._checked_resolve(destination, root)
        with self._directory_fd(root, source_parent) as source_fd:
            with self._directory_fd(root, destination_parent) as destination_fd:
                with self._os_errors("move", source_rel):
                    if (
                        source_parent == destination_parent
                        and source.name == destination.name
                    ):
                        if not overwrite:
                            raise FileShareConflict(
                                f"Path '{destination_rel}' already exists"
                            )
                    elif overwrite:
                        os.replace(
                            source.name,
                            destination.name,
                            src_dir_fd=source_fd,
                            dst_dir_fd=destination_fd,
                        )
                    else:
                        _rename_noreplace(
                            source_fd, source.name, destination_fd, destination.name
                        )
                    snapshot = os.stat(
                        destination.name, dir_fd=destination_fd, follow_symlinks=False
                    )
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "source_path": source_rel,
            "destination_path": destination_rel,
            "entry": self._metadata_from_stat(share, destination_rel, snapshot),
        }

    def delete(
        self,
        share: ResolvedFileShare,
        path: str,
        *,
        recursive: bool = False,
    ) -> dict[str, Any]:
        self._require_write(share)
        root, candidate, _, rel_path = self._existing_path(share, path)
        if rel_path == ".":
            raise FileShareError("Cannot delete the share root")
        parent = self._checked_existing_dir(candidate.parent, root)
        with self._directory_fd(root, parent) as parent_fd:
            with self._os_errors("delete", rel_path):
                snapshot = os.stat(
                    candidate.name, dir_fd=parent_fd, follow_symlinks=False
                )
                if stat.S_ISDIR(snapshot.st_mode):
                    if recursive:
                        if not shutil.rmtree.avoids_symlink_attacks:
                            raise FileShareError(
                                "Safe recursive deletes require descriptor support"
                            )
                        shutil.rmtree(candidate.name, dir_fd=parent_fd)
                    else:
                        os.rmdir(candidate.name, dir_fd=parent_fd)
                else:
                    os.unlink(candidate.name, dir_fd=parent_fd)
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "deleted": rel_path,
            "recursive": recursive,
        }

    @contextmanager
    def _os_errors(self, action: str, rel_path: str):
        try:
            yield
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise FileShareForbidden("Path changed or contains a symlink") from exc
            if exc.errno == errno.ENOENT:
                raise FileShareNotFound(f"Path '{rel_path}' was not found") from exc
            if exc.errno in (errno.EEXIST, errno.ENOTEMPTY, errno.EISDIR):
                raise FileShareConflict(
                    f"Path '{rel_path}' conflicts with an existing entry"
                ) from exc
            self._raise_os_error(action, rel_path, exc)

    @contextmanager
    def _directory_fd(self, root: Path, directory: Path, *, create: bool = False):
        """Pin canonical ancestors and operate relative to them, never by path again."""
        if os.name != "posix" or not all(
            hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
        ):
            raise FileShareError(
                "Safe file operations require POSIX descriptor support"
            )
        relative = directory.relative_to(root).parts
        fd = None
        with self._os_errors("open directory", "."):
            try:
                fd = os.open(root.anchor, _directory_flags())
                for part in root.parts[1:]:
                    child_fd = os.open(part, _directory_flags(), dir_fd=fd)
                    os.close(fd)
                    fd = child_fd
                for part in relative:
                    if create:
                        try:
                            os.mkdir(part, dir_fd=fd)
                        except FileExistsError:
                            pass
                    child_fd = os.open(part, _directory_flags(), dir_fd=fd)
                    os.close(fd)
                    fd = child_fd
                yield fd
            finally:
                if fd is not None:
                    os.close(fd)

    @contextmanager
    def _open_contained_path(self, root: Path, resolved: Path, rel_path: str):
        parent = resolved.parent if resolved != root else root
        with self._directory_fd(root, parent) as parent_fd:
            with self._os_errors("read", rel_path):
                fd = os.open(
                    resolved.name if resolved != root else ".",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent_fd,
                )
                try:
                    yield fd, os.fstat(fd)
                finally:
                    os.close(fd)

    @contextmanager
    def _open_regular_file(self, root: Path, resolved: Path, rel_path: str):
        with self._open_contained_path(root, resolved, rel_path) as (fd, snapshot):
            if not stat.S_ISREG(snapshot.st_mode):
                raise FileShareError(f"Path '{rel_path}' is not a file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                yield stream, snapshot

    def _require_write(self, share: ResolvedFileShare) -> None:
        if share.access != "read_write":
            raise FileShareForbidden(f"Share '{share.name}' is read-only")

    def _existing_path(
        self,
        share: ResolvedFileShare,
        path: str,
    ) -> tuple[Path, Path, Path, str]:
        root = self._resolved_root(share)
        parts, rel_path = _normalize_client_path(path)
        candidate = root.joinpath(*parts)
        try:
            resolved = self._checked_resolve(candidate, root)
        except FileNotFoundError as exc:
            raise FileShareNotFound(f"Path '{rel_path}' was not found") from exc
        return root, candidate, resolved, rel_path

    def _destination_path(
        self,
        share: ResolvedFileShare,
        path: str,
    ) -> tuple[Path, Path, str]:
        root = self._resolved_root(share)
        parts, rel_path = _normalize_client_path(path)
        return root, root.joinpath(*parts), rel_path

    def _resolved_root(self, share: ResolvedFileShare) -> Path:
        # Resolve configured symlinks once at service construction. A later
        # replacement must not redefine which host directory is authorized.
        root = share.root
        if not root.exists():
            raise FileShareNotFound(f"File share root for '{share.name}' was not found")
        if root.is_symlink():
            raise FileShareForbidden("File share root changed to a symlink")
        if not root.is_dir():
            raise FileShareError(
                f"File share root for '{share.name}' is not a directory"
            )
        return root

    def _checked_resolve(self, path: Path, root: Path) -> Path:
        resolved = path.resolve(strict=True)
        if not _is_relative_to(resolved, root):
            raise FileShareForbidden("Path escapes the file share root")
        return resolved

    def _checked_existing_dir(self, path: Path, root: Path) -> Path:
        try:
            resolved = self._checked_resolve(path, root)
        except FileNotFoundError as exc:
            raise FileShareNotFound(
                f"Parent directory '{path.name}' was not found"
            ) from exc
        if not resolved.is_dir():
            raise FileShareConflict(f"Parent path '{path.name}' is not a directory")
        return resolved

    def _iter_entries(
        self, root: Path, directory: Path, *, recursive: bool
    ) -> Iterator[Path]:
        stack = [directory]
        while stack:
            current = stack.pop()
            try:
                with self._directory_fd(root, current) as fd:
                    listing_fd = os.open(
                        ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                    )
                    try:
                        children = sorted(os.listdir(listing_fd))
                    finally:
                        os.close(listing_fd)
                    for name in children:
                        child = current / name
                        yield child
                        snapshot = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if recursive and stat.S_ISDIR(snapshot.st_mode):
                            stack.append(child)
            except (OSError, FileShareError):
                logger.warning("file_share_list_failed", exc_info=True)
                continue
            if not recursive:
                break

    def _metadata(
        self,
        share: ResolvedFileShare,
        root: Path,
        path: Path,
        *,
        resolved: Path | None = None,
    ) -> dict[str, Any]:
        canonical = resolved or self._checked_resolve(path, root)
        rel_path = "." if path == root else path.relative_to(root).as_posix()
        with self._directory_fd(
            root, canonical.parent if canonical != root else root
        ) as fd:
            with self._os_errors("stat", rel_path):
                snapshot = os.stat(
                    canonical.name if canonical != root else ".",
                    dir_fd=fd,
                    follow_symlinks=False,
                )
        return self._metadata_from_stat(share, rel_path, snapshot)

    def _metadata_from_stat(
        self, share: ResolvedFileShare, rel_path: str, snapshot: os.stat_result
    ) -> dict[str, Any]:
        if stat.S_ISDIR(snapshot.st_mode):
            kind, size = "directory", None
        elif stat.S_ISREG(snapshot.st_mode):
            kind, size = "file", snapshot.st_size
        else:
            kind, size = "other", None
        payload: dict[str, Any] = {
            "name": "." if rel_path == "." else PurePosixPath(rel_path).name,
            "path": rel_path,
            "type": kind,
            "size": size,
            "modified": snapshot.st_mtime,
            "url": self.url_for(share.tool_name, share.name, rel_path),
        }
        if kind == "file":
            payload["download_url"] = payload["url"]
        return payload

    def _decode_content(self, content: str, encoding: str) -> bytes:
        if encoding == "utf-8":
            return content.encode("utf-8")
        if encoding == "base64":
            try:
                return base64.b64decode(content.encode("ascii"), validate=True)
            except (UnicodeEncodeError, binascii.Error) as exc:
                raise FileShareError("content is not valid base64") from exc
        raise FileShareError("encoding must be one of: utf-8, base64")

    def _raise_os_error(
        self,
        action: str,
        rel_path: str,
        exc: OSError,
        error_cls: type[FileShareError] = FileShareError,
    ) -> None:
        logger.warning(
            "file_share_os_error",
            exc_info=True,
            extra={"action": action, "path": rel_path, "errno": exc.errno},
        )
        suffix = f" (errno {exc.errno})" if exc.errno is not None else ""
        raise error_cls(f"Failed to {action} '{rel_path}'{suffix}") from exc


def _normalize_client_path(path: str) -> tuple[tuple[str, ...], str]:
    if path is None or path == "":
        path = "."
    if "\x00" in path:
        raise FileShareForbidden("Path contains a NUL byte")
    if "\\" in path:
        raise FileShareForbidden("Path must use '/' separators")

    pure = PurePosixPath(path)
    if pure.is_absolute():
        raise FileShareForbidden("Path must be relative")

    parts: list[str] = []
    for part in pure.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise FileShareForbidden("Path must not contain '..'")
        parts.append(part)

    rel_path = "/".join(parts) if parts else "."
    return tuple(parts), rel_path


def _directory_flags() -> int:
    return getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW


def _rename_noreplace(
    source_fd: int, source: str, destination_fd: int, destination: str
) -> None:
    """Use the OS's atomic no-replace primitive, including for directories.

    There is no race-free exists()+rename fallback. Unsupported hosts fail
    closed instead of silently overwriting a concurrently created target.
    """
    if not sys.platform.startswith("linux"):
        raise FileShareError(
            "Atomic no-overwrite moves require Linux renameat2 support"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise FileShareError("Atomic no-overwrite moves require renameat2 support")
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    if (
        rename(
            source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _exceeds_file_limit(size: int, max_file_bytes: int) -> bool:
    """A configured zero disables the per-file quota."""
    return max_file_bytes > 0 and size > max_file_bytes


def _inline_read_limit(share: ResolvedFileShare) -> tuple[int, str]:
    """Keep buffered reads bounded even when the per-file quota is disabled."""
    inline_limit = share.max_inline_read_bytes
    if inline_limit is None:
        inline_limit = share.max_file_bytes or _DEFAULT_INLINE_READ_BYTES
    if share.max_file_bytes > 0 and share.max_file_bytes <= inline_limit:
        return share.max_file_bytes, "max_file_bytes"
    return inline_limit, "max_inline_read_bytes"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
