"""Safe file sharing for configured tool host directories."""

from __future__ import annotations

import base64
import binascii
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import quote

from .config import Config

ShareAccess = Literal["read", "read_write"]


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
                    root=Path(tool_cfg.working_dir),
                    access="read",
                    max_file_bytes=sharing_cfg.max_file_bytes,
                )

            for share in sharing_cfg.shares:
                tool_shares[share.name] = ResolvedFileShare(
                    tool_name=tool_name,
                    name=share.name,
                    root=Path(share.path),
                    access=share.access,
                    max_file_bytes=sharing_cfg.max_file_bytes,
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
        for entry in self._iter_entries(resolved, recursive=recursive):
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

    def local_path_for_read(
        self,
        share: ResolvedFileShare,
        path: str = ".",
    ) -> tuple[Path, str]:
        """Return a safe local path for authenticated HTTP read/download."""

        _, _, resolved, rel_path = self._existing_path(share, path)
        if resolved.is_file() and resolved.stat().st_size > share.max_file_bytes:
            raise FileShareTooLarge(
                f"File '{rel_path}' exceeds max_file_bytes ({share.max_file_bytes})"
            )
        return resolved, rel_path

    def read_file(
        self,
        share: ResolvedFileShare,
        path: str,
        *,
        encoding: str = "auto",
    ) -> dict[str, Any]:
        root, candidate, resolved, rel_path = self._existing_path(share, path)
        if not resolved.is_file():
            raise FileShareError(f"Path '{rel_path}' is not a file")

        size = resolved.stat().st_size
        if size > share.max_file_bytes:
            raise FileShareTooLarge(
                f"File '{rel_path}' exceeds max_file_bytes ({share.max_file_bytes})"
            )

        data = resolved.read_bytes()
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
        if len(data) > share.max_file_bytes:
            raise FileShareTooLarge(
                f"Write exceeds max_file_bytes ({share.max_file_bytes})"
            )

        root, candidate, rel_path = self._destination_path(share, path)
        if rel_path == ".":
            raise FileShareError("Cannot write to the share root")

        if candidate.exists() or candidate.is_symlink():
            if not overwrite:
                raise FileShareConflict(f"Path '{rel_path}' already exists")
            try:
                resolved = self._checked_resolve(candidate, root)
            except FileNotFoundError as exc:
                raise FileShareNotFound(f"Path '{rel_path}' was not found") from exc
            if resolved.is_dir():
                raise FileShareConflict(f"Path '{rel_path}' is a directory")
        else:
            self._checked_existing_dir(candidate.parent, root)

        try:
            candidate.write_bytes(data)
        except OSError as exc:
            raise FileShareError(f"Failed to write '{rel_path}': {exc}") from exc
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "entry": self._metadata(share, root, candidate),
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

        if rel_path == ".":
            return {
                "ok": True,
                "tool": share.tool_name,
                "share": share.name,
                "entry": self._metadata(share, root, root),
            }

        if candidate.exists() and not candidate.is_dir():
            raise FileShareConflict(f"Path '{rel_path}' already exists and is not a directory")

        if parents:
            self._checked_nearest_existing_parent(candidate, root)
        else:
            self._checked_existing_dir(candidate.parent, root)
        try:
            candidate.mkdir(parents=parents, exist_ok=True)
        except OSError as exc:
            raise FileShareError(f"Failed to create directory '{rel_path}': {exc}") from exc
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "entry": self._metadata(share, root, candidate),
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
        root, source_candidate, source_resolved, source_rel = self._existing_path(
            share, source_path
        )
        if source_rel == ".":
            raise FileShareError("Cannot move the share root")

        _, destination_candidate, destination_rel = self._destination_path(
            share, destination_path
        )
        if destination_rel == ".":
            raise FileShareError("Cannot move to the share root")

        if destination_candidate.exists() or destination_candidate.is_symlink():
            try:
                destination_resolved = self._checked_resolve(
                    destination_candidate,
                    root,
                )
            except FileNotFoundError as exc:
                raise FileShareNotFound(
                    f"Path '{destination_rel}' was not found"
                ) from exc
            if not overwrite:
                raise FileShareConflict(f"Path '{destination_rel}' already exists")
            if destination_resolved.is_dir():
                raise FileShareConflict(
                    f"Destination '{destination_rel}' is a directory"
                )
            destination_candidate.unlink()
        else:
            self._checked_existing_dir(destination_candidate.parent, root)

        try:
            source_candidate.replace(destination_candidate)
        except OSError as exc:
            raise FileShareError(
                f"Failed to move '{source_rel}' to '{destination_rel}': {exc}"
            ) from exc
        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "source_path": source_rel,
            "destination_path": destination_rel,
            "entry": self._metadata(share, root, destination_candidate),
        }

    def delete(
        self,
        share: ResolvedFileShare,
        path: str,
        *,
        recursive: bool = False,
    ) -> dict[str, Any]:
        self._require_write(share)
        root, candidate, resolved, rel_path = self._existing_path(share, path)
        if rel_path == ".":
            raise FileShareError("Cannot delete the share root")

        if candidate.is_symlink() or resolved.is_file():
            try:
                candidate.unlink()
            except OSError as exc:
                raise FileShareError(f"Failed to delete '{rel_path}': {exc}") from exc
        elif resolved.is_dir():
            try:
                if recursive:
                    shutil.rmtree(candidate)
                else:
                    candidate.rmdir()
            except OSError as exc:
                raise FileShareConflict(
                    f"Failed to delete directory '{rel_path}': {exc}"
                ) from exc
        else:
            raise FileShareError(f"Path '{rel_path}' is not a file or directory")

        return {
            "ok": True,
            "tool": share.tool_name,
            "share": share.name,
            "deleted": rel_path,
            "recursive": recursive,
        }

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
        try:
            root = share.root.resolve(strict=True)
        except FileNotFoundError as exc:
            raise FileShareNotFound(
                f"File share root for '{share.name}' was not found"
            ) from exc
        if not root.is_dir():
            raise FileShareError(f"File share root for '{share.name}' is not a directory")
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
            raise FileShareNotFound(f"Parent directory '{path.name}' was not found") from exc
        if not resolved.is_dir():
            raise FileShareConflict(f"Parent path '{path.name}' is not a directory")
        return resolved

    def _checked_nearest_existing_parent(self, path: Path, root: Path) -> Path:
        current = path.parent
        while not current.exists() and current != root:
            current = current.parent
        return self._checked_existing_dir(current, root)

    def _iter_entries(self, root: Path, *, recursive: bool) -> list[Path]:
        entries: list[Path] = []
        stack = [root]
        while stack:
            current = stack.pop()
            for child in sorted(current.iterdir(), key=lambda item: item.name):
                entries.append(child)
                if recursive and child.is_dir() and not child.is_symlink():
                    stack.append(child)
            if not recursive:
                break
        return entries

    def _metadata(
        self,
        share: ResolvedFileShare,
        root: Path,
        path: Path,
        *,
        resolved: Path | None = None,
    ) -> dict[str, Any]:
        resolved_path = resolved or self._checked_resolve(path, root)
        rel_path = "." if path == root else path.relative_to(root).as_posix()
        stat = resolved_path.stat()

        if resolved_path.is_dir():
            kind = "directory"
            size: int | None = None
        elif resolved_path.is_file():
            kind = "file"
            size = stat.st_size
        else:
            kind = "other"
            size = None

        payload: dict[str, Any] = {
            "name": "." if rel_path == "." else PurePosixPath(rel_path).name,
            "path": rel_path,
            "type": kind,
            "size": size,
            "modified": stat.st_mtime,
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


def _normalize_client_path(path: str) -> tuple[tuple[str, ...], str]:
    if path is None or path == "":
        path = "."
    if "\x00" in path:
        raise FileShareForbidden("Path contains a NUL byte")

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


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
