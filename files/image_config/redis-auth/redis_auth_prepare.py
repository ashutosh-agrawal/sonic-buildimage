#!/usr/bin/env python3
"""Prepare persistent and runtime Redis writer credentials.

This module is intentionally not wired into the image yet.  A future systemd
oneshot can invoke it before Redis and any authenticated writer start.
"""

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from typing import Optional, Sequence


DEFAULT_STATE_ROOT = "/host/redis-auth"
DEFAULT_RUNTIME_ROOT = "/run/redis-auth"

SCHEMA_VERSION = 1
GENERATION_ONE = "0000000000000001"
ENCODING = "base64url-unpadded"
SOURCE = "local-generated"

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_GENERATION_RE = re.compile(r"^[0-9]{16}$")
_TRANSACTION_RE = re.compile(r"^[0-9a-f]{32}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

_DIRECTORY_FLAG = getattr(os, "O_DIRECTORY", 0)
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC_FLAG = getattr(os, "O_CLOEXEC", 0)


class CredentialStateError(RuntimeError):
    """Persistent or runtime credential state is unsafe or invalid."""


@dataclass(frozen=True)
class PreparationResult:
    """Non-secret result returned to callers and safe to log."""

    domain: str
    generation: str
    initialized: bool


@dataclass(frozen=True)
class _LoadedCredential:
    generation: str
    credential: str
    digest: str


def _mode(st_result: os.stat_result) -> int:
    return stat.S_IMODE(st_result.st_mode)


def _clean_absolute_path(path: str, description: str) -> str:
    if not path or not os.path.isabs(path):
        raise CredentialStateError(f"{description} must be an absolute path")
    normalized = os.path.normpath(path)
    if normalized != path or normalized == "/":
        raise CredentialStateError(
            f"{description} must be a canonical non-root path")
    return normalized


def _validate_ancestor_chain(path: str, owner_uid: int) -> None:
    """Reject symlinks and writable/untrusted ancestors already on disk."""

    current = "/"
    for component in path.split(os.sep)[1:]:
        current = os.path.join(current, component)
        try:
            st_result = os.lstat(current)
        except FileNotFoundError:
            return

        if stat.S_ISLNK(st_result.st_mode):
            raise CredentialStateError(
                f"path component is a symlink: {current}")
        if not stat.S_ISDIR(st_result.st_mode):
            raise CredentialStateError(
                f"path component is not a directory: {current}")
        if st_result.st_uid not in (0, owner_uid):
            raise CredentialStateError(
                f"path component has an untrusted owner: {current}")

        component_mode = _mode(st_result)
        writable = component_mode & (stat.S_IWGRP | stat.S_IWOTH)
        root_sticky = (
            st_result.st_uid == 0
            and bool(component_mode & stat.S_ISVTX)
        )
        if writable and not root_sticky:
            raise CredentialStateError(
                f"path component is group/world writable: {current}")


def _set_fd_metadata(
    fd: int, mode: int, owner_uid: int, owner_gid: int
) -> None:
    st_result = os.fstat(fd)
    if st_result.st_uid != owner_uid or st_result.st_gid != owner_gid:
        os.fchown(fd, owner_uid, owner_gid)
    os.fchmod(fd, mode)


def _set_path_metadata(
    path: str, mode: int, owner_uid: int, owner_gid: int
) -> None:
    st_result = os.lstat(path)
    if stat.S_ISLNK(st_result.st_mode):
        raise CredentialStateError(
            f"refusing to change metadata through symlink: {path}")
    if st_result.st_uid != owner_uid or st_result.st_gid != owner_gid:
        os.chown(path, owner_uid, owner_gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


def _fsync_directory(path: str) -> None:
    flags = os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG | _CLOEXEC_FLAG
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CredentialStateError(
            f"cannot open directory safely: {path}") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise CredentialStateError(
            f"cannot synchronize directory: {path}") from exc
    finally:
        os.close(fd)


def _validate_directory(
    path: str,
    expected_mode: int,
    owner_uid: int,
    owner_gid: int,
) -> os.stat_result:
    try:
        st_result = os.lstat(path)
    except FileNotFoundError as exc:
        raise CredentialStateError(
            f"required directory is missing: {path}") from exc
    if not stat.S_ISDIR(st_result.st_mode):
        raise CredentialStateError(f"path is not a real directory: {path}")
    if st_result.st_uid != owner_uid or st_result.st_gid != owner_gid:
        raise CredentialStateError(
            f"directory has incorrect ownership: {path}")
    if _mode(st_result) != expected_mode:
        raise CredentialStateError(f"directory has incorrect mode: {path}")
    return st_result


def _ensure_directory(
    path: str,
    expected_mode: int,
    owner_uid: int,
    owner_gid: int,
    *,
    create: bool,
) -> bool:
    """Validate a directory or create it with exact metadata.

    Returns True only when this invocation created the directory.
    """

    _validate_ancestor_chain(os.path.dirname(path), owner_uid)
    try:
        os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise CredentialStateError(
                f"required directory is missing: {path}")
        try:
            os.mkdir(path, expected_mode)
        except FileExistsError:
            # Another initializer may have won the first-state-root mkdir
            # before either process could acquire the directory lock.  Adopt
            # only an already-complete directory with the exact trusted
            # metadata; symlinks and partially prepared directories still
            # fail closed.
            _validate_directory(
                path, expected_mode, owner_uid, owner_gid
            )
            return False
        except OSError as exc:
            raise CredentialStateError(
                f"cannot create directory: {path}") from exc
        _set_path_metadata(path, expected_mode, owner_uid, owner_gid)
        _fsync_directory(path)
        _fsync_directory(os.path.dirname(path))
        _validate_directory(path, expected_mode, owner_uid, owner_gid)
        return True

    _validate_directory(path, expected_mode, owner_uid, owner_gid)
    return False


def _validate_regular_file_fd(
    fd: int,
    path: str,
    expected_mode: int,
    owner_uid: int,
    owner_gid: int,
) -> os.stat_result:
    st_result = os.fstat(fd)
    if not stat.S_ISREG(st_result.st_mode):
        raise CredentialStateError(f"path is not a regular file: {path}")
    if st_result.st_nlink != 1:
        raise CredentialStateError(
            f"file has an unexpected link count: {path}")
    if st_result.st_uid != owner_uid or st_result.st_gid != owner_gid:
        raise CredentialStateError(f"file has incorrect ownership: {path}")
    if _mode(st_result) != expected_mode:
        raise CredentialStateError(f"file has incorrect mode: {path}")
    return st_result


def _read_regular_file(
    path: str,
    expected_mode: int,
    owner_uid: int,
    owner_gid: int,
    maximum_size: int,
) -> bytes:
    _validate_ancestor_chain(os.path.dirname(path), owner_uid)
    flags = os.O_RDONLY | _NOFOLLOW_FLAG | _CLOEXEC_FLAG
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CredentialStateError(
            f"cannot open required file safely: {path}") from exc
    try:
        st_result = _validate_regular_file_fd(
            fd, path, expected_mode, owner_uid, owner_gid
        )
        if st_result.st_size < 1 or st_result.st_size > maximum_size:
            raise CredentialStateError(f"file has an invalid size: {path}")
        data = bytearray()
        while len(data) <= maximum_size:
            chunk = os.read(fd, min(4096, maximum_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != st_result.st_size or len(data) > maximum_size:
            raise CredentialStateError(
                f"file changed while it was being read: {path}")
        return bytes(data)
    finally:
        os.close(fd)


def _write_all(fd: int, content: bytes, path: str) -> None:
    offset = 0
    while offset < len(content):
        try:
            written = os.write(fd, content[offset:])
        except OSError as exc:
            raise CredentialStateError(
                f"cannot write credential state file: {path}") from exc
        if written <= 0:
            raise CredentialStateError(f"short write while creating: {path}")
        offset += written


def _atomic_write_new_file(
    path: str,
    content: bytes,
    mode: int,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Create a file using an exclusive temporary and durable rename."""

    parent = os.path.dirname(path)
    _validate_ancestor_chain(parent, owner_uid)
    if os.path.lexists(path):
        raise CredentialStateError(
            f"refusing to replace existing path: {path}")

    temporary = os.path.join(
        parent,
        f".{os.path.basename(path)}.tmp-{secrets.token_hex(16)}",
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _NOFOLLOW_FLAG
        | _CLOEXEC_FLAG
    )
    fd: Optional[int] = None
    renamed = False
    try:
        fd = os.open(temporary, flags, 0o600)
        _set_fd_metadata(fd, mode, owner_uid, owner_gid)
        _write_all(fd, content, path)
        os.fsync(fd)
        os.close(fd)
        fd = None
        if os.path.lexists(path):
            raise CredentialStateError(
                f"target appeared during atomic write: {path}")
        os.replace(temporary, path)
        renamed = True
        _fsync_directory(parent)
    except CredentialStateError:
        raise
    except OSError as exc:
        raise CredentialStateError(
            f"cannot commit credential state file: {path}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if not renamed:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _directory_entries(path: str) -> set:
    try:
        return set(os.listdir(path))
    except OSError as exc:
        raise CredentialStateError(
            f"cannot enumerate directory: {path}") from exc


def _validate_exact_entries(path: str, expected: set) -> None:
    if _directory_entries(path) != expected:
        raise CredentialStateError(
            f"directory contains incomplete or unexpected state: {path}")


def _encode_credential(raw: bytes) -> str:
    if len(raw) != 32:
        raise CredentialStateError(
            "credential generator returned an invalid byte count")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_and_validate_credential(content: bytes, path: str) -> str:
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CredentialStateError(f"credential is not ASCII: {path}") from exc
    credential = text
    if not _CREDENTIAL_RE.fullmatch(credential):
        raise CredentialStateError(
            f"credential is not canonical base64url: {path}")
    try:
        raw = base64.b64decode(
            credential + "=",
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise CredentialStateError(
            f"credential is not valid base64url: {path}") from exc
    if len(raw) != 32 or _encode_credential(raw) != credential:
        raise CredentialStateError(
            f"credential has invalid entropy or encoding: {path}")
    return credential


def _credential_digest(credential: str) -> str:
    return hashlib.sha256(credential.encode("ascii")).hexdigest()


def _manifest_bytes(domain: str, generation: str, credential: str) -> bytes:
    manifest = {
        "credential_sha256": _credential_digest(credential),
        "domain": domain,
        "encoding": ENCODING,
        "generation": generation,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "transaction_id": secrets.token_hex(16),
    }
    serialized = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return (serialized + "\n").encode("ascii")


def _load_manifest(content: bytes, path: str) -> dict:
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate manifest key")
            result[key] = value
        return result

    try:
        manifest = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CredentialStateError(
            f"manifest is not valid JSON: {path}") from exc
    expected_keys = {
        "credential_sha256",
        "domain",
        "encoding",
        "generation",
        "schema_version",
        "source",
        "transaction_id",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise CredentialStateError(
            f"manifest has an unsupported schema: {path}")
    return manifest


def _load_generation(
    generation_path: str,
    domain: str,
    generation: str,
    owner_uid: int,
    owner_gid: int,
) -> _LoadedCredential:
    _validate_directory(generation_path, 0o700, owner_uid, owner_gid)
    _validate_exact_entries(
        generation_path, {"manifest.json", "writer.secret"})

    secret_path = os.path.join(generation_path, "writer.secret")
    credential = _decode_and_validate_credential(
        _read_regular_file(secret_path, 0o400, owner_uid, owner_gid, 256),
        secret_path,
    )
    digest = _credential_digest(credential)

    manifest_path = os.path.join(generation_path, "manifest.json")
    manifest = _load_manifest(
        _read_regular_file(manifest_path, 0o600, owner_uid,
                           owner_gid, 16 * 1024),
        manifest_path,
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != SCHEMA_VERSION
    ):
        raise CredentialStateError(
            f"manifest schema version is unsupported: {manifest_path}")
    if manifest["domain"] != domain:
        raise CredentialStateError(
            f"manifest domain does not match its directory: {manifest_path}")
    if manifest["generation"] != generation:
        raise CredentialStateError(
            "manifest generation does not match its directory: "
            f"{manifest_path}"
        )
    if manifest["encoding"] != ENCODING or manifest["source"] != SOURCE:
        raise CredentialStateError(
            f"manifest encoding or source is unsupported: {manifest_path}")
    transaction_id = manifest["transaction_id"]
    if (
        not isinstance(transaction_id, str)
        or not _TRANSACTION_RE.fullmatch(transaction_id)
    ):
        raise CredentialStateError(
            f"manifest transaction identifier is invalid: {manifest_path}")
    manifest_digest = manifest["credential_sha256"]
    if (
        not isinstance(manifest_digest, str)
        or not _DIGEST_RE.fullmatch(manifest_digest)
    ):
        raise CredentialStateError(
            f"manifest credential digest is invalid: {manifest_path}")
    if manifest_digest != digest:
        raise CredentialStateError(
            f"manifest credential digest does not match: {manifest_path}")
    return _LoadedCredential(generation, credential, digest)


def _load_domain(
    domain_path: str,
    domain: str,
    owner_uid: int,
    owner_gid: int,
) -> _LoadedCredential:
    _validate_directory(domain_path, 0o700, owner_uid, owner_gid)
    _validate_exact_entries(domain_path, {"active", "generations"})

    generations_path = os.path.join(domain_path, "generations")
    _validate_directory(generations_path, 0o700, owner_uid, owner_gid)
    generation_names = _directory_entries(generations_path)
    if not generation_names:
        raise CredentialStateError(
            f"no credential generations exist: {generations_path}")
    if any(not _GENERATION_RE.fullmatch(name) for name in generation_names):
        raise CredentialStateError(
            "credential generations contain partial or invalid state: "
            f"{generations_path}"
        )

    loaded = {}
    for generation in sorted(generation_names):
        loaded[generation] = _load_generation(
            os.path.join(generations_path, generation),
            domain,
            generation,
            owner_uid,
            owner_gid,
        )

    active_path = os.path.join(domain_path, "active")
    active_content = _read_regular_file(
        active_path, 0o600, owner_uid, owner_gid, 128
    )
    try:
        active_text = active_content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CredentialStateError(
            f"active selector is not ASCII: {active_path}") from exc
    if not active_text.endswith("\n") or active_text.count("\n") != 1:
        raise CredentialStateError(
            f"active selector is not canonical: {active_path}")
    active_generation = active_text[:-1]
    if not _GENERATION_RE.fullmatch(active_generation):
        raise CredentialStateError(
            f"active selector is invalid: {active_path}")
    if active_generation not in loaded:
        raise CredentialStateError(
            f"active selector names a missing generation: {active_path}")
    return loaded[active_generation]


def _temporary_file_name(entries: set, file_name: str) -> Optional[str]:
    """Return one recognized atomic-write temporary or reject the entries."""

    pattern = _atomic_temporary_file_pattern(file_name)
    matches = [entry for entry in entries if pattern.fullmatch(entry)]
    if len(matches) == 1:
        return matches[0]
    return None


def _remove_initialization_temporary(
    directory_path: str,
    temporary_name: str,
    allowed_modes: set,
    maximum_size: int,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Remove only an exact, safely owned interrupted write temporary."""

    temporary_path = os.path.join(directory_path, temporary_name)
    try:
        st_result = os.lstat(temporary_path)
    except OSError as exc:
        raise CredentialStateError(
            "cannot inspect interrupted credential initialization") from exc
    if (
        not stat.S_ISREG(st_result.st_mode)
        or st_result.st_nlink != 1
        or st_result.st_uid != owner_uid
        or st_result.st_gid != owner_gid
        or _mode(st_result) not in allowed_modes
        or st_result.st_size > maximum_size
    ):
        raise CredentialStateError(
            "interrupted credential initialization temporary is unsafe: "
            f"{temporary_path}"
        )
    try:
        os.unlink(temporary_path)
    except OSError as exc:
        raise CredentialStateError(
            "cannot remove interrupted credential initialization temporary"
        ) from exc
    _fsync_directory(directory_path)


def _resume_initializing_domain(
    initializing_path: str,
    domain: str,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Complete only an exact prefix of the initial-domain transaction."""

    _validate_directory(initializing_path, 0o700, owner_uid, owner_gid)
    root_entries = _directory_entries(initializing_path)
    active_temporary = _temporary_file_name(root_entries, "active")
    if active_temporary is not None:
        if root_entries != {"generations", active_temporary}:
            raise CredentialStateError(
                "initializing credential domain contains unexpected state: "
                f"{initializing_path}"
            )
        generations_path = os.path.join(initializing_path, "generations")
        generation_path = os.path.join(generations_path, GENERATION_ONE)
        _validate_directory(generations_path, 0o700, owner_uid, owner_gid)
        _validate_exact_entries(generations_path, {GENERATION_ONE})
        _load_generation(
            generation_path, domain, GENERATION_ONE, owner_uid, owner_gid
        )
        _remove_initialization_temporary(
            initializing_path,
            active_temporary,
            {0o600},
            128,
            owner_uid,
            owner_gid,
        )
        root_entries = {"generations"}

    if "active" in root_entries:
        if root_entries != {"active", "generations"}:
            raise CredentialStateError(
                "initializing credential domain contains unexpected state: "
                f"{initializing_path}"
            )
        _load_domain(initializing_path, domain, owner_uid, owner_gid)
        return

    if root_entries not in (set(), {"generations"}):
        raise CredentialStateError(
            "initializing credential domain contains unexpected state: "
            f"{initializing_path}"
        )

    generations_path = os.path.join(initializing_path, "generations")
    if not root_entries:
        _ensure_directory(
            generations_path, 0o700, owner_uid, owner_gid, create=True
        )
    else:
        _validate_directory(generations_path, 0o700, owner_uid, owner_gid)

    generation_entries = _directory_entries(generations_path)
    if generation_entries not in (set(), {GENERATION_ONE}):
        raise CredentialStateError(
            "initializing credential generations contain unexpected state: "
            f"{generations_path}"
        )

    generation_path = os.path.join(generations_path, GENERATION_ONE)
    if not generation_entries:
        _ensure_directory(
            generation_path, 0o700, owner_uid, owner_gid, create=True
        )
    else:
        _validate_directory(generation_path, 0o700, owner_uid, owner_gid)

    credential_entries = _directory_entries(generation_path)
    writer_temporary = _temporary_file_name(
        credential_entries, "writer.secret"
    )
    manifest_temporary = _temporary_file_name(
        credential_entries, "manifest.json"
    )
    if writer_temporary is not None:
        if credential_entries != {writer_temporary}:
            raise CredentialStateError(
                "initializing credential generation contains unexpected "
                f"state: {generation_path}"
            )
        _remove_initialization_temporary(
            generation_path,
            writer_temporary,
            {0o400, 0o600},
            256,
            owner_uid,
            owner_gid,
        )
        credential_entries = set()
    elif manifest_temporary is not None:
        if credential_entries != {"writer.secret", manifest_temporary}:
            raise CredentialStateError(
                "initializing credential generation contains unexpected "
                f"state: {generation_path}"
            )
        secret_path = os.path.join(generation_path, "writer.secret")
        credential = _decode_and_validate_credential(
            _read_regular_file(
                secret_path, 0o400, owner_uid, owner_gid, 256
            ),
            secret_path,
        )
        _remove_initialization_temporary(
            generation_path,
            manifest_temporary,
            {0o600},
            16 * 1024,
            owner_uid,
            owner_gid,
        )
        credential_entries = {"writer.secret"}

    if credential_entries == set():
        credential = _encode_credential(secrets.token_bytes(32))
        _atomic_write_new_file(
            os.path.join(generation_path, "writer.secret"),
            credential.encode("ascii"),
            0o400,
            owner_uid,
            owner_gid,
        )
    elif credential_entries == {"writer.secret"}:
        secret_path = os.path.join(generation_path, "writer.secret")
        credential = _decode_and_validate_credential(
            _read_regular_file(
                secret_path, 0o400, owner_uid, owner_gid, 256
            ),
            secret_path,
        )
    elif credential_entries == {"manifest.json", "writer.secret"}:
        _load_generation(
            generation_path, domain, GENERATION_ONE, owner_uid, owner_gid
        )
        credential = ""
    else:
        raise CredentialStateError(
            "initializing credential generation contains unexpected state: "
            f"{generation_path}"
        )

    if "manifest.json" not in credential_entries:
        _atomic_write_new_file(
            os.path.join(generation_path, "manifest.json"),
            _manifest_bytes(domain, GENERATION_ONE, credential),
            0o600,
            owner_uid,
            owner_gid,
        )
    _load_generation(
        generation_path, domain, GENERATION_ONE, owner_uid, owner_gid
    )

    _atomic_write_new_file(
        os.path.join(initializing_path, "active"),
        (GENERATION_ONE + "\n").encode("ascii"),
        0o600,
        owner_uid,
        owner_gid,
    )
    _fsync_directory(initializing_path)
    _load_domain(initializing_path, domain, owner_uid, owner_gid)


def _initialize_domain(
    state_root: str,
    domain_path: str,
    domain: str,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Build a complete sibling tree and publish it as one transaction."""

    initializing_path = os.path.join(state_root, f".initializing-{domain}")
    initializing_exists = os.path.lexists(initializing_path)
    _ensure_directory(
        initializing_path,
        0o700,
        owner_uid,
        owner_gid,
        create=not initializing_exists,
    )
    _resume_initializing_domain(
        initializing_path, domain, owner_uid, owner_gid
    )

    if os.path.lexists(domain_path):
        raise CredentialStateError(
            f"credential domain appeared during initialization: {domain_path}"
        )
    try:
        os.rename(initializing_path, domain_path)
    except OSError as exc:
        raise CredentialStateError(
            "cannot publish initial credential domain") from exc
    _fsync_directory(state_root)


def _validate_runtime_file(
    path: str,
    expected_content: bytes,
    owner_uid: int,
    owner_gid: int,
) -> None:
    actual = _read_regular_file(path, 0o400, owner_uid, owner_gid, 256)
    if actual != expected_content:
        raise CredentialStateError(
            f"runtime credential artifact does not match active state: {path}"
        )


def _atomic_temporary_file_pattern(file_name: str) -> re.Pattern:
    return re.compile(
        rf"^{re.escape('.' + file_name + '.tmp-')}[0-9a-f]{{32}}$"
    )


def _remove_recognized_runtime_temporaries(
    directory_path: str,
    file_name: str,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Remove only safe temporary files left by our atomic writer."""

    temporary_pattern = _atomic_temporary_file_pattern(file_name)
    removed = False
    for entry in _directory_entries(directory_path):
        if entry == file_name:
            continue
        if not temporary_pattern.fullmatch(entry):
            raise CredentialStateError(
                "runtime credential directory contains incomplete or "
                f"unexpected state: {directory_path}"
            )
        temporary_path = os.path.join(directory_path, entry)
        try:
            st_result = os.lstat(temporary_path)
        except OSError as exc:
            raise CredentialStateError(
                "cannot inspect interrupted runtime credential state"
            ) from exc
        if (
            not stat.S_ISREG(st_result.st_mode)
            or st_result.st_nlink != 1
            or st_result.st_uid != owner_uid
            or st_result.st_gid != owner_gid
            or _mode(st_result) not in (0o400, 0o600)
        ):
            raise CredentialStateError(
                "interrupted runtime credential temporary is unsafe: "
                f"{temporary_path}"
            )
        try:
            os.unlink(temporary_path)
        except OSError as exc:
            raise CredentialStateError(
                "cannot remove interrupted runtime credential temporary"
            ) from exc
        removed = True
    if removed:
        _fsync_directory(directory_path)


def _complete_runtime_domain_directory(
    directory_path: str,
    file_name: str,
    expected_content: bytes,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Validate a published directory or finish recognized derived state."""

    _validate_directory(directory_path, 0o700, owner_uid, owner_gid)
    _remove_recognized_runtime_temporaries(
        directory_path, file_name, owner_uid, owner_gid
    )
    entries = _directory_entries(directory_path)
    artifact_path = os.path.join(directory_path, file_name)
    if not entries:
        _atomic_write_new_file(
            artifact_path,
            expected_content,
            0o400,
            owner_uid,
            owner_gid,
        )
    elif entries != {file_name}:
        raise CredentialStateError(
            "runtime credential directory contains incomplete or unexpected "
            f"state: {directory_path}"
        )

    _validate_exact_entries(directory_path, {file_name})
    _validate_runtime_file(
        artifact_path, expected_content, owner_uid, owner_gid
    )


def _discard_runtime_incoming_directory(
    incoming_path: str,
    parent_path: str,
    file_name: str,
    expected_content: bytes,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Validate and remove a redundant complete incoming directory."""

    _complete_runtime_domain_directory(
        incoming_path,
        file_name,
        expected_content,
        owner_uid,
        owner_gid,
    )
    try:
        os.unlink(os.path.join(incoming_path, file_name))
        _fsync_directory(incoming_path)
        os.rmdir(incoming_path)
        _fsync_directory(parent_path)
    except OSError as exc:
        raise CredentialStateError(
            "cannot remove redundant runtime credential staging directory"
        ) from exc


def _publish_runtime_domain(
    parent_path: str,
    domain: str,
    file_name: str,
    expected_content: bytes,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Publish one complete runtime domain with restartable staging."""

    domain_path = os.path.join(parent_path, domain)
    incoming_path = os.path.join(parent_path, f".incoming-{domain}")
    domain_exists = os.path.lexists(domain_path)
    incoming_exists = os.path.lexists(incoming_path)

    if domain_exists:
        _complete_runtime_domain_directory(
            domain_path,
            file_name,
            expected_content,
            owner_uid,
            owner_gid,
        )
        if incoming_exists:
            _discard_runtime_incoming_directory(
                incoming_path,
                parent_path,
                file_name,
                expected_content,
                owner_uid,
                owner_gid,
            )
        return

    _ensure_directory(
        incoming_path,
        0o700,
        owner_uid,
        owner_gid,
        create=not incoming_exists,
    )
    _complete_runtime_domain_directory(
        incoming_path,
        file_name,
        expected_content,
        owner_uid,
        owner_gid,
    )
    if os.path.lexists(domain_path):
        raise CredentialStateError(
            f"runtime credential domain appeared unexpectedly: {domain_path}"
        )
    try:
        os.replace(incoming_path, domain_path)
    except OSError as exc:
        raise CredentialStateError(
            f"cannot publish runtime credential domain: {domain_path}"
        ) from exc
    _fsync_directory(parent_path)
    _complete_runtime_domain_directory(
        domain_path,
        file_name,
        expected_content,
        owner_uid,
        owner_gid,
    )


def _stage_runtime(
    runtime_root: str,
    domain: str,
    loaded: _LoadedCredential,
    owner_uid: int,
    owner_gid: int,
) -> None:
    _ensure_directory(runtime_root, 0o711, owner_uid, owner_gid, create=True)
    clients_path = os.path.join(runtime_root, "clients")
    server_path = os.path.join(runtime_root, "server")

    clients_exists = os.path.lexists(clients_path)
    server_exists = os.path.lexists(server_path)
    _ensure_directory(clients_path, 0o711, owner_uid,
                      owner_gid, create=not clients_exists)
    _ensure_directory(server_path, 0o700, owner_uid,
                      owner_gid, create=not server_exists)

    # RedisAuthConfig validates the entire file as canonical base64url and
    # deliberately does not trim whitespace.  Keep this file newline-free.
    secret_content = loaded.credential.encode("ascii")
    digest_content = (loaded.digest + "\n").encode("ascii")

    _publish_runtime_domain(
        server_path,
        domain,
        "writer.sha256",
        digest_content,
        owner_uid,
        owner_gid,
    )
    _publish_runtime_domain(
        clients_path,
        domain,
        "writer.secret",
        secret_content,
        owner_uid,
        owner_gid,
    )


def prepare_credential(
    domain: str,
    *,
    state_root: str = DEFAULT_STATE_ROOT,
    runtime_root: str = DEFAULT_RUNTIME_ROOT,
    initialize: bool = False,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> PreparationResult:
    """Validate/reuse one credential and stage its runtime artifacts.

    ``initialize`` authorizes creation or exact-prefix recovery only while the
    published domain is absent.  It never repairs, replaces, or rotates a
    published domain.
    """

    if not _DOMAIN_RE.fullmatch(domain):
        raise CredentialStateError(
            "domain must contain only safe identifier characters")
    if owner_uid < 0 or owner_gid < 0:
        raise CredentialStateError("owner identifiers must be non-negative")
    state_root = _clean_absolute_path(state_root, "state root")
    runtime_root = _clean_absolute_path(runtime_root, "runtime root")
    common_root = os.path.commonpath((state_root, runtime_root))
    if common_root in (state_root, runtime_root):
        raise CredentialStateError(
            "state and runtime roots must be separate directory trees"
        )

    state_exists = os.path.lexists(state_root)
    if not state_exists and not initialize:
        raise CredentialStateError(
            "persistent credential state is absent; explicit initialization "
            "is required"
        )
    _ensure_directory(
        state_root,
        0o700,
        owner_uid,
        owner_gid,
        create=initialize and not state_exists,
    )

    state_flags = (
        os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG | _CLOEXEC_FLAG
    )
    try:
        state_fd = os.open(state_root, state_flags)
    except OSError as exc:
        raise CredentialStateError(
            "cannot lock persistent credential state") from exc

    initialized = False
    try:
        fcntl.flock(state_fd, fcntl.LOCK_EX)
        domain_path = os.path.join(state_root, domain)
        initializing_path = os.path.join(
            state_root, f".initializing-{domain}"
        )
        domain_exists = os.path.lexists(domain_path)
        initializing_exists = os.path.lexists(initializing_path)
        if domain_exists and initializing_exists:
            raise CredentialStateError(
                "published and initializing credential domains both exist"
            )
        if not domain_exists:
            if not initialize:
                raise CredentialStateError(
                    "credential domain is absent; explicit initialization "
                    "is required"
                )
            _initialize_domain(
                state_root,
                domain_path,
                domain,
                owner_uid,
                owner_gid,
            )
            initialized = True

        loaded = _load_domain(domain_path, domain, owner_uid, owner_gid)
        _stage_runtime(runtime_root, domain, loaded, owner_uid, owner_gid)
        return PreparationResult(domain, loaded.generation, initialized)
    finally:
        try:
            fcntl.flock(state_fd, fcntl.LOCK_UN)
        finally:
            os.close(state_fd)


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and stage a SONiC Redis writer credential",
    )
    parser.add_argument("--domain", required=True,
                        help="security-domain identifier")
    parser.add_argument(
        "--state-root",
        default=DEFAULT_STATE_ROOT,
        help=f"persistent state root (default: {DEFAULT_STATE_ROOT})",
    )
    parser.add_argument(
        "--runtime-root",
        default=DEFAULT_RUNTIME_ROOT,
        help=f"runtime artifact root (default: {DEFAULT_RUNTIME_ROOT})",
    )
    parser.add_argument(
        "--initialize",
        action="store_true",
        help=(
            "explicitly authorize first generation or interrupted staging "
            "for an absent published domain"
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("redis-auth-prepare: must run as root", file=sys.stderr)
        return 1
    try:
        result = prepare_credential(
            args.domain,
            state_root=args.state_root,
            runtime_root=args.runtime_root,
            initialize=args.initialize,
        )
    except CredentialStateError as exc:
        print(f"redis-auth-prepare: {exc}", file=sys.stderr)
        return 1
    except OSError:
        # Keep unexpected operating-system diagnostics deterministic and avoid
        # echoing attacker-controlled paths or internal exception details.
        print(
            "redis-auth-prepare: operating-system failure",
            file=sys.stderr,
        )
        return 1

    action = "initialized" if result.initialized else "reused"
    print(
        "redis-auth-prepare: "
        f"domain={result.domain} generation={result.generation} "
        f"action={action}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
