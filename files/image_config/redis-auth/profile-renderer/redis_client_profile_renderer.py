#!/usr/bin/env python3
"""Render the root host's Redis client profile from finalized DB maps.

This prototype is deliberately not wired into systemd or database startup.
It consumes only Redis endpoint metadata and never opens the writer credential
or its digest.
"""

import argparse
import json
import os
import pwd
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple


PROFILE_NAME = "local-system"
DOMAIN = "local-system"
WRITER_USERNAME = "sonic-trusted-writer"

DEFAULT_DATABASE_ROOT = "/var/run"
DEFAULT_DATABASE_CONFIG = "/var/run/redis/sonic-db/database_config.json"
DEFAULT_DATABASE_GLOBAL = "/var/run/redis/sonic-db/database_global.json"
DEFAULT_CREDENTIAL_FILE = (
    "/run/redis-auth/clients/local-system/writer.secret"
)
DEFAULT_OUTPUT_FILE = "/run/redis-auth/client-profiles.json"

SCHEMA_VERSION = 1
DATABASE_VERSION = "1.0"
MAX_INPUT_BYTES = 1024 * 1024
# Keep this exactly aligned with RedisAuthConfig::MAX_PROFILE_FILE_LENGTH.
MAX_OUTPUT_BYTES = 64 * 1024

REMOTE_INSTANCE = "remote_redis"
CHASSIS_INSTANCE = "redis_chassis"

_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class ProfileRenderError(RuntimeError):
    """The profile cannot be rendered without weakening its trust boundary."""


@dataclass(frozen=True)
class ConfigSource:
    path: str
    local_chassis_only: bool = False


@dataclass(frozen=True)
class RenderResult:
    endpoint_count: int
    source_count: int
    changed: bool


def _mode(st_result: os.stat_result) -> int:
    return stat.S_IMODE(st_result.st_mode)


def _clean_absolute_path(path: str, description: str) -> str:
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        raise ProfileRenderError(f"{description} must be an absolute path")
    if "\x00" in path or os.path.normpath(path) != path or path == "/":
        raise ProfileRenderError(
            f"{description} must be a canonical non-root path")
    return path


def _validate_no_symlinks(path: str, *, include_leaf: bool = True) -> None:
    """Reject symlinks in an existing path.

    The production database root is conventionally spelled ``/var/run`` even
    when that one system path aliases ``/run``. Database paths are handled by
    ``_DatabaseRoot`` below; other security-sensitive paths use this stricter
    helper.
    """

    current = "/"
    components = path.split(os.sep)[1:]
    if not include_leaf:
        components = components[:-1]
    for component in components:
        current = os.path.join(current, component)
        try:
            st_result = os.lstat(current)
        except FileNotFoundError as exc:
            raise ProfileRenderError(
                f"path does not exist: {current}") from exc
        if stat.S_ISLNK(st_result.st_mode):
            raise ProfileRenderError(f"path component is a symlink: {current}")


class _DatabaseRoot:
    """Resolve database files beneath one trusted runtime tree."""

    def __init__(self, path: str):
        self.lexical = _clean_absolute_path(path, "database root")
        self.real = os.path.realpath(self.lexical)
        if self.lexical != self.real:
            if not (self.lexical == "/var/run" and self.real == "/run"):
                raise ProfileRenderError("database root must not be a symlink")
        try:
            root_stat = os.stat(self.real)
        except OSError as exc:
            raise ProfileRenderError("database root is unavailable") from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ProfileRenderError("database root is not a directory")

    def resolve(self, path: str) -> str:
        path = _clean_absolute_path(path, "database configuration path")
        try:
            common = os.path.commonpath((self.lexical, path))
        except ValueError as exc:
            raise ProfileRenderError(
                "database configuration escapes database root") from exc
        if common != self.lexical:
            raise ProfileRenderError(
                "database configuration escapes database root")

        relative = os.path.relpath(path, self.lexical)
        resolved = os.path.normpath(os.path.join(self.real, relative))
        if os.path.realpath(resolved) != resolved:
            raise ProfileRenderError(
                f"database configuration path contains a symlink: {path}")
        try:
            real_common = os.path.commonpath((self.real, resolved))
        except ValueError as exc:
            raise ProfileRenderError(
                "database configuration escapes database root") from exc
        if real_common != self.real:
            raise ProfileRenderError(
                "database configuration escapes database root")
        return resolved


def _read_regular_file(
    path: str,
    *,
    trusted_uids: Set[int],
    exact_mode: Optional[int] = None,
    max_bytes: int = MAX_INPUT_BYTES,
) -> bytes:
    flags = os.O_RDONLY | _NOFOLLOW | _CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProfileRenderError(f"cannot open trusted file: {path}") from exc
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid not in trusted_uids):
            raise ProfileRenderError(
                f"trusted file metadata is invalid: {path}")
        file_mode = _mode(before)
        if exact_mode is not None:
            if file_mode != exact_mode:
                raise ProfileRenderError(
                    f"trusted file mode is invalid: {path}")
        elif file_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProfileRenderError(
                f"trusted file is group or world writable: {path}")
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise ProfileRenderError(f"trusted file size is invalid: {path}")

        remaining = before.st_size
        chunks = []
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                raise ProfileRenderError(f"trusted file was truncated: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise ProfileRenderError(
                f"trusted file changed while read: {path}")

        after = os.fstat(fd)
        stable_fields = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if stable_fields != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ProfileRenderError(
                f"trusted file changed while read: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _reject_duplicate_keys(pairs: Iterable[Tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProfileRenderError(
                f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _load_json_file(
    path: str,
    *,
    database_root: _DatabaseRoot,
    trusted_uids: Set[int],
) -> Tuple[str, dict]:
    resolved = database_root.resolve(path)
    raw = _read_regular_file(resolved, trusted_uids=trusted_uids)
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ProfileRenderError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileRenderError(
            f"database configuration is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ProfileRenderError(
            f"database configuration root is not an object: {path}")
    return resolved, value


def _safe_context_token(value: object, description: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ProfileRenderError(f"{description} is invalid")
    return value


def _sources_from_global(
    global_path: str,
    *,
    database_root: _DatabaseRoot,
    trusted_uids: Set[int],
) -> List[ConfigSource]:
    _, document = _load_json_file(
        global_path,
        database_root=database_root,
        trusted_uids=trusted_uids,
    )
    if document.get("VERSION") != DATABASE_VERSION:
        raise ProfileRenderError("database global version is unsupported")
    includes = document.get("INCLUDES")
    if not isinstance(includes, list) or not includes:
        raise ProfileRenderError("database global includes are missing")

    sources = []
    paths = set()
    contexts = set()
    base_count = 0
    lexical_dir = os.path.dirname(global_path)
    for include in includes:
        if not isinstance(include, dict):
            raise ProfileRenderError(
                "database global include is not an object")
        include_path = include.get("include")
        if (not isinstance(include_path, str) or not include_path or
                "\x00" in include_path or os.path.isabs(include_path)):
            raise ProfileRenderError("database global include path is invalid")
        namespace = include.get("namespace")
        container_name = include.get("container_name")
        if namespace is not None and container_name is not None:
            raise ProfileRenderError(
                "database global include has two endpoint contexts")
        if namespace is not None:
            context = "namespace:" + _safe_context_token(
                namespace, "database namespace")
        elif container_name is not None:
            context = "container:" + _safe_context_token(
                container_name, "database container name")
        else:
            context = "base"
            base_count += 1

        combined = os.path.normpath(os.path.join(lexical_dir, include_path))
        if not os.path.isabs(combined):
            raise ProfileRenderError("database global include path is invalid")
        resolved_include = database_root.resolve(combined)
        if resolved_include in paths:
            raise ProfileRenderError("database global repeats an include file")
        if context in contexts:
            raise ProfileRenderError(
                "database global repeats an endpoint context")
        paths.add(resolved_include)
        contexts.add(context)
        sources.append(ConfigSource(combined))

    if base_count != 1:
        raise ProfileRenderError(
            "database global must contain exactly one base include")
    return sources


def _validate_instance(instance_name: str, value: object) -> dict:
    if not _INSTANCE_RE.fullmatch(instance_name):
        raise ProfileRenderError("database instance name is invalid")
    if not isinstance(value, dict):
        raise ProfileRenderError(
            f"database instance is not an object: {instance_name}")
    hostname = value.get("hostname")
    port = value.get("port")
    socket_path = value.get("unix_socket_path", "")
    if (not isinstance(hostname, str) or not hostname or len(hostname) > 255 or
            any(ord(character) <= 32 or ord(character) == 127
                for character in hostname)):
        raise ProfileRenderError(
            f"database instance hostname is invalid: {instance_name}")
    if type(port) is not int or port < 0 or port > 65535:
        raise ProfileRenderError(
            f"database instance port is invalid: {instance_name}")
    if (not isinstance(socket_path, str) or
            any(ord(character) < 32 or ord(character) == 127
                for character in socket_path)):
        raise ProfileRenderError(
            f"database instance socket is invalid: {instance_name}")
    if socket_path:
        if (not os.path.isabs(socket_path) or
                os.path.normpath(socket_path) != socket_path or
                socket_path == "/"):
            raise ProfileRenderError(
                f"database instance socket is unsafe: {instance_name}")
    elif port == 0:
        raise ProfileRenderError(
            f"database instance has no usable transport: {instance_name}")
    return {
        "hostname": hostname,
        "port": port,
        "unix_socket_path": socket_path,
    }


def _endpoints_from_source(
    source: ConfigSource,
    *,
    database_root: _DatabaseRoot,
    trusted_uids: Set[int],
) -> List[Tuple[Tuple[object, ...], dict]]:
    _, document = _load_json_file(
        source.path,
        database_root=database_root,
        trusted_uids=trusted_uids,
    )
    if document.get("VERSION") != DATABASE_VERSION:
        raise ProfileRenderError(
            f"database configuration version is unsupported: {source.path}")
    instances = document.get("INSTANCES")
    databases = document.get("DATABASES")
    if not isinstance(instances, dict) or not instances:
        raise ProfileRenderError(
            f"database instances are missing: {source.path}")
    if not isinstance(databases, dict) or not databases:
        raise ProfileRenderError(
            f"database definitions are missing: {source.path}")

    validated_instances = {
        name: _validate_instance(name, value)
        for name, value in instances.items()
    }
    referenced = set()
    for db_name, value in databases.items():
        if not isinstance(db_name, str) or not _TOKEN_RE.fullmatch(db_name):
            raise ProfileRenderError("database name is invalid")
        if not isinstance(value, dict):
            raise ProfileRenderError(
                f"database definition is invalid: {db_name}")
        instance_name = value.get("instance")
        db_id = value.get("id")
        separator = value.get("separator")
        if (not isinstance(instance_name, str) or
                instance_name not in validated_instances):
            raise ProfileRenderError(
                f"database references an unknown instance: {db_name}")
        if type(db_id) is not int or db_id < 0 or db_id > 2147483647:
            raise ProfileRenderError(f"database id is invalid: {db_name}")
        if (not isinstance(separator, str) or not separator or
                "\x00" in separator):
            raise ProfileRenderError(
                f"database separator is invalid: {db_name}")
        referenced.add(instance_name)

    unreferenced_instances = set(validated_instances) - referenced
    if unreferenced_instances:
        raise ProfileRenderError(
            "database instance is not referenced by a database")

    if source.local_chassis_only:
        if set(validated_instances) != {CHASSIS_INSTANCE}:
            raise ProfileRenderError(
                "local chassis config must contain only redis_chassis")
        selected = {CHASSIS_INSTANCE}
    else:
        selected = set(validated_instances) - {
            REMOTE_INSTANCE,
            CHASSIS_INSTANCE,
        }

    endpoints = []
    for instance_name in sorted(selected):
        instance = validated_instances[instance_name]
        if instance["port"] != 0:
            tcp_key = ("tcp", instance["hostname"], instance["port"])
            endpoints.append((
                tcp_key,
                {
                    "transport": "tcp",
                    "hostname": instance["hostname"],
                    "port": instance["port"],
                },
            ))
        socket_path = instance["unix_socket_path"]
        if socket_path:
            endpoints.append((
                ("unix", socket_path),
                {"transport": "unix", "path": socket_path},
            ))
    return endpoints


def _validate_credential_metadata(
    credential_file: str,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    credential_file = _clean_absolute_path(
        credential_file, "writer credential file")
    _validate_no_symlinks(credential_file)
    try:
        st_result = os.lstat(credential_file)
    except OSError as exc:
        raise ProfileRenderError(
            "writer credential file is unavailable") from exc
    if (not stat.S_ISREG(st_result.st_mode) or st_result.st_nlink != 1 or
            st_result.st_uid != owner_uid or st_result.st_gid != owner_gid or
            _mode(st_result) != 0o400):
        raise ProfileRenderError("writer credential file metadata is invalid")


def _profile_bytes(credential_file: str, endpoints: List[dict]) -> bytes:
    document = {
        "schema_version": SCHEMA_VERSION,
        "profiles": {
            PROFILE_NAME: {
                "username": WRITER_USERNAME,
                "domain": DOMAIN,
                "credential_file": credential_file,
                "endpoints": endpoints,
            },
        },
    }
    return (json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _validate_output_directory(
    directory: str,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    _validate_no_symlinks(directory)
    try:
        st_result = os.lstat(directory)
    except OSError as exc:
        raise ProfileRenderError(
            "profile output directory is unavailable") from exc
    if (not stat.S_ISDIR(st_result.st_mode) or
            st_result.st_uid != owner_uid or st_result.st_gid != owner_gid or
            _mode(st_result) != 0o711):
        raise ProfileRenderError(
            "profile output directory metadata is invalid")


def _existing_output(
    output_file: str,
    *,
    owner_uid: int,
    owner_gid: int,
) -> Optional[bytes]:
    if not os.path.lexists(output_file):
        return None
    try:
        st_result = os.lstat(output_file)
    except OSError as exc:
        raise ProfileRenderError(
            "cannot inspect existing profile file") from exc
    if (not stat.S_ISREG(st_result.st_mode) or st_result.st_nlink != 1 or
            st_result.st_uid != owner_uid or st_result.st_gid != owner_gid or
            _mode(st_result) != 0o444):
        raise ProfileRenderError("existing profile file metadata is invalid")
    return _read_regular_file(
        output_file,
        trusted_uids={owner_uid},
        exact_mode=0o444,
        max_bytes=MAX_OUTPUT_BYTES,
    )


def _write_profile(
    output_file: str,
    content: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
) -> bool:
    output_file = _clean_absolute_path(output_file, "profile output file")
    output_dir = os.path.dirname(output_file)
    _validate_output_directory(
        output_dir, owner_uid=owner_uid, owner_gid=owner_gid)
    existing = _existing_output(
        output_file, owner_uid=owner_uid, owner_gid=owner_gid)
    if existing == content:
        return False

    temp_path = os.path.join(
        output_dir,
        ".client-profiles.json.tmp." + secrets.token_hex(16),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
    fd = None
    try:
        fd = os.open(temp_path, flags, 0o444)
        os.fchmod(fd, 0o444)
        if owner_uid != os.geteuid() or owner_gid != os.getegid():
            os.fchown(fd, owner_uid, owner_gid)
        offset = 0
        while offset < len(content):
            written = os.write(fd, content[offset:])
            if written <= 0:
                raise ProfileRenderError("cannot write client profile")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temp_path, output_file)
        directory_fd = os.open(output_dir, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return True
    except ProfileRenderError:
        raise
    except OSError as exc:
        raise ProfileRenderError("cannot commit client profile") from exc
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _default_trusted_config_uids() -> Set[int]:
    trusted = {0}
    try:
        trusted.add(pwd.getpwnam("redis").pw_uid)
    except KeyError:
        pass
    return trusted


def render_client_profiles(
    *,
    database_root: str = DEFAULT_DATABASE_ROOT,
    database_global: Optional[str] = None,
    database_configs: Sequence[str] = (),
    local_chassis_config: Optional[str] = None,
    credential_file: str = DEFAULT_CREDENTIAL_FILE,
    output_file: str = DEFAULT_OUTPUT_FILE,
    trusted_config_uids: Optional[Set[int]] = None,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> RenderResult:
    """Render a deterministic root host profile without reading its secret."""

    if owner_uid < 0 or owner_gid < 0:
        raise ProfileRenderError("profile owner identifiers are invalid")
    database_root_obj = _DatabaseRoot(database_root)
    if trusted_config_uids is None:
        trusted_config_uids = _default_trusted_config_uids()
    trusted_config_uids = set(trusted_config_uids)
    if not trusted_config_uids or any(uid < 0 for uid in trusted_config_uids):
        raise ProfileRenderError("trusted config owner set is invalid")

    configs = list(database_configs)
    if database_global is None and not configs:
        default_global = os.path.join(
            database_root, "redis/sonic-db/database_global.json")
        default_config = os.path.join(
            database_root, "redis/sonic-db/database_config.json")
        if os.path.lexists(default_global):
            database_global = default_global
        else:
            configs.append(default_config)

    sources = []
    if database_global is not None:
        sources.extend(_sources_from_global(
            database_global,
            database_root=database_root_obj,
            trusted_uids=trusted_config_uids,
        ))
    for config in configs:
        sources.append(ConfigSource(config))
    if local_chassis_config is not None:
        sources.append(ConfigSource(
            local_chassis_config,
            local_chassis_only=True,
        ))
    if not sources:
        raise ProfileRenderError("no database configurations were selected")

    resolved_sources = set()
    endpoint_keys = set()
    endpoints = []
    for source in sources:
        resolved = database_root_obj.resolve(source.path)
        if resolved in resolved_sources:
            raise ProfileRenderError(
                "database configuration was selected twice")
        resolved_sources.add(resolved)
        for endpoint_key, endpoint in _endpoints_from_source(
                source,
                database_root=database_root_obj,
                trusted_uids=trusted_config_uids):
            if endpoint_key in endpoint_keys:
                # Namespace databases commonly repeat 127.0.0.1:6379 while
                # using distinct network namespaces. RedisAuthConfig matches
                # the endpoint string after namespace selection and has no
                # namespace field, so one copy is the exact policy required
                # for all of those connections.
                continue
            endpoint_keys.add(endpoint_key)
            endpoints.append(endpoint)

    if not endpoints:
        raise ProfileRenderError(
            "selected database maps have no local endpoints")
    endpoints.sort(key=lambda endpoint: (
        endpoint["transport"],
        endpoint.get("hostname", endpoint.get("path", "")),
        endpoint.get("port", 0),
    ))

    credential_file = _clean_absolute_path(
        credential_file, "writer credential file")
    _validate_credential_metadata(
        credential_file, owner_uid=owner_uid, owner_gid=owner_gid)
    content = _profile_bytes(credential_file, endpoints)
    if len(content) > MAX_OUTPUT_BYTES:
        raise ProfileRenderError(
            "client profile exceeds RedisAuthConfig limit")
    changed = _write_profile(
        output_file,
        content,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    return RenderResult(len(endpoints), len(sources), changed)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render the root host Redis client profile",
    )
    parser.add_argument(
        "--database-root",
        default=DEFAULT_DATABASE_ROOT,
        help=(f"trusted database runtime tree "
              f"(default: {DEFAULT_DATABASE_ROOT})"),
    )
    parser.add_argument(
        "--database-global",
        help=("finalized database_global.json; when omitted with no explicit "
              "configs, use the runtime global map if present"),
    )
    parser.add_argument(
        "--database-config",
        action="append",
        default=[],
        help="additional finalized local database_config.json (repeatable)",
    )
    parser.add_argument(
        "--local-chassis-config",
        help=("finalized config from a locally owned database-chassis "
              "service; "
              "required to authorize redis_chassis"),
    )
    parser.add_argument(
        "--credential-file",
        default=DEFAULT_CREDENTIAL_FILE,
        help="prepared clear credential path (metadata only; never read)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help=f"profile output path (default: {DEFAULT_OUTPUT_FILE})",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _argument_parser().parse_args(argv)
    if os.geteuid() != 0:
        print(
            "redis-client-profile-renderer: must run as root",
            file=sys.stderr,
        )
        return 1
    try:
        result = render_client_profiles(
            database_root=args.database_root,
            database_global=args.database_global,
            database_configs=args.database_config,
            local_chassis_config=args.local_chassis_config,
            credential_file=args.credential_file,
            output_file=args.output,
        )
    except ProfileRenderError as exc:
        print(f"redis-client-profile-renderer: {exc}", file=sys.stderr)
        return 1
    action = "updated" if result.changed else "unchanged"
    print(
        "redis-client-profile-renderer: "
        f"profile={PROFILE_NAME} endpoints={result.endpoint_count} "
        f"sources={result.source_count} action={action}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
