#!/usr/bin/python3
"""Focused tests for redis-auth-render-acl.

The tests invoke the tool as a process so argument parsing, redacted errors,
filesystem modes, and idempotence are covered together.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
RENDERER = HERE / "redis-auth-render-acl"
WRITER_USER = "sonic-trusted-writer"
MANIFEST = ".redis-auth-managed.json"


def endpoint(port=6379, socket="/var/run/redis/redis.sock", **extra):
    value = {
        "hostname": "127.0.0.1",
        "port": port,
        "unix_socket_path": socket,
        "persistence_for_warm_boot": "yes",
    }
    value.update(extra)
    return value


def database(database_id, instance, separator="|"):
    return {"id": database_id, "separator": separator, "instance": instance}


class RedisAuthRenderAclTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.config_path = self.root / "database_config.json"
        self.hash_path = self.root / "writer.sha256"
        self.output_path = self.root / "acl"
        self.password_hash = hashlib.sha256(
            b"test-only-writer-credential").hexdigest()
        self.hash_path.write_text(self.password_hash + "\n", encoding="ascii")
        self.hash_path.chmod(0o400)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_config(self, instances, databases, **extra):
        config = {"INSTANCES": instances, "DATABASES": databases}
        config.update(extra)
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

    def run_renderer(
        self,
        *,
        output_path=None,
        config_path=None,
        hash_path=None,
        extra_arguments=None,
    ):
        command = [
            sys.executable,
            str(RENDERER),
            "--database-config",
            str(config_path or self.config_path),
            "--writer-password-hash",
            str(hash_path or self.hash_path),
            "--output-dir",
            str(output_path or self.output_path),
            "--path-trust-root",
            str(self.root),
            "--owner-uid",
            str(os.getuid()),
            "--owner-gid",
            str(os.getgid()),
        ]
        if extra_arguments:
            command.extend(extra_arguments)
        return subprocess.run(command, text=True,
                              capture_output=True, check=False)

    def assert_failed_without_hash_disclosure(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        combined = result.stdout + result.stderr
        self.assertNotIn(self.password_hash, combined)
        self.assertNotIn("test-only-writer-credential", combined)

    def test_single_instance_policy_and_production_metadata(self):
        self.write_config(
            {"redis": endpoint()},
            {"CONFIG_DB": database(4, "redis")},
            VERSION="1.0",
        )

        result = self.run_renderer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "Rendered ACL policy for 1 local Redis instance(s)\n")
        self.assertNotIn(self.password_hash, result.stdout + result.stderr)
        expected = (
            "user default reset on nopass ~* &* +@all -acl +acl|whoami\n"
            f"user {WRITER_USER} reset on #{self.password_hash} "
            "~* &* +@all -acl +acl|whoami\n"
        )
        acl_path = self.output_path / "redis-auth-redis.acl"
        self.assertEqual(acl_path.read_text(encoding="ascii"), expected)
        self.assertEqual(stat.S_IMODE(acl_path.stat().st_mode), 0o440)
        self.assertEqual(acl_path.stat().st_uid, os.getuid())
        self.assertEqual(acl_path.stat().st_gid, os.getgid())
        self.assertEqual(stat.S_IMODE(self.output_path.stat().st_mode), 0o750)
        manifest = json.loads(
            (self.output_path /
             MANIFEST).read_text(
                encoding="ascii"))
        self.assertEqual(
            manifest,
            {"schema_version": 1, "files": ["redis-auth-redis.acl"]},
        )

    def test_main_post_transform_config_renders_only_served_instances(self):
        instances = {
            "redis": endpoint(
                bmc_link_ip="169.254.0.2", bmc_link_if="eth0-midplane"
            ),
            "redis1": endpoint(6378, "/var/run/redis/redis1.sock"),
            "redis2": endpoint(6377, "/var/run/redis/redis2.sock"),
            "redis3": endpoint(6376, "/var/run/redis/redis3.sock"),
            "redis4": endpoint(6375, "/var/run/redis/redis4.sock"),
            "redis_bmp": endpoint(6400, "/var/run/redis/redis_bmp.sock"),
            "remote_redis": endpoint(
                6381, "", hostname="169.254.200.254"
            ),
        }
        databases = {
            "CONFIG_DB": database(4, "redis"),
            "APPL_DB": database(0, "redis1", ":"),
            "ASIC_DB": database(1, "redis2", ":"),
            "COUNTERS_DB": database(2, "redis3", ":"),
            "BMC_DB": database(12, "redis4", ":"),
            "BMP_STATE_DB": database(20, "redis_bmp"),
            "DPU_STATE_DB": database(17, "remote_redis"),
        }
        self.write_config(instances, databases)

        result = self.run_renderer()

        self.assertEqual(result.returncode, 0, result.stderr)
        expected_files = {
            MANIFEST,
            "redis-auth-redis.acl",
            "redis-auth-redis1.acl",
            "redis-auth-redis2.acl",
            "redis-auth-redis3.acl",
            "redis-auth-redis4.acl",
            "redis-auth-redis_bmp.acl",
        }
        self.assertEqual(
            {path.name for path in self.output_path.iterdir()}, expected_files)
        self.assertFalse(
            (self.output_path / "redis-auth-remote_redis.acl").exists())

    def test_database_chassis_post_transform_config_renders_chassis_only(self):
        self.write_config(
            {
                "redis_chassis": endpoint(
                    6380,
                    "/var/run/redis-chassis/redis_chassis.sock",
                    hostname="redis_chassis.server",
                )
            },
            {"CHASSIS_STATE_DB": database(13, "redis_chassis")},
        )

        result = self.run_renderer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {path.name for path in self.output_path.iterdir()},
            {MANIFEST, "redis-auth-redis_chassis.acl"},
        )

    def test_dpu_configuration_may_map_databases_to_remote_instance(self):
        self.write_config(
            {
                "redis": endpoint(
                    6382,
                    "/var/run/redisdpu0/redis.sock",
                    hostname="169.254.200.254",
                    database_type="dpudb",
                ),
                "remote_redis": endpoint(
                    6381, "", hostname="169.254.200.1"
                ),
            },
            {
                "CONFIG_DB": database(4, "redis"),
                "DPU_APPL_DB": database(15, "remote_redis", ":"),
            },
        )

        result = self.run_renderer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output_path / "redis-auth-redis.acl").is_file())
        self.assertFalse(
            (self.output_path / "redis-auth-remote_redis.acl").exists())

    def test_invalid_database_schemas_fail_closed(self):
        invalid_configs = [
            {"INSTANCES": [], "DATABASES": {}},
            {
                "INSTANCES": {"redis": endpoint()},
                "DATABASES": {"CONFIG_DB": database(4, "missing")},
            },
            {
                "INSTANCES": {"redis": endpoint(port=True)},
                "DATABASES": {"CONFIG_DB": database(4, "redis")},
            },
            {
                "INSTANCES": {"redis": endpoint(socket="")},
                "DATABASES": {"CONFIG_DB": database(4, "redis")},
            },
            {
                "INSTANCES": {"remote_redis": endpoint(socket="")},
                "DATABASES": {"DPU_STATE_DB": database(17, "remote_redis")},
            },
        ]
        for index, invalid_config in enumerate(invalid_configs):
            with self.subTest(index=index):
                self.config_path.write_text(
                    json.dumps(invalid_config), encoding="utf-8")
                result = self.run_renderer(
                    output_path=self.root / f"invalid-{index}")
                self.assert_failed_without_hash_disclosure(result)

        self.config_path.write_text(
            '{"INSTANCES":{},"INSTANCES":{},"DATABASES":{}}', encoding="utf-8"
        )
        result = self.run_renderer(output_path=self.root / "duplicate-key")
        self.assert_failed_without_hash_disclosure(result)

    def test_invalid_hash_files_fail_closed_without_echoing_contents(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        invalid_values = [
            self.password_hash.upper(),
            self.password_hash[:-1],
            self.password_hash + "\n\n",
            "do-not-print-this-invalid-secret",
        ]
        for index, value in enumerate(invalid_values):
            with self.subTest(index=index):
                bad_hash = self.root / f"bad-hash-{index}"
                bad_hash.write_text(value, encoding="ascii")
                bad_hash.chmod(0o400)
                result = self.run_renderer(
                    output_path=self.root / f"bad-output-{index}",
                    hash_path=bad_hash,
                )
                self.assert_failed_without_hash_disclosure(result)
                self.assertNotIn(value, result.stdout + result.stderr)

        result = self.run_renderer(
            output_path=self.root / "missing-output",
            hash_path=self.root / "missing-hash",
        )
        self.assert_failed_without_hash_disclosure(result)

        for index, mode in enumerate((0o600, 0o440, 0o644)):
            with self.subTest(mode=oct(mode)):
                wrong_mode_hash = self.root / f"wrong-mode-hash-{index}"
                wrong_mode_hash.write_text(
                    self.password_hash + "\n", encoding="ascii"
                )
                wrong_mode_hash.chmod(mode)
                result = self.run_renderer(
                    output_path=self.root / f"wrong-mode-output-{index}",
                    hash_path=wrong_mode_hash,
                )
                self.assert_failed_without_hash_disclosure(result)

    def test_unsafe_instance_name_is_rejected(self):
        self.write_config(
            {"../redis": endpoint()},
            {"CONFIG_DB": database(4, "../redis")},
        )
        result = self.run_renderer(output_path=self.root / "unsafe-instance")
        self.assert_failed_without_hash_disclosure(result)
        self.assertFalse((self.root / "redis-auth-redis.acl").exists())

    def test_input_and_output_symlinks_are_rejected(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )

        hash_link = self.root / "hash-link"
        hash_link.symlink_to(self.hash_path)
        result = self.run_renderer(
            output_path=self.root / "hash-link-output", hash_path=hash_link
        )
        self.assert_failed_without_hash_disclosure(result)

        config_link = self.root / "config-link"
        config_link.symlink_to(self.config_path)
        result = self.run_renderer(
            output_path=self.root / "config-link-output",
            config_path=config_link,
        )
        self.assert_failed_without_hash_disclosure(result)

        real_output = self.root / "real-output"
        real_output.mkdir(mode=0o750)
        output_link = self.root / "output-link"
        output_link.symlink_to(real_output, target_is_directory=True)
        result = self.run_renderer(output_path=output_link)
        self.assert_failed_without_hash_disclosure(result)

        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o750)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        result = self.run_renderer(output_path=parent_link / "acl")
        self.assert_failed_without_hash_disclosure(result)

        target_output = self.root / "target-output"
        target_output.mkdir(mode=0o750)
        outside = self.root / "outside"
        outside.write_text("unchanged", encoding="ascii")
        (target_output / "redis-auth-redis.acl").symlink_to(outside)
        result = self.run_renderer(output_path=target_output)
        self.assert_failed_without_hash_disclosure(result)
        self.assertEqual(outside.read_text(encoding="ascii"), "unchanged")

    def test_group_writable_output_directory_is_rejected(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        self.output_path.mkdir(mode=0o770)
        self.output_path.chmod(0o770)

        result = self.run_renderer()

        self.assert_failed_without_hash_disclosure(result)
        self.assertEqual(list(self.output_path.iterdir()), [])

        unsafe_parent = self.root / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o770)
        unsafe_parent.chmod(0o770)
        result = self.run_renderer(output_path=unsafe_parent / "acl")
        self.assert_failed_without_hash_disclosure(result)
        self.assertFalse((unsafe_parent / "acl").exists())

    def test_stale_manifest_entries_are_pruned_and_foreign_files_remain(self):
        self.write_config(
            {
                "redis": endpoint(),
                "redis1": endpoint(6378, "/var/run/redis/redis1.sock"),
            },
            {
                "CONFIG_DB": database(4, "redis"),
                "APPL_DB": database(0, "redis1", ":"),
            },
        )
        first = self.run_renderer()
        self.assertEqual(first.returncode, 0, first.stderr)
        foreign = self.output_path / "operator-note"
        foreign.write_text("leave me alone", encoding="ascii")

        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        second = self.run_renderer()

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertFalse((self.output_path / "redis-auth-redis1.acl").exists())
        self.assertEqual(foreign.read_text(encoding="ascii"), "leave me alone")
        manifest = json.loads(
            (self.output_path /
             MANIFEST).read_text(
                encoding="ascii"))
        self.assertEqual(manifest["files"], ["redis-auth-redis.acl"])

    def test_missing_manifest_is_recovered_by_reserved_prefix_scan(self):
        self.write_config(
            {
                "redis": endpoint(),
                "redis1": endpoint(6378, "/var/run/redis/redis1.sock"),
            },
            {
                "CONFIG_DB": database(4, "redis"),
                "APPL_DB": database(0, "redis1", ":"),
            },
        )
        first = self.run_renderer()
        self.assertEqual(first.returncode, 0, first.stderr)

        # Simulate interruption after ACL renames but before the manifest
        # rename.
        (self.output_path / MANIFEST).unlink()
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )

        recovered = self.run_renderer()

        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(
            {
                path.name
                for path in self.output_path.iterdir()
                if path.name.startswith("redis-auth-")
            },
            {"redis-auth-redis.acl"},
        )
        manifest = json.loads(
            (self.output_path /
             MANIFEST).read_text(
                encoding="ascii"))
        self.assertEqual(manifest["files"], ["redis-auth-redis.acl"])

    def test_dead_renderer_temps_are_removed_but_similar_files_remain(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        self.output_path.mkdir(mode=0o750)
        dead_pid = "9999999"
        nonce = "0123456789abcdef"
        stale_acl = self.output_path / (
            f".redis-auth-redis.acl.tmp.{dead_pid}.{nonce}"
        )
        stale_manifest = self.output_path / (
            f"..redis-auth-managed.json.tmp.{dead_pid}.{nonce}"
        )
        stale_acl.write_text("partial ACL", encoding="ascii")
        stale_acl.chmod(0o600)
        stale_manifest.write_text("partial manifest", encoding="ascii")
        stale_manifest.chmod(0o440)
        live_temp = self.output_path / (
            f".redis-auth-redis.acl.tmp.{os.getpid()}.fedcba9876543210"
        )
        live_temp.write_text("active renderer", encoding="ascii")
        live_temp.chmod(0o600)
        similar_foreign = self.output_path / (
            f".redis-auth-redis.acl.tmp.not-a-pid.{nonce}"
        )
        similar_foreign.write_text("leave me alone", encoding="ascii")

        result = self.run_renderer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(stale_acl.exists())
        self.assertFalse(stale_manifest.exists())
        self.assertEqual(
            live_temp.read_text(encoding="ascii"), "active renderer"
        )
        self.assertEqual(
            similar_foreign.read_text(encoding="ascii"), "leave me alone"
        )

    def test_matching_stale_temp_symlink_is_rejected(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        self.output_path.mkdir(mode=0o750)
        outside = self.root / "stale-temp-outside"
        outside.write_text("unchanged", encoding="ascii")
        stale_link = self.output_path / (
            ".redis-auth-redis.acl.tmp.9999999.0123456789abcdef"
        )
        stale_link.symlink_to(outside)

        result = self.run_renderer()

        self.assert_failed_without_hash_disclosure(result)
        self.assertTrue(stale_link.is_symlink())
        self.assertEqual(outside.read_text(encoding="ascii"), "unchanged")

    def test_invalid_reserved_prefix_file_fails_closed(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        self.output_path.mkdir(mode=0o750)
        invalid = self.output_path / "redis-auth-bad name.acl"
        invalid.write_text("foreign", encoding="ascii")
        invalid.chmod(0o440)

        result = self.run_renderer()

        self.assert_failed_without_hash_disclosure(result)
        self.assertEqual(invalid.read_text(encoding="ascii"), "foreign")

    def test_stale_symlink_is_rejected_instead_of_followed_or_removed(self):
        self.write_config(
            {
                "redis": endpoint(),
                "redis1": endpoint(6378, "/var/run/redis/redis1.sock"),
            },
            {
                "CONFIG_DB": database(4, "redis"),
                "APPL_DB": database(0, "redis1", ":"),
            },
        )
        first = self.run_renderer()
        self.assertEqual(first.returncode, 0, first.stderr)

        stale = self.output_path / "redis-auth-redis1.acl"
        stale.unlink()
        outside = self.root / "stale-outside"
        outside.write_text("unchanged", encoding="ascii")
        stale.symlink_to(outside)
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )

        second = self.run_renderer()

        self.assert_failed_without_hash_disclosure(second)
        self.assertTrue(stale.is_symlink())
        self.assertEqual(outside.read_text(encoding="ascii"), "unchanged")

    def test_identical_second_render_does_not_replace_files(self):
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        first = self.run_renderer()
        self.assertEqual(first.returncode, 0, first.stderr)
        paths = [
            self.output_path / "redis-auth-redis.acl",
            self.output_path / MANIFEST,
        ]
        before = {
            path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
            for path in paths
        }

        second = self.run_renderer()

        self.assertEqual(second.returncode, 0, second.stderr)
        after = {
            path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
            for path in paths
        }
        self.assertEqual(after, before)

    @unittest.skipUnless(
        shutil.which("redis-server") and shutil.which("redis-cli"),
        "redis-server and redis-cli are required for ACL syntax validation",
    )
    def test_generated_policy_loads_and_enforces_writer_acl(self):
        version = subprocess.run(
            [shutil.which("redis-server"), "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
        match = re.search(r"\bv=([0-9]+)\.", version.stdout + version.stderr)
        if match is None or int(match.group(1)) < 7:
            self.skipTest(
                "target ACL syntax requires Redis 7 or newer")

        credential = secrets.token_urlsafe(32)
        self.password_hash = hashlib.sha256(
            credential.encode("ascii")).hexdigest()
        self.hash_path.chmod(0o600)
        self.hash_path.write_text(self.password_hash + "\n", encoding="ascii")
        self.hash_path.chmod(0o400)
        self.write_config(
            {"redis": endpoint()}, {"CONFIG_DB": database(4, "redis")}
        )
        rendered = self.run_renderer()
        self.assertEqual(rendered.returncode, 0, rendered.stderr)

        socket_path = self.root / "redis.sock"
        server = subprocess.Popen(
            [
                shutil.which("redis-server"),
                "--port",
                "0",
                "--unixsocket",
                str(socket_path),
                "--unixsocketperm",
                "700",
                "--aclfile",
                str(self.output_path / "redis-auth-redis.acl"),
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    stdout, stderr = server.communicate()
                    self.fail(
                        "redis-server rejected generated ACL policy: "
                        f"{stdout}{stderr}"
                    )
                if socket_path.exists():
                    break
                time.sleep(0.05)
            else:
                self.fail("redis-server did not create its Unix socket")

            default_ping = subprocess.run(
                [shutil.which("redis-cli"), "-s",
                 str(socket_path), "--raw", "PING"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(default_ping.stdout.strip(), "PONG")

            def default_command(*arguments):
                return subprocess.run(
                    [
                        shutil.which("redis-cli"),
                        "-s",
                        str(socket_path),
                        "--raw",
                        *arguments,
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )

            compatibility_write = default_command(
                "SET", "anonymous-compatibility-write", "ok"
            )
            self.assertEqual(compatibility_write.stdout.strip(), "OK")
            default_setuser = default_command(
                "ACL", "SETUSER", "forbidden-default", "on"
            )
            self.assertIn(
                "NOPERM", default_setuser.stdout + default_setuser.stderr
            )
            default_deluser = default_command(
                "ACL", "DELUSER", WRITER_USER
            )
            self.assertIn(
                "NOPERM", default_deluser.stdout + default_deluser.stderr
            )

            writer_environment = os.environ.copy()
            writer_environment["REDISCLI_AUTH"] = credential

            def writer_command(*arguments):
                return subprocess.run(
                    [
                        shutil.which("redis-cli"),
                        "-s",
                        str(socket_path),
                        "--raw",
                        "--user",
                        WRITER_USER,
                        *arguments,
                    ],
                    env=writer_environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            whoami = writer_command("ACL", "WHOAMI")
            self.assertEqual(whoami.stdout.strip(), WRITER_USER)
            write = writer_command("SET", "renderer-test", "ok")
            self.assertEqual(write.stdout.strip(), "OK")
            acl_admin = writer_command("ACL", "SETUSER", "forbidden", "on")
            self.assertIn("NOPERM", acl_admin.stdout + acl_admin.stderr)

            # Migration deliberately preserves legacy CONFIG SET callers.
            # Denying direct ACL commands protects the named identity from
            # deletion, but does not make the write-capable default user an
            # authentication-administration boundary.
            default_requirepass = default_command(
                "CONFIG", "SET", "requirepass", "temporary-test-password"
            )
            self.assertEqual(default_requirepass.stdout.strip(), "OK")
            unauthenticated_ping = default_command("PING")
            self.assertIn(
                "NOAUTH",
                unauthenticated_ping.stdout + unauthenticated_ping.stderr,
            )
            writer_after_default_change = writer_command("ACL", "WHOAMI")
            self.assertEqual(
                writer_after_default_change.stdout.strip(), WRITER_USER
            )
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            if server.stdout is not None:
                server.stdout.close()
            if server.stderr is not None:
                server.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
