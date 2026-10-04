import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "redis_client_profile_renderer.py"
SPEC = importlib.util.spec_from_file_location("profile_renderer", MODULE_PATH)
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)

try:
    from swsscommon import swsscommon
except (ImportError, OSError):
    swsscommon = None


def instance(host="127.0.0.1", port=6379,
             socket="/var/run/redis/redis.sock"):
    return {
        "hostname": host,
        "port": port,
        "unix_socket_path": socket,
        "persistence_for_warm_boot": "yes",
    }


def database(db_id, target="redis", separator="|"):
    return {"id": db_id, "instance": target, "separator": separator}


def config(instances=None, databases=None):
    return {
        "INSTANCES": instances or {"redis": instance()},
        "DATABASES": databases or {"CONFIG_DB": database(4)},
        "VERSION": "1.0",
    }


class ProfileRendererTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="redis-profile-test-")
        self.root = Path(self.temp.name)
        self.database_root = self.root / "run"
        self.database_root.mkdir(mode=0o755)
        self.runtime = self.root / "redis-auth"
        self.runtime.mkdir(mode=0o711)
        self.clients = self.runtime / "clients" / "local-system"
        self.clients.mkdir(parents=True, mode=0o700)
        self.credential = self.clients / "writer.secret"
        self.credential.write_bytes(b"content-is-deliberately-not-parsed")
        self.credential.chmod(0o400)
        self.output = self.runtime / "client-profiles.json"
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, relative, value, mode=0o644):
        path = self.database_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        path.chmod(mode)
        return path

    def render(self, *, configs=(), global_path=None, chassis=None):
        return renderer.render_client_profiles(
            database_root=str(self.database_root),
            database_global=None if global_path is None else str(global_path),
            database_configs=[str(path) for path in configs],
            local_chassis_config=None if chassis is None else str(chassis),
            credential_file=str(self.credential),
            output_file=str(self.output),
            trusted_config_uids={self.uid},
            owner_uid=self.uid,
            owner_gid=self.gid,
        )

    def output_document(self):
        return json.loads(self.output.read_text())

    def test_single_instance_renders_exact_swsscommon_schema(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        result = self.render(configs=[source])

        self.assertTrue(result.changed)
        self.assertEqual(result.endpoint_count, 2)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o444)
        self.assertEqual(self.output.stat().st_uid, self.uid)
        profile = self.output_document()["profiles"]["local-system"]
        self.assertEqual(profile["username"], "sonic-trusted-writer")
        self.assertEqual(profile["domain"], "local-system")
        self.assertEqual(profile["credential_file"], str(self.credential))
        self.assertEqual(profile["endpoints"], [
            {"hostname": "127.0.0.1", "port": 6379, "transport": "tcp"},
            {"path": "/var/run/redis/redis.sock", "transport": "unix"},
        ])

    def test_unix_only_instance_omits_disabled_tcp_endpoint(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json",
            config({
                "redis": instance(
                    port=0, socket="/var/run/redis/redis.sock")
            }),
        )

        result = self.render(configs=[source])

        self.assertEqual(result.endpoint_count, 1)
        profile = self.output_document()["profiles"]["local-system"]
        self.assertEqual(profile["endpoints"], [
            {"path": "/var/run/redis/redis.sock", "transport": "unix"},
        ])

    def test_global_map_collects_base_namespace_and_dpu(self):
        base = self.write_json(
            "redis/sonic-db/database_config.json",
            config())
        asic = self.write_json(
            "redis0/sonic-db/database_config.json",
            config(
                {"redis": instance("172.17.0.2", 6379,
                                   "/var/run/redis0/redis.sock")},
                {"CONFIG_DB": database(4)}))
        dpu = self.write_json(
            "redisdpu0/sonic-db/database_config.json",
            config(
                {"redis": instance("169.254.200.254", 6381,
                                   "/var/run/redisdpu0/redis.sock")},
                {"DPU_APPL_DB": database(15, separator=":")}))
        global_path = self.write_json(
            "redis/sonic-db/database_global.json",
            {
                "INCLUDES": [
                    {"include": "database_config.json"},
                    {"namespace": "asic0",
                     "include": "../../redis0/sonic-db/database_config.json"},
                    {"container_name": "dpu0",
                     "include":
                         "../../redisdpu0/sonic-db/database_config.json"},
                ],
                "VERSION": "1.0",
            })

        result = self.render(global_path=global_path)
        self.assertEqual(result.source_count, 3)
        self.assertEqual(result.endpoint_count, 6)
        endpoints = self.output_document()["profiles"]["local-system"][
            "endpoints"]
        self.assertIn(
            {"path": "/var/run/redis0/redis.sock", "transport": "unix"},
            endpoints)
        self.assertIn(
            {"hostname": "169.254.200.254", "port": 6381,
             "transport": "tcp"},
            endpoints)
        self.assertTrue(base.is_file() and asic.is_file() and dpu.is_file())

    def test_remote_and_ambiguous_chassis_are_excluded(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json",
            config(
                {
                    "redis": instance(),
                    "redis_chassis": instance(
                        "redis_chassis.server", 6380,
                        "/var/run/redis-chassis/redis_chassis.sock"),
                    "remote_redis": instance("169.254.200.254", 6381, ""),
                },
                {
                    "CONFIG_DB": database(4),
                    "CHASSIS_APP_DB": database(12, "redis_chassis"),
                    "DPU_APPL_DB": database(15, "remote_redis", ":"),
                }))

        result = self.render(configs=[source])
        self.assertEqual(result.endpoint_count, 2)
        rendered = json.dumps(self.output_document())
        self.assertNotIn("redis_chassis.server", rendered)
        self.assertNotIn("169.254.200.254", rendered)

    def test_explicit_local_chassis_config_adds_chassis_endpoints(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        chassis = self.write_json(
            "redis-chassis/sonic-db/database_config.json",
            config(
                {"redis_chassis": instance(
                    "redis_chassis.server", 6380,
                    "/var/run/redis-chassis/redis_chassis.sock")},
                {"CHASSIS_STATE_DB": database(13, "redis_chassis")}))

        result = self.render(configs=[source], chassis=chassis)
        self.assertEqual(result.endpoint_count, 4)
        endpoints = self.output_document()["profiles"]["local-system"][
            "endpoints"]
        self.assertIn(
            {"hostname": "redis_chassis.server", "port": 6380,
             "transport": "tcp"},
            endpoints)

    def test_idempotent_render_does_not_replace_output(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        first = self.render(configs=[source])
        inode = self.output.stat().st_ino
        second = self.render(configs=[source])
        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertEqual(self.output.stat().st_ino, inode)

    def test_safe_topology_change_atomically_replaces_output(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        self.render(configs=[source])
        inode = self.output.stat().st_ino
        source.write_text(json.dumps(config(
            {"redis": instance(port=6388)},
            {"CONFIG_DB": database(4)})))
        source.chmod(0o644)

        result = self.render(configs=[source])
        self.assertTrue(result.changed)
        self.assertNotEqual(self.output.stat().st_ino, inode)
        endpoints = self.output_document()["profiles"]["local-system"][
            "endpoints"]
        self.assertIn(
            {"hostname": "127.0.0.1", "port": 6388, "transport": "tcp"},
            endpoints)

    def test_multi_asic_shared_tcp_endpoint_is_rendered_once(self):
        base = self.write_json(
            "redis/sonic-db/database_config.json",
            config({"redis": instance(socket="/var/run/redis/redis.sock")}))
        asic = self.write_json(
            "redis0/sonic-db/database_config.json",
            config({"redis": instance(socket="/var/run/redis0/redis.sock")}))
        global_path = self.write_json(
            "redis/sonic-db/database_global.json",
            {
                "INCLUDES": [
                    {"include": "database_config.json"},
                    {"namespace": "asic0",
                     "include": "../../redis0/sonic-db/database_config.json"},
                ],
                "VERSION": "1.0",
            })

        result = self.render(global_path=global_path)
        self.assertEqual(result.endpoint_count, 3)
        endpoints = self.output_document()["profiles"]["local-system"][
            "endpoints"]
        self.assertEqual(endpoints.count(
            {"hostname": "127.0.0.1", "port": 6379,
             "transport": "tcp"}), 1)
        self.assertIn(
            {"path": "/var/run/redis/redis.sock", "transport": "unix"},
            endpoints)
        self.assertIn(
            {"path": "/var/run/redis0/redis.sock", "transport": "unix"},
            endpoints)
        self.assertTrue(base.is_file() and asic.is_file())

    def test_remote_only_map_fails(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json",
            config(
                {"remote_redis": instance("169.254.200.254", 6381, "")},
                {"DPU_APPL_DB": database(15, "remote_redis", ":")}))
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source])
        self.assertFalse(self.output.exists())

    def test_partial_config_fails(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json",
            {"INSTANCES": {"redis": instance()}, "VERSION": "1.0"})
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source])

    def test_duplicate_json_key_fails(self):
        source = self.database_root / "redis/sonic-db/database_config.json"
        source.parent.mkdir(parents=True)
        source.write_text(
            '{"INSTANCES":{"redis":{"hostname":"127.0.0.1",'
            '"port":6379,"port":6380,"unix_socket_path":"/x"}},'
            '"DATABASES":{"CONFIG_DB":{"id":4,"instance":"redis",'
            '"separator":"|"}},"VERSION":"1.0"}')
        source.chmod(0o644)
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source])

    def test_global_include_escape_fails(self):
        global_path = self.write_json(
            "redis/sonic-db/database_global.json",
            {"INCLUDES": [{"include": "../../../../outside.json"}],
             "VERSION": "1.0"})
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(global_path=global_path)

    def test_symlinked_config_fails(self):
        real = self.write_json("real.json", config())
        linked = self.database_root / "redis/sonic-db/database_config.json"
        linked.parent.mkdir(parents=True)
        linked.symlink_to(real)
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[linked])

    def test_group_writable_config_fails(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json", config(), mode=0o664)
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source])

    def test_unsafe_existing_output_fails_closed(self):
        target = self.runtime / "attacker-file"
        target.write_text("unchanged")
        self.output.symlink_to(target)
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source])
        self.assertEqual(target.read_text(), "unchanged")

    def test_bad_credential_metadata_fails_without_reading_it(self):
        self.credential.chmod(0o600)
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source])

    def test_local_chassis_input_rejects_non_chassis_instance(self):
        source = self.write_json(
            "redis/sonic-db/database_config.json", config())
        bad_chassis = self.write_json(
            "redis-chassis/sonic-db/database_config.json", config())
        with self.assertRaises(renderer.ProfileRenderError):
            self.render(configs=[source], chassis=bad_chassis)


@unittest.skipUnless(
    swsscommon is not None
    and hasattr(swsscommon, "RedisAuthConfig")
    and os.geteuid() == 0,
    "requires the candidate swsscommon binding and root metadata",
)
class SwsscommonContractTest(unittest.TestCase):
    def test_rendered_file_is_accepted_by_redis_auth_config(self):
        with tempfile.TemporaryDirectory(
                prefix="redis-profile-contract-") as temp:
            root = Path(temp)
            database_root = root / "run"
            database_root.mkdir(mode=0o755)
            runtime = root / "redis-auth"
            runtime.mkdir(mode=0o711)
            credential = runtime / "clients/local-system/writer.secret"
            credential.parent.mkdir(parents=True, mode=0o700)
            credential.write_bytes(b"A" * 43)
            credential.chmod(0o400)
            source = database_root / "redis/sonic-db/database_config.json"
            source.parent.mkdir(parents=True)
            source.write_text(json.dumps(config()))
            source.chmod(0o644)
            output = runtime / "client-profiles.json"

            renderer.render_client_profiles(
                database_root=str(database_root),
                database_configs=[str(source)],
                credential_file=str(credential),
                output_file=str(output),
                trusted_config_uids={0},
                owner_uid=0,
                owner_gid=0,
            )

            auth = swsscommon.RedisAuthConfig.fromProfile(
                "local-system", str(output))
            self.assertEqual(auth.getUsername(), "sonic-trusted-writer")
            self.assertEqual(auth.getCredentialFile(), str(credential))
            self.assertEqual(auth.getDomain(), "local-system")
            auth.validateTcpEndpoint("127.0.0.1", 6379)
            auth.validateUnixEndpoint("/var/run/redis/redis.sock")
            with self.assertRaises(RuntimeError):
                auth.validateTcpEndpoint("127.0.0.1", 6380)


if __name__ == "__main__":
    unittest.main()
