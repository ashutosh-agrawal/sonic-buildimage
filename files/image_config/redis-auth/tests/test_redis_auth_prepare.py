import base64
import contextlib
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


HELPER_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPER_DIRECTORY))

import redis_auth_prepare  # noqa: E402


def _concurrent_initialize_worker(
    state_root,
    runtime_root,
    owner_uid,
    owner_gid,
    barrier,
    result_queue,
):
    """Force two processes to observe the initial state root as absent."""

    real_lexists = redis_auth_prepare.os.path.lexists
    synchronized = False

    def synchronized_lexists(path):
        nonlocal synchronized
        if path == state_root and not synchronized:
            synchronized = True
            observed = real_lexists(path)
            barrier.wait(timeout=10)
            return observed
        return real_lexists(path)

    redis_auth_prepare.os.path.lexists = synchronized_lexists
    try:
        result = redis_auth_prepare.prepare_credential(
            RedisAuthPrepareTest.DOMAIN,
            state_root=state_root,
            runtime_root=runtime_root,
            initialize=True,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        result_queue.put(
            ("ok", result.initialized, result.generation)
        )
    except Exception as exc:  # pragma: no cover - reported to parent test
        result_queue.put(("error", type(exc).__name__, str(exc)))


class RedisAuthPrepareTest(unittest.TestCase):
    DOMAIN = "local-system"
    FIXED_RANDOM = bytes(range(32))

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="redis-auth-prepare-test-"
        )
        self.addCleanup(self.temporary_directory.cleanup)
        base = Path(self.temporary_directory.name)
        self.state_root = base / "state"
        self.runtime_root = base / "run"
        self.owner_uid = os.getuid()
        self.owner_gid = os.getgid()

    def prepare(self, *, initialize=False):
        return redis_auth_prepare.prepare_credential(
            self.DOMAIN,
            state_root=str(self.state_root),
            runtime_root=str(self.runtime_root),
            initialize=initialize,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )

    def initialize(self):
        original_token_bytes = redis_auth_prepare.secrets.token_bytes

        def token_bytes(size):
            if size == 32:
                return self.FIXED_RANDOM
            return original_token_bytes(size)

        with mock.patch.object(
            redis_auth_prepare.secrets,
            "token_bytes",
            side_effect=token_bytes,
        ):
            return self.prepare(initialize=True)

    def assert_metadata(self, path, expected_mode):
        st_result = os.lstat(path)
        self.assertFalse(stat.S_ISLNK(st_result.st_mode))
        self.assertEqual(stat.S_IMODE(st_result.st_mode), expected_mode)
        self.assertEqual(st_result.st_uid, self.owner_uid)
        self.assertEqual(st_result.st_gid, self.owner_gid)
        if stat.S_ISREG(st_result.st_mode):
            self.assertEqual(st_result.st_nlink, 1)

    @property
    def generation_path(self):
        return (
            self.state_root
            / self.DOMAIN
            / "generations"
            / redis_auth_prepare.GENERATION_ONE
        )

    @property
    def initializing_path(self):
        return self.state_root / (".initializing-" + self.DOMAIN)

    @property
    def initializing_generation_path(self):
        return (
            self.initializing_path
            / "generations"
            / redis_auth_prepare.GENERATION_ONE
        )

    @property
    def persistent_secret_path(self):
        return self.generation_path / "writer.secret"

    @property
    def runtime_secret_path(self):
        return self.runtime_root / "clients" / self.DOMAIN / "writer.secret"

    @property
    def runtime_hash_path(self):
        return self.runtime_root / "server" / self.DOMAIN / "writer.sha256"

    def test_absence_does_not_imply_first_boot(self):
        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "explicit initialization is required",
        ):
            self.prepare()

        self.assertFalse(self.state_root.exists())
        self.assertFalse(self.runtime_root.exists())

    def test_explicit_initialization_creates_versioned_durable_state(self):
        result = self.initialize()

        self.assertEqual(result.domain, self.DOMAIN)
        self.assertEqual(result.generation, redis_auth_prepare.GENERATION_ONE)
        self.assertTrue(result.initialized)

        active_path = self.state_root / self.DOMAIN / "active"
        manifest_path = self.generation_path / "manifest.json"
        self.assertEqual(
            active_path.read_text(encoding="ascii"),
            redis_auth_prepare.GENERATION_ONE + "\n",
        )

        credential = self.persistent_secret_path.read_text(encoding="ascii")
        self.assertRegex(credential, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn("=", credential)
        decoded = base64.b64decode(
            credential + "=", altchars=b"-_", validate=True)
        self.assertEqual(decoded, self.FIXED_RANDOM)
        self.assertEqual(
            base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii"),
            credential,
        )

        expected_digest = hashlib.sha256(
            credential.encode("ascii")).hexdigest()
        self.assertRegex(expected_digest, r"^[0-9a-f]{64}$")
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["domain"], self.DOMAIN)
        self.assertEqual(manifest["generation"],
                         redis_auth_prepare.GENERATION_ONE)
        self.assertEqual(manifest["encoding"], "base64url-unpadded")
        self.assertEqual(manifest["credential_sha256"], expected_digest)
        self.assertRegex(manifest["transaction_id"], r"^[0-9a-f]{32}$")

        self.assertEqual(self.runtime_secret_path.read_text(), credential)
        self.assertEqual(self.runtime_hash_path.read_text(),
                         expected_digest + "\n")

        expected_metadata = {
            self.state_root: 0o700,
            self.state_root / self.DOMAIN: 0o700,
            self.state_root / self.DOMAIN / "generations": 0o700,
            self.generation_path: 0o700,
            self.persistent_secret_path: 0o400,
            manifest_path: 0o600,
            active_path: 0o600,
            self.runtime_root: 0o711,
            self.runtime_root / "clients": 0o711,
            self.runtime_root / "server": 0o700,
            self.runtime_root / "clients" / self.DOMAIN: 0o700,
            self.runtime_root / "server" / self.DOMAIN: 0o700,
            self.runtime_secret_path: 0o400,
            self.runtime_hash_path: 0o400,
        }
        for path, expected_mode in expected_metadata.items():
            with self.subTest(path=path):
                self.assert_metadata(path, expected_mode)

        incoming = list(
            (self.state_root / self.DOMAIN / "generations").glob(".incoming-*")
        )
        temporary_files = list(self.state_root.rglob("*.tmp-*"))
        temporary_files += list(self.runtime_root.rglob("*.tmp-*"))
        self.assertEqual(incoming, [])
        self.assertEqual(temporary_files, [])

    def test_repeated_preparation_reuses_same_generation_and_credential(self):
        first = self.initialize()
        persistent_before = self.persistent_secret_path.read_bytes()
        runtime_before = self.runtime_secret_path.read_bytes()
        persistent_inode = self.persistent_secret_path.stat().st_ino
        runtime_inode = self.runtime_secret_path.stat().st_ino

        second = self.prepare()
        third = self.prepare(initialize=True)

        self.assertTrue(first.initialized)
        self.assertFalse(second.initialized)
        self.assertFalse(third.initialized)
        self.assertEqual(second.generation, first.generation)
        self.assertEqual(third.generation, first.generation)
        self.assertEqual(
            self.persistent_secret_path.read_bytes(), persistent_before)
        self.assertEqual(self.runtime_secret_path.read_bytes(), runtime_before)
        self.assertEqual(
            self.persistent_secret_path.stat().st_ino, persistent_inode)
        self.assertEqual(self.runtime_secret_path.stat().st_ino, runtime_inode)
        generations = list(
            (self.state_root / self.DOMAIN / "generations").iterdir())
        self.assertEqual([path.name for path in generations],
                         [first.generation])

    def test_interrupted_initialization_requires_explicit_resume(self):
        original_write = redis_auth_prepare._atomic_write_new_file
        writer_path = self.initializing_generation_path / "writer.secret"
        interrupted = False

        def interrupt_after_writer(path, *args, **kwargs):
            nonlocal interrupted
            original_write(path, *args, **kwargs)
            if not interrupted and path == str(writer_path):
                interrupted = True
                raise RuntimeError("simulated initialization interruption")

        with mock.patch.object(
            redis_auth_prepare,
            "_atomic_write_new_file",
            side_effect=interrupt_after_writer,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated initialization interruption"
            ):
                self.initialize()

        credential = writer_path.read_bytes()
        self.assertFalse((self.state_root / self.DOMAIN).exists())
        self.assertFalse(self.runtime_root.exists())

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "explicit initialization is required",
        ):
            self.prepare()
        self.assertEqual(writer_path.read_bytes(), credential)

        result = self.prepare(initialize=True)

        self.assertTrue(result.initialized)
        self.assertFalse(self.initializing_path.exists())
        self.assertEqual(self.persistent_secret_path.read_bytes(), credential)
        self.assertEqual(self.runtime_secret_path.read_bytes(), credential)

    def test_complete_initializing_tree_is_published_on_explicit_resume(self):
        original_write = redis_auth_prepare._atomic_write_new_file
        active_path = self.initializing_path / "active"
        interrupted = False

        def interrupt_after_active(path, *args, **kwargs):
            nonlocal interrupted
            original_write(path, *args, **kwargs)
            if not interrupted and path == str(active_path):
                interrupted = True
                raise RuntimeError("simulated initialization interruption")

        with mock.patch.object(
            redis_auth_prepare,
            "_atomic_write_new_file",
            side_effect=interrupt_after_active,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated initialization interruption"
            ):
                self.initialize()

        credential = (
            self.initializing_generation_path / "writer.secret"
        ).read_bytes()
        self.assertTrue(active_path.is_file())
        self.assertFalse((self.state_root / self.DOMAIN).exists())

        result = self.prepare(initialize=True)

        self.assertTrue(result.initialized)
        self.assertFalse(self.initializing_path.exists())
        self.assertEqual(self.persistent_secret_path.read_bytes(), credential)

    def test_publish_is_the_commit_point_before_state_root_fsync(self):
        original_fsync = redis_auth_prepare._fsync_directory
        domain_path = self.state_root / self.DOMAIN
        interrupted = False

        def interrupt_after_publish(path):
            nonlocal interrupted
            if (
                not interrupted
                and path == str(self.state_root)
                and domain_path.is_dir()
                and not self.initializing_path.exists()
            ):
                interrupted = True
                raise RuntimeError("simulated post-publish interruption")
            return original_fsync(path)

        with mock.patch.object(
            redis_auth_prepare,
            "_fsync_directory",
            side_effect=interrupt_after_publish,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated post-publish interruption"
            ):
                self.initialize()

        self.assertTrue(domain_path.is_dir())
        self.assertFalse(self.initializing_path.exists())
        result = self.prepare()
        self.assertFalse(result.initialized)
        self.assertTrue(self.runtime_secret_path.is_file())

    def test_recognized_initialization_temporaries_are_recovered(self):
        self.state_root.mkdir(mode=0o700)
        self.initializing_path.mkdir(mode=0o700)
        generations = self.initializing_path / "generations"
        generations.mkdir(mode=0o700)
        self.initializing_generation_path.mkdir(mode=0o700)
        temporary = (
            self.initializing_generation_path
            / (".writer.secret.tmp-" + "0" * 32)
        )
        temporary.write_bytes(b"partial")
        temporary.chmod(0o600)

        result = self.prepare(initialize=True)

        self.assertTrue(result.initialized)
        self.assertFalse(temporary.exists())
        self.assertTrue(self.persistent_secret_path.is_file())

    def test_manifest_initialization_temporary_is_recovered(self):
        self.state_root.mkdir(mode=0o700)
        self.initializing_path.mkdir(mode=0o700)
        generations = self.initializing_path / "generations"
        generations.mkdir(mode=0o700)
        self.initializing_generation_path.mkdir(mode=0o700)
        credential = base64.urlsafe_b64encode(
            self.FIXED_RANDOM
        ).rstrip(b"=")
        writer = self.initializing_generation_path / "writer.secret"
        writer.write_bytes(credential)
        writer.chmod(0o400)
        temporary = (
            self.initializing_generation_path
            / (".manifest.json.tmp-" + "0" * 32)
        )
        temporary.write_bytes(b"partial")
        temporary.chmod(0o600)

        result = self.prepare(initialize=True)

        self.assertTrue(result.initialized)
        self.assertFalse(temporary.exists())
        self.assertEqual(self.persistent_secret_path.read_bytes(), credential)

    def test_active_initialization_temporary_is_recovered(self):
        original_write = redis_auth_prepare._atomic_write_new_file
        manifest_path = (
            self.initializing_generation_path / "manifest.json"
        )
        interrupted = False

        def interrupt_after_manifest(path, *args, **kwargs):
            nonlocal interrupted
            original_write(path, *args, **kwargs)
            if not interrupted and path == str(manifest_path):
                interrupted = True
                raise RuntimeError("simulated initialization interruption")

        with mock.patch.object(
            redis_auth_prepare,
            "_atomic_write_new_file",
            side_effect=interrupt_after_manifest,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated initialization interruption"
            ):
                self.initialize()

        temporary = self.initializing_path / (".active.tmp-" + "0" * 32)
        temporary.write_bytes(b"partial")
        temporary.chmod(0o600)
        credential = (
            self.initializing_generation_path / "writer.secret"
        ).read_bytes()

        result = self.prepare(initialize=True)

        self.assertTrue(result.initialized)
        self.assertFalse(temporary.exists())
        self.assertEqual(self.persistent_secret_path.read_bytes(), credential)

    def test_unsafe_initialization_temporary_is_rejected(self):
        self.state_root.mkdir(mode=0o700)
        self.initializing_path.mkdir(mode=0o700)
        generations = self.initializing_path / "generations"
        generations.mkdir(mode=0o700)
        self.initializing_generation_path.mkdir(mode=0o700)
        temporary = (
            self.initializing_generation_path
            / (".writer.secret.tmp-" + "0" * 32)
        )
        temporary.symlink_to(self.state_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "temporary is unsafe",
        ):
            self.prepare(initialize=True)

        self.assertTrue(temporary.is_symlink())
        self.assertFalse((self.state_root / self.DOMAIN).exists())
        self.assertFalse(self.runtime_root.exists())

    def test_symlink_initializing_directory_is_rejected(self):
        self.state_root.mkdir(mode=0o700)
        real_staging = Path(self.temporary_directory.name) / "real-staging"
        real_staging.mkdir(mode=0o700)
        self.initializing_path.symlink_to(real_staging)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "real directory",
        ):
            self.prepare(initialize=True)

        self.assertTrue(self.initializing_path.is_symlink())
        self.assertFalse((self.state_root / self.DOMAIN).exists())
        self.assertFalse(self.runtime_root.exists())

    def test_hard_linked_initialization_temporary_is_rejected(self):
        self.state_root.mkdir(mode=0o700)
        self.initializing_path.mkdir(mode=0o700)
        generations = self.initializing_path / "generations"
        generations.mkdir(mode=0o700)
        self.initializing_generation_path.mkdir(mode=0o700)
        source = Path(self.temporary_directory.name) / "temporary-source"
        source.write_bytes(b"partial")
        source.chmod(0o600)
        temporary = (
            self.initializing_generation_path
            / (".writer.secret.tmp-" + "0" * 32)
        )
        os.link(source, temporary)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "temporary is unsafe",
        ):
            self.prepare(initialize=True)

        self.assertEqual(source.stat().st_nlink, 2)
        self.assertFalse((self.state_root / self.DOMAIN).exists())

    def test_unknown_initializing_state_is_rejected(self):
        self.state_root.mkdir(mode=0o700)
        self.initializing_path.mkdir(mode=0o700)
        unexpected = self.initializing_path / "unexpected"
        unexpected.write_text("unexpected", encoding="ascii")
        unexpected.chmod(0o600)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "unexpected state",
        ):
            self.prepare(initialize=True)

        self.assertTrue(unexpected.is_file())
        self.assertFalse((self.state_root / self.DOMAIN).exists())
        self.assertFalse(self.runtime_root.exists())

    def test_initializing_tree_never_replaces_published_domain(self):
        self.initialize()
        credential = self.persistent_secret_path.read_bytes()
        inode = self.persistent_secret_path.stat().st_ino
        self.initializing_path.mkdir(mode=0o700)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "published and initializing credential domains both exist",
        ):
            self.prepare(initialize=True)

        self.assertEqual(self.persistent_secret_path.read_bytes(), credential)
        self.assertEqual(self.persistent_secret_path.stat().st_ino, inode)

    def test_missing_active_in_published_domain_is_never_repaired(self):
        self.initialize()
        credential = self.persistent_secret_path.read_bytes()
        active_path = self.state_root / self.DOMAIN / "active"
        active_path.unlink()
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "incomplete or unexpected state",
        ):
            self.prepare(initialize=True)

        self.assertFalse(active_path.exists())
        self.assertFalse(self.initializing_path.exists())
        self.assertEqual(self.persistent_secret_path.read_bytes(), credential)
        self.assertFalse(self.runtime_root.exists())

    def test_concurrent_first_initialization_converges_on_one_credential(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("concurrency test requires multiprocessing fork")
        context = multiprocessing.get_context("fork")
        barrier = context.Barrier(2)
        result_queue = context.Queue()
        arguments = (
            str(self.state_root),
            str(self.runtime_root),
            self.owner_uid,
            self.owner_gid,
            barrier,
            result_queue,
        )
        processes = [
            context.Process(
                target=_concurrent_initialize_worker,
                args=arguments,
            )
            for _ in range(2)
        ]
        try:
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=15)
            self.assertTrue(
                all(not process.is_alive() for process in processes),
                "concurrent initialization did not complete",
            )
            self.assertEqual(
                [process.exitcode for process in processes], [0, 0]
            )
            results = [result_queue.get(timeout=5) for _ in processes]
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            result_queue.close()

        self.assertTrue(all(result[0] == "ok" for result in results), results)
        self.assertEqual(
            sorted(result[1] for result in results), [False, True]
        )
        self.assertEqual(
            {result[2] for result in results},
            {redis_auth_prepare.GENERATION_ONE},
        )
        credential = self.persistent_secret_path.read_bytes()
        self.assertEqual(self.runtime_secret_path.read_bytes(), credential)
        generations = list(
            (self.state_root / self.DOMAIN / "generations").iterdir()
        )
        self.assertEqual(
            [path.name for path in generations],
            [redis_auth_prepare.GENERATION_ONE],
        )

    def test_missing_runtime_tree_is_rebuilt_from_persistent_state(self):
        self.initialize()
        persistent_secret = self.persistent_secret_path.read_bytes()
        persistent_inode = self.persistent_secret_path.stat().st_ino
        expected_runtime_secret = self.runtime_secret_path.read_bytes()
        expected_runtime_hash = self.runtime_hash_path.read_bytes()
        shutil.rmtree(self.runtime_root)

        result = self.prepare()

        self.assertFalse(result.initialized)
        self.assertEqual(
            self.persistent_secret_path.read_bytes(), persistent_secret)
        self.assertEqual(
            self.persistent_secret_path.stat().st_ino, persistent_inode)
        self.assertEqual(
            self.runtime_secret_path.read_bytes(), expected_runtime_secret)
        self.assertEqual(
            self.runtime_hash_path.read_bytes(), expected_runtime_hash)

    def test_interrupted_incoming_runtime_directory_is_resumed(self):
        self.initialize()
        expected_secret = self.runtime_secret_path.read_bytes()
        expected_hash = self.runtime_hash_path.read_bytes()
        shutil.rmtree(self.runtime_root)
        original_write = redis_auth_prepare._atomic_write_new_file
        interrupted = False

        def interrupt_after_server_hash(path, *args, **kwargs):
            nonlocal interrupted
            original_write(path, *args, **kwargs)
            if (
                not interrupted
                and path.endswith(
                    "/server/.incoming-local-system/writer.sha256"
                )
            ):
                interrupted = True
                raise RuntimeError("simulated process interruption")

        with mock.patch.object(
            redis_auth_prepare,
            "_atomic_write_new_file",
            side_effect=interrupt_after_server_hash,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated process interruption"
            ):
                self.prepare()

        incoming = (
            self.runtime_root / "server" / ".incoming-local-system"
        )
        self.assertTrue(incoming.is_dir())

        result = self.prepare()

        self.assertFalse(result.initialized)
        self.assertFalse(incoming.exists())
        self.assertEqual(
            self.runtime_secret_path.read_bytes(), expected_secret
        )
        self.assertEqual(self.runtime_hash_path.read_bytes(), expected_hash)

    def test_interruption_between_server_and_client_publish_is_recovered(self):
        self.initialize()
        expected_secret = self.runtime_secret_path.read_bytes()
        expected_hash = self.runtime_hash_path.read_bytes()
        shutil.rmtree(self.runtime_root)
        original_publish = redis_auth_prepare._publish_runtime_domain
        interrupted = False

        def interrupt_after_server_publish(parent_path, *args, **kwargs):
            nonlocal interrupted
            original_publish(parent_path, *args, **kwargs)
            if not interrupted and parent_path.endswith("/server"):
                interrupted = True
                raise RuntimeError("simulated process interruption")

        with mock.patch.object(
            redis_auth_prepare,
            "_publish_runtime_domain",
            side_effect=interrupt_after_server_publish,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "simulated process interruption"
            ):
                self.prepare()

        self.assertTrue(self.runtime_hash_path.is_file())
        self.assertFalse(self.runtime_secret_path.exists())

        result = self.prepare()

        self.assertFalse(result.initialized)
        self.assertEqual(
            self.runtime_secret_path.read_bytes(), expected_secret
        )
        self.assertEqual(self.runtime_hash_path.read_bytes(), expected_hash)

    def test_multiple_domains_keep_distinct_credentials_and_hashes(self):
        second_domain = "remote-domain"
        second_random = bytes(range(32, 64))
        original_token_bytes = redis_auth_prepare.secrets.token_bytes

        first = self.initialize()

        def second_token_bytes(size):
            if size == 32:
                return second_random
            return original_token_bytes(size)

        with mock.patch.object(
            redis_auth_prepare.secrets,
            "token_bytes",
            side_effect=second_token_bytes,
        ):
            second = redis_auth_prepare.prepare_credential(
                second_domain,
                state_root=str(self.state_root),
                runtime_root=str(self.runtime_root),
                initialize=True,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
            )

        first_secret_path = self.runtime_secret_path
        first_hash_path = self.runtime_hash_path
        second_secret_path = (
            self.runtime_root / "clients" / second_domain / "writer.secret"
        )
        second_hash_path = (
            self.runtime_root / "server" / second_domain / "writer.sha256"
        )
        first_secret = first_secret_path.read_bytes()
        first_hash = first_hash_path.read_bytes()
        second_secret = second_secret_path.read_bytes()
        second_hash = second_hash_path.read_bytes()

        self.assertTrue(first.initialized)
        self.assertTrue(second.initialized)
        self.assertNotEqual(first_secret, second_secret)
        self.assertNotEqual(first_hash, second_hash)
        self.assertEqual(
            hashlib.sha256(first_secret).hexdigest().encode() + b"\n",
            first_hash,
        )
        self.assertEqual(
            hashlib.sha256(second_secret).hexdigest().encode() + b"\n",
            second_hash,
        )

        first_again = self.prepare()
        second_again = redis_auth_prepare.prepare_credential(
            second_domain,
            state_root=str(self.state_root),
            runtime_root=str(self.runtime_root),
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )

        self.assertFalse(first_again.initialized)
        self.assertFalse(second_again.initialized)
        self.assertEqual(first_secret_path.read_bytes(), first_secret)
        self.assertEqual(first_hash_path.read_bytes(), first_hash)
        self.assertEqual(second_secret_path.read_bytes(), second_secret)
        self.assertEqual(second_hash_path.read_bytes(), second_hash)

    def test_partial_persistent_state_is_rejected_even_with_initialize(self):
        self.state_root.mkdir(mode=0o700)
        domain_path = self.state_root / self.DOMAIN
        domain_path.mkdir(mode=0o700)
        (domain_path / "generations").mkdir(mode=0o700)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "incomplete or unexpected state",
        ):
            self.prepare(initialize=True)
        self.assertFalse(self.runtime_root.exists())

    def test_incoming_generation_is_treated_as_interrupted_state(self):
        self.initialize()
        incoming = (
            self.state_root
            / self.DOMAIN
            / "generations"
            / ".incoming-dead"
        )
        incoming.mkdir(mode=0o700)
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "partial or invalid state",
        ):
            self.prepare()
        self.assertFalse(self.runtime_root.exists())

    def test_symlink_active_selector_is_rejected(self):
        self.initialize()
        active_path = self.state_root / self.DOMAIN / "active"
        active_path.unlink()
        active_path.symlink_to("generations/0000000000000001")
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "open required file safely",
        ):
            self.prepare()
        self.assertFalse(self.runtime_root.exists())

    def test_symlink_in_configured_root_is_rejected(self):
        real_state = Path(self.temporary_directory.name) / "real-state"
        self.state_root.symlink_to(real_state)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "real directory",
        ):
            self.prepare(initialize=True)
        self.assertFalse(real_state.exists())
        self.assertFalse(self.runtime_root.exists())

    def test_wrong_persistent_mode_is_rejected_before_runtime_staging(self):
        self.initialize()
        os.chmod(self.persistent_secret_path, 0o600)
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "incorrect mode",
        ):
            self.prepare()
        self.assertFalse(self.runtime_root.exists())

    def test_corrupt_credential_is_rejected_before_runtime_staging(self):
        self.initialize()
        os.chmod(self.persistent_secret_path, 0o600)
        self.persistent_secret_path.write_text(
            "not-base64url\n", encoding="ascii")
        os.chmod(self.persistent_secret_path, 0o400)
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "not canonical base64url",
        ):
            self.prepare()
        self.assertFalse(self.runtime_root.exists())

    def test_manifest_digest_mismatch_is_rejected(self):
        self.initialize()
        manifest_path = self.generation_path / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["credential_sha256"] = "0" * 64
        os.chmod(manifest_path, 0o600)
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "digest does not match",
        ):
            self.prepare()
        self.assertFalse(self.runtime_root.exists())

    def test_runtime_metadata_and_content_corruption_still_fail_closed(self):
        self.initialize()
        os.chmod(self.runtime_hash_path, 0o600)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "incorrect mode",
        ):
            self.prepare()

        os.chmod(self.runtime_hash_path, 0o400)
        original_secret = self.runtime_secret_path.read_bytes()
        self.runtime_secret_path.unlink()

        # A securely owned missing derived artifact is reconstructed, while a
        # present artifact with the wrong content remains a hard failure.
        recovered = self.prepare()
        self.assertFalse(recovered.initialized)
        self.assertEqual(
            self.runtime_secret_path.read_bytes(), original_secret
        )

        self.runtime_secret_path.chmod(0o600)
        self.runtime_secret_path.write_bytes(b"A" * len(original_secret))
        self.runtime_secret_path.chmod(0o400)
        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "does not match active state",
        ):
            self.prepare()

    def test_unknown_runtime_entries_and_unsafe_temporaries_fail_closed(self):
        self.initialize()
        unexpected = self.runtime_secret_path.parent / "unexpected"
        unexpected.write_text("unexpected", encoding="ascii")
        unexpected.chmod(0o400)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "incomplete or unexpected state",
        ):
            self.prepare()

        unexpected.unlink()
        temporary = (
            self.runtime_secret_path.parent
            / ".writer.secret.tmp-00000000000000000000000000000000"
        )
        temporary.symlink_to(self.runtime_secret_path)
        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "temporary is unsafe",
        ):
            self.prepare()

    def test_hard_linked_persistent_secret_is_rejected(self):
        self.initialize()
        extra_link = Path(self.temporary_directory.name) / "secret-link"
        os.link(self.persistent_secret_path, extra_link)
        shutil.rmtree(self.runtime_root)

        with self.assertRaisesRegex(
            redis_auth_prepare.CredentialStateError,
            "unexpected link count",
        ):
            self.prepare()
        self.assertFalse(self.runtime_root.exists())

    def test_invalid_domain_and_noncanonical_roots_are_rejected(self):
        with self.assertRaises(redis_auth_prepare.CredentialStateError):
            redis_auth_prepare.prepare_credential(
                "../escape",
                state_root=str(self.state_root),
                runtime_root=str(self.runtime_root),
                initialize=True,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
            )
        with self.assertRaises(redis_auth_prepare.CredentialStateError):
            redis_auth_prepare.prepare_credential(
                self.DOMAIN,
                state_root=str(self.state_root) + "/../state",
                runtime_root=str(self.runtime_root),
                initialize=True,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
            )
        with self.assertRaises(redis_auth_prepare.CredentialStateError):
            redis_auth_prepare.prepare_credential(
                self.DOMAIN,
                state_root=str(self.state_root),
                runtime_root=str(self.state_root / "runtime"),
                initialize=True,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
            )

    def test_core_emits_no_secret_or_hash(self):
        expected_credential = base64.urlsafe_b64encode(
            self.FIXED_RANDOM).rstrip(b"=").decode()
        expected_digest = hashlib.sha256(
            expected_credential.encode()).hexdigest()
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            self.initialize()

        combined = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(combined, "")
        self.assertNotIn(expected_credential, combined)
        self.assertNotIn(expected_digest, combined)

    def test_cli_status_contains_only_non_secret_identifiers(self):
        secret_marker = "secret-must-not-be-logged"
        digest_marker = "a" * 64
        stdout = io.StringIO()
        stderr = io.StringIO()
        result = redis_auth_prepare.PreparationResult(
            self.DOMAIN,
            redis_auth_prepare.GENERATION_ONE,
            False,
        )

        with mock.patch.object(
            redis_auth_prepare.os, "geteuid", return_value=0
        ), mock.patch.object(
            redis_auth_prepare,
            "prepare_credential",
            return_value=result,
        ), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            exit_code = redis_auth_prepare.main(["--domain", self.DOMAIN])

        self.assertEqual(exit_code, 0)
        output = stdout.getvalue() + stderr.getvalue()
        self.assertIn(self.DOMAIN, output)
        self.assertIn(redis_auth_prepare.GENERATION_ONE, output)
        self.assertNotIn(secret_marker, output)
        self.assertNotIn(digest_marker, output)

    def test_cli_rejects_non_root_before_preparing_state(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(
            redis_auth_prepare.os, "geteuid", return_value=1000
        ), mock.patch.object(
            redis_auth_prepare, "prepare_credential"
        ) as prepare_mock, contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(
            stderr
        ):
            exit_code = redis_auth_prepare.main(["--domain", self.DOMAIN])

        self.assertEqual(exit_code, 1)
        prepare_mock.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("must run as root", stderr.getvalue())

    def test_cli_contains_unexpected_operating_system_errors(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        sensitive_detail = "/secret/internal/path"

        with mock.patch.object(
            redis_auth_prepare.os, "geteuid", return_value=0
        ), mock.patch.object(
            redis_auth_prepare,
            "prepare_credential",
            side_effect=OSError(sensitive_detail),
        ), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(
            stderr
        ):
            exit_code = redis_auth_prepare.main(["--domain", self.DOMAIN])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("operating-system failure", stderr.getvalue())
        self.assertNotIn(sensitive_detail, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
