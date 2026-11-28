"""Generate ignored protobuf modules and provide shared test fixtures."""

import os
import platform
import stat
import subprocess
import sys
import time

import pytest


target_architecture = os.environ.get("CONFIGURED_ARCH", platform.machine())
is_armhf = target_architecture == "armhf" or target_architecture.startswith(
    ("armv6", "armv7", "armv8l")
)

if sys.version_info < (3, 9) or is_armhf:
    collect_ignore = [
        "test_generate_protos.py",
        "test_generated_modules.py",
        "test_gnoi_client.py",
        "test_gnoi_testing.py",
    ]
else:
    from generate_protos import generate

    generate()


@pytest.fixture
def legacy_redis(tmp_path):
    import redis

    path = str(tmp_path / 'redis.sock')
    server = subprocess.Popen([
        'redis-server', '--port', '0', '--unixsocket', path,
        '--save', '', '--appendonly', 'no'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    client = redis.Redis(unix_socket_path=path)
    try:
        for _ in range(200):
            try:
                client.ping()
                break
            except redis.ConnectionError:
                if server.poll() is not None:
                    pytest.fail('fixture Redis exited')
                time.sleep(0.01)
        else:
            pytest.fail('fixture Redis did not start')
        yield path, client
    finally:
        client.close()
        server.terminate()
        server.wait(timeout=10)


# These unit fixtures exercise real modes and symlinks without requiring chown.
# The explicit root acceptance files use actual ownership and UID transitions.
@pytest.fixture
def root_owned_auth_files(monkeypatch):
    from sonic_py_common import redis_auth

    original_os = redis_auth.os
    owners = []

    class FixtureOS:
        def __getattr__(self, name):
            return getattr(original_os, name)

        def fstat(self, fd):
            info = original_os.fstat(fd)
            path = original_os.readlink('/proc/self/fd/' + str(fd))
            for directory, owner in reversed(owners):
                if path == directory or path.startswith(directory + '/'):
                    values = list(info)
                    values[stat.ST_UID] = owner
                    return original_os.stat_result(values)
            return info

    def register(directory, owner=0):
        if original_os.geteuid() == 0 and owner == 0:
            return
        owners.append((original_os.path.realpath(directory), owner))
        monkeypatch.setattr(redis_auth, 'os', FixtureOS())

    return register
