"""Generate ignored protobuf modules and provide shared test fixtures."""

import os
import platform
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
