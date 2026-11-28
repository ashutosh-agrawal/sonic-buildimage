"""Exercise the redis-dump-load wheel against disposable Redis."""

import io
import json

import pytest
import redisdl


def test_library_keeps_requested_encoding(legacy_redis):
    path, client = legacy_redis
    client.set('binary', b'\x00\xff')
    assert json.loads(redisdl.dumps(unix_socket_path=path, encoding='latin-1'))['binary']['value'] == '\x00\xff'


def test_library_loads_sorted_set_with_current_client(legacy_redis):
    path, client = legacy_redis
    redisdl.loads('{"sorted":{"type":"zset","value":[["one",1.5]]}}', unix_socket_path=path)
    assert client.zscore('sorted', 'one') == 1.5


@pytest.mark.parametrize('pretty', [False, True])
def test_library_round_trip_preserves_persistent_keys(legacy_redis, pretty):
    path, client = legacy_redis
    client.set('persistent', 'value')
    if pretty:
        saved = redisdl.dumps(unix_socket_path=path, pretty=True)
    else:
        output = io.StringIO()
        redisdl.dump(output, unix_socket_path=path)
        saved = output.getvalue()
    client.flushdb()
    redisdl.loads(saved, unix_socket_path=path)
    assert client.get('persistent') == b'value'
    assert client.ttl('persistent') == -1


@pytest.mark.parametrize('streaming', [False, True])
@pytest.mark.parametrize('use_expireat', [False, True])
def test_library_restores_legacy_persistent_keys(legacy_redis, monkeypatch, streaming, use_expireat):
    path, client = legacy_redis
    saved = {'persistent': {'type': 'string', 'value': 'value', 'ttl': -0.001, 'expireat': 1}}
    monkeypatch.setattr(redisdl, 'have_streaming_load', streaming)
    redisdl.load(io.StringIO(json.dumps(saved)), unix_socket_path=path, use_expireat=use_expireat)
    assert client.get('persistent') == b'value'
    assert client.ttl('persistent') == -1
