"""Qualify file-backed layouts before Redis, without a topology cache."""
import configparser
import importlib
import json
import os
from pathlib import Path
import sys
import types

import pytest

import redis_auth_startup as startup

PLATFORM_LAYOUT = startup.platform_layout
ERRORS = (startup.CredentialStateError, OSError, ValueError, KeyError, TypeError, configparser.Error)


@pytest.fixture
def host(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('requires root-owned startup metadata')
    # Exercise the real file-based SONiC APIs. Any ConfigDB access is a failure.
    def no_database(*_args, **_kwargs):
        raise AssertionError('layout discovery must not connect to Redis')
    native = types.ModuleType('swsscommon.swsscommon')
    native.ConfigDBConnector = native.SonicV2Connector = no_database
    monkeypatch.setitem(sys.modules, 'swsscommon', types.ModuleType('swsscommon'))
    monkeypatch.setitem(sys.modules, 'swsscommon.swsscommon', native)
    root = Path(__file__).resolve().parents[4]
    monkeypatch.syspath_prepend(str(root / 'src/sonic-py-common'))
    device = importlib.import_module('sonic_py_common.device_info')
    monkeypatch.delenv('PLATFORM', raising=False)
    monkeypatch.setattr(device, 'MACHINE_CONF_PATH', str(tmp_path / 'host/machine.conf'))
    monkeypatch.setattr(device, 'HOST_DEVICE_PATH', str(tmp_path / 'usr/share/sonic/device'))
    monkeypatch.setattr(device, 'CONTAINER_PLATFORM_PATH', str(tmp_path / 'usr/share/sonic/platform'))
    monkeypatch.setattr(startup, 'CONFIG', tmp_path / 'etc/sonic')
    monkeypatch.setattr(startup, 'NETNS', tmp_path / 'run/netns')
    monkeypatch.setattr(startup, 'platform_layout', PLATFORM_LAYOUT)

    def write(name, value):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path
    platform = 'usr/share/sonic/device/example/'
    write('host/machine.conf', 'onie_platform=example\n')
    write('etc/sonic/config_db.json', {'DEVICE_METADATA': {'localhost': {
        'platform': 'example', 'type': 'ToRRouter'}}})
    write(platform + 'asic.conf', 'NUM_ASIC=1\n')
    return tmp_path, write, platform


def qualify():
    layout = startup.platform_layout()
    startup.check_layout(*layout)
    return startup.configured_instances()


def test_single_host_defaults_and_local_bmc_client(host):
    root, write, platform = host
    assert len(qualify()) == 2
    (root / platform / 'asic.conf').unlink()
    write('etc/sonic/bmc.json', {'bmc_addr': '10.0.0.2'})
    write(platform + 'platform_env.conf', 'switch_host=1\n')
    assert len(qualify()) == 2


@pytest.mark.parametrize('file,value', [
    ('asic.conf', 'NUM_ASIC=0'), ('asic.conf', 'NUM_ASIC=unknown'), ('asic.conf', ''),
    ('asic.conf', 'NUM_ASIC=2\nNUM_ASIC=4'), ('asic.conf', '[other]\nNUM_ASIC=2'),
    ('platform.json', {'DPU': {}}), ('platform.json', {'DPUS': {}}), ('platform.json', '{'),
    ('platform_env.conf', 'supervisor=1'), ('platform_env.conf', 'supervisor=unknown'),
    ('platform_env.conf', 'disaggregated_chassis=1'), ('platform_env.conf', 'switch_bmc=1'),
    ('chassisdb.conf', ''),
])
def test_unsupported_or_malformed_platform(host, file, value):
    _, write, platform = host
    write(platform + file, value)
    with pytest.raises(ERRORS):
        qualify()


@pytest.mark.parametrize('field,value', [
    ('switch_type', 'voq'), ('switch_type', 'dpu'), ('switch_type', 'chassis-packet'),
    ('switch_type', ''), ('switch_type', None), ('switch_type', 'unknown'),
    ('type', 'SpineRouter'), ('type', 'SmartSwitchDPU'), ('type', 'unknown'),
    ('subtype', 'SmartSwitch'), ('subtype', 'Supervisor'), ('platform', 'other'),
])
def test_unsupported_role_or_identity(host, field, value):
    root, write, _ = host
    data = json.loads((root / 'etc/sonic/config_db.json').read_text())
    data['DEVICE_METADATA']['localhost'][field] = value
    write('etc/sonic/config_db.json', data)
    with pytest.raises(ERRORS):
        qualify()


@pytest.mark.parametrize('file', ['etc/sonic/config_db.json', 'host/machine.conf'])
def test_required_metadata_must_exist_and_parse(host, file):
    root, write, _ = host
    (root / file).unlink()
    with pytest.raises(ERRORS):
        qualify()
    write(file, '{')
    with pytest.raises(ERRORS):
        qualify()


@pytest.mark.parametrize('file', ['asic.conf', 'platform_env.conf', 'platform.json'])
def test_broken_optional_file_is_not_a_default(host, file):
    root, _, platform = host
    path = root / platform / file
    path.unlink(missing_ok=True)
    path.symlink_to('missing')
    with pytest.raises(ERRORS):
        qualify()


def test_conflicting_platform_alias(host):
    root, _, _ = host
    (root / 'usr/share/sonic/platform').symlink_to('device/other')
    with pytest.raises(ERRORS):
        qualify()


@pytest.mark.parametrize('file,value', [
    ('config_db0.json', {}), ('database_config0.json', {}), ('database_configdpu0.json', {}),
    ('chassisdb_address', ''), ('enable_multidb', ''),
    ('database_global.json', {'INCLUDES': [{'namespace': 'asic0', 'include': 'other'}]}),
    ('database_global.json', '{'),
])
def test_extra_layout_is_rejected_in_current_and_saved_config(host, file, value):
    root, write, _ = host
    for directory in ('etc/sonic/', 'etc/sonic/old_config/'):
        path = write(directory + file, value)
        with pytest.raises(ERRORS):
            qualify()
        path.unlink()


@pytest.mark.parametrize('count', [2, 4, 6])
def test_file_backed_discovery_before_and_after_namespaces(host, count):
    _, write, platform = host
    write(platform + 'asic.conf', f'NUM_ASIC={count}')
    includes = [{'include': '../../redis/sonic-db/database_config.json'}] + [
        {'namespace': f'asic{i}', 'include': f'../../redis{i}/sonic-db/database_config.json'}
        for i in range(count)]
    write('etc/sonic/database_global.json', {'INCLUDES': includes})
    assert len(qualify()) == 2 * (count + 1)
    for i in range(count):
        write(f'run/netns/asic{i}', '')
        write(f'etc/sonic/config_db{i}.json', {})
    assert len(qualify()) == 2 * (count + 1)
    write(f'run/netns/asic{count}', '')
    with pytest.raises(ERRORS):
        qualify()


def test_saved_metadata_and_published_inventory_are_the_boot_boundary(host, root_directory, monkeypatch):
    root, write, platform = host
    write(platform + 'asic.conf', 'NUM_ASIC=2')
    write('etc/sonic/pending_config_migration', '')
    saved = root / 'etc/sonic/old_config'
    saved.mkdir()
    (root / 'etc/sonic/config_db.json').rename(saved / 'config_db.json')
    monkeypatch.setattr(startup, 'build_enabled', lambda: True)
    intent, runtime = root_directory / 'intent.json', root_directory / 'runtime'
    intent.write_text('{"mode":"enforce"}')
    assert len(startup.prepare_selected(intent_path=intent, runtime=runtime)) == 6
    assert not (runtime / 'server/topology.json').exists()
    (saved / 'config_db.json').unlink()
    assert startup.runtime_required(intent_path=intent, runtime=runtime)
    assert len(startup.prepare_selected(intent_path=intent, runtime=runtime)) == 6


def test_legacy_and_disabled_modes_do_not_discover_layout(host, root_directory, monkeypatch):
    intent, runtime = root_directory / 'intent.json', root_directory / 'runtime'
    monkeypatch.setattr(startup, 'platform_layout', lambda: pytest.fail('must not discover layout'))
    monkeypatch.setattr(startup, 'build_enabled', lambda: True)
    assert startup.prepare_selected(intent_path=intent, runtime=runtime) == []
    assert not startup.runtime_required(intent_path=intent, runtime=runtime)
    monkeypatch.setattr(startup, 'build_enabled', lambda: False)
    intent.write_text('{"mode":"enforce"}')
    assert startup.prepare_selected(intent_path=intent, runtime=runtime) == []


@pytest.mark.parametrize('relative', ['server/users.acl', 'server/instances.json', 'local.json',
                                    'local-system/writer.secret', 'local-system/writer.sha256'])
def test_missing_published_file_never_initializes_state(host, root_directory, monkeypatch, relative):
    monkeypatch.setattr(startup, 'build_enabled', lambda: True)
    intent, runtime = root_directory / 'intent.json', root_directory / 'runtime'
    intent.write_text('{"mode":"enforce"}')
    startup.prepare_selected(intent_path=intent, runtime=runtime)
    path = runtime / relative
    path.unlink()
    with pytest.raises(ERRORS):
        startup.runtime_required(intent_path=intent, runtime=runtime)
    assert not path.exists()
