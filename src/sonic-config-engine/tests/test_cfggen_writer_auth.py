import os
import runpy
import sys
import types

from contextlib import contextmanager
from unittest import TestCase
from unittest.mock import patch


class _ConfigDBConnector(object):
    @staticmethod
    def serialize_key(key):
        return key

    @staticmethod
    def deserialize_key(key):
        return key


class _SonicDBConfig(object):
    @staticmethod
    def isGlobalInit():
        return True

    @staticmethod
    def isInit():
        return True


class _PipeConnector(object):
    instances = []
    auth_error = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.connect_calls = []
        self.connect_with_auth_calls = []
        self.mod_config_calls = []
        self.__class__.instances.append(self)

    def connect(self, *args, **kwargs):
        self.connect_calls.append((args, kwargs))

    def connect_with_auth(self, *args, **kwargs):
        self.connect_with_auth_calls.append((args, kwargs))
        if self.__class__.auth_error is not None:
            raise self.__class__.auth_error

    def mod_config(self, data):
        self.mod_config_calls.append(data)

    def get_config(self):
        return {}


class _RedisAuthConfig(object):
    profiles = []
    result = object()
    error = None

    @classmethod
    def fromProfile(cls, profile):
        cls.profiles.append(profile)
        if cls.error is not None:
            raise cls.error
        return cls.result


def _module(name, **attributes):
    module = types.ModuleType(name)
    for attribute, value in attributes.items():
        setattr(module, attribute, value)
    return module


def _unused(*args, **kwargs):
    return None


@contextmanager
def _load_cfggen():
    """Load sonic-cfggen with only its unrelated imports stubbed."""
    netaddr = _module(
        'netaddr',
        IPNetwork=type('IPNetwork', (object,), {}),
        AddrFormatError=ValueError)
    config_samples = _module(
        'config_samples',
        generate_sample_config=_unused,
        get_available_config=lambda: [])
    minigraph = _module(
        'minigraph',
        minigraph_encoder=type('Encoder', (object,), {}),
        parse_device_desc_xml=_unused,
        parse_asic_sub_role=_unused,
        parse_asic_switch_type=_unused,
        parse_hostname=_unused)
    minigraph_ext = _module('minigraph_ext', parse_xml=_unused)
    portconfig = _module(
        'portconfig', get_port_config=_unused, get_breakout_mode=_unused)

    sonic_py_common = _module('sonic_py_common')
    sonic_py_common.__path__ = []
    multi_asic = _module(
        'sonic_py_common.multi_asic',
        get_asic_id_from_name=_unused,
        get_asic_device_id=_unused,
        is_multi_asic=lambda: False,
        get_asic_sub_role=_unused)
    bgp = _module('sonic_py_common.bgp', validate_asn=_unused)
    device_info = _module(
        'sonic_py_common.device_info',
        VS_PLATFORM='x86_64-kvm_x86_64-r0',
        get_platform=lambda: None)
    sonic_py_common.multi_asic = multi_asic
    sonic_py_common.bgp = bgp
    sonic_py_common.device_info = device_info

    swsscommon_package = _module('swsscommon')
    swsscommon_package.__path__ = []
    swsscommon_module = _module(
        'swsscommon.swsscommon',
        ConfigDBConnector=_ConfigDBConnector,
        SonicDBConfig=_SonicDBConfig,
        ConfigDBPipeConnector=_PipeConnector,
        isInterfaceNameValid=lambda name: True)
    swsscommon_package.swsscommon = swsscommon_module

    asic_sensors = _module(
        'asic_sensors_config', get_asic_sensors_config=lambda: {})
    sonic_yang_generator = _module(
        'sonic_yang_cfg_generator',
        SonicYangCfgDbGenerator=type('SonicYangCfgDbGenerator', (object,), {}))

    modules = {
        'netaddr': netaddr,
        'config_samples': config_samples,
        'minigraph': minigraph,
        'minigraph_ext': minigraph_ext,
        'portconfig': portconfig,
        'sonic_py_common': sonic_py_common,
        'sonic_py_common.multi_asic': multi_asic,
        'sonic_py_common.bgp': bgp,
        'sonic_py_common.device_info': device_info,
        'swsscommon': swsscommon_package,
        'swsscommon.swsscommon': swsscommon_module,
        'asic_sensors_config': asic_sensors,
        'sonic_yang_cfg_generator': sonic_yang_generator,
    }
    script = os.path.join(os.path.dirname(__file__), '..', 'sonic-cfggen')
    with patch.dict(sys.modules, modules):
        namespace = runpy.run_path(script)
        yield namespace, swsscommon_module


class TestCfggenWriterAuth(TestCase):
    def setUp(self):
        _PipeConnector.instances = []
        _PipeConnector.auth_error = None
        _RedisAuthConfig.profiles = []
        _RedisAuthConfig.result = object()
        _RedisAuthConfig.error = None

    def _run(self, namespace, arguments):
        with patch.object(sys, 'argv', ['sonic-cfggen'] + arguments):
            namespace['main']()

    def test_writer_profile_requires_write_to_db(self):
        with _load_cfggen() as (namespace, _):
            with patch.object(sys, 'argv', [
                    'sonic-cfggen', '--writer-profile', 'local-system']):
                with self.assertRaises(SystemExit) as error:
                    namespace['main']()

        self.assertEqual(error.exception.code, 2)
        self.assertEqual(_PipeConnector.instances, [])

    def test_writer_profile_requires_value(self):
        with _load_cfggen() as (namespace, _):
            with patch.object(sys, 'argv', [
                    'sonic-cfggen', '--writer-profile', '-w']):
                with self.assertRaises(SystemExit) as error:
                    namespace['main']()

        self.assertEqual(error.exception.code, 2)
        self.assertEqual(_PipeConnector.instances, [])

    def test_local_system_writer_profile_authenticates(self):
        with _load_cfggen() as (namespace, swsscommon_module):
            swsscommon_module.RedisAuthConfig = _RedisAuthConfig
            self._run(namespace, [
                '--writer-profile', 'local-system', '-w'])

        self.assertEqual(_RedisAuthConfig.profiles, ['local-system'])
        connector = _PipeConnector.instances[0]
        self.assertEqual(connector.connect_calls, [])
        self.assertEqual(connector.connect_with_auth_calls, [
            ((False, False, _RedisAuthConfig.result), {})])
        self.assertEqual(connector.mod_config_calls, [{}])

    def test_explicit_profile_preserves_namespace_resolution(self):
        with _load_cfggen() as (namespace, swsscommon_module):
            swsscommon_module.RedisAuthConfig = _RedisAuthConfig
            self._run(namespace, [
                '-n', 'asic0', '-s', '/run/redis/asic0.sock',
                '--writer-profile', 'asic0-system', '-w'])

        self.assertEqual(_RedisAuthConfig.profiles, ['asic0-system'])
        connector = _PipeConnector.instances[0]
        self.assertEqual(connector.kwargs, {
            'use_unix_socket_path': True,
            'namespace': 'asic0',
            'unix_socket_path': '/run/redis/asic0.sock',
        })
        self.assertEqual(len(connector.connect_with_auth_calls), 1)

    def test_profile_failure_propagates_without_fallback_or_write(self):
        expected = RuntimeError('profile rejected')
        _RedisAuthConfig.error = expected
        with _load_cfggen() as (namespace, swsscommon_module):
            swsscommon_module.RedisAuthConfig = _RedisAuthConfig
            with self.assertRaises(RuntimeError) as error:
                self._run(namespace, [
                    '--writer-profile', 'local-system', '-w'])

        self.assertIs(error.exception, expected)
        connector = _PipeConnector.instances[0]
        self.assertEqual(connector.connect_calls, [])
        self.assertEqual(connector.connect_with_auth_calls, [])
        self.assertEqual(connector.mod_config_calls, [])

    def test_connection_auth_failure_propagates_without_fallback_or_write(
            self):
        expected = RuntimeError('AUTH failed')
        _PipeConnector.auth_error = expected
        with _load_cfggen() as (namespace, swsscommon_module):
            swsscommon_module.RedisAuthConfig = _RedisAuthConfig
            with self.assertRaises(RuntimeError) as error:
                self._run(namespace, [
                    '--writer-profile', 'local-system', '-w'])

        self.assertIs(error.exception, expected)
        connector = _PipeConnector.instances[0]
        self.assertEqual(connector.connect_calls, [])
        self.assertEqual(len(connector.connect_with_auth_calls), 1)
        self.assertEqual(connector.mod_config_calls, [])

    def test_legacy_write_does_not_load_or_use_auth(self):
        with _load_cfggen() as (namespace, swsscommon_module):
            self.assertFalse(hasattr(swsscommon_module, 'RedisAuthConfig'))
            self._run(namespace, ['-w'])

        connector = _PipeConnector.instances[0]
        self.assertEqual(connector.connect_calls, [((False,), {})])
        self.assertEqual(connector.connect_with_auth_calls, [])
        self.assertEqual(connector.mod_config_calls, [{}])

    def test_read_path_does_not_load_or_use_auth(self):
        with _load_cfggen() as (namespace, swsscommon_module):
            self.assertFalse(hasattr(swsscommon_module, 'RedisAuthConfig'))
            self._run(namespace, ['-d'])

        connector = _PipeConnector.instances[0]
        self.assertEqual(connector.connect_calls, [((), {})])
        self.assertEqual(connector.connect_with_auth_calls, [])
        self.assertEqual(connector.mod_config_calls, [])
