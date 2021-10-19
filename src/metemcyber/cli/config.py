#
#    Copyright 2021, NTT Communications Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

import copy
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address
from pathlib import Path
from shutil import copyfile, rmtree, which
from typing import Any, Callable, ClassVar, List, Optional, Tuple, Type

import typer
import validators
from eth_typing import ChecksumAddress
from omegaconf import OmegaConf
from omegaconf.dictconfig import DictConfig
from web3 import Web3

from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.contract import Contract
from metemcyber.core.bc.cti_broker import CTIBroker
from metemcyber.core.bc.cti_catalog import CTICatalog
from metemcyber.core.bc.cti_operator import CTIOperator
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
from metemcyber.core.bc.util import decode_keyfile as util_decode_keyfile
from metemcyber.core.plugin import PluginManager

METEMCTL_CONFIG_FILEPATH = f'{APP_DIR}/metemctl.yaml'
WORKSPACE_PREFIX = 'workspace.'
WORKSPACE_DEFAULT = 'pricom-mainnet'
WORKSPACE_CONFIG_FILENAME = 'config.yaml'
WORKSPACE_MINIMAL_DIRS = {
    'upload',
    'download',
}


def decode_keyfile(keyfile: str, pw_candidate: Optional[str]) -> Tuple[ChecksumAddress, str]:
    def pwf():
        return pw_candidate or typer.prompt('Enter password for keyfile', hide_input=True)
    return util_decode_keyfile(keyfile, password_func=pwf)


def _fake_echo(*_args, **_kwargs):
    pass


def _skip_validation(_key: Optional[str],
                     echo: Callable[..., None] = _fake_echo, pref: str = ''):
    if not str:
        return
    echo(f'skip: {pref}validator not implemented for this param.')


def _regularfile_validator(filepath: str,
                           echo: Callable[..., None] = _fake_echo, pref: str = ''):
    if not os.path.exists(filepath):
        raise Exception(f"{pref}No such file or directory: '{filepath}'")
    if not os.path.isfile(filepath):
        raise Exception(f"{pref}Not a regular file: '{filepath}'")
    echo(f'ok: {pref}{filepath} is a regular file.')


def _directory_validator(filepath: str,
                         echo: Callable[..., None] = _fake_echo, pref: str = ''):
    if not os.path.exists(filepath):
        raise Exception(f"{pref}No such file or directory: '{filepath}'")
    if not os.path.isdir(filepath):
        raise Exception(f"{pref}Not a directory: '{filepath}'")
    echo(f'ok: {pref}{filepath} is a directory.')


def _keyfile_validator(keyfile: str, keyfile_password: str,
                       echo: Callable[..., None] = _fake_echo, pref: str = ''):
    if keyfile and keyfile_password:
        try:
            eoaa, _pkey = decode_keyfile(keyfile, keyfile_password)
            echo(f'ok: {pref}valid for EOA {eoaa}.')
        except Exception as err:
            raise Exception(f'{pref}{err}') from err
    else:
        echo(f'skip: {pref}not configured.')


def _int_range_validator(num: int, minimum: Optional[int] = None, maximum: Optional[int] = None,
                         echo: Callable[..., None] = _fake_echo, pref: str = ''):
    if minimum is not None and num < minimum:
        raise Exception(f'Too small value: {pref}{num} (should >= {minimum})')
    if maximum is not None and num > maximum:
        raise Exception(f'Too big value: {pref}{num} (should <= {maximum})')
    echo(f'ok: {pref}{num} is a valid number.')


def _url_validator(url: str,
                   echo: Callable[..., None] = _fake_echo, pref: str = ''):
    result = validators.url(url)
    if result is not True:
        raise Exception(f'Invalid URL: {pref}{url}')
    echo(f'ok: {pref}{url} is a valid URL.')


def _uuid_validator(str_uuid: str,
                    echo: Callable[..., None] = _fake_echo, pref: str = ''):
    result = validators.uuid(str_uuid)
    if result is not True:
        raise Exception(f'Invalid UUID: {pref}{str_uuid}')
    echo(f'ok: {pref}{str_uuid} is a valid UUID.')


class IPAddressValidator(ABC):
    @classmethod
    @abstractmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        pass


@dataclass
class ListenAddressV4Config(IPAddressValidator):
    listen_address: str = '127.0.0.1'

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        if not dconf.listen_address:
            return
        try:
            _ipaddr4 = IPv4Address(dconf.listen_address)
            echo(f'ok: {pref}listen_address: {dconf.listen_address} is a valid IPv4 address.')
        except Exception as err:
            raise Exception(f'Invalid IP address: {pref}listen_address: '
                            f'{dconf.listen_address}: {err}') from err


@dataclass
class SeekerConfig(ListenAddressV4Config):
    listen_port: int = 0
    use_ngrok: bool = False

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        super().validator(dconf, echo=echo, pref=pref)
        _int_range_validator(dconf.listen_port, minimum=0, maximum=60999,
                             echo=echo, pref=f'{pref}listen_port: ')
        # no validator for use_ngrok(bool).


@dataclass
class NgrokConfig:
    ngrok_path: str = which('ngrok') or f'{APP_DIR}/ngrok'
    web_port: int = 0

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        try:
            _regularfile_validator(dconf.ngrok_path, echo=echo, pref=f'{pref}ngrok_path: ')
        except Exception as err:
            echo(f'caution: {err}')
        _int_range_validator(dconf.web_port, minimum=0, maximum=60999,
                             echo=echo, pref=f'{pref}web_port: ')


@dataclass
class GCSSolverConfig:
    functions_url: Optional[str] = None
    functions_token: Optional[str] = None

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        if dconf.functions_url:
            _url_validator(dconf.functions_url, echo=echo, pref=f'{pref}functions_url: ')
        _skip_validation(dconf.functions_token, echo=echo, pref=f'{pref}functions_token: ')


@dataclass
class StandaloneSolverConfig(ListenAddressV4Config):
    pass


@dataclass
class SolverConfig:
    shared_solver_url: str = ''
    plugin: str = 'gcs_solver.py'
    keyfile: str = '${..keyfile}'
    keyfile_password: str = '${..keyfile_password}'
    gcs_solver: GCSSolverConfig = GCSSolverConfig()
    standalone_solver: StandaloneSolverConfig = StandaloneSolverConfig()

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        if dconf.shared_solver_url:
            _url_validator(dconf.shared_solver_url, echo=echo, pref=f'{pref}shared_solver_url: ')
        if dconf.plugin:
            mgr = PluginManager()
            mgr.load()
            if mgr.is_pluginfile(dconf.plugin):
                echo(f'ok: {pref}plugin: {dconf.plugin} is a valid plugin.')
            else:
                raise Exception(f'No such plugin: {pref}plugin: {dconf.plugin}')
        _keyfile_validator(dconf.keyfile, dconf.keyfile_password,
                           echo=echo, pref=f'{pref}keyfile{{,_password}}: ')
        for key in ['gcs_solver', 'standalone_solver']:
            kcls = OmegaConf.get_type(dconf[key])
            assert kcls
            if hasattr(kcls, 'validator'):
                getattr(kcls, 'validator')(dconf[key], echo=echo, pref=f'{pref}{key}.')


@dataclass
class AssetManagerConfig(ListenAddressV4Config):
    listen_port: int = 48000

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        super().validator(dconf, echo=echo, pref=pref)
        _int_range_validator(dconf.listen_port, minimum=1, maximum=60999,
                             echo=echo, pref=f'{pref}listen_port: ')


class BCValidator(ABC):
    @classmethod
    @abstractmethod
    def bc_validator(cls, dconf: DictConfig, account: Account,
                     echo: Callable[..., None] = _fake_echo, pref: str = ''):
        pass


def _contract_type_validator(ctype: Type[Contract],
                             account: Account,
                             address: ChecksumAddress,
                             echo: Callable[..., None] = _fake_echo, pref: str = ''):
    try:
        contract = ctype(account).get(address)
        echo(f'ok: {pref}{address} is {contract.__class__.__name__}.')
    except Exception as err:
        raise Exception(f'{pref}{err}') from err


@dataclass
class ActiveContractLists(BCValidator):
    _contract_class: ClassVar[Type[Contract]]
    actives: List[str] = field(default_factory=lambda: [])
    reserves: List[str] = field(default_factory=lambda: [])

    @classmethod
    def bc_validator(cls, dconf: DictConfig, account: Account,
                     echo: Callable[..., None] = _fake_echo, pref: str = ''):
        for idx, addr in enumerate(dconf.actives):
            _contract_type_validator(cls._contract_class, account, addr,
                                     echo=echo, pref=f'{pref}actives[{idx}]: ')
        for idx, addr in enumerate(dconf.reserves):
            _contract_type_validator(cls._contract_class, account, addr,
                                     echo=echo, pref=f'{pref}reserves[{idx}]: ')


@dataclass
class ContractAddress(BCValidator):
    _contract_class: ClassVar[Type[Contract]]
    address: str = ''

    @classmethod
    def bc_validator(cls, dconf: DictConfig, account: Account,
                     echo: Callable[..., None] = _fake_echo, pref: str = ''):
        if dconf.address == '':
            return
        _contract_type_validator(cls._contract_class, account, dconf.address,
                                 echo=echo, pref=f'{pref}address: ')


@dataclass
class ContractLibrary(ContractAddress):
    placeholder: str = ''

    @classmethod
    def bc_validator(cls, dconf: DictConfig, account: Account,
                     echo: Callable[..., None] = _fake_echo, pref: str = ''):
        super().bc_validator(dconf, account, echo=echo, pref=pref)
        if not dconf.address:
            return
        # having address, thus placeholder is required
        expected = Web3.keccak(text=cls._contract_class.contract_id).hex()[2:36]
        if dconf.placeholder != f'__${expected}$__':
            raise Exception(f'Wrong placeholder for {cls._contract_class.__name__}: '
                            f'{dconf.placeholder}')
        echo(f'ok: {pref}placeholder: {dconf.placeholder} is valid '
             f'for {cls._contract_class.__name__}.')


class CatalogConfig(ActiveContractLists):
    _contract_class = CTICatalog


class BrokerConfig(ContractAddress):
    _contract_class = CTIBroker


class OperatorConfig(ContractAddress):
    _contract_class = CTIOperator


class MetemcyberUtilConfig(ContractLibrary):
    _contract_class = MetemcyberUtil


@dataclass
class BlockChainConfig:
    endpoint_url: str = ''
    airdrop_url: str = ''
    keyfile: str = ''
    keyfile_password: str = '${oc.env:METEMCTL_KEYFILE_PASSWORD,""}'
    catalog: CatalogConfig = CatalogConfig()
    broker: BrokerConfig = BrokerConfig()
    operator: OperatorConfig = OperatorConfig()
    metemcyber_util: MetemcyberUtilConfig = MetemcyberUtilConfig()
    seeker: SeekerConfig = SeekerConfig()
    ngrok: NgrokConfig = NgrokConfig()
    solver: SolverConfig = SolverConfig()
    assetmanager: AssetManagerConfig = AssetManagerConfig()

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        _keyfile_validator(dconf.keyfile, dconf.keyfile_password,
                           echo=echo, pref=f'{pref}keyfile{{,_password}}: ')
        if dconf.airdrop_url:
            _url_validator(dconf.airdrop_url, echo=echo, pref=f'{pref}airdrop_url: ')
        if (OmegaConf.is_missing(dconf, 'endpoint_url') or
                OmegaConf.is_missing(dconf, 'keyfile') or
                not dconf.endpoint_url or not dconf.keyfile):
            echo('skip: blockchain is not yet configured. '
                 '("endpoint_url" and "keyfile" are required.)')
            return

        account = None
        for key in dconf.keys():
            kcls = OmegaConf.get_type(dconf[key])
            assert kcls
            if issubclass(kcls, BCValidator):
                if not account:
                    echo('validating contracts with EOA.')
                    eoaa, pkey = decode_keyfile(dconf.keyfile, dconf.keyfile_password)
                    account = Account(Ether(dconf.endpoint_url), eoaa, pkey)
                kcls.bc_validator(dconf[key], account, echo=echo, pref=f'{pref}{key}.')
            if hasattr(kcls, 'validator'):
                getattr(kcls, 'validator')(dconf[key], echo=echo, pref=f'{pref}{key}.')


class SSLCertVerify(Enum):
    DISABLE = 0
    DISABLE_WITH_WARNING = 1
    ENABLE = 2


@dataclass
class MispConfig:
    url: str = ''
    api_key: str = ''
    ssl_cert_verify: SSLCertVerify = SSLCertVerify.ENABLE
    download_filepath: str = f'{APP_DIR}/misp/download'
    upload_filepath: str = f'{APP_DIR}/misp/upload'
    gcp_cloud_iap_cred: str = ''
    gcp_client_id: str = ''

    @classmethod
    def validator(cls, dconf: DictConfig,
                  echo: Callable[..., None] = _fake_echo, pref: str = ''):
        if dconf.url:
            _url_validator(dconf.url, echo=echo, pref=f'{pref}url: ')
        for key in ['download_filepath', 'upload_filepath']:
            if OmegaConf.select(dconf, key):
                _directory_validator(OmegaConf.select(dconf, key),
                                     echo=echo, pref=f'{pref}{key}: ')
        for key in ['api_key', 'gcp_cloud_iap_cred', 'gcp_client_id']:
            _skip_validation(OmegaConf.select(dconf, key),
                             echo=echo, pref=f'{pref}{key}: ')


@dataclass
class RuntimeConfig:
    print_config_validation: bool = False
    solver_keepalive: bool = False
    app_dir: str = APP_DIR
    workspace_root: str = f'{APP_DIR}/{WORKSPACE_PREFIX}${{workspace}}'
    workspace_config_filepath: str = f'${{runtime.workspace_root}}/{WORKSPACE_CONFIG_FILENAME}'
    seeker_download_filepath: str = f'${{runtime.workspace_root}}/download'
    seeker_tty_filepath: str = f'${{runtime.workspace_root}}/.tty4seeker.lnk'
    seeker_pid_filepath: str = f'${{runtime.workspace_root}}/seeker.pid'
    ngrok_pid_filepath: str = f'${{runtime.workspace_root}}/ngrok.pid'
    asset_filepath: str = f'${{runtime.workspace_root}}/upload'
    solver_pid_filepath: str = f'${{runtime.workspace_root}}/solver.pid'
    solver_socket_filepath: str = f'${{runtime.workspace_root}}/solver.sock'
    solver_snapshot_filepath: str = f'${{runtime.workspace_root}}/.solver.snapshot'
    assetmanager_pid_filepath: str = f'${{runtime.workspace_root}}/assetmanager.pid'


@dataclass
class MetemctlConfig:
    workspace: str = '???'
    project: str = ''
    slack_webhook_url: str = ''
    blockchain: BlockChainConfig = BlockChainConfig()
    misp: MispConfig = MispConfig()
    runtime: RuntimeConfig = RuntimeConfig()

    @classmethod
    def validator(cls, dconf: DictConfig, echo: Callable[..., None] = _fake_echo):
        echo('validating configurations...')
        if dconf.project:
            _uuid_validator(dconf.project, echo=echo, pref=f'project: ')
        if dconf.slack_webhook_url:
            _url_validator(dconf.slack_webhook_url, echo=echo, pref=f'slack_webhook_url: ')
        if dconf.workspace not in ws_list():
            raise Exception(f'Invalid workspace: {dconf.workspace}')
        echo('BlockChainConfig:')
        BlockChainConfig.validator(dconf.blockchain, echo=echo)
        echo('MispConfig:')
        MispConfig.validator(dconf.misp, echo=echo)
        # no validator for runtime
        echo('validation succeeded.')


def load_config(ctx: Optional[typer.Context] = None,
                ignore_schema: bool = False) -> DictConfig:
    if ctx and ctx.meta.get('config'):
        return ctx.meta['config']
    config = _load_config(ignore_schema=ignore_schema)
    if ctx:
        ctx.meta['config'] = config
    return config


def _flush_cache(ctx: Optional[typer.Context], g_config: Optional[DictConfig]):
    if ctx:
        ctx.meta['config'] = g_config


def _setup_initial_config(g_config: DictConfig) -> DictConfig:
    if OmegaConf.is_missing(g_config, 'workspace') or not g_config.workspace:
        typer.echo('your workspace is not yet configured.')
        name = typer.prompt('input workspace:', default=WORKSPACE_DEFAULT, type=str)
        if name not in ws_list():
            ws_create(g_config, name)
            typer.echo(f'new workspace created: {name}')
        g_config = ws_switch(g_config, name)
        OmegaConf.set_readonly(g_config, False)
        typer.echo(f'switched workspace: {name}')

    # FIXME: setup for others, e.g. MISP.

    return g_config


def _load_root_config() -> DictConfig:  # mostly for workspace controll
    g_yaml = METEMCTL_CONFIG_FILEPATH
    g_schema = OmegaConf.structured(MetemctlConfig)
    g_data = OmegaConf.load(g_yaml) if os.path.isfile(g_yaml) else DictConfig({})
    g_config = OmegaConf.merge(g_schema, g_data)
    assert isinstance(g_config, DictConfig)
    # Note: return writable config
    return g_config


def _load_config(ignore_schema: bool = False,
                 pseudo_workspace: Optional[str] = None) -> DictConfig:
    g_yaml = METEMCTL_CONFIG_FILEPATH
    g_schema = OmegaConf.structured(MetemctlConfig)
    if ignore_schema:
        g_config = OmegaConf.load(g_yaml) if os.path.isfile(g_yaml) else DictConfig({})
        g_config.runtime = g_schema.runtime
    else:
        g_data = OmegaConf.load(g_yaml) if os.path.isfile(g_yaml) else DictConfig({})
        g_config = OmegaConf.merge(g_schema, g_data)
    assert isinstance(g_config, DictConfig)

    if pseudo_workspace:
        g_config.workspace = pseudo_workspace
    elif OmegaConf.is_missing(g_config, 'workspace') or not g_config.workspace:
        g_config = _setup_initial_config(g_config)

    if ignore_schema:
        ws_config = (OmegaConf.load(g_config.runtime.workspace_config_filepath) if
                     os.path.isfile(g_config.runtime.workspace_config_filepath) else DictConfig({}))
    else:
        ws_schema = OmegaConf.structured(BlockChainConfig)
        ws_data = (OmegaConf.load(g_config.runtime.workspace_config_filepath) if
                   os.path.isfile(g_config.runtime.workspace_config_filepath) else DictConfig({}))
        ws_config = OmegaConf.merge(ws_schema, ws_data)

    g_config.blockchain = ws_config
    OmegaConf.set_readonly(g_config, True)
    return g_config


def _inherit_runtime(src: DictConfig, dst: DictConfig) -> DictConfig:
    OmegaConf.set_readonly(dst, False)
    dst.runtime = src.runtime
    OmegaConf.set_readonly(dst, True)
    return dst


def _save_root_config(g_config: DictConfig):
    non_root_configs = [
        'blockchain',
        'runtime',
    ]
    masked_keys = [str(x) for x in list(g_config.keys()) if x not in non_root_configs]
    OmegaConf.save(OmegaConf.masked_copy(g_config, masked_keys), f=METEMCTL_CONFIG_FILEPATH)


def _save_config(g_config: DictConfig, save_root: bool = True, save_workspace: bool = True):
    if g_config.workspace and save_workspace:
        OmegaConf.save(g_config.blockchain, f=g_config.runtime.workspace_config_filepath)
    if save_root:
        _save_root_config(g_config)
    typer.echo('saved config files.')


def print_config(g_config: DictConfig, runtime: bool = False, resolve: bool = False):
    tmp_config = g_config.copy()
    OmegaConf.set_readonly(tmp_config, False)
    if not runtime:
        del tmp_config.runtime  # hidden params
    if resolve:
        OmegaConf.resolve(tmp_config)
    typer.echo(OmegaConf.to_yaml(tmp_config))


def update_config(g_config: DictConfig,
                  key: str,
                  value: Any,
                  ctx: Optional[typer.Context] = None,
                  validate: bool = True,
                  save: bool = True,
                  ) -> DictConfig:
    new_config = copy.deepcopy(g_config)
    OmegaConf.set_readonly(new_config, False)  # set writable
    OmegaConf.update(new_config, key, value)
    if validate:
        _validate(new_config)
    if save:
        _save_config(new_config)
    _flush_cache(ctx, new_config)
    OmegaConf.set_readonly(new_config, True)  # set readonly
    return new_config


def _validate(g_config: DictConfig):
    echo = typer.echo if g_config.runtime.print_config_validation else _fake_echo
    MetemctlConfig.validator(g_config, echo=echo)


def edit_config(g_config: DictConfig = DictConfig({}),
                ctx: Optional[typer.Context] = None, validate: bool = True,) -> DictConfig:
    current_config = g_config or load_config(ctx)
    tmp_config = copy.deepcopy(current_config)
    OmegaConf.set_readonly(tmp_config, False)
    del tmp_config.runtime
    config_hints = (
        '###\n'
        '### config hints here!\n'
        '###\n'
        '\n'
    )

    # edit config with yaml format
    edited = typer.edit(config_hints + OmegaConf.to_yaml(tmp_config))

    if not edited:
        typer.echo('(not modified)')
        return current_config

    def _str2config(edited_: str, schema_: DictConfig, current_: DictConfig) -> DictConfig:
        try:
            new_config_ = OmegaConf.create(edited_)  # create from yaml string without schema.
            new_config_ = OmegaConf.merge(schema_, new_config_)  # apply schema.
            new_config_.runtime = current_.runtime  # inherit runtime configs.
            assert isinstance(new_config_, DictConfig)
        except Exception as err:
            raise Exception(f'ConfigError: {err}') from err
        if new_config_.workspace != current_.workspace:
            typer.echo('Do NOT modify workspace with this command. '
                       'Use "metemctl workspace switch" instead.')
            raise Exception('ValidationError: Workspace modification not supported')
        return new_config_

    schema = OmegaConf.structured(MetemctlConfig)
    new_config = None
    while True:
        try:
            new_config = _str2config(edited, schema, current_config)
            try:
                if validate:
                    _validate(new_config)
                elif new_config.runtime.print_config_validation:
                    typer.echo('validation skipped.')
                break
            except Exception as err:
                raise Exception(f'ValidationError: {err}') from err
        except Exception as err:
            typer.echo(err)  # print what's wrong

        try:
            if not typer.confirm('continue?', default=True, abort=True):
                raise Exception('quit')
            if new_config:
                if OmegaConf.select(new_config, 'runtime'):
                    del new_config.runtime
                edited = config_hints + OmegaConf.to_yaml(new_config)

            # edit again
            edited = typer.edit(edited)

            if not edited:
                raise Exception('abort')
            continue
        except Exception:
            typer.echo('(aborted)')
            return current_config

    OmegaConf.set_readonly(new_config, True)
    _save_config(new_config)
    _flush_cache(ctx, new_config)
    return new_config


def ws_list() -> List[str]:
    return sorted([
        os.path.basename(tmp)[len(WORKSPACE_PREFIX):] for tmp
        in Path(APP_DIR).glob(f'{WORKSPACE_PREFIX}*')
        if os.path.isdir(tmp) and os.path.isfile(f'{tmp}/{WORKSPACE_CONFIG_FILENAME}')
    ])


def ws_switch(g_config: Optional[DictConfig], name: str,
              ctx: Optional[typer.Context] = None) -> DictConfig:
    if g_config and not OmegaConf.is_missing(g_config, 'workspace'):
        if name == g_config.workspace:
            raise Exception(f'Already in workspace: {name}')
        if name not in ws_list():
            raise Exception(f'No such workspace: {name}')
    root_config = _load_root_config()
    root_config.workspace = name
    _save_root_config(root_config)

    new_config = _load_config()
    if g_config is not None:
        new_config = _inherit_runtime(g_config, new_config)
        _flush_cache(ctx, new_config)
    return new_config


def ws_create(g_config: DictConfig, name: str):
    if name in ws_list():
        raise Exception(f'Workspace already exists: {name}')
    p_config = _load_config(pseudo_workspace=name)
    p_config = _inherit_runtime(g_config, p_config)
    _make_minimal_workspace(p_config.runtime.workspace_root)
    _save_config(p_config, save_root=False, save_workspace=True)


def ws_copy(g_config: DictConfig, src: str, dst: str):
    spaces = ws_list()
    if src not in spaces:
        raise Exception(f'No such workspace: {src}')
    if dst in spaces:
        raise Exception(f'Workspace already exists: {dst}')
    src_config = _load_config(pseudo_workspace=src)
    dst_config = _load_config(pseudo_workspace=dst)
    dst_config = _inherit_runtime(g_config, dst_config)
    _make_minimal_workspace(dst_config.runtime.workspace_root)
    copyfile(src_config.runtime.workspace_config_filepath,
             dst_config.runtime.workspace_config_filepath,
             follow_symlinks=True)


def ws_destroy(name: str, force: bool = False) -> Optional[str]:
    if name not in ws_list():
        raise Exception(f'No such workspace: {name}')
    p_config = _load_config(pseudo_workspace=name)
    if not force:
        return (f'Please remove unnecessary files (at least {WORKSPACE_CONFIG_FILENAME})'
                f' and directories under {p_config.runtime.workspace_root} by hand.'
                f' Or give --force option to remove the entire directory above.')
    rmtree(p_config.runtime.workspace_root)
    return None


def _make_minimal_workspace(workspace_dir: str):
    if os.path.isdir(workspace_dir):
        typer.echo(f'reuse existing directory as a workspace: {workspace_dir}')
    else:
        typer.echo(f'creating workspace directory: {workspace_dir}')
        os.makedirs(workspace_dir, exist_ok=False)
    for tgt in WORKSPACE_MINIMAL_DIRS:
        tgt_path = f'{workspace_dir}/{tgt}'
        if os.path.isdir(tgt_path):
            typer.echo(f'reuse existing directory: {tgt_path}')
        else:
            typer.echo(f'creating directory: {tgt_path}')
            os.makedirs(tgt_path, exist_ok=True)
