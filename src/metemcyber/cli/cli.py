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

#pylint: disable=too-many-lines

import errno
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from shutil import copyfile, copytree
from subprocess import CalledProcessError
from time import sleep
from typing import Callable, Dict, List, Optional, Tuple, Union, cast
from uuid import UUID, uuid4

import eth_account
import pymisp
import requests
import typer
import urllib3
import yaml
from eth_typing import ChecksumAddress
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from web3 import Web3

from metemcyber import __version__
from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.broker import Broker
from metemcyber.core.bc.catalog import Catalog, TokenInfo
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
from metemcyber.core.bc.operator import TASK_STATES, Operator
from metemcyber.core.bc.token import Token
from metemcyber.core.bc.util import ADDRESS0, decode_keyfile, deploy_erc1820
from metemcyber.core.logger import get_logger
from metemcyber.core.multi_solver import MCSClient, MCSErrno, MCSError
from metemcyber.core.ngrok import DEFAULT_CONFIGS as DC_NGROK
from metemcyber.core.ngrok import NgrokMgr
from metemcyber.core.seeker import DEFAULT_CONFIGS as DC_SEEKER
from metemcyber.core.seeker import TTY_FILEPATH as TTYLINK4SEEKER
from metemcyber.core.seeker import Seeker
from metemcyber.core.util import config2str, merge_config
from metemcyber.plugins.gcs_solver import DEFAULT_CONFIGS as DC_SOLV_GCS
from metemcyber.plugins.standalone_solver import DEFAULT_CONFIGS as DC_SOLV_ALN

CONFIG_FILE_NAME = "metemctl.ini"
CONFIG_FILE_PATH = Path(APP_DIR) / CONFIG_FILE_NAME
WORKSPACE_CONFIG_FILENAME = 'config.ini'
WORKFLOW_FILE_NAME = "workflow.yml"
DATA_FILE_NAME = "source_of_truth.yml"
METEM_STARTER_ALIASES = {
    "ir-exercise"
}
METEM_STARTERS_REPO = "git+https://github.com/nttcom/metemcyber-starters.git"


DEFAULT_CONFIGS = {
    'general': {
        'project': '00000000-0000-0000-0000-000000000000',
        'slack_webhook_url': 'SLACK_WEBHOOK_URL',
        'endpoint_url': 'YOUR_ETHEREUM_JSON_RPC_URL',
        'airdrop_url': 'AIRDROP_FUNCTION_URL',
        'keyfile': '/PATH/TO/YOUR/KEYFILE',
        'workspace': str(Path(APP_DIR) / 'workspace'),
    },
    'catalog': {
        'actives': '',
        'reserves': '',
    },
    'broker': {
        'address': '',
    },
    'operator': {
        'address': '',
    },
    'metemcyber_util': {
        'address': '',
        'placeholder': '',
    },
    'solver': {
        'plugin': 'gcs_solver.py',
    },
    'seeker': DC_SEEKER['seeker'],
    'ngrok': DC_NGROK['ngrok'],
    'standalone_solver': DC_SOLV_ALN['standalone_solver'],
    'gcs_solver': DC_SOLV_GCS['gcs_solver'],
    'misp': {
        'url': 'YOUR_MISP_URL',
        'api_key': 'YOUR_MISP_API_KEY',
        'ssl_cert': '2',
        'download': str(Path(APP_DIR) / 'misp' / 'download'),
        'gcp_cloud_iap_cred': '',
        'gcp_client_id': '',
    }
}

app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp", help="Manage your MISP instance.")

account_app = typer.Typer()
app.add_typer(account_app, name="account", help="Manage your accounts.")

ix_app = typer.Typer()
app.add_typer(ix_app, name="ix", help="Manage CTI tokens to collect CTIs.")
ix_catalog_app = typer.Typer()
ix_app.add_typer(ix_catalog_app, name='catalog', help="Manage the list of CTI catalogs to use")

contract_app = typer.Typer()
app.add_typer(contract_app, name="contract", help="Manage your smart contracts.")
contract_token_app = typer.Typer()
contract_app.add_typer(contract_token_app, name='token', help="Manage the CTI token contract.")
contract_catalog_app = typer.Typer()
contract_app.add_typer(
    contract_catalog_app,
    name="catalog",
    help="Manage the CTI catalog contract.")
contract_broker_app = typer.Typer()
contract_app.add_typer(contract_broker_app, name='broker', help="Manage the CTI broker contract.")
contract_operator_app = typer.Typer()
contract_app.add_typer(contract_operator_app, name='operator',
                       help="Manage the CTI operator contract.")

seeker_app = typer.Typer()
app.add_typer(seeker_app, name='seeker', help='Manage the CTI seeker subprocess.')
solver_app = typer.Typer()
app.add_typer(solver_app, name='solver', help='Manage the CTI solver subprocess.')

config_app = typer.Typer()
app.add_typer(config_app, name='config', help="Manage your config file of metemctl")


# pylint: disable=invalid-name
def getLogger(name='cli'):
    return get_logger(name=name, app_dir=APP_DIR, file_prefix='cli')


def _workspace_confpath(ctx):
    return f'{_load_config(ctx)["general"]["workspace"]}/{WORKSPACE_CONFIG_FILENAME}'


def _load_config(ctx: typer.Context, reload: bool = False) -> ConfigParser:
    if 'config' in ctx.meta.keys():
        if not reload:
            return ctx.meta['config']
        del ctx.meta['config']
    # at first, load default config and overwrite with metemctl.ini.
    if os.path.exists(CONFIG_FILE_PATH):
        logger = getLogger()
        logger.info(f"Load config file from {CONFIG_FILE_PATH}")
        config = merge_config(CONFIG_FILE_PATH, DEFAULT_CONFIGS)
    else:
        config = merge_config(None, DEFAULT_CONFIGS)
    # at next, overwrite with workspace/config.ini if exists.
    tmp_workspace = config['general']['workspace']
    work_conf_file = f'{tmp_workspace}/{WORKSPACE_CONFIG_FILENAME}'
    if os.path.exists(work_conf_file):
        config = merge_config(work_conf_file, {}, config)
        if Path(tmp_workspace) != Path(config['general']['workspace']):
            raise Exception('contradictory configuration: general.workspace.')
    # ok. cache and return
    ctx.meta['config'] = config
    return config


def _save_config(ctx: typer.Context, config: ConfigParser) -> None:
    logger = getLogger()
    for sect in config.sections():
        for opt in config.options(sect):
            val = config[sect][opt]
            if val.startswith('~'):
                config[sect][opt] = str(Path(val).expanduser())
    try:
        workspace_conf = _workspace_confpath(ctx)
        filepath = workspace_conf if os.path.exists(workspace_conf) else CONFIG_FILE_PATH
        with open(filepath, 'wt') as fout:
            config.write(fout)
    except Exception as err:
        logger.exception(f'Cannot save configuration: {err}')
        raise
    logger.debug('updated config file')


def find_ngrok(config: ConfigParser):
    if not shutil.which("ngrok"):
        config['ngrok']['ngrok_path'] = str(Path(APP_DIR) / 'ngrok')
    return config


def _init_app_dir(ctx: typer.Context) -> None:
    logger = getLogger()
    os.makedirs(APP_DIR, exist_ok=True)

    template_app_dir = Path(__file__).with_name('app_dir')
    entries = os.listdir(template_app_dir)

    for entry in entries:
        src = Path(template_app_dir) / entry
        dst = Path(APP_DIR) / entry
        if os.path.isdir(src):
            copytree(src, dst, symlinks=True)
        else:
            copyfile(src, dst, follow_symlinks=False)

    config = _load_config(ctx)
    config = find_ngrok(config)
    _save_config(ctx, config)

    default_workspace = Path(APP_DIR) / 'workspace.pricom-mainnet'
    workspace = Path(APP_DIR) / 'workspace'
    try:
        os.symlink(default_workspace, workspace)
    except (NotImplementedError, OSError) as err:
        logger.warning(f'Cannot create a symbolic link: {err}')
        copytree(default_workspace, workspace)

    _load_config(ctx, reload=True)


def _get_keyfile_password() -> str:
    word = os.getenv('METEMCTL_KEYFILE_PASSWORD', "")
    if word:
        return word
    typer.echo('You can also use an env METEMCTL_KEYFILE_PASSWORD.')
    try:
        return typer.prompt('Enter password for keyfile', hide_input=True)
    except Exception as err:
        raise Exception('Interrupted') from err  # click.exceptions.Abort has no message


def _load_account(ctx: typer.Context) -> Account:
    if 'account' in ctx.meta.keys():
        return ctx.meta['account']
    config = _load_config(ctx)
    if config['general']['endpoint_url'] in (None, ''):
        raise Exception('Missing configuration: endpoint_url')
    ether = Ether(config['general']['endpoint_url'])
    if config['general']['keyfile'] in (None, '', DEFAULT_CONFIGS['general']['keyfile']):
        raise Exception('Missing configuration: keyfile')
    eoa, pkey = decode_keyfile(config['general']['keyfile'], _get_keyfile_password)
    account = Account(ether, eoa, pkey)
    ctx.meta['account'] = account
    return account


def _load_contract_libs(ctx: typer.Context):
    account = _load_account(ctx)
    config = _load_config(ctx)
    deploy_erc1820(account.eoa, account.web3)
    if config.has_section('metemcyber_util'):
        util_addr = config['metemcyber_util'].get('address')
        util_ph = config['metemcyber_util'].get('placeholder')
    else:
        util_addr = util_ph = ''
        config.add_section('metemcyber_util')
    if util_addr and util_ph:
        _ph = MetemcyberUtil.register_library(util_addr)
        assert _ph == util_ph
    else:
        util = MetemcyberUtil(account).new()
        util_ph = util.register_library(util.address)
        config.set('metemcyber_util', 'address', util.address)
        config.set('metemcyber_util', 'placeholder', util_ph)
        _save_config(ctx, config)


def _load_catalog_manager(ctx: typer.Context) -> CatalogManager:
    if 'catalog_manager' in ctx.meta.keys():
        return ctx.meta['catalog_manager']
    account = _load_account(ctx)
    catalog_mgr = CatalogManager(account)
    config = _load_config(ctx)
    if config.has_section('catalog'):
        actives = config['catalog'].get('actives')
        if actives:
            catalog_mgr.add(
                cast(List[ChecksumAddress], actives.strip().split(',')), activate=True)
        reserves = config['catalog'].get('reserves')
        if reserves:
            catalog_mgr.add(
                cast(List[ChecksumAddress], reserves.strip().split(',')), activate=False)
    ctx.meta['catalog_manager'] = catalog_mgr
    return catalog_mgr


def _load_broker(ctx: typer.Context) -> Broker:
    if 'broker' in ctx.meta.keys():
        return ctx.meta['broker']
    try:
        config = _load_config(ctx)
        broker_address = cast(ChecksumAddress, config['broker']['address'])
        assert broker_address
    except Exception as err:
        raise Exception('Missing configuration: broker.address') from err
    account = _load_account(ctx)
    broker = Broker(account).get(broker_address)
    ctx.meta['broker'] = broker
    return broker


def _load_operator(ctx: typer.Context) -> Operator:
    if 'operator' in ctx.meta.keys():
        return ctx.meta['operator']
    config = _load_config(ctx)
    try:
        operator_address = cast(ChecksumAddress, config['operator']['address'])
        assert operator_address
    except Exception as err:
        raise Exception('Missing configuration: operator.address') from err
    account = _load_account(ctx)
    operator = Operator(account).get(operator_address)
    ctx.meta['operator'] = operator
    return operator


def common_logging(func):
    def wrapper(*args, **kwargs):
        logger = getLogger()
        try:
            return func(*args, **kwargs)
        except Exception as err:
            logger.exception(err)
            typer.echo(f'failed operation: {err}')
        return None
    return wrapper


def version_callback(value: bool):
    if value:
        typer.echo(f'metemctl version {__version__}')
        raise typer.Exit()


@app.callback()
def app_callback(
    ctx: typer.Context,
    _version: bool = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True),
):
    # init app directory if it does not exist
    logger = getLogger()
    if os.path.exists(APP_DIR):
        if os.path.isdir(APP_DIR):
            if not os.path.exists(CONFIG_FILE_PATH):
                logger.info(f'Run the application directory initialize: {APP_DIR}')
                _init_app_dir(ctx)
        else:
            logger.error(f'Invalid the application directory: {APP_DIR}')
    else:
        logger.info(f'Create the application directory: {APP_DIR}')
        _init_app_dir(ctx)


class IntelligenceCategory(str, Enum):
    fraud = 'Fraud'
    ir = 'IR'
    ra = 'RA'
    secops = 'SecOps'
    seclead = 'SecLead'
    vuln = 'Vuln'


class IntelligenceContents(str, Enum):
    iocs = 'IOC'
    ttps = 'TTP'
    workflow = 'Workflow'


def create_workflow_config(
        config: Dict[str, Union[str, List[str]]],
        dst: Path,
        event_id: str,
        category: str,
        contents: List[str]):
    logger = getLogger()

    config['project_name'] = event_id
    config['repo_name'] = event_id
    config['python_package'] = "metemcyber_" + event_id.replace('-', '_')
    config['intelligece_category'] = category
    config['intelligece_contents'] = contents

    logger.info(f"Write the workflow config to: {dst}")
    with open(dst, 'w') as fout:
        yaml.dump(config, fout)
        logger.info(f"Write successful.")


def create_data_for_workflow(yml_filepath: Path):
    logger = getLogger()
    output_dir = None
    repo_name = None

    logger.info(f"check the config from: {yml_filepath}")
    with open(yml_filepath) as fin:
        config = yaml.safe_load(fin)
        if 'output_dir' in config:
            output_dir = config['output_dir']
        if 'repo_name' in config:
            repo_name = config['repo_name']

    if output_dir and repo_name:
        workflow_dir = Path(output_dir) / repo_name
        raw_data_dir = workflow_dir / 'data' / '01_raw'
        logger.info(f"detect the workflow raw data dir: {raw_data_dir}")
        if os.path.isdir(raw_data_dir):
            template = Path(__file__).with_name(DATA_FILE_NAME)
            data_file_path = raw_data_dir / DATA_FILE_NAME
            if not os.path.exists(data_file_path):
                logger.info(f"create a data template to : {data_file_path}")
                copyfile(template, data_file_path)


def create_workflow(event_id, category, contents, starter):
    logger = getLogger()
    logger.info(f"Create the workflow: {event_id}")
    # find current directory
    yml_filepath = Path(os.getcwd()) / WORKFLOW_FILE_NAME
    if not os.path.isfile(yml_filepath):
        # find app directory
        yml_filepath = Path(APP_DIR) / WORKFLOW_FILE_NAME
        if not os.path.isfile(yml_filepath):
            # use template
            yml_filepath = Path(__file__).with_name(WORKFLOW_FILE_NAME)
    logger.info(f"Load the workflow config from: {yml_filepath}")

    dist_yml_filepath = Path(os.getcwd()) / f'{event_id}-{WORKFLOW_FILE_NAME}'
    with open(yml_filepath) as fin:
        config = yaml.safe_load(fin)
        logger.info(f"Loaded the workflow config.")
        create_workflow_config(
            config,
            dist_yml_filepath,
            event_id,
            category,
            contents)

    if os.path.isfile(dist_yml_filepath):
        logger.info(f"Run command: kedro new --config {dist_yml_filepath}")
        try:
            if starter:
                if starter in METEM_STARTER_ALIASES:
                    subprocess.run(['kedro', 'new', '--config',
                                    dist_yml_filepath,
                                    '--starter', METEM_STARTERS_REPO,
                                    '--directory', starter,
                                    '--checkout', 'main'], check=True)
                else:
                    subprocess.run(['kedro', 'new', '--config',
                                    dist_yml_filepath,
                                    '--starter', starter], check=True)
            else:
                subprocess.run(['kedro', 'new', '--config',
                                dist_yml_filepath], check=True)
            create_data_for_workflow(dist_yml_filepath)
        except CalledProcessError as err:
            logger.exception(err)
            typer.echo(f'An error occurred while creating the workflow. {err}')
            raise typer.Abort()


def pick_up_contents() -> Optional[List[IntelligenceContents]]:
    contents = []
    # allow index selector
    contents_selector = list(IntelligenceContents)
    for i, content_type in enumerate(contents_selector):
        typer.echo(f'{i}: {content_type}')
    items = typer.prompt('Choose contents to be include', "0,1")
    indices = [int(i) for i in items.split(',') if i.isdecimal()]
    for i in indices:
        if i <= len(contents_selector):
            contents.append(IntelligenceContents(contents_selector[i]))

    if len(contents) > 0:
        return contents

    return None


@app.command(help="Create a new intelligence workflow.")
def new(
    ctx: typer.Context,
    event_uuid: UUID = typer.Option(
        None,
        help='Recommend to be the same as the UUID of the misp object'),
    category: IntelligenceCategory = typer.Option(
        IntelligenceCategory.ir,
        prompt='Select Intelligence Category',
        case_sensitive=False,
        help='Fraud, Incident Response, Risk Analysis, Security Operations, \
            Security Leadership, Vulnerability Management'),
    contents: Optional[List[IntelligenceContents]] = typer.Option(
        None,
        case_sensitive=False,
        help='Pick up all workflow products (Indicator of Compomise, etc.)',),
    starter: Optional[str] = typer.Option(
        None,
        case_sensitive=False,
        help="Enter starter's name when using starter (ir-exercise, etc.)")
):
    logger = getLogger()
    # TODO: Use Enum names
    # See https://github.com/tiangolo/typer/pull/224/files
    formal_category = {
        'Fraud': 'Fraud',
        'IR': 'Incident Response',
        'RA': 'Risk Analysis',
        'SecOps': 'Security Operations',
        'SecLead': 'Security Leadership',
        'Vuln': 'Vulnerability Management',
    }
    logger.info(f"Intelligence Category: {formal_category[category]}")

    formal_contents = {
        'IOC': 'IOCs',
        'TTP': 'TTPs',
        'Workflow': 'Workflow',
    }

    # convert uuid(event_id) to string
    if event_uuid:
        event_id = str(event_uuid)
    else:
        # create new uuid if not exist
        event_id = typer.prompt(
            'Input a new event_id(UUID)', str(uuid4()))

    logger.info(f"EventID: {event_id}")

    if not contents:
        contents = pick_up_contents()
    if contents:
        # deduplication
        contents_set = set(contents)
        display_contents = [formal_contents[x.value] for x in contents_set]
    else:
        display_contents = []

    logger.info(f"Contents: {display_contents}")

    typer.echo(f'{"":=<64}')
    typer.echo(f'Event ID: {event_id}')
    typer.echo(f'Category: {formal_category[category]}')
    typer.echo(f'Contents: {display_contents}')
    typer.echo(f'{"":=<64}')

    answer = typer.confirm('Are you sure you want to create it?', abort=True)
    # run "kedro new --config workflow.yml"
    if answer:
        create_workflow(
            event_id,
            formal_category[category],
            display_contents,
            starter)
        # TODO: manage the project id on workspace directory
        config = _load_config(ctx)
        config.set('general', 'project', event_id)
        _save_config(ctx, config)


def config_update_catalog(ctx: typer.Context):
    catalog_mgr = _load_catalog_manager(ctx)
    config = _load_config(ctx)
    if catalog_mgr is None:
        config.remove_section('catalog')
    else:
        if not config.has_section('catalog'):
            config.add_section('catalog')
        config.set('catalog', 'actives',
                   ','.join(catalog_mgr.active_catalogs.keys()))
        config.set('catalog', 'reserves',
                   ','.join(catalog_mgr.reserved_catalogs.keys()))
    _save_config(ctx, config)
    del ctx.meta['catalog_manager']
    Catalog(_load_account(ctx)).uncache(entire=True)


def config_update_broker(ctx: typer.Context):
    config = _load_config(ctx)
    try:
        broker = _load_broker(ctx)
        if not config.has_section('broker'):
            config.add_section('broker')
        config.set('broker', 'address', broker.address)
    except Exception:
        config.remove_section('broker')
    _save_config(ctx, config)


def config_update_operator(ctx: typer.Context):
    config = _load_config(ctx)
    try:
        operator = _load_operator(ctx)
        if not config.has_section('operator'):
            config.add_section('operator')
        config.set('operator', 'address', operator.address)
    except Exception:
        config.remove_section('operator')
    _save_config(ctx, config)


class TokenInfoEx(TokenInfo):
    """ Class for pack token data. do not cache my instance.
    """

    def __init__(self, tinfo, amount, balance):
        super().__init__(tinfo.address, tinfo.token_id, tinfo.owner, tinfo.uuid,
                         tinfo.title, tinfo.price, tinfo.operator, tinfo.like_count)
        self.amount = amount
        self.balance = balance


def _get_tokens_population(ctx: typer.Context,
                           mine: bool = True, mine_only: bool = False, soldout: bool = False,
                           own: bool = True, own_only: bool = False
                           ) -> Dict[int, List[TokenInfoEx]]:
    account = _load_account(ctx)
    ret: Dict[int, List[TokenInfoEx]] = {}
    for caddr, cid in sorted(
            _load_catalog_manager(ctx).active_catalogs.items(), key=lambda x: x[1], reverse=True):
        token_infos = sorted(
            Catalog(account).get(caddr).tokens.values(),
            key=lambda x: x.token_id,
            reverse=True)
        amounts = _load_broker(ctx).get_amounts(caddr, [token.address for token in token_infos])
        ret[cid] = []
        for idx, tinfo in enumerate(token_infos):
            if account.eoa == tinfo.owner:
                if not mine:
                    continue
            elif mine_only:
                continue
            if not soldout and amounts[idx] == 0:
                continue
            balance = Token(account).get(tinfo.address).balance_of(account.eoa)
            if balance == 0:
                if own_only:
                    continue
            elif not own:
                continue
            ret[cid].append(TokenInfoEx(tinfo, amounts[idx], balance))
    return ret


def _get_accepting_tokens(ctx: typer.Context) -> List[ChecksumAddress]:
    solver = _solver_client(ctx)
    solver.get_solver()
    return solver.solver('accepting_tokens')


def _ix_list_tokens(ctx: typer.Context, keyword, mine, mine_only, soldout, own, own_only):
    account = _load_account(ctx)
    try:
        accepting = _get_accepting_tokens(ctx)
    except Exception:
        accepting = []
    if mine:
        typer.echo(' o   = published by you')
        typer.echo('  *  = currently accepting')
    typer.echo('    C-T: title  /  C = CatalogId, T = TokenId in catalog')
    typer.echo('--------')

    population = _get_tokens_population(
        ctx, mine=mine, mine_only=mine_only, soldout=soldout, own=own, own_only=own_only)
    for cid, tokens in sorted(population.items(), reverse=True):
        for tinfo in tokens:
            if keyword.lower() in tinfo.title.lower():
                mrk = ('o' if tinfo.owner == account.eoa else ' ') + \
                    ('*' if tinfo.address in accepting else ' ')

                typer.echo(
                    f' {mrk} {cid}-{tinfo.token_id}: {tinfo.title}' + '\n'
                    f'     ├ UUID : {tinfo.uuid}' + '\n'
                    f'     ├ Addr : {tinfo.address}' + '\n'
                    f'     └ Price: {tinfo.price} pts / {tinfo.amount} tokens left' +
                    ('' if tinfo.balance == 0 else f' (you have {tinfo.balance})'))


class FlexibleIndexCatalog:
    ctx: typer.Context
    address: ChecksumAddress
    index: int

    def __init__(self, ctx: typer.Context, id_or_addr: str):
        try:
            self.ctx = ctx
            catalog_mgr = _load_catalog_manager(ctx)
            if Web3.isChecksumAddress(id_or_addr):
                self.address = cast(ChecksumAddress, id_or_addr)
                self.index = catalog_mgr.address2id(self.address)
            else:
                self.index = int(id_or_addr)
                self.address = catalog_mgr.id2address(self.index)
        except Exception as err:
            raise Exception('Invalid catalog id') from err

    @property
    def info(self) -> Catalog:  # had better to return CatalogInfo?
        return Catalog(_load_account(self.ctx)).get(self.address)


class FlexibleIndexToken:
    address: ChecksumAddress
    index: Optional[int]
    catalog: Optional[FlexibleIndexCatalog]
    _info: Optional[TokenInfo]

    def __init__(self, ctx: typer.Context, id_or_addr: Union[List[str], str]):
        self.ctx = ctx
        self._info = None
        if isinstance(id_or_addr, tuple):  # why typer gives tuple instead of list?
            id_or_addr = list(id_or_addr)
        if isinstance(id_or_addr, list) and len(id_or_addr) == 1:
            id_or_addr = id_or_addr[0]
        if isinstance(id_or_addr, list):
            cid, tid = cast(list, id_or_addr)
        elif '-' in id_or_addr:
            cid, tid = cast(str, id_or_addr).split('-', 1)
        else:
            cid, tid = None, id_or_addr
        self.catalog = FlexibleIndexCatalog(ctx, cid) if cid else None
        if Web3.isChecksumAddress(tid):
            tid = cast(ChecksumAddress, tid)
            self.address = tid
            self.index = self.catalog.info.get_tokeninfo(tid).token_id if self.catalog else None
        else:
            if self.catalog is None:
                raise Exception('Token index is valid only with catalog')
            self.index = int(tid)
            self.address = self.catalog.info.id2address(self.index)

    @property
    def info(self) -> TokenInfo:
        if not self._info:
            if not self.catalog:
                raise Exception('Internal error: initialized without catalog info')
            self._info = self.catalog.info.get_tokeninfo(self.address)
        return self._info


@ix_app.command('search', help="Show CTI tokens on the active list of CTI catalogs.")
def ix_search(ctx: typer.Context,
              keyword: str,
              mine: bool = typer.Option(True, help='show tokens published by you'),
              mine_only: bool = typer.Option(False),
              soldout: bool = typer.Option(False, help='show soldout tokens'),
              own: bool = typer.Option(True, help='show tokens you own'),
              own_only: bool = typer.Option(False)):
    _ix_search(ctx, keyword, mine, mine_only, soldout, own, own_only)


@common_logging
def _ix_search(ctx, keyword, mine, mine_only, soldout, own, own_only):
    if (mine_only and not mine) or (own_only and not own):
        typer.echo('contradictory options')
        return
    _ix_list_tokens(ctx, keyword, mine, mine_only, soldout, own, own_only)


@ix_app.command('buy', help="Buy the CTI Token by index. (Check metemctl ix list)")
def ix_buy(ctx: typer.Context, catalog_and_token: List[str]):
    _ix_buy(ctx, catalog_and_token)


@common_logging
def _ix_buy(ctx, catalog_and_token):
    flx = FlexibleIndexToken(ctx, catalog_and_token)
    broker = _load_broker(ctx)
    broker.buy(flx.catalog.address, flx.address, flx.info.price, allow_cheaper=False)
    typer.echo(f'bought token {flx.catalog.index}-{flx.index} for {flx.info.price} pts.')


@contract_broker_app.command('serve', help="Pass your tokens to the broker for disseminate.")
def broker_serve(ctx: typer.Context, catalog_and_token: List[str], amount: int):
    _broker_serve(ctx, catalog_and_token, amount)


@common_logging
def _broker_serve(ctx, catalog_and_token, amount):
    if amount <= 0:
        raise Exception(f'Invalid amount: {amount}')
    if len(catalog_and_token) > 2:
        raise Exception('Redundant arguments for CATALOG_AND_TOKEN')
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    if not flx_token.catalog:
        raise Exception('Missing catalog information')

    account = _load_account(ctx)
    token = Token(account).get(flx_token.address)
    if token.publisher != account.eoa:
        raise Exception(f'Not a token published by you')
    balance = token.balance_of(account.eoa)
    if balance < amount:
        raise Exception(f'transfer amount({amount}) exceeds balance({balance})')
    broker = _load_broker(ctx)
    broker.consign(flx_token.catalog.address, flx_token.address, amount)
    typer.echo(f'consigned {amount} of token({flx_token.address}) to broker({broker.address}).')


@contract_broker_app.command('takeback', help='Takeback tokens from the broker.')
def broker_takeback(ctx: typer.Context, catalog_and_token: List[str], amount: int):
    _broker_takeback(ctx, catalog_and_token, amount)


@common_logging
def _broker_takeback(ctx, catalog_and_token, amount):
    if amount <= 0:
        raise Exception(f'Invalid amount: {amount}')
    if len(catalog_and_token) > 2:
        raise Exception('Redundant arguments for CATALOG_AND_TOKEN')
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    if not flx_token.catalog:
        raise Exception('Missing catalog information')
    account = _load_account(ctx)
    token = Token(account).get(flx_token.address)
    if token.publisher != account.eoa:
        raise Exception(f'Not a token published by you')
    broker = _load_broker(ctx)
    balance = token.balance_of(broker.address)
    if balance < amount:
        raise Exception(f'transfer amount({amount}) exceeds balance({balance})')
    broker.takeback(flx_token.catalog.address, flx_token.address, amount)
    typer.echo(f'took back {amount} of token({flx_token.address}) from broker({broker.address}).')


@contract_token_app.command('create')
def token_create(ctx: typer.Context, initial_supply: int):
    _token_create(ctx, initial_supply)


@common_logging
def _token_create(ctx, initial_supply) -> Optional[ChecksumAddress]:
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    if initial_supply <= 0:
        raise Exception(f'Invalid initial-supply: {initial_supply}')
    token = Token(account).new(initial_supply, [])
    typer.echo(f'created a new token. address is {token.address}.')
    return token.address


@contract_token_app.command('mint')
def token_mint(ctx: typer.Context, token: str, amount: int,
               dest: Optional[str] = typer.Option(
                   None, help='Account EOA minted tokens are given to, instead of you. '
                   'Do not assign Broker, it does not mean serving.')):
    _token_mint(ctx, token, amount, dest)


@common_logging
def _token_mint(ctx, token, amount, dest):
    account = _load_account(ctx)
    dest = dest if dest else account.eoa
    flx = FlexibleIndexToken(ctx, token)
    Token(account).get(flx.address).mint(amount, dest=cast(ChecksumAddress, dest))
    typer.echo(f'minted {amount} of token({flx.address}) for account({dest}).')


@contract_token_app.command('burn')
def token_burn(ctx: typer.Context, token: str, amount: int, data: str = ''):
    _token_burn(ctx, token, amount, data)


@common_logging
def _token_burn(ctx, token, amount, data):
    if amount <= 0:
        raise Exception(f'Invalid amount: {amount}.')
    account = _load_account(ctx)
    flx = FlexibleIndexToken(ctx, token)
    Token(account).get(flx.address).burn(amount, data)
    typer.echo(f'burned {amount} of token({flx.address}).')


@contract_token_app.command('publish')
def token_publish(ctx: typer.Context,
                  catalog: str = typer.Option(
                      '1',
                      help='A CTI catalog id/address to use for dissemination'),
                  token_address: Optional[str] = typer.Option(
                      None,
                      help='A CTI token address to use for dissemination'),
                  uuid: Optional[str] = typer.Option(
                      None,
                      help='The uuid of misp object'),
                  title: Optional[str] = typer.Option(
                      None,
                      help='The title of misp object'),
                  price: int = typer.Option(
                      10,
                      help='A price of CTI token (dissemination cost)'),
                  initial_amount: int = typer.Option(
                      100,
                      help='An initial supply amount of CTI tokens'),
                  serve_amount: int = typer.Option(
                      99,
                      help='An amount of CTI tokens to give CTI broker'),
                  ):
    _token_publish(ctx, catalog, token_address, uuid, title, price, initial_amount, serve_amount)


@common_logging
def _token_publish(ctx, catalog, token_address, uuid, title, price, initial_amount, serve_amount):
    operator_address = _load_operator(ctx).address
    flx_catalog = FlexibleIndexCatalog(ctx, catalog)
    notice_token, fix_token = _fix_amounts(ctx, token_address, initial_amount, serve_amount)

    typer.echo(f'{"":=<64}')
    typer.echo(f'{title}')
    typer.echo(f'{"":-<64}')
    typer.echo(f' - UUID: {uuid}')
    typer.echo(f' - Price: {price}')
    if token_address:
        typer.echo(f' - Charge: {serve_amount} (Token: {token_address})')
        if notice_token:
            typer.echo(f'           <!> {notice_token} <!>')
    else:
        typer.echo(f' - Sales Quantity: {serve_amount} (Initial Supply: {initial_amount})')
    typer.echo(f' - Exchanger: {operator_address}')
    typer.echo(f' - Catalog: {flx_catalog.index}: {flx_catalog.address}')
    typer.echo(f'{"":=<64}')

    try:
        typer.confirm('Are you sure you want to publish it?', abort=True)
    except Exception as err:
        raise Exception('Interrupted') from err  # click.exceptions.Abort has no message

    if not token_address:
        token_address = _token_create(ctx, initial_amount)
    elif fix_token:
        fix_token()  # mint or burn

    account = _load_account(ctx)
    catalog = Catalog(account).get(flx_catalog.address)
    catalog.register_cti(
        cast(
            ChecksumAddress,
            token_address),
        uuid,
        title,
        price,
        operator_address)
    typer.echo(f'registered token({token_address}) onto catalog({catalog.address}).')
    catalog.publish_cti(account.eoa, cast(ChecksumAddress, token_address))
    typer.echo(f'Token({token_address}) was published on catalog({catalog.address}).')
    _broker_serve(ctx, [catalog.address, token_address], serve_amount)

    return token_address


@seeker_app.command('status')
def seeker_status(ctx: typer.Context):
    _seeker_status(ctx)


@common_logging
def _seeker_status(ctx):
    seeker = Seeker(APP_DIR, _load_operator(ctx).address)
    if seeker.pid == 0:
        typer.echo(f'not running.')
    else:
        typer.echo(f'running on pid {seeker.pid}, listening {seeker.address}:{seeker.port}.')
    ngrok_mgr = NgrokMgr(APP_DIR)
    if ngrok_mgr.pid > 0:
        typer.echo(f'and ngrok running on pid {ngrok_mgr.pid}, '
                   f'with public url: {ngrok_mgr.public_url}.')


@seeker_app.command('start')
def seeker_start(
    ctx: typer.Context,
    ngrok: Optional[bool] = typer.Option(
        None,
        help='Launch ngrok with seeker. the default depends on your configuration '
        'of ngrok in seeker section.')):
    _seeker_start(ctx, ngrok)


@common_logging
def _seeker_start(ctx, ngrok):
    if ngrok is None:
        ngrok = int(_load_config(ctx)['seeker']['ngrok']) > 0
    endpoint_url = _load_config(ctx)['general']['endpoint_url']
    if not endpoint_url:
        raise Exception('Missing configuration: endpoint_url')
    config = _workspace_confpath(ctx)
    seeker = Seeker(APP_DIR, _load_operator(ctx).address, endpoint_url, config)
    seeker.start()
    typer.echo(f'seeker started on process {seeker.pid}, '
               f'listening {seeker.address}:{seeker.port}.')
    if ngrok:
        ngrok_mgr = NgrokMgr(APP_DIR, seeker.port, config)
        if ngrok_mgr.pid == 0:
            ngrok_mgr.start()
        else:
            typer.echo('restarging ngrok...')
            ngrok_mgr.stop()
            ngrok_mgr.start()
        typer.echo(f'ngrok started on process {ngrok_mgr.pid}, '
                   f'with public url: {ngrok_mgr.public_url}.')


@seeker_app.command('stop')
def seeker_stop(ctx: typer.Context):
    _seeker_stop(ctx)


@common_logging
def _seeker_stop(ctx):
    seeker = Seeker(APP_DIR, _load_operator(ctx).address)
    seeker.stop()
    typer.echo('seeker stopped.')
    ngrok_mgr = NgrokMgr(APP_DIR)
    if ngrok_mgr.pid > 0:
        ngrok_mgr.stop()
        typer.echo('ngrok also stopped.')


def _solver_client(ctx: typer.Context, account: Optional[Account] = None) -> MCSClient:
    if 'solver_client' in ctx.meta.keys():
        return ctx.meta['solver_client']
    account = account if account else _load_account(ctx)
    solver = MCSClient(account, APP_DIR)
    solver.connect()
    solver.login()
    ctx.meta['solver_client'] = solver
    return solver


@solver_app.command('status',
                    help='Show Solver status.')
def solver_status(ctx: typer.Context):
    typer.echo(_solver_status(ctx)[1])


def _solver_status(ctx: typer.Context) -> Tuple[bool, str]:
    logger = getLogger()
    try:
        solver = _solver_client(ctx)
    except Exception as err:
        logger.exception(err)
        return False, str(err)
    try:
        solver.get_solver()
    except MCSError as err:
        if err.code == MCSErrno.ENOENT:
            msg = 'Solver running without your operator.'
        else:
            msg = str(err)
        return False, msg
    except Exception as err:
        logger.exception(err)
        return False, f'failed operation: {err}'
    try:
        operator = _load_operator(ctx)
    except Exception:
        return False, 'Solver running, but you have not yet configured operator.'
    if solver.operator_address == operator.address:
        msg = f'Solver running with operator you configured({operator.address}).'
    else:
        msg = f'[WARNING] Solver running with another operator({solver.operator_address}).'
    return True, msg


@solver_app.command('start',
                    help='Start Solver process.')
def solver_start(ctx: typer.Context,
                 enable: bool = typer.Option(False, help='auto enable with default config.')):
    _solver_start(ctx, enable)


@common_logging
def _solver_start(ctx, enable):
    try:
        _solver_client(ctx)
        raise Exception('Solver already running.')
    except Exception as err:
        if not str(err).startswith('Socket not found.'):
            raise
    config = _load_config(ctx)
    endpoint_url = config['general']['endpoint_url']
    solv_cli_py = os.path.dirname(__file__) + '/../core/multi_solver_cli.py'
    subprocess.Popen(
        ['python3', solv_cli_py, '-e', endpoint_url, '-m', 'server', '-w', APP_DIR],
        shell=False)
    typer.echo('Solver started as a subprocess.')
    if enable:
        typer.echo('Enabling your operator.')
        sleep(2)
        _solver_enable(ctx, None)


@solver_app.command('stop',
                    help='Kill Solver process, all solver (not only yours) are killed.')
def solver_stop(ctx: typer.Context):
    _solver_stop(ctx)


@common_logging
def _solver_stop(ctx):
    solver = _solver_client(ctx)
    solver.shutdown()
    typer.echo('Solver shutted down.')


@solver_app.command('enable',
                    help='Solver start running with operator you configured.')
def solver_enable(
    ctx: typer.Context,
    plugin: Optional[str] = typer.Option(
        None,
        help='solver plugin filename. the default depends on your configuration of '
        'plugin in solver section. please note that another configuration '
        'may be required by plugin.')):
    _solver_enable(ctx, plugin)


def _solver_enable(ctx, plugin):
    logger = getLogger()
    try:
        plugin = plugin if plugin else _load_config(ctx)['solver']['plugin']

        # exceptional case not to use _load_account: private key is required by new_solver().
        eoaa, pkey = decode_keyfile(_load_config(ctx)['general']['keyfile'], _get_keyfile_password)
        account = Account(Ether(_load_config(ctx)['general']['endpoint_url']), eoaa, pkey)
        if not ctx.meta.get('account'):
            ctx.meta['account'] = account
        operator = _load_operator(ctx)
        solver = _solver_client(ctx, account=account)
        config = _workspace_confpath(ctx)
        applied = solver.new_solver(
            operator.address, pkey, pluginfile=plugin, configfile=str(config))

        assert applied == operator.address
        typer.echo(f'Solver is now running with your operator({applied}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')
        return

    # start accept tokens already registered if exists.
    try:
        population = _get_tokens_population(
            ctx, mine=True, mine_only=True, soldout=True, own=True, own_only=False)
        token_addresses = [t.address for lst in population.values() for t in lst]
        if len(token_addresses) == 0:
            return
    except Exception:
        return

    try:
        msg = solver.solver('accept_registered', token_addresses)
        acceptings = solver.solver('accepting_tokens')
        if acceptings:
            typer.echo(f'and accepting {len(acceptings)} token(s) already registered.')
        else:
            typer.echo(f'No token registered on this operator.')
        if msg:
            typer.echo(msg)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'accepting registerd tokens failed: {err}')


@solver_app.command('disable',
                    help='Solver will purge your operator, and keep running.')
def solver_disable(ctx: typer.Context):
    _solver_disable(ctx)


@common_logging
def _solver_disable(ctx):
    solver = _solver_client(ctx)
    solver.get_solver()
    solver.purge_solver()
    typer.echo('Solver is now running without your operator.')


@solver_app.command('support',
                    help='Register token to accept challenge.')
def solver_support(ctx: typer.Context, token: str):
    __solver_support(ctx, token)


@common_logging
def __solver_support(ctx, token):
    _solver_support(ctx, token)


def _solver_support(ctx, token):
    flx = FlexibleIndexToken(ctx, token)
    solver = _solver_client(ctx)
    solver.get_solver()
    msg = solver.solver('accept_challenges', [flx.address])
    if msg:
        typer.echo(msg)
    typer.echo(f'Token({token}) object was supported by Solver.')
    typer.echo(f'Your MISP object is now available for download.')


@solver_app.command('obsolete',
                    help='Unregister token not to accept challenge.')
def solver_obsolete(ctx: typer.Context, token: str):
    _solver_obsolete(ctx, token)


@common_logging
def _solver_obsolete(ctx, token):
    flx = FlexibleIndexToken(ctx, token)
    solver = _solver_client(ctx)
    solver.get_solver()
    solver.solver('refuse_challenges', [flx.address])
    typer.echo(f'obsoleted challenge for token({flx.address}) by solver.')


@ix_app.command('use', help="Use the token to challenge the task. (Get the MISP object, etc.")
def ix_use(ctx: typer.Context, token: str,
           seeker: str = typer.Option(
               '', help='Globally accessible url which seeker is listening. '
                        'This option overwrites --ngrok.'),
           ngrok: bool = typer.Option(
               True, help='Use ngrok public url bound up with seeker if launched.'),
           monitor: bool = typer.Option(
               True, help='Print messages from Seeker on current terminal.')):
    _ix_use(ctx, token, seeker, ngrok, monitor)


@common_logging
def _ix_use(ctx, token, seeker, ngrok, monitor):
    flx = FlexibleIndexToken(ctx, token)
    account = _load_account(ctx)
    operator = _load_operator(ctx)
    assert operator.address
    data = seeker if seeker else (NgrokMgr(APP_DIR).public_url or '') if ngrok else ''
    if not data:
        raise Exception('Seeker url is not specified (or ngrok is not running)')
    Token(account).get(flx.address).send(operator.address, amount=1, data=data)
    typer.echo(f'Started challenge with token({flx.address}).')
    if monitor:
        _monitor_seeker_message()


def _monitor_seeker_message():
    try:
        tty = subprocess.run(['tty'], check=True, capture_output=True, text=True).stdout.strip()
        if not os.path.exists(tty):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), tty)
    except Exception as err:
        typer.echo(f'cannot get tty: {err}')
        typer.echo('give up monitoring seeker message. '
                   'try "metemctl ix show [--done]" to check task status.')
        return
    try:
        typer.echo('>> Start monitoring seeker message. type CTRL-C to abort.')
        if os.path.exists(TTYLINK4SEEKER):
            typer.echo('[CAUTION] TTY used by another monitoring process is overwritten.')
            os.unlink(TTYLINK4SEEKER)  # force overwrite
        os.symlink(tty, TTYLINK4SEEKER)
        while input():
            pass
    except KeyboardInterrupt:
        pass
    finally:
        os.unlink(TTYLINK4SEEKER)


def _is_correct_sha256(filename, sha256):

    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        if sha256_hash.hexdigest() == sha256:
            return True
    return False


def _download_contents(external_files: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    logger = getLogger()
    for path, attr in external_files.items():
        logger.info(f'file download: {attr["link"]}')
        temp_file, headers = urllib.request.urlretrieve(attr['link'])
        logger.info(f'downloaded: {path}')
        logger.debug(f'header: {headers}')
        if _is_correct_sha256(temp_file, attr['sha256']):
            external_files[path]['temp_file'] = temp_file
        else:
            logger.warning('hash mismatch: {temp_file}')
    return external_files


def _extract_contents(misp_object: Path):
    event = pymisp.mispevent.MISPEvent()
    event.load_file(misp_object)
    external_files: Dict[str, Dict[str, str]] = dict()
    for attr in event.attributes:
        if attr.type == "link":
            external_files[attr.comment] = dict()
            external_files[attr.comment]['link'] = attr.value
    for attr in event.attributes:
        if attr.type == "sha256":
            if attr.comment in external_files.keys():
                external_files[attr.comment]['sha256'] = attr.value
    if external_files:
        return external_files

    return None


def _find_project_dir(ctx: typer.Context):
    config = _load_config(ctx)
    project_dir = Path(os.getcwd()) / config['general']['project']
    if os.path.isdir(project_dir):
        if os.access(project_dir, os.W_OK):
            return project_dir
    return None


def place_contents(external_files: Dict[str, Dict[str, str]], target_dir: Path):
    for path, attr in external_files.items():
        output_path = target_dir / Path(path)
        output_dir = output_path.parent
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        if attr['temp_file']:
            shutil.move(attr['temp_file'], output_path)
            typer.echo(f'put: {output_path}')


@ix_app.command('extract', help="Extract the contents from the downloaded MISP object.")
def ix_extract(ctx: typer.Context, used_token: str):
    _ix_extract(ctx, used_token)


@common_logging
def _ix_extract(ctx, used_token):
    config = _load_config(ctx)
    workspace = config['general']['workspace']
    flx = FlexibleIndexToken(ctx, used_token)
    downloaded_misp = Path(f'{workspace}/download/{flx.address}.json')

    target_dir = _find_project_dir(ctx)
    if not target_dir:
        target_dir = Path(workspace)

    external_files = None
    if os.path.isfile(downloaded_misp):
        if _is_misp_object(downloaded_misp):
            external_files = _extract_contents(downloaded_misp)
        else:
            raise Exception(f'Invalid MISP Object: {downloaded_misp}')
    else:
        type.echo('Try \"metemctl ix use {used_token}}\".')
        return

    if external_files:
        typer.echo(f'Extract the contents to: {target_dir}')
        for path, attr in external_files.items():
            typer.echo(f'- {path}: {attr}')
        try:
            typer.confirm('continue?', abort=True)
        except Exception as err:
            raise Exception('Interrupted') from err

        external_files = _download_contents(external_files)
        place_contents(external_files, target_dir)


def _find_token_info(ctx: typer.Context, token_address: ChecksumAddress) -> TokenInfo:
    account = _load_account(ctx)
    catalog_mgr = _load_catalog_manager(ctx)
    for catalog_address in catalog_mgr.all_catalogs.keys():
        try:
            return Catalog(account).get(catalog_address).get_tokeninfo(token_address)
        except Exception:
            pass
    raise Exception('No info found for token({token_address}) on registered catalogs')


def _get_challenges(ctx: typer.Context
                    ) -> List[Tuple[int, ChecksumAddress, ChecksumAddress, ChecksumAddress, int]]:
    operator = _load_operator(ctx)
    raw_tasks = []
    limit_atonce = 64
    offset = 0
    while True:
        tmp = operator.history(ADDRESS0, ADDRESS0, limit_atonce, offset)
        raw_tasks.extend(tmp)
        if len(tmp) < limit_atonce:
            break
        offset += limit_atonce
    return raw_tasks


@ix_app.command('show', help="Show CTI tokens available.")
def ix_challenge_show(ctx: typer.Context,
                      done: bool = typer.Option(False, help='show finished and cancelled'),
                      mine_only: bool = typer.Option(True, help='show yours only'),
                      verbose: bool = typer.Option(False, help='show seekr and solver')):
    _ix_challenge_show(ctx, done, mine_only, verbose)


@common_logging
def _ix_challenge_show(ctx, done, mine_only, verbose):
    account = _load_account(ctx)
    raw_tasks = _get_challenges(ctx)
    for (task_id, token, solver, seeker, state) in reversed(raw_tasks):
        if mine_only and seeker != account.eoa:
            continue
        if not done and state in (2, 3):  # ('Finished', 'Cancelled')
            continue
        try:
            title = _find_token_info(ctx, token).title
        except Exception:
            title = '(no information found on current catalogs)'
        ext_msg = f'    ├ Seeker: {seeker}' + '\n' +\
                  f'    ├ Solver: {solver}' + '\n' \
                  if verbose else ''
        typer.echo(
            f'  {task_id}: {title}' + '\n'
            f'    ├ Token: {token}' + '\n'
            f'{ext_msg}'
            f'    └ State: {TASK_STATES[state]}')


@ix_app.command('cancel', help="Abort the task in progress.")
def ix_cancel(ctx: typer.Context, challenge_id: int):
    _ix_cancel(ctx, challenge_id)


@common_logging
def _ix_cancel(ctx, challenge_id):
    operator = _load_operator(ctx)
    operator.cancel_challenge(challenge_id)
    typer.echo(f'cancelled challenge: {challenge_id}.')


@contract_broker_app.command('show')
def broker_show(ctx: typer.Context):
    _broker_show(ctx)


@common_logging
def _broker_show(ctx):
    broker = _load_broker(ctx)
    typer.echo(f'Broker address is {broker.address}.')


@contract_broker_app.command('create')
def broker_create(ctx: typer.Context,
                  switch: bool = typer.Option(True, help='switch to deployed broker')):
    _broker_create(ctx, switch)


@common_logging
def _broker_create(ctx, switch):
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    broker = Broker(account).new()
    typer.echo(f'deployed a new broker. address is {broker.address}.')
    if switch:
        ctx.meta['broker'] = broker
        config_update_broker(ctx)
        typer.echo('configured to use the broker above.')


# @contract_broker_app.command('set')
def broker_set(ctx: typer.Context, broker_address: str):
    _broker_set(ctx, broker_address)


@common_logging
def _broker_set(ctx, broker_address):
    account = _load_account(ctx)
    broker = Broker(account).get(cast(ChecksumAddress, broker_address))
    ctx.meta['broker'] = broker
    config_update_broker(ctx)
    typer.echo(f'configured to use broker({broker_address}).')


@contract_operator_app.command('show', help="Show the contract address of the operator.")
def operator_show(ctx: typer.Context):
    _operator_show(ctx)


@common_logging
def _operator_show(ctx):
    operator = _load_operator(ctx)
    typer.echo(f'Operator address is {operator.address}.')


@contract_operator_app.command('create')
def operator_create(ctx: typer.Context,
                    switch: bool = typer.Option(True, help='switch to deployed operator')):
    _operator_create(ctx, switch)


@common_logging
def _operator_create(ctx, switch):
    try:
        old_operator = _load_operator(ctx)
    except Exception:
        old_operator = None
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    operator = Operator(account).new()
    operator.set_recipient()
    typer.echo(f'deployed a new operator. address is {operator.address}.')
    if switch or old_operator is None:
        ctx.meta['operator'] = operator
        config_update_operator(ctx)
        typer.echo('configured to use the operator above.')
        if old_operator:
            typer.echo('you should restart seeker and solver, if launched.')


# @contract_operator_app.command('set')
def operator_set(ctx: typer.Context, operator_address: str):
    _operator_set(ctx, operator_address)


@common_logging
def _operator_set(ctx, operator_address):
    try:
        old_operator = _load_operator(ctx)
    except Exception:
        old_operator = None
    account = _load_account(ctx)
    operator = Operator(account).get(cast(ChecksumAddress, operator_address))
    ctx.meta['operator'] = operator
    config_update_operator(ctx)
    typer.echo(f'configured to use operator({operator_address}).')
    if operator_address != old_operator:
        typer.echo('you should restart seeker and solver, if launched.')


@ix_catalog_app.command('show', help="Show the list of CTI catalogs")
@contract_catalog_app.command('show', help="Show the list of CTI catalogs")
def catalog_show(ctx: typer.Context):
    _catalog_show(ctx)


@common_logging
def _catalog_show(ctx):
    catalog_mgr = _load_catalog_manager(ctx)
    typer.echo('Catalogs *:active')
    for caddr, cid in sorted(
            catalog_mgr.all_catalogs.items(), key=lambda x: x[1]):
        typer.echo(
            f'  {"*" if caddr in catalog_mgr.actives else " "}{cid} {caddr}')


# @contract_catalog_app.command('add', help="Add the CTI catalog to the list.")
def catalog_add(ctx: typer.Context, catalog_address: str,
                activate: bool = typer.Option(True, help='activate added catalog')):
    _catalog_add(ctx, catalog_address, activate)


@common_logging
def _catalog_add(ctx, catalog_address, activate):
    catalog_mgr = _load_catalog_manager(ctx)
    catalog_mgr.add([cast(ChecksumAddress, catalog_address)], activate=activate)
    config_update_catalog(ctx)
    catalog_show(ctx)


@contract_catalog_app.command('create', help="Create a new CTI catalog.")
def catalog_create(ctx: typer.Context,
                   group: Optional[str] = typer.Option(None, help='permitted user group'),
                   activate: bool = typer.Option(False, help='activate created catalog')):
    _catalog_create(ctx, group, activate)


@common_logging
def _catalog_create(ctx, group, activate):
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    group = group if group else ADDRESS0
    catalog: Catalog = Catalog(account).new(group)
    typer.echo('deployed a new '
               f'{"private" if group == ADDRESS0 else "public"} catalog. '
               f'address is {catalog.address}.')
    catalog_add(ctx, str(catalog.address), activate)


@common_logging
def _catalog_ctrl(
        act: str, ctx: typer.Context, catalog: str):
    catalog_mgr = _load_catalog_manager(ctx)
    if act not in ('remove', 'activate', 'deactivate'):
        raise Exception('Invalid act: ' + act)
    flx = FlexibleIndexCatalog(ctx, catalog)
    func: Callable[[List[ChecksumAddress]], None] = getattr(catalog_mgr, act)
    func([flx.address])
    config_update_catalog(ctx)
    catalog_show(ctx)


# @contract_catalog_app.command('remove', help="Remove the CTI catalog from the list.")
def catalog_remove(ctx: typer.Context, catalog: str):
    _catalog_ctrl('remove', ctx, catalog)


@ix_catalog_app.command('enable', help="Activate the CTI catalog on the list.")
def ix_catalog_enable(ctx: typer.Context, catalog: str):
    _catalog_ctrl('activate', ctx, catalog)


@ix_catalog_app.command('disable', help="Deactivate the CTI catalog on the list.")
def ix_catalog_desable(ctx: typer.Context, catalog: str):
    _catalog_ctrl('deactivate', ctx, catalog)


@app.command()
def misp():
    typer.echo(f"misp")


@misp_app.command("open", help="Go to your MISP instance.")
def misp_open(ctx: typer.Context):
    logger = getLogger()
    try:
        misp_url = _load_config(ctx)['misp']['url']
        logger.info(f"Open MISP: {misp_url}")
        typer.echo(misp_url)
        typer.launch(misp_url)
    except KeyError as err:
        typer.echo(err, err=True)
        logger.error(err)


class IAPAuth(requests.auth.AuthBase):

    def __init__(self, ctx):
        self.client_id = _load_config(ctx)['misp']['gcp_client_id']

        credential_path = _load_config(ctx)['misp']['gcp_cloud_iap_cred']
        if credential_path:
            # Set the GOOGLE_APPLICATION_CREDENTIALS to use service account
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = str(credential_path)

    def __call__(self, r):
        open_id_connect_token = id_token.fetch_id_token(Request(), self.client_id)
        r.headers['Proxy-Authorization'] = 'Bearer {}'.format(open_id_connect_token)
        return r


def _dump_json(data, dumpdir, force=False, indent=None):
    try:
        uuid = data['Event']['uuid']
        if len(uuid) == 0:
            raise Exception('Empty UUID')
    except Exception as err:
        raise Exception('Unexpected data: missing Event or UUID') from err

    filename = uuid + '.json'
    fpath = Path(dumpdir) / filename
    if os.path.isfile(fpath) and not force:
        raise Exception(f'already exists: {fpath}')
    with open(fpath, 'w') as fout:
        json.dump(data, fout, indent=indent, ensure_ascii=False)

    return fpath


def _store_pretty_json(results, json_dumpdir):
    # store json file
    indent = 2
    for val in results:
        try:
            fpath = _dump_json(val, json_dumpdir, True, indent)
            typer.echo(f'dumped to {fpath}')
        except OSError as err:
            typer.echo(err)


def _ssl_settings(ssl_cert: int) -> bool:
    if ssl_cert == 0:
        urllib3.disable_warnings()
        return False
    if ssl_cert == 1:
        return False
    return True


def _pymisp_client(ctx: typer.Context):
    logger = getLogger()

    url = _load_config(ctx)['misp']['url']
    api_key = _load_config(ctx)['misp']['api_key']
    ssl_cert = int(_load_config(ctx)['misp']['ssl_cert'])

    logger.info(f"Fetch MISP: {url}")

    client_id = _load_config(ctx)['misp']['gcp_client_id']

    if client_id:
        return pymisp.PyMISP(url, api_key, _ssl_settings(ssl_cert), auth=IAPAuth(ctx))

    return pymisp.PyMISP(url, api_key, _ssl_settings(ssl_cert))


@misp_app.command("fetch", help="Export events from your MISP instance.")
def misp_fetch(
    ctx: typer.Context,
    limit: int = typer.Option(
        1000,
        help='Limit the number of results.'),
    page: int = typer.Option(
        1,
        help='Sets the page to be returned.'),
    date_from: Optional[str] = typer.Option(
        None,
        help='Published Events with the date set to a date after the one specified.'),
    date_to: Optional[str] = typer.Option(
        None,
        help='Published Events with the date set to a date before the one specified.'),
    publish_timestamp: Optional[float] = typer.Option(
        None,
        help='Restrict the results by the last publish timestamp.'),
    timestamp: Optional[float] = typer.Option(
        str((datetime.now() - timedelta(days=60)).timestamp()),
        help='Restrict the results by the timestamp. (Default is 30 days before)'),
    tags: Optional[List[str]] = typer.Option(
        None,
        help='Tags to search or to exclude. You can pass a list.'),
    threatlevel: Optional[List[str]] = typer.Option(
        None,
        help='Threat level(s) (1,2,3,4).'),
    distribution: Optional[List[str]] = typer.Option(
        None,
        help='Distribution level(s) (0,1,2,3).'),
    org: Optional[List[Union[str]]] = typer.Option(
        None,
        help='Search by the creator organisation by supplying the organisation identifier.')
):
    results = _pymisp_client(ctx).search(
        limit=limit,
        page=page,
        data_from=date_from,
        date_to=date_to,
        publish_timestamp=publish_timestamp,
        timestamp=timestamp,
        # Maybe unbound bug in mypy https://github.com/python/mypy/issues/9354
        tags=cast(Optional[pymisp.api.SearchParameterTypes], tags),  # type: ignore
        threatlevel=cast(Optional[List[pymisp.api.SearchType]], threatlevel),  # type: ignore
        distribution=cast(Optional[List[pymisp.api.SearchType]], distribution),  # type: ignore
        org=cast(Optional[pymisp.api.SearchParameterTypes], org))  # type: ignore

    json_dumpdir = Path(_load_config(ctx)['misp']['download'])
    _store_pretty_json(results, json_dumpdir)


def _load_misp_event(filepath):
    logger = getLogger()
    event = pymisp.mispevent.MISPEvent()
    try:
        event.load_file(filepath)
    except (TypeError, json.decoder.JSONDecodeError) as err:
        logger.exception(f'{err}: {filepath}')
        typer.echo(f'{err}: {filepath}')
    if not hasattr(event, 'date'):
        raise Exception(f'The date field of the new event is required. ({filepath})')
    return event


@misp_app.command("event", help="Show exported MISP events")
def misp_event(ctx: typer.Context):
    json_dumpdir = Path(_load_config(ctx)['misp']['download'])

    files = json_dumpdir.glob('*.json')
    files_sort_by_date = sorted(list(files), key=lambda f: _load_misp_event(f).date, reverse=True)

    output_line = []
    for file in files_sort_by_date:
        event = _load_misp_event(file)
        output_line.append(f'{event.date} - {event.uuid}: {event.info}')

    typer.echo_via_pager('\n'.join(output_line))


def setup_kedro(cwd):
    subprocess.run(['kedro', 'build-reqs'], check=True, cwd=cwd)
    subprocess.run(['kedro', 'install'], check=True, cwd=cwd)


@app.command(help="Run the current intelligence workflow.")
def run(ctx: typer.Context, setup: bool = typer.Option(
        False, help='kedro build-reqs && kedro install')):
    logger = getLogger()
    logger.info(f"Run command: kedro run")
    try:
        # TODO: check the existence of a CWD path
        cwd = _load_config(ctx)['general']['project']
        if setup:
            setup_kedro(cwd)
        subprocess.run(['kedro', 'run'], check=True, cwd=cwd)
    except CalledProcessError as err:
        logger.exception(err)
        typer.echo(f'An error occurred while running the workflow. {err}')


@app.command(help="Validate the current intelligence cylcle")
def check(
    ctx: typer.Context,
    setup: bool = typer.Option(
        False,
        help='kedro build-reqs && kedro install'),
        viz: bool = typer.Option(
            False,
        help='Show the visualized current workflow')):
    # TODO: check the available intelligece workflow
    # TODO: check available intelligece contents
    logger = getLogger()
    logger.info(f"Run command: kedro test")
    try:
        # TODO: check the existence of a CWD path
        cwd = _load_config(ctx)['general']['project']
        if setup:
            setup_kedro(cwd)
        subprocess.run(['kedro', 'test'], check=True, cwd=cwd)
        if viz:
            logger.info(f"Run command: kedro viz")
            subprocess.run(['kedro', 'viz'], check=True, cwd=cwd)
    except CalledProcessError as err:
        logger.exception(err)
        typer.echo(f'An error occurred while testing the workflow. {err}')


@app.command(help="Deploy the CTI token to disseminate CTI.")
def publish(
        ctx: typer.Context,
        misp_object: Optional[str] = None,
        catalog: str = typer.Option(
            '1',
            help='A CTI catalog id/address to use for dissemination'),
        token_address: Optional[str] = typer.Option(
            None,
            help='A CTI token address to use for dissemination'),
        price: int = typer.Option(
            10,
            help='A price of CTI token (dissemination cost)'),
        initial_amount: int = typer.Option(
            100,
            help='An initial supply amount of CTI tokens'),
        serve_amount: int = typer.Option(
            99,
            help='An amount of CTI tokens to give CTI broker'),
):
    _publish(
        ctx,
        misp_object,
        catalog,
        token_address,
        price,
        initial_amount,
        serve_amount)


def _uuid_to_misp_download_path(_ctx, uuid) -> Path:
    return Path(f'{APP_DIR}/misp/download/{str(UUID(uuid))}.json')


def _address_to_solver_assets_path(ctx, address) -> Path:
    workspace = _load_config(ctx)['general']['workspace']
    return Path(f'{workspace}/upload/{address}')


def _is_misp_object(load_filepath):
    with open(load_filepath) as fin:
        dict_object = json.load(fin)
        if 'Event' in dict_object.keys():
            return True
    return False


def _store_misp_object(ctx, load_filepath) -> Tuple[str, str]:
    typer.echo(f'loading: {load_filepath}')
    event = _load_misp_event(load_filepath)

    download_filepath = _uuid_to_misp_download_path(ctx, event.uuid)
    if os.path.exists(download_filepath):
        if Path(download_filepath).resolve() != Path(load_filepath).resolve():
            typer.echo(f'MISP download file already exists: {download_filepath}')
            try:
                typer.confirm('overwrite and continue?', abort=True)
            except Exception as err:
                raise Exception('Interrupted') from err  # click.exceptions.Abort has no message
        else:
            return event.uuid, event.info

    # save the loadable MISP objects
    misp_object = pymisp.AbstractMISP()
    misp_object.Event = event
    with open(download_filepath, 'w') as fout:
        # dump json correctly with ensure_ascii=False
        # cannot set ensure_ascii=False in fout.write(misp_object.to_json())
        json.dump(json.loads(misp_object.to_json()), fout, ensure_ascii=False, indent=2)
        typer.echo(f'saved MISP object as {download_filepath}')

    return event.uuid, event.info


def _fix_amounts(ctx, token_address, initial_amount, serve_amount
                 ) -> Tuple[Optional[str], Optional[Callable[[], None]]]:
    if initial_amount <= 0:
        raise Exception(f'Invalid initial_amount: {initial_amount}')
    if serve_amount < 0:
        raise Exception(f'Invalid serve_amount: {serve_amount}')
    if initial_amount < serve_amount:
        raise Exception(
            f'Serve amount is in excess of initial supply: {serve_amount} > {initial_amount}')
    if token_address:
        account = _load_account(ctx)
        token = Token(account).get(token_address)
        balance = token.balance_of(account.eoa)
        diff = balance - initial_amount
        if diff < 0:
            return (
                f'You only have {balance} tokens. {-diff} tokens will be minted.',
                lambda: token.mint(-diff, account.eoa)
            )
        if diff > 0:
            return (
                f'You already have {balance} tokens. {diff} tokens will be burned.',
                lambda: token.burn(diff, '')
            )
    return None, None


def _find_project_report(ctx: typer.Context):
    config = _load_config(ctx)
    project_dir = Path(os.getcwd()) / config['general']['project']
    if os.path.isdir(project_dir):
        report_dir = project_dir / 'data' / '08_reporting'
        json_files = Path(report_dir).glob('*.json')
        for json_file in json_files:
            if _is_misp_object(json_file):
                return json_file
    return None


@common_logging
def _publish(
        ctx,
        misp_object,
        catalog,
        token_address,
        price,
        initial_amount,
        serve_amount):

    if not misp_object:
        misp_object = _find_project_report(ctx)
        if not misp_object:
            raise Exception(
                'MISP obeject not found in the current project. '
                'Try \"metemctl publish --misp_object MISP_OBJECT_PATH\".')

    if price < 0:
        raise Exception(f'Invalid price: {price}')

    uuid, title = _store_misp_object(ctx, misp_object)
    token_address = _token_publish(
        ctx,
        catalog,
        token_address,
        uuid,
        title,
        price,
        initial_amount,
        serve_amount)

    assets_path = _address_to_solver_assets_path(ctx, token_address)
    if os.path.exists(assets_path):
        os.unlink(assets_path)  # force overwrite
    os.symlink(_uuid_to_misp_download_path(ctx, uuid), assets_path)
    typer.echo(f'created a symlink of MISP object as a solver asset for token: {token_address}.')

    if _solver_status(ctx)[0]:
        try:
            _solver_support(ctx, token_address)
            return
        except Exception as err:
            typer.echo(f'failed solver support: {err}')
    typer.echo(f'Run \"mtemctl solver support {token_address}\" after enabling Solver')


@app.command(help="Unregister disseminated CTI token from catalog.")
def discontinue(
        ctx: typer.Context,
        catalog_and_token: List[str]):
    _discontinue(ctx, catalog_and_token)


@common_logging
def _discontinue(ctx, catalog_and_token):
    account = _load_account(ctx)
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    catalog = Catalog(account).get(flx_token.catalog.address)
    broker = _load_broker(ctx)
    broker.uncache(catalog=catalog.address, token=flx_token.address)
    amount = broker.get_amounts(catalog.address, [flx_token.address])[0]
    if amount > 0:
        broker.takeback(catalog.address, flx_token.address, amount)
        typer.echo(f'took back all({amount}) of token({flx_token.address}) from broker.')
    catalog.unregister_cti(flx_token.address)
    typer.echo(f'unregistered token({flx_token.address}) from catalog({catalog.address}).')
    if _solver_status(ctx)[0]:
        _solver_obsolete(ctx, flx_token.address)
    else:
        _load_operator(ctx).unregister_tokens([flx_token.address])


@account_app.command("show", help="Show the current account information.")
def account_show(ctx: typer.Context):
    _account_show(ctx)


@common_logging
def _account_show(ctx):
    account = _load_account(ctx)
    typer.echo(f'--------------------')
    typer.echo(f'Summary')
    typer.echo(f'  - EOA Address: {account.wallet.eoa}')
    typer.echo(f'  - Balance: {account.wallet.balance} Wei')
    typer.echo(f'--------------------')

    catalog_mgr = _load_catalog_manager(ctx)
    for caddr, cid in sorted(
            catalog_mgr.active_catalogs.items(), key=lambda x: x[1]):
        typer.echo(f'Catalog {cid}: {caddr}')
        catalog = Catalog(account).get(caddr)
        if len(catalog.tokens) > 0:
            typer.echo('  Tokens <id, balance, address>')
            for taddr, tinfo in sorted(
                    catalog.tokens.items(), key=lambda x: x[1].token_id):
                token = Token(account).get(taddr)
                balance = token.balance_of(account.eoa)
                if balance > 0:
                    typer.echo(f'  {tinfo.token_id}: {balance}: {taddr}')


@account_app.command("create", help="Create New Account.")
def account_create(ctx: typer.Context):
    _account_create(ctx)


@common_logging
def _account_create(ctx: typer.Context):
    # Ref: https://github.com/ethereum/go-ethereum/blob/v1.10.1/cmd/geth/accountcmd.go
    typer.echo('Your new account is locked with a password. Please give a password.')
    acct = eth_account.Account.create('')

    # https://pages.nist.gov/800-63-3/sp800-63b.html
    # 5.1.1.1 Memorized Secret Authenticators
    # Memorized secrets SHALL be at least 8 characters in length if chosen by the subscriber.
    password = ''
    while len(password) < 8:
        typer.echo('Do not forget this password. The password must contain at least 8 characters.')
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True,)

    encrypted = eth_account.Account().encrypt(acct.key, password)

    # Use the Geth keyfile name format
    created_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%S.%f000Z')
    keyfile_name = f'UTC--{created_time}--{int(acct.address, 16):x}'
    keyfile_path = Path(APP_DIR) / keyfile_name
    with open(keyfile_path, mode='w') as fout:
        json.dump(encrypted, fout)

    typer.echo(f'- Public address of the key:\t{acct.address}')
    typer.echo(f'- Path of the secret key file:\t{keyfile_path}')

    typer.echo('* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *')
    typer.echo('* You must BACKUP your key file & REMEMBER your password! *')
    typer.echo('* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *')

    config = _load_config(ctx)
    current_keyfile = config.get('general', 'keyfile')
    if not current_keyfile or current_keyfile == '/PATH/TO/YOUR/KEYFILE':
        config.set('general', 'keyfile', str(keyfile_path))
        _save_config(ctx, config)
        typer.echo('Update your config file.')


@account_app.command("airdrop", help="Get some ETH from Promote Code. (for devnet)")
def account_airdrop(ctx: typer.Context, promote_code: str):
    _account_airdrop(ctx, promote_code)


@common_logging
def _account_airdrop(ctx: typer.Context, promote_code: str):
    if len(promote_code) != 64:
        raise typer.Abort('Invalid promote code.')

    config = _load_config(ctx)
    url = config['general']['airdrop_url']
    if 'http' not in url:
        raise Exception('Invalid airdrop_url:', url)

    account = _load_account(ctx)
    data = {
        'address': account.eoa,
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {promote_code}'
    }

    req = urllib.request.Request(url, json.dumps(data).encode(), headers)
    with urllib.request.urlopen(req) as res:
        body = res.read()
        content = json.loads(body.decode('utf8'))

    if 'result' in content:
        if content['result'] == 'ok':
            typer.echo(f'Airdrop 1000 ETH to {account.eoa}')
            # HACK: use promote code as API token
            config['gcs_solver']['functions_token'] = promote_code
            _save_config(ctx, config)
            typer.echo('Let me check: metemctl account show')
        else:
            typer.echo('Airdrop failed.')
    else:
        typer.echo(f'A network error has occurred. {content}')


@config_app.command('show', help="Show your config file of metemctl")
def config_show(ctx: typer.Context,
                raw: bool = typer.Option(False, help='omit complementing system defaults.'),
                general: bool = typer.Option(
                    False, help='show metemctl.ini instead of config.ini in workspace')):
    _config_show(ctx, raw, general)


@common_logging
def _config_show(ctx, raw, general):
    if raw:
        filepath = CONFIG_FILE_PATH if general else _workspace_confpath(ctx)
        with open(filepath) as fin:
            typer.echo(fin.read())
    else:
        typer.echo(config2str(_load_config(ctx)))


@config_app.command('edit', help="Edit your config file of metemctl")
def config_edit(ctx: typer.Context,
                raw: bool = typer.Option(False, help='omit complementing system defaults.'),
                general: bool = typer.Option(
                    False, help='edit metemctl.ini instead of config.ini in workspace.')):
    _config_edit(ctx, raw, general)


@common_logging
def _config_edit(ctx, raw, general):
    workspace_conf = _workspace_confpath(ctx)
    if raw:
        filepath = CONFIG_FILE_PATH if general else workspace_conf
        typer.edit(filename=filepath)
    else:
        config = _load_config(ctx)
        contents = typer.edit(config2str(config))
        filepath = workspace_conf if os.path.exists(workspace_conf) else CONFIG_FILE_PATH
        if contents:
            with open(filepath, 'wt') as fout:
                fout.write(contents)
            if '~' in contents:
                _save_config(ctx, config)  # expanduser


@app.command(help="Start an interactive intelligence cycle.")
def console():
    typer.echo(f"console")


@app.command(help="Show practical security services.")
def external_link():
    json_path = Path(APP_DIR) / 'external-links.json'
    with open(json_path) as fin:
        services = json.load(fin)
        for service in services:
            # https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
            hyperlink = f'\x1b]8;;{service["url"]}\x1b\\{service["name"]}\x1b]8;;\x1b\\'
            typer.echo(f"- {hyperlink}: {service['description']}")


@app.command(help="Check Metemcyber issues")
def issue():
    typer.launch('https://github.com/nttcom/metemcyber/issues')


@app.command(help="Access the application directoy of Metemcyber")
def open_app_dir(
    print_only: bool = typer.Option(
        False,
        help='Output only the application directory path.')):
    if print_only:
        typer.echo(f"{APP_DIR}")
    else:
        typer.echo(f"Open \'{APP_DIR}\'")
        typer.launch(APP_DIR)


if __name__ == "__main__":
    app()
