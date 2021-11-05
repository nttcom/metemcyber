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
import functools
import hashlib
import ipaddress
import json
import os
import pickle
import shutil
import subprocess
import urllib.request
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from shutil import copyfile, copytree, ignore_patterns
from subprocess import CalledProcessError
from typing import Callable, Dict, List, Optional, Tuple, Union, cast
from urllib.parse import urlparse
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
from omegaconf import OmegaConf
from web3 import Web3
from web3.datastructures import AttributeDict

from metemcyber import __version__
from metemcyber.cli.config import (METEMCTL_CONFIG_FILEPATH, SSLCertVerify, decode_keyfile,
                                   edit_config, load_config, print_config, update_config, ws_copy,
                                   ws_create, ws_destroy, ws_list, ws_switch)
from metemcyber.cli.constants import APP_DIR
from metemcyber.core.asset_manager import AssetManagerClient, AssetManagerController
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.broker import Broker
from metemcyber.core.bc.catalog import Catalog, TokenInfo
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.eventlistener import BasicEventListener
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
from metemcyber.core.bc.operator import TASK_STATES, Operator
from metemcyber.core.bc.token import Token
from metemcyber.core.bc.util import ADDRESS0, deploy_erc1820
from metemcyber.core.constants import PTS_RATE
from metemcyber.core.logger import get_logger
from metemcyber.core.ngrok import NgrokMgr
from metemcyber.core.seeker import Seeker
from metemcyber.core.solver_server import SolverClient, SolverController

WORKFLOW_FILE_NAME = "workflow.yml"
DATA_FILE_NAME = "source_of_truth.yml"
METEM_STARTER_ALIASES = {
    "ir-exercise"
}
METEM_STARTERS_REPO = "git+https://github.com/nttcom/metemcyber-starters.git"


app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp", help="Manage your MISP instance.")

account_app = typer.Typer()
app.add_typer(account_app, name="account", help="Manage your accounts.")

ix_app = typer.Typer()
app.add_typer(ix_app, name="ix", help="Manage CTI tokens to collect CTIs.")
ix_catalog_app = typer.Typer()
ix_app.add_typer(ix_catalog_app, name='catalog', help="Manage the list of CTI catalogs to use")
ix_issue_app = typer.Typer()
ix_app.add_typer(ix_issue_app, name='issue', help='Manage issue to vote.')

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
assetmgr_app = typer.Typer()
app.add_typer(assetmgr_app, name='asset-manager', help='Manage the Asset Manager subprocess.')

config_app = typer.Typer()
app.add_typer(config_app, name='config', help="Manage your config file of metemctl")
workspace_app = typer.Typer()
app.add_typer(workspace_app, name='workspace', help='Manage your workspace.')


# pylint: disable=invalid-name
def getLogger(name='cli'):
    return get_logger(name=name, app_dir=APP_DIR, file_prefix='cli')


def _init_app_dir(ctx: typer.Context) -> None:
    typer.echo(f'initializing metemcyber application directory: {APP_DIR}')
    os.makedirs(APP_DIR, exist_ok=True)

    template_app_dir = Path(__file__).with_name('app_dir')
    entries = os.listdir(template_app_dir)

    typer.echo(f'copying template files from {template_app_dir}.')
    for entry in entries:
        src = Path(template_app_dir) / entry
        dst = Path(APP_DIR) / entry
        if os.path.isdir(src):
            copytree(src, dst, symlinks=True, ignore=ignore_patterns('.gitkeep'))
        else:
            copyfile(src, dst, follow_symlinks=False)
    typer.echo('initialized metemcyber application directory. ')
    typer.echo('execute "metemctl open-app-dir --print-only" to print application directory.')
    typer.echo('')
    typer.echo(f'generated workspaces: {",".join(ws_list())}')

    load_config(ctx)  # will launch minimal setup


def _load_account(ctx: typer.Context) -> Account:
    if 'account' in ctx.meta.keys():
        return ctx.meta['account']
    config = load_config(ctx)
    required = ['workspace.endpoint_url', 'workspace.keyfile']
    for key in required:
        if OmegaConf.is_missing(config, key) or not OmegaConf.select(config, key):
            raise Exception(f'Missing configuration: {key}')
    eoaa, pkey, _ = decode_keyfile(config.workspace.keyfile, config.workspace.keyfile_password)
    account = Account(Ether(config.workspace.endpoint_url), eoaa, pkey)
    ctx.meta['account'] = account
    return account


def _load_solver_account(ctx: typer.Context) -> Account:
    if 'solver_account' in ctx.meta.keys():
        return ctx.meta['solver_account']
    config = load_config(ctx)
    required = ['workspace.endpoint_url', 'workspace.solver.keyfile']
    for key in required:
        if not OmegaConf.select(config, key):
            raise Exception(f'Missing configuration: {key}')
    eoaa, pkey, _ = decode_keyfile(config.workspace.solver.keyfile,
                                   config.workspace.solver.keyfile_password)
    solver_account = Account(Ether(config.workspace.endpoint_url), eoaa, pkey)
    ctx.meta['solver_account'] = solver_account
    return solver_account


def _load_contract_libs(ctx: typer.Context):
    account = _load_account(ctx)
    config = load_config(ctx)
    deploy_erc1820(account.eoa, account.web3)

    conf_util = config.workspace.metemcyber_util
    if conf_util.address and conf_util.placeholder:
        _ph = MetemcyberUtil.register_library(conf_util.address)
        assert _ph == conf_util.placeholder
    else:
        util = MetemcyberUtil(account).new()
        util_ph = util.register_library(util.address)
        config = update_config(config, 'workspace.metemcyber_util.address', util.address,
                               ctx=ctx, save=False, validate=False)  # not save
        config = update_config(config, 'workspace.metemcyber_util.placeholder', util_ph,
                               ctx=ctx, save=True, validate=False)  # save


def _load_catalog_manager(ctx: typer.Context) -> CatalogManager:
    if 'catalog_manager' in ctx.meta.keys():
        return ctx.meta['catalog_manager']
    account = _load_account(ctx)
    config = load_config(ctx)
    catalog_mgr = CatalogManager(account)
    if config.workspace.catalog.actives:
        catalog_mgr.add(
            cast(List[ChecksumAddress], config.workspace.catalog.actives), activate=True)
    if config.workspace.catalog.reserves:
        catalog_mgr.add(
            cast(List[ChecksumAddress], config.workspace.catalog.reserves), activate=False)
    ctx.meta['catalog_manager'] = catalog_mgr
    return catalog_mgr


def _load_broker(ctx: typer.Context) -> Broker:
    if 'broker' in ctx.meta.keys():
        return ctx.meta['broker']
    try:
        config = load_config(ctx)
        broker_address = cast(ChecksumAddress, config.workspace.broker.address)
        assert broker_address
    except Exception as err:
        raise Exception('Missing configuration: workspace.broker.address') from err
    account = _load_account(ctx)
    broker = Broker(account).get(broker_address)
    ctx.meta['broker'] = broker
    return broker


def _load_operator(ctx: typer.Context) -> Operator:
    if 'operator' in ctx.meta.keys():
        return ctx.meta['operator']
    config = load_config(ctx)
    try:
        operator_address = cast(ChecksumAddress, config.workspace.operator.address)
        assert operator_address
    except Exception as err:
        raise Exception('Missing configuration: workspace.operator.address') from err
    account = _load_account(ctx)
    operator = Operator(account).get(operator_address)
    ctx.meta['operator'] = operator
    return operator


def common_logging(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = getLogger()
        try:
            func(*args, **kwargs)
        except Exception as err:
            logger.exception(err)
            typer.echo(f'failed operation: {str(err) or err.__class__.__name__}')
    return wrapper


def version_callback(value: bool):
    if value:
        typer.echo(f'metemctl version {__version__}')
        raise typer.Exit()


@app.callback()
def app_callback(ctx: typer.Context,
                 _version: bool = typer.Option(None, "--version",
                                               callback=version_callback, is_eager=True),
                 ):
    # init app directory if it does not exist
    logger = getLogger()
    if os.path.exists(APP_DIR):
        if os.path.isdir(APP_DIR):
            if not os.path.exists(METEMCTL_CONFIG_FILEPATH):
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
    config['intelligence_category'] = category
    config['intelligence_contents'] = contents

    logger.info(f"Write the workflow config to: {dst}")
    with open(dst, 'w', encoding='utf-8') as fout:
        yaml.dump(config, fout)
        logger.info(f"Write successful.")


def create_data_for_workflow(yml_filepath: Path):
    logger = getLogger()
    output_dir = None
    repo_name = None

    logger.info(f"check the config from: {yml_filepath}")
    with open(yml_filepath, encoding='utf-8') as fin:
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
    with open(yml_filepath, encoding='utf-8') as fin:
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
        update_config(load_config(ctx), 'project', event_id, save=True, validate=False)


def config_update_catalog(ctx: typer.Context):
    catalog_mgr = _load_catalog_manager(ctx)
    config = load_config(ctx)
    config = update_config(config, 'workspace.catalog.actives',
                           list(catalog_mgr.active_catalogs.keys()),
                           ctx=ctx, validate=False, save=False)
    config = update_config(config, 'workspace.catalog.reserves',
                           list(catalog_mgr.reserved_catalogs.keys()),
                           ctx=ctx, validate=True, save=True)
    Catalog(_load_account(ctx)).uncache(entire=True)


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


def _get_accepting_tokens(ctx: typer.Context, addresses: List[ChecksumAddress]
                          ) -> List[ChecksumAddress]:
    if _shared_solver_enabled(ctx):
        return _shared_solver_list_accepting(ctx, addresses=addresses)

    solver = _solver_client(ctx)
    all_accepting = solver.solver('accepting_tokens')
    if not load_config(ctx).runtime.solver_keepalive:
        solver.disconnect()
    return [addr for addr in addresses if addr in all_accepting]


def _ix_list_tokens(ctx: typer.Context, keyword, mine, mine_only, soldout, own, own_only):
    account = _load_account(ctx)
    if mine:
        typer.echo(' o   = published by you')
        typer.echo('  *  = currently accepting')
    typer.echo('    C-T: title  /  C = CatalogId, T = TokenId in catalog')
    typer.echo('--------')

    population = _get_tokens_population(
        ctx, mine=mine, mine_only=mine_only, soldout=soldout, own=own, own_only=own_only)
    addresses = list({ex.address for ex_list in population.values() for ex in ex_list})
    try:
        accepting = _get_accepting_tokens(ctx, addresses)
    except Exception:
        accepting = []
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
@common_logging
def ix_search(ctx: typer.Context,
              keyword: str,
              mine: bool = typer.Option(True, help='show tokens published by you'),
              mine_only: bool = typer.Option(False),
              soldout: bool = typer.Option(False, help='show soldout tokens'),
              own: bool = typer.Option(True, help='show tokens you own'),
              own_only: bool = typer.Option(False)):
    if (mine_only and not mine) or (own_only and not own):
        raise Exception('contradictory options')
    _ix_list_tokens(ctx, keyword, mine, mine_only, soldout, own, own_only)


@ix_app.command('buy', help="Buy the CTI Token by index. (Check metemctl ix list)")
@common_logging
def ix_buy(ctx: typer.Context, catalog_and_token: str):
    _ix_buy(ctx, catalog_and_token)


def _ix_buy(ctx, catalog_and_token):
    flx = FlexibleIndexToken(ctx, catalog_and_token)
    if flx.info.price * PTS_RATE > _load_account(ctx).wallet.balance:
        raise Exception(f'Short of ETHER to buy token {flx.catalog.index}-{flx.index}.')
    broker = _load_broker(ctx)
    broker.buy(flx.catalog.address, flx.address, flx.info.price, allow_cheaper=False)
    typer.echo(f'bought token {flx.catalog.index}-{flx.index} for {flx.info.price} pts.')


@ix_app.command('bulk-buy', help='Buy each CTI Token listed on catalog.')
@common_logging
def ix_bulk_buy(ctx: typer.Context, catalog: str,
                duplicated: bool = typer.Option(False, help='buy tokens even if already have')):
    flx = FlexibleIndexCatalog(ctx, catalog)
    tokens = _get_tokens_population(ctx, soldout=True, own=duplicated).get(flx.index)
    if not tokens:
        typer.echo(f'No tokens to buy on catalog {flx.index}: {flx.address}.')
        return
    typer.echo(f'bulk buying tokens in catalog {flx.index}: {flx.address}.')
    for token in tokens:
        if token.amount == 0:
            typer.echo(f'{flx.index}-{token.token_id} is soldout.')
            continue
        _ix_buy(ctx, f'{flx.index}-{token.token_id}')


@contract_broker_app.command('serve', help="Pass your tokens to the broker for disseminate.")
@common_logging
def broker_serve(ctx: typer.Context, catalog_and_token: str, amount: int):
    _broker_serve(ctx, catalog_and_token, amount)


def _broker_serve(ctx, catalog_and_token, amount):
    if amount <= 0:
        raise Exception(f'Invalid amount: {amount}')
    if isinstance(catalog_and_token, list) and len(catalog_and_token) > 2:
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
@common_logging
def broker_takeback(ctx: typer.Context, catalog_and_token: str, amount: int):
    if amount <= 0:
        raise Exception(f'Invalid amount: {amount}')
    if isinstance(catalog_and_token, list) and len(catalog_and_token) > 2:
        raise Exception('Redundant arguments for CATALOG_AND_TOKEN')
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    if not flx_token.catalog:
        raise Exception('Missing catalog information')
    account = _load_account(ctx)
    token = Token(account).get(flx_token.address)
    if token.publisher != account.eoa:
        raise Exception(f'Not a token published by you')
    broker = _load_broker(ctx)
    if not broker.address:
        raise Exception('Missing the broker address')
    balance = token.balance_of(broker.address)
    if balance < amount:
        raise Exception(f'transfer amount({amount}) exceeds balance({balance})')
    broker.takeback(flx_token.catalog.address, flx_token.address, amount)
    typer.echo(f'took back {amount} of token({flx_token.address}) from broker({broker.address}).')


@contract_token_app.command('create')
@common_logging
def token_create(ctx: typer.Context, initial_supply: int,
                 editable: bool = typer.Option(False, help="Anyone can edit vote candidates")):
    _token_create(ctx, initial_supply, editable)


def _token_create(ctx, initial_supply, editable=False) -> ChecksumAddress:
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    if initial_supply <= 0:
        raise Exception(f'Invalid initial-supply: {initial_supply}')
    token = Token(account).new(initial_supply, [], editable)
    typer.echo(f'created a new token. address is {token.address}.')
    return token.address


@contract_token_app.command('set-editable')
@common_logging
def token_set_editable(ctx: typer.Context, catalog_and_token: str, anyone_editable: bool):
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    Token(_load_account(ctx)).get(flx_token.address).set_editable(anyone_editable)


@contract_token_app.command('mint')
@common_logging
def token_mint(ctx: typer.Context, token: str, amount: int,
               dest: Optional[str] = typer.Option(
                   None, help='Account EOA minted tokens are given to, instead of you. '
                   'Do not assign Broker, it does not mean serving.')):
    account = _load_account(ctx)
    dest = dest if dest else account.eoa
    flx = FlexibleIndexToken(ctx, token)
    Token(account).get(flx.address).mint(amount, dest=cast(ChecksumAddress, dest))
    typer.echo(f'minted {amount} of token({flx.address}) for account({dest}).')


@contract_token_app.command('burn')
@common_logging
def token_burn(ctx: typer.Context, token: str, amount: int, data: str = ''):
    if amount <= 0:
        raise Exception(f'Invalid amount: {amount}.')
    account = _load_account(ctx)
    flx = FlexibleIndexToken(ctx, token)
    Token(account).get(flx.address).burn(amount, data)
    typer.echo(f'burned {amount} of token({flx.address}).')


@contract_token_app.command('publish')
@common_logging
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
    _token_publish(
        ctx, catalog, token_address, uuid, title, price, initial_amount, serve_amount)


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


def _authorize_eoaa(ctx, token_address: ChecksumAddress, eoaa: ChecksumAddress):
    account = _load_account(ctx)
    token = Token(account).get(token_address)
    if token.is_operator(eoaa, account.eoa):
        return
    token.authorize_operator(eoaa)
    typer.echo(f'authorized EOA({eoaa}) as a token operator.')


def _revoke_eoaa(ctx, token_address: ChecksumAddress, eoaa: ChecksumAddress):
    account = _load_account(ctx)
    token = Token(account).get(token_address)
    if not token.is_operator(eoaa, account.eoa):
        return
    token.revoke_operator(eoaa)
    typer.echo(f'revoked EOA({eoaa}) from token operator.')


def _authorize_solver(ctx, token_address: ChecksumAddress):
    _authorize_eoaa(ctx, token_address, _load_solver_account(ctx).eoa)


def _revoke_solver(ctx, token_address: ChecksumAddress):
    _revoke_eoaa(ctx, token_address, _load_solver_account(ctx).eoa)


@seeker_app.command('status')
def seeker_status(ctx: typer.Context):
    typer.echo(_seeker_status(ctx)[1])


def _seeker_status(ctx) -> Tuple[bool, str]:
    config = load_config(ctx)
    for key in ['endpoint_url', 'keyfile', 'operator.address']:
        if not OmegaConf.select(config.workspace, key):
            return False, 'not configured'
    seeker = Seeker(config)
    if not seeker.pid:
        return False, 'not running'

    # seeker is running
    msg = (f'running on pid {seeker.pid}, '
           f'listening {seeker.listen_address}:{seeker.listen_port}.')
    ngrok_mgr = NgrokMgr(config)
    if ngrok_mgr.pid > 0:
        msg += ('\n'
                f'and ngrok running on pid {ngrok_mgr.pid}, '
                f'with public url: {ngrok_mgr.public_url}.')
    return True, msg


def _seeker_url(ctx, auto_start: bool = False) -> str:
    config = load_config(ctx)
    seeker = Seeker(config)
    if seeker.pid == 0:
        if auto_start:
            typer.echo('auto starting seeker...')
            _seeker_start(ctx)
            return _seeker_url(ctx, auto_start=False)
        raise Exception('Seeker not running')
    ngrok_mgr = NgrokMgr(config)
    return ngrok_mgr.public_url or f'http://{seeker.listen_address}:{seeker.listen_port}'


@seeker_app.command('start')
@common_logging
def seeker_start(ctx: typer.Context):
    _seeker_start(ctx)


def _seeker_start(ctx):
    config = load_config(ctx)
    seeker = Seeker(config)
    seeker.start()
    typer.echo(f'seeker started on process {seeker.pid}, '
               f'listening {seeker.listen_address}:{seeker.listen_port}.')
    if config.workspace.seeker.use_ngrok:
        ngrok_mgr = NgrokMgr(config, seeker.listen_port)
        if ngrok_mgr.pid == 0:
            ngrok_mgr.start()
        else:
            typer.echo('restarging ngrok...')
            ngrok_mgr.stop()
            ngrok_mgr.start()
        typer.echo(f'ngrok started on process {ngrok_mgr.pid}, '
                   f'with public url: {ngrok_mgr.public_url}.')
    elif seeker.listen_address:
        _display_ngrok_support_message(seeker.listen_address)


@seeker_app.command('stop')
@common_logging
def seeker_stop(ctx: typer.Context):
    config = load_config(ctx)
    seeker = Seeker(config)
    seeker.stop()
    typer.echo('seeker stopped.')
    ngrok_mgr = NgrokMgr(config)
    if ngrok_mgr.pid > 0:
        ngrok_mgr.stop()
        typer.echo('ngrok also stopped.')


def _solver_client(ctx: typer.Context) -> SolverClient:
    if 'solver_client' in ctx.meta.keys():
        try:
            solver = ctx.meta['solver_client']
            solver.ping()
            return solver
        except Exception:
            ctx.meta['solver_client'] = None
            # FALLTHROUGH
    solver = SolverClient(_load_solver_account(ctx), load_config(ctx))
    solver.connect()
    ctx.meta['solver_client'] = solver
    return solver


@solver_app.command('status',
                    help='Show Solver status.')
@common_logging
def solver_status(ctx: typer.Context,
                  nonce: bool = typer.Option(
                      False, help='Generate or get nonce. (only for Shared Solver)')):
    if _shared_solver_enabled(ctx):
        eoaa = _load_account(ctx).eoa if nonce else None
        typer.echo(json.dumps(_shared_solver_getinfo(ctx, address=eoaa), indent=2))
    else:
        typer.echo(_local_solver_status(ctx)[1])


def _solver_is_ready(ctx: typer.Context) -> bool:
    logger = getLogger()
    if _shared_solver_enabled(ctx):
        try:
            return _shared_solver_getinfo(ctx)['solver_status'] == 'running'
        except Exception as err:
            logger.exception(err)
            return False
    return _local_solver_status(ctx)[0]


def _local_solver_status(ctx: typer.Context) -> Tuple[bool, str]:
    config = load_config(ctx)
    for key in ['endpoint_url', 'keyfile', 'operator.address']:
        if not OmegaConf.select(config.workspace, key):
            return False, 'not configured'
    ctrl = SolverController(config)
    if ctrl.pid <= 0:
        return False, 'not running'
    if ctrl.operator_address == _load_operator(ctx).address:
        msg = (f'Solver running on pid {ctrl.pid} with EOA({ctrl.solver_eoaa}) '
               f'with operator({ctrl.operator_address}).')
    else:
        msg = (f'[WARNING] Solver running with EOA({ctrl.solver_eoaa}) '
               f'with ANOTHER operator({ctrl.operator_address}).')
    return True, msg


@solver_app.command('start',
                    help='Start Solver process.')
@common_logging
def solver_start(ctx: typer.Context):
    ctrl = SolverController(load_config(ctx))
    ctrl.start()
    typer.echo(f'Solver started as a subprocess(pid={ctrl.pid}).')


@solver_app.command('stop',
                    help='Kill Solver process, all solver (not only yours) are killed.')
@common_logging
def solver_stop(ctx: typer.Context):
    ctrl = SolverController(load_config(ctx))
    ctrl.stop()
    typer.echo('Solver shutted down.')


@solver_app.command('put')
@common_logging
def solver_put(ctx: typer.Context, token: str, filepath: str):
    if _shared_solver_enabled(ctx):
        _shared_solver_post(ctx, token, filepath)
    else:
        _local_solver_put(ctx, token, filepath)


def _local_solver_put(ctx, token, filepath):
    flx = FlexibleIndexToken(ctx, token)
    asset_filepath = _address_to_solver_assets_path(ctx, flx.address)
    if os.path.exists(asset_filepath):
        os.unlink(asset_filepath)
    shutil.copy(filepath, asset_filepath, follow_symlinks=True)
    typer.echo(f'copied asset file for token: {flx.address}.')


@solver_app.command('link')
@common_logging
def solver_link(ctx: typer.Context, token: str,
                force: bool = typer.Option(False, help='overwrite destination file')):
    if _shared_solver_enabled(ctx):
        raise Exception('Not supported for Shared Solver')
    _local_solver_link(ctx, token, force)


def _local_solver_link(ctx, token, force=False):
    flx = FlexibleIndexToken(ctx, token)
    src_path = _uuid_to_misp_download_path(ctx, flx.info.uuid)
    dst_path = _address_to_solver_assets_path(ctx, flx.address)
    if not os.path.exists(src_path):
        raise Exception(f'Source file does not exist for UUID: {flx.info.uuid}')
    if os.path.exists(dst_path):
        if force:
            os.unlink(dst_path)
        else:
            raise Exception('Destination file exists. Give --force option to overwrite it')
    os.symlink(src_path, dst_path)
    typer.echo(f'created symlink for token: {flx.address}, UUID: {flx.info.uuid}.')


@solver_app.command('remove')
@common_logging
def solver_remove(ctx: typer.Context, token: str):
    if _shared_solver_enabled(ctx):
        _shared_solver_delete(ctx, token)
    else:
        _local_solver_remove(ctx, token)


def _local_solver_remove(ctx, token):
    flx = FlexibleIndexToken(ctx, token)
    asset_filepath = _address_to_solver_assets_path(ctx, flx.address)
    os.unlink(asset_filepath)
    typer.echo(f'removed asset file for token: {flx.address}.')


@solver_app.command('support',
                    help='Register token to accept challenge.')
@common_logging
def solver_support(ctx: typer.Context, token: str):
    if _shared_solver_enabled(ctx):
        _shared_solver_support(ctx, token)
    else:
        _local_solver_support(ctx, token)


def _local_solver_support(ctx, token):
    flx = FlexibleIndexToken(ctx, token)
    solver = _solver_client(ctx)
    _authorize_solver(ctx, flx.address)
    msg = solver.solver('accept_challenges', [flx.address])
    if msg:
        typer.echo(msg)
    typer.echo(f'Token({token}) object was supported by Solver.')
    typer.echo(f'Your MISP object is now available for download.')
    if not load_config(ctx).runtime.solver_keepalive:
        solver.disconnect()


@solver_app.command('obsolete',
                    help='Unregister token not to accept challenge.')
@common_logging
def solver_obsolete(ctx: typer.Context, token: str):
    if _shared_solver_enabled(ctx):
        _shared_solver_obsolete(ctx, token)
    else:
        _local_solver_obsolete(ctx, token)


def _local_solver_obsolete(ctx, token):
    flx = FlexibleIndexToken(ctx, token)
    solver = _solver_client(ctx)
    _revoke_solver(ctx, flx.address)
    solver.solver('refuse_challenges', [flx.address])
    typer.echo(f'obsoleted challenge for token({flx.address}) by solver.')
    if not load_config(ctx).runtime.solver_keepalive:
        solver.disconnect()


@assetmgr_app.command('start',
                      help='Start Asset Manager service.')
@common_logging
def assetmgr_start(ctx: typer.Context):
    ctrl = AssetManagerController(_load_solver_account(ctx), load_config(ctx))
    if ctrl.pid > 0:
        raise Exception('Asset Manager already running.')
    ctrl.start()
    typer.echo(f'Asset Manager started as a subprocess(pid={ctrl.pid}), '
               f'listening {ctrl.listen_address}:{ctrl.listen_port}.')


@assetmgr_app.command('stop',
                      help='Stop Asset Manager service.')
@common_logging
def assetmgr_stop(ctx: typer.Context):
    _assetmgr_stop(ctx)


def _assetmgr_stop(ctx):
    ctrl = AssetManagerController(_load_solver_account(ctx), load_config(ctx))
    if ctrl.pid == 0:
        raise Exception('Asset Manager not running')
    ctrl.stop()
    typer.echo('Asset Manager stopped.')


@assetmgr_app.command('status',
                      help='Show Asset Manager status.')
@common_logging
def assetmgr_status(ctx: typer.Context):
    typer.echo(_assetmgr_status(ctx)[1])


def _assetmgr_status(ctx) -> Tuple[bool, str]:
    config = load_config(ctx)
    for key in ['endpoint_url', 'keyfile', 'operator.address']:
        if not OmegaConf.select(config.workspace, key):
            return False, 'not configured'
    ctrl = AssetManagerController(_load_solver_account(ctx), config)
    if ctrl.pid == 0:
        return False, 'not running.'
    return True, f'running on pid {ctrl.pid}, listening {ctrl.listen_address}:{ctrl.listen_port}.'


def _shared_solver_enabled(ctx) -> bool:
    return bool(load_config(ctx).workspace.solver.shared_solver_url)


def _load_shared_solver(ctx) -> AssetManagerClient:
    url = load_config(ctx).workspace.solver.shared_solver_url
    if 'asset_client' in ctx.meta.keys():
        return ctx.meta['asset_client']
    client = AssetManagerClient(url)
    ctx.meta['asset_client'] = client
    return client


def _shared_solver_getinfo(ctx, address: Optional[ChecksumAddress] = None) -> dict:
    return _load_shared_solver(ctx).get_info(address=address)


def _shared_solver_post(ctx, token, filepath, support=False):
    account = _load_account(ctx)
    info = _shared_solver_getinfo(ctx, address=account.eoa)
    flx = FlexibleIndexToken(ctx, token)
    _authorize_eoaa(ctx, flx.address, info['solver_address'])
    result = _load_shared_solver(ctx).post_asset(account,
                                                 flx.address,
                                                 filepath,
                                                 support,
                                                 nonce=info['nonce'])
    typer.echo(f'uploaded asset file for token: {flx.address} onto shared solver.')
    if result == 'ok':
        if support:
            typer.echo(f'and token is now supported (shared solver is accepting challenges).')
    else:
        typer.echo(f'CAUTION: {result}')


def _shared_solver_delete(ctx, token):
    account = _load_account(ctx)
    info = _shared_solver_getinfo(ctx, address=account.eoa)
    solver_eoaa = info['solver_address']
    flx = FlexibleIndexToken(ctx, token)
    result = _load_shared_solver(ctx).delete_asset(account,
                                                   flx.address,
                                                   nonce=info['nonce'])
    if result == 'ok':
        typer.echo(f'removed asset file for token: {flx.address}.')
    else:
        typer.echo(f'CAUTION: {result}')
    _revoke_eoaa(ctx, flx.address, solver_eoaa)


def _shared_solver_support(ctx, token):
    account = _load_account(ctx)
    info = _shared_solver_getinfo(ctx, address=account.eoa)
    flx = FlexibleIndexToken(ctx, token)
    _authorize_eoaa(ctx, flx.address, info['solver_address'])
    result = _load_shared_solver(ctx).post_accepting(account,
                                                     [flx.address],
                                                     nonce=info['nonce'])
    if result == 'ok':
        typer.echo(f'Now, Token({flx.address}) is supported by Shared Solver.')
    else:
        typer.echo(result)


def _shared_solver_obsolete(ctx, token):
    account = _load_account(ctx)
    info = _shared_solver_getinfo(ctx, address=account.eoa)
    flx = FlexibleIndexToken(ctx, token)
    result = _load_shared_solver(ctx).delete_accepting(account,
                                                       [flx.address],
                                                       nonce=info['nonce'])
    if result == 'ok':
        typer.echo(f'Token({flx.address}) is obsoleted by Shared Solver.')
    else:
        typer.echo(result)
    _revoke_eoaa(ctx, flx.address, info['solver_address'])


def _shared_solver_list_accepting(ctx, addresses: List[ChecksumAddress]) -> List[ChecksumAddress]:
    return _load_shared_solver(ctx).list_accepting(token_addresses=addresses)


@ix_app.command('use', help="Use the token to challenge the task. (Get the MISP object, etc.")
@common_logging
def ix_use(ctx: typer.Context, token: str,
           seeker_url: str = typer.Option(
               '', help='Globally accessible url which seeker is listening. '
                        'Auto generated in default.'),
           monitor: bool = typer.Option(
               True, help='Print messages from Seeker on current terminal.')):
    flx = FlexibleIndexToken(ctx, token)
    account = _load_account(ctx)
    operator = _load_operator(ctx)
    if not seeker_url:
        seeker_url = _seeker_url(ctx, auto_start=True)
    hostname = urlparse(seeker_url).hostname
    if not hostname:
        raise Exception('Missing the hostname')
    _display_ngrok_support_message(hostname)
    Token(account).get(flx.address).send(operator.address, amount=1, data=seeker_url)
    typer.echo(f'Started challenge with token({flx.address}).')
    if monitor:
        _watch_token_sent(ctx, flx.address)
        _monitor_seeker_message()


def _display_ngrok_support_message(address: str):
    try:
        dest_ip = ipaddress.ip_address(address)
        if dest_ip.is_loopback:
            typer.echo(f'[Caution] loopback detected without ngrok: {dest_ip}')
            typer.echo(f'Hint: To use ngrok, set "seeker.use_ngrok: true" by metemctl config edit.')
    except ValueError:
        pass


def _load_eventlistener(ctx) -> BasicEventListener:
    if 'eventlistener' not in ctx.meta.keys():
        listener = BasicEventListener('CommonEventListener')
        listener.start()
        ctx.meta['eventlistener'] = listener
    return ctx.meta['eventlistener']


def _watch_token_sent(ctx, token_address):
    account = _load_account(ctx)
    operator = _load_operator(ctx)
    listener = _load_eventlistener(ctx)
    filter_key = f'Sent:{operator.address}'

    def _callback(event: AttributeDict):
        ext_msg = f' with message: {event["args"]["data"].decode("utf-8")}' \
            if event['args'].get('data') else ''
        typer.echo(f'Challenge token({token_address}) returned{ext_msg}.')
        listener.remove_event_filter_in_callback(filter_key)

    event_filter = Token(account).get(token_address).event_filter(
        'Sent',
        fromBlock='latest',
        argument_filters={
            'from': operator.address,
            'to': account.eoa,
        },
    )
    listener.add_event_filter(filter_key, event_filter, _callback)


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
        tty_linkpath = load_config().runtime.seeker_tty_filepath
        typer.echo('>> Start monitoring seeker message. type CTRL-C to abort.')
        if os.path.exists(tty_linkpath):
            typer.echo('[CAUTION] TTY used by another monitoring process is overwritten.')
            os.unlink(tty_linkpath)  # force overwrite
        os.symlink(tty, tty_linkpath)
        while input():
            pass
    except KeyboardInterrupt:
        pass
    finally:
        os.unlink(tty_linkpath)


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
    external_files: Dict[str, Dict[str, str]] = {}
    for attr in event.attributes:
        if attr.type == "link":
            external_files[attr.comment] = {}
            external_files[attr.comment]['link'] = attr.value
    for attr in event.attributes:
        if attr.type == "sha256":
            if attr.comment in external_files:
                external_files[attr.comment]['sha256'] = attr.value
    if external_files:
        return external_files

    return None


def _find_project_dir(ctx: typer.Context):
    config = load_config(ctx)
    project_dir = Path(os.getcwd()) / config.project
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
@common_logging
def ix_extract(ctx: typer.Context, used_token: str):
    config = load_config(ctx)
    flx = FlexibleIndexToken(ctx, used_token)
    downloaded_misp = Path(f'{config.runtime.seeker_download_filepath}/{flx.address}.json')

    target_dir = _find_project_dir(ctx)
    if not target_dir:
        target_dir = Path(config.runtime.workspace_root)

    external_files = None
    if os.path.isfile(downloaded_misp):
        if _is_misp_object(downloaded_misp):
            external_files = _extract_contents(downloaded_misp)
        else:
            raise Exception(f'Invalid MISP Object: {downloaded_misp}')
    else:
        typer.echo('Try \"metemctl ix use {used_token}}\".')
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
@common_logging
def ix_challenge_show(ctx: typer.Context,
                      done: bool = typer.Option(False, help='show finished and cancelled'),
                      mine_only: bool = typer.Option(True, help='show yours only'),
                      verbose: bool = typer.Option(False, help='show seeker and solver')):
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
@common_logging
def ix_cancel(ctx: typer.Context, challenge_id: int):
    operator = _load_operator(ctx)
    operator.cancel_challenge(challenge_id)
    typer.echo(f'cancelled challenge: {challenge_id}.')


@ix_app.command('vote', help='Vote amount of (solved) token to an issue.')
@common_logging
def ix_vote(ctx: typer.Context, catalog_and_token: str, issue: int,
            amount: int = typer.Option(1, help='amount of token to vote')):
    index = int(issue)
    amount = int(amount)
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    token = Token(_load_account(ctx)).get(flx_token.address)
    token.vote(index, amount)
    typer.echo('voted. try "metemctl ix issue list TOKEN" to see list.')


@ix_issue_app.command('list')
@common_logging
def ix_issue_list(ctx: typer.Context, catalog_and_token: str):
    account = _load_account(ctx)
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    token = Token(account).get(flx_token.address)
    candidates = token.list_candidates()
    if len(candidates) == 0:
        typer.echo('No issue to vote.')
        if token.editable or token.publisher == account.eoa:
            typer.echo('You can add issues by "metemctl ix issue add TOKEN ISSUE".')
        return
    typer.echo(' index: (score) issue')
    for index, score, desc in candidates:
        typer.echo(f' {index}: ({score}) {desc}')


@ix_issue_app.command('add')
@common_logging
def ix_issue_add(ctx: typer.Context, catalog_and_token: str, issue: str):
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    Token(_load_account(ctx)).get(flx_token.address).add_candidates([issue])
    typer.echo('added issue. try "metemctl ix issue list" to list issues.')


@ix_issue_app.command('remove')
@common_logging
def ix_issue_remove(ctx: typer.Context, catalog_and_token: str, index: int):
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    Token(_load_account(ctx)).get(flx_token.address).remove_candidates([int(index)])
    typer.echo('removed indexed issue. try "metemctl ix issue list" to list issues.')


@contract_broker_app.command('show')
@common_logging
def broker_show(ctx: typer.Context):
    broker = _load_broker(ctx)
    typer.echo(f'Broker address is {broker.address}.')


@contract_broker_app.command('create')
@common_logging
def broker_create(ctx: typer.Context,
                  switch: bool = typer.Option(True, help='switch to deployed broker')):
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    broker = Broker(account).new()
    typer.echo(f'deployed a new broker. address is {broker.address}.')
    if switch:
        typer.echo('configuring to use the broker above.')
        ctx.meta['broker'] = broker
        update_config(load_config(ctx), 'workspace.broker.address', broker.address,
                      ctx=ctx, save=True, validate=False)


@contract_operator_app.command('show', help="Show the contract address of the operator.")
@common_logging
def operator_show(ctx: typer.Context):
    operator = _load_operator(ctx)
    typer.echo(f'Operator address is {operator.address}.')


@contract_operator_app.command('create')
@common_logging
def operator_create(ctx: typer.Context,
                    switch: bool = typer.Option(True, help='switch to deployed operator')):
    try:
        old_operator: Optional[Operator] = _load_operator(ctx)
    except Exception:
        old_operator = None
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    operator = Operator(account).new()
    operator.set_recipient()
    typer.echo(f'deployed a new operator. address is {operator.address}.')
    if switch or old_operator is None:
        typer.echo('configuring to use the operator above.')
        ctx.meta['operator'] = operator
        update_config(load_config(ctx), 'workspace.operator.address', operator.address,
                      ctx=ctx, save=True, validate=False)
        if old_operator:
            typer.echo('you should restart seeker and solver, if launched.')


@ix_catalog_app.command('show', help="Show the list of CTI catalogs")
@contract_catalog_app.command('show', help="Show the list of CTI catalogs")
@common_logging
def catalog_show(ctx: typer.Context):
    catalog_mgr = _load_catalog_manager(ctx)
    typer.echo('Catalogs *:active')
    for caddr, cid in sorted(
            catalog_mgr.all_catalogs.items(), key=lambda x: x[1]):
        typer.echo(
            f'  {"*" if caddr in catalog_mgr.actives else " "}{cid} {caddr}')


# @contract_catalog_app.command('add', help="Add the CTI catalog to the list.")
@common_logging
def catalog_add(ctx: typer.Context, catalog_address: str,
                activate: bool = typer.Option(True, help='activate added catalog')):
    catalog_mgr = _load_catalog_manager(ctx)
    catalog_mgr.add([cast(ChecksumAddress, catalog_address)], activate=activate)
    config_update_catalog(ctx)
    catalog_show(ctx)


@contract_catalog_app.command('create', help="Create a new CTI catalog.")
@common_logging
def catalog_create(ctx: typer.Context,
                   group: Optional[str] = typer.Option(None, help='permitted user group'),
                   activate: bool = typer.Option(False, help='activate created catalog')):
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    group = group if group else ADDRESS0
    if Web3.isChecksumAddress(group):
        group = cast(ChecksumAddress, group)
    else:
        raise Exception('group is not ChecksumAddress')
    catalog: Catalog = Catalog(account).new(group)
    typer.echo('deployed a new '
               f'{"private" if group == ADDRESS0 else "public"} catalog. '
               f'address is {catalog.address}.')
    catalog_add(ctx, str(catalog.address), activate)


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
@common_logging
def misp_open(ctx: typer.Context):
    logger = getLogger()
    misp_url = load_config(ctx).misp.url
    logger.info(f"Open MISP: {misp_url}")
    typer.echo(misp_url)
    typer.launch(misp_url)


class IAPAuth(requests.auth.AuthBase):

    def __init__(self, ctx):
        config = load_config(ctx)
        self.client_id = config.misp.gcp_client_id
        credential_path = config.misp.gcp_cloud_iap_cred
        if credential_path:
            # Set the GOOGLE_APPLICATION_CREDENTIALS to use service account
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = str(credential_path)

    def __call__(self, r):
        open_id_connect_token = id_token.fetch_id_token(Request(), self.client_id)
        r.headers['Proxy-Authorization'] = f'Bearer {open_id_connect_token}'
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
    with open(fpath, 'w', encoding='utf-8') as fout:
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


def _ssl_settings(ssl_cert: SSLCertVerify) -> bool:
    if ssl_cert == SSLCertVerify.DISABLE:
        urllib3.disable_warnings()
        return False
    if ssl_cert == SSLCertVerify.DISABLE_WITH_WARNING:
        return False
    return True


def _pymisp_client(ctx: typer.Context):
    logger = getLogger()

    config = load_config(ctx)
    url = config.misp.url
    api_key = config.misp.api_key
    ssl_cert = config.misp.ssl_cert_verify

    logger.info(f"Fetch MISP: {url}")

    client_id = config.misp.gcp_client_id

    if client_id:
        return pymisp.PyMISP(url, api_key, _ssl_settings(ssl_cert), auth=IAPAuth(ctx))

    return pymisp.PyMISP(url, api_key, _ssl_settings(ssl_cert))


@misp_app.command("pull", help="Export events from your MISP instance.")
def misp_pull(
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
        ['tlp:white', 'tlp:green'],
        help='Tags to search or to exclude. You can pass a list.'),
    threatlevel: Optional[List[str]] = typer.Option(
        None,
        help='Threat level(s) (1,2,3,4).'),
    distribution: Optional[List[str]] = typer.Option(
        None,
        help='Distribution level(s) (0,1,2,3).'),
    org: Optional[List[Union[str]]] = typer.Option(
        None,
        help='Search by the creator organization by supplying the organization identifier.')
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

    json_dumpdir = Path(load_config(ctx).misp.download_filepath)
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
    json_dumpdir = Path(load_config(ctx).misp.download_filepath)
    # load metadata pickle for efficiency
    if not os.path.isdir(json_dumpdir):
        raise FileNotFoundError(f'The directory of MISP download does not exist. ({json_dumpdir})')
    metadata_cache_path = Path(json_dumpdir, '_download_metadata_cache.pkl')
    if os.path.isfile(metadata_cache_path):
        with open(metadata_cache_path, 'rb') as fp:
            try:
                metadata_cache = pickle.load(fp)
            except pickle.UnpicklingError as err:
                typer.echo(err)
                os.remove(metadata_cache_path)
    else:
        metadata_cache = {}

    files = json_dumpdir.glob('*.json')
    # found misp hash for this time
    found = set()
    for file in files:
        with open(file, 'rb') as fp:
            misp_hash = hashlib.sha256(fp.read()).hexdigest()
            found.add(misp_hash)
        if misp_hash not in metadata_cache:
            event = _load_misp_event(file)
            metadata_cache[misp_hash] = (event.date, event.uuid, event.info)
    # delete metadata of not-found misp hash
    for deleted in set(metadata_cache.keys()) - found:
        metadata_cache.pop(deleted)
    with open(metadata_cache_path, 'wb') as fp:
        pickle.dump(metadata_cache, fp)

    output_line = []
    for metadata in sorted(metadata_cache.values(), reverse=True):
        output_line.append(f'{metadata[0]} - {metadata[1]}: {metadata[2]}')

    typer.echo_via_pager('\n'.join(output_line))


@misp_app.command("push", help="Upload events to your MISP instance.")
def misp_push(ctx: typer.Context):
    json_dumpdir = Path(load_config(ctx).misp.upload_filepath)
    files = json_dumpdir.glob('*.json')
    for file in files:
        event = _load_misp_event(file)
        result = _pymisp_client(ctx).add_event(event, pythonify=True)
        typer.echo(f'uploaded: {result.uuid} - {result.info}')


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
        cwd = load_config(ctx).project
        if setup:
            setup_kedro(cwd)
        subprocess.run(['kedro', 'run'], check=True, cwd=cwd)
    except CalledProcessError as err:
        logger.exception(err)
        typer.echo(f'An error occurred while running the workflow. {err}')


@app.command(help="Validate the current intelligence cycle")
def check(
    ctx: typer.Context,
    setup: bool = typer.Option(
        False,
        help='kedro build-reqs && kedro install'),
        viz: bool = typer.Option(
            False,
        help='Show the visualized current workflow')):
    # TODO: check the available intelligence workflow
    # TODO: check available intelligence contents
    logger = getLogger()
    logger.info(f"Run command: kedro test")
    try:
        # TODO: check the existence of a CWD path
        cwd = load_config(ctx).project
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
@common_logging
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
    if not misp_object:
        misp_object = _find_project_report(ctx)
        if not misp_object:
            raise Exception(
                'MISP object not found in the current project. '
                'Try \"metemctl publish --misp_object MISP_OBJECT_PATH\".')

    if price < 0:
        raise Exception(f'Invalid price: {price}')

    uuid, title, fixed_filepath = _store_misp_object(ctx, misp_object)
    token_address = _token_publish(
        ctx,
        catalog,
        token_address,
        uuid,
        title,
        price,
        initial_amount,
        serve_amount)

    if _solver_is_ready(ctx):
        try:
            if _shared_solver_enabled(ctx):
                _shared_solver_post(ctx, token_address, fixed_filepath, support=True)
            else:
                _local_solver_link(ctx, f'{catalog}-{token_address}')
                _local_solver_support(ctx, token_address)
        except Exception as err:
            typer.echo(f'failed solver support: {err}')
    else:
        typer.echo(f'Run \"metemctl solver support {token_address}\" after enabling Solver')


def _uuid_to_misp_download_path(ctx, uuid) -> Path:
    return Path(f'{load_config(ctx).misp.download_filepath}/{UUID(str(uuid))}.json')


def _address_to_solver_assets_path(ctx, address) -> Path:
    return Path(f'{load_config(ctx).runtime.asset_filepath}/{address}')


def _is_misp_object(load_filepath):
    with open(load_filepath, encoding='utf-8') as fin:
        dict_object = json.load(fin)
        if 'Event' in dict_object.keys():
            return True
    return False


def _store_misp_object(ctx, load_filepath) -> Tuple[str, str, Path]:
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
            return event.uuid, event.info, download_filepath

    # save the loadable MISP objects
    misp_object = pymisp.AbstractMISP()
    misp_object.Event = event
    with open(download_filepath, 'w', encoding='utf-8') as fout:
        # dump json correctly with ensure_ascii=False
        # cannot set ensure_ascii=False in fout.write(misp_object.to_json())
        json.dump(json.loads(misp_object.to_json()), fout, ensure_ascii=False, indent=2)
        typer.echo(f'saved MISP object as {download_filepath}')

    return event.uuid, event.info, download_filepath


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
    config = load_config(ctx)
    project_dir = Path(os.getcwd()) / config.project
    if os.path.isdir(project_dir):
        report_dir = project_dir / 'data' / '08_reporting'
        json_files = Path(report_dir).glob('*.json')
        for json_file in json_files:
            if _is_misp_object(json_file):
                return json_file
    return None


@app.command(help="Unregister disseminated CTI token from catalog.")
@common_logging
def discontinue(
        ctx: typer.Context,
        catalog_and_token: str):
    account = _load_account(ctx)
    flx_token = FlexibleIndexToken(ctx, catalog_and_token)
    assert flx_token.catalog
    catalog = Catalog(account).get(flx_token.catalog.address)
    broker = _load_broker(ctx)
    assert catalog.address
    broker.uncache(catalog=catalog.address, token=flx_token.address)
    amount = broker.get_amounts(catalog.address, [flx_token.address])[0]
    if amount > 0:
        broker.takeback(catalog.address, flx_token.address, amount)
        typer.echo(f'took back all({amount}) of token({flx_token.address}) from broker.')
    catalog.unregister_cti(flx_token.address)
    typer.echo(f'unregistered token({flx_token.address}) from catalog({catalog.address}).')
    if _solver_is_ready(ctx):
        solver_obsolete(ctx, flx_token.address)
        # TODO shoud call solver_remove?


@account_app.command("show", help="Show the current account information.")
@common_logging
def account_show(ctx: typer.Context):
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
@common_logging
def account_create(ctx: typer.Context):
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
    with open(keyfile_path, mode='w', encoding='utf-8') as fout:
        json.dump(encrypted, fout)

    typer.echo(f'- Public address of the key:\t{acct.address}')
    typer.echo(f'- Path of the secret key file:\t{keyfile_path}')

    typer.echo('* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *')
    typer.echo('* You must BACKUP your key file & REMEMBER your password! *')
    typer.echo('* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *')

    config = load_config(ctx)
    if not config.workspace.keyfile:
        fix = True
    else:
        typer.echo(f'Metemctl is configured to use keyfile: {config.workspace.keyfile}')
        fix = typer.confirm('Modify config to use the created keyfile?')
    if fix:
        update_config(config, 'workspace.keyfile', str(keyfile_path), save=True, validate=False)
        typer.echo('You should edit config to set workspace.keyfile_password.')


@account_app.command("airdrop", help="Get some ETH from Promote Code. (for devnet)")
@common_logging
def account_airdrop(ctx: typer.Context, promote_code: str):
    if len(promote_code) != 64:
        raise typer.Abort('Invalid promote code.')

    config = load_config(ctx)
    url = config.workspace.airdrop_url
    if not url:
        raise Exception('Missing configuration: workspace.airdrop_url')
    if 'http' not in url:
        raise Exception(f'Invalid airdrop_url: {url}')

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
            key = 'workspace.solver.gcs_solver.functions_token'
            if not OmegaConf.select(config, key):
                update_config(config, key, promote_code, save=True, validate=False)
            typer.echo('Let me check: metemctl account show')
        else:
            typer.echo('Airdrop failed.')
    else:
        typer.echo(f'A network error has occurred. {content}')


@config_app.command('show', help="Show your config file of metemctl")
@common_logging
def config_show(ctx: typer.Context,
                runtime: bool = typer.Option(False, help='show runtime config.'),
                resolve: bool = typer.Option(False, help='resolve all interpolations.'),
                force: bool = typer.Option(False, help='force show broken config.'),
                ):
    print_config(load_config(ctx, ignore_schema=force),
                 runtime=runtime, resolve=resolve)


@config_app.command('edit', help="Edit your config file of metemctl")
@common_logging
def config_edit(ctx: typer.Context,
                validate: bool = typer.Option(True, help='vaildate before saving files.'),
                verbose: bool = typer.Option(True, help='print validation details.'),
                force: bool = typer.Option(False, help='force edit broken config.'),
                ):
    conf = load_config(ctx, ignore_schema=force)
    if verbose:
        conf = update_config(conf, 'runtime.print_config_validation', True,
                             save=False, validate=False)
    edit_config(conf, ctx=ctx, validate=validate)


@workspace_app.command('list')
@common_logging
def print_workspace_list(ctx: typer.Context):
    config = load_config(ctx)
    for space in ws_list():
        typer.echo(f'{" *" if space == config.workspace_name else "  "}{space}')


@workspace_app.command('switch')
@common_logging
def workspace_switch(ctx: typer.Context, name: str,
                     force: bool = typer.Option(False, help='leave running daemons.')):
    if not force:
        if _seeker_status(ctx)[0]:
            raise Exception('Seeker is running on current workspace')
        if _local_solver_status(ctx)[0]:
            raise Exception('Local Solver is running on current workspace')
        if _assetmgr_status(ctx)[0]:
            raise Exception('Asset Manager is running on current workspace')
    ws_switch(load_config(ctx), name)
    typer.echo(f'switched workspace: {name}')


@workspace_app.command('create')
@common_logging
def workspace_create(ctx: typer.Context, name: str):
    ws_create(load_config(ctx), name)
    typer.echo(f'created a new workspace: {name}')
    typer.echo(f'switch to {name} workspace and fix your configuration.')


@workspace_app.command('destroy')
@common_logging
def workspace_destroy(_ctx: typer.Context, name: str,
                      force: bool = typer.Option(False, help='Force remove workspace directory.')):
    msg = ws_destroy(name, force=force)
    typer.echo(msg or f'removed workspace: {name}')


@workspace_app.command('copy')
@common_logging
def workspace_copy(ctx: typer.Context, src: str, dst: str):
    ws_copy(load_config(ctx), src, dst)
    typer.echo(f'copied config from {src} to {dst} workspace.')
    typer.echo(f'switch to {dst} workspace and fix your configuration.')


@app.command(help="Start an interactive intelligence cycle.")
def console():
    typer.echo(f"console")


@app.command(help="Show practical security services.")
def external_link():
    json_path = Path(APP_DIR) / 'external-links.json'
    with open(json_path, encoding='utf-8') as fin:
        services = json.load(fin)
        for service in services:
            # https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
            hyperlink = f'\x1b]8;;{service["url"]}\x1b\\{service["name"]}\x1b]8;;\x1b\\'
            typer.echo(f"- {hyperlink}: {service['description']}")


@app.command('issue', help="Check Metemcyber issues")
def issue_():
    typer.launch('https://github.com/nttcom/metemcyber/issues')


@app.command(help="Access the application directory of Metemcyber")
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
