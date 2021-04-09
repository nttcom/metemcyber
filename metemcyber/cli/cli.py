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

import json
import os
import subprocess
from configparser import ConfigParser
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from shutil import copyfile
from subprocess import CalledProcessError
from typing import Callable, Dict, List, Optional, Tuple, Union, cast
from uuid import UUID, uuid4

import eth_account
import typer
import yaml
from eth_typing import ChecksumAddress
from web3 import Web3

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
from metemcyber.core.seeker import Seeker
from metemcyber.core.util import config2str, merge_config
from metemcyber.plugins.gcs_solver import DEFAULT_CONFIGS as DC_SOLV_GCS
from metemcyber.plugins.standalone_solver import DEFAULT_CONFIGS as DC_SOLV_ALN

APP_NAME = "metemcyber"
APP_DIR = typer.get_app_dir(APP_NAME)
CONFIG_FILE_NAME = "metemctl.ini"
CONFIG_FILE_PATH = Path(APP_DIR) / CONFIG_FILE_NAME
WORKFLOW_FILE_NAME = "workflow.yml"
DATA_FILE_NAME = "source_of_truth.yml"

DEFAULT_CONFIGS = {
    'general': {
        'project': '00000000-0000-0000-0000-000000000000',
        'misp_url': 'http://your.misp.url',
        'misp_auth_key': 'YOUR_MISP_AUTH_KEY',
        'misp_ssl_cert': '0',
        'misp_json_dumpdir': 'fetched_misp_events',
        'slack_webhook_url': 'SLACK_WEBHOOK_URL',
        'endpoint_url': 'https://rpc.metemcyber.ntt.com',
        'keyfile': '/PATH/TO/YOUR/KEYFILE',
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


def _load_config(ctx: typer.Context, reload: bool = False) -> ConfigParser:
    if 'config' in ctx.meta.keys():
        if not reload:
            return ctx.meta['config']
        del ctx.meta['config']
    if os.path.exists(CONFIG_FILE_PATH):
        logger = getLogger()
        logger.info(f"Load config file from {CONFIG_FILE_PATH}")
        config = merge_config(CONFIG_FILE_PATH, DEFAULT_CONFIGS)
    else:
        config = merge_config(None, DEFAULT_CONFIGS)
    ctx.meta['config'] = config
    return config


def _save_config(config: ConfigParser) -> None:
    logger = getLogger()
    for sect in config.sections():
        for opt in config.options(sect):
            val = config[sect][opt]
            if val.startswith('~'):
                config[sect][opt] = str(Path(val).expanduser())
    try:
        with open(CONFIG_FILE_PATH, 'wt') as fout:
            config.write(fout)
    except Exception as err:
        logger.exception(f'Cannot save configuration: {err}')
        raise
    logger.debug('updated config file')


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
        _save_config(config)


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
            func(*args, **kwargs)
        except Exception as err:
            logger.exception(err)
            typer.echo(f'failed operation: {err}')
    return wrapper


@app.callback()
def app_callback(_ctx: typer.Context):
    pass


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


def create_workflow(event_id, category, contents):
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
            subprocess.run(['kedro', 'new', '--config', dist_yml_filepath], check=True)
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
        help='Pick up all workflow products (Indicator of Compomise, etc.)',)
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

    typer.echo(f'{"":=<32}')
    typer.echo(f'Event ID: {event_id}')
    typer.echo(f'Category: {formal_category[category]}')
    typer.echo(f'Contents: {display_contents}')
    typer.echo(f'{"":=<32}')

    answer = typer.confirm('Are you sure you want to create it?', abort=True)
    # run "kedro new --config workflow.yml"
    if answer:
        create_workflow(event_id, formal_category[category], display_contents)
        # TODO: manage the project id on workspace directory
        config = _load_config(ctx)
        config.set('general', 'project', event_id)
        _save_config(config)


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
    _save_config(config)
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
    _save_config(config)


def config_update_operator(ctx: typer.Context):
    config = _load_config(ctx)
    try:
        operator = _load_operator(ctx)
        if not config.has_section('operator'):
            config.add_section('operator')
        config.set('operator', 'address', operator.address)
    except Exception:
        config.remove_section('operator')
    _save_config(config)


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


def _ix_list_tokens(ctx: typer.Context, mine, mine_only, soldout, own, own_only):
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
              mine: bool = typer.Option(True, help='show tokens published by you'),
              mine_only: bool = typer.Option(False),
              soldout: bool = typer.Option(False, help='show soldout tokens'),
              own: bool = typer.Option(True, help='show tokens you own'),
              own_only: bool = typer.Option(False)):
    _ix_search(ctx, mine, mine_only, soldout, own, own_only)


@common_logging
def _ix_search(ctx, mine, mine_only, soldout, own, own_only):
    if (mine_only and not mine) or (own_only and not own):
        typer.echo('contradictory options')
        return
    _ix_list_tokens(ctx, mine, mine_only, soldout, own, own_only)


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


@contract_token_app.command('create')
def token_create(ctx: typer.Context, initial_supply: int):
    _token_create(ctx, initial_supply)


@common_logging
def _token_create(ctx, initial_supply):
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    if initial_supply <= 0:
        raise Exception(f'Invalid initial-supply: {initial_supply}')
    token = Token(account).new(initial_supply, [])
    typer.echo(f'created a new token. address is {token.address}.')


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
def seeker_start(ctx: typer.Context,
                 ngrok: Optional[bool] = typer.Option(
                     None,
                     help='Launch ngrok with seeker. the default depends on your configuration '
                          'of ngrok in seeker section.'),
                 config: Optional[str] = typer.Option(
                     CONFIG_FILE_PATH, help='seeker config filepath')):
    _seeker_start(ctx, ngrok, config)


@common_logging
def _seeker_start(ctx, ngrok, config):
    if ngrok is None:
        ngrok = int(_load_config(ctx)['seeker']['ngrok']) > 0
    endpoint_url = _load_config(ctx)['general']['endpoint_url']
    if not endpoint_url:
        raise Exception('Missing configuration: endpoint_url')
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
    logger = getLogger()
    try:
        solver = _solver_client(ctx)
        solver.get_solver()
        try:
            operator = _load_operator(ctx)
        except Exception:
            typer.echo('Solver running, but you have not yet configured operator.')
            return
        if solver.operator_address == operator.address:
            typer.echo(f'Solver running with operator you configured({operator.address}).')
        else:
            typer.echo('[WARNING] '
                       f'Solver running with another operator({solver.operator_address}).')
    except MCSError as err:
        if err.code == MCSErrno.ENOENT:
            typer.echo('Solver running without your operator.')
        else:
            typer.echo(f'failed operation: {err}')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@solver_app.command('start',
                    help='Start Solver process.')
def solver_start(ctx: typer.Context):
    _solver_start(ctx)


@common_logging
def _solver_start(ctx):
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
def solver_enable(ctx: typer.Context,
                  plugin: Optional[str] = typer.Option(
                      None,
                      help='solver plugin filename. the default depends on your configuration of '
                           'plugin in solver section. please note that another configuration '
                           'may be required by plugin.'),
                  config: Optional[str] = typer.Option(
                      CONFIG_FILE_PATH, help='solver config filepath')):
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
    _solver_support(ctx, token)


@common_logging
def _solver_support(ctx, token):
    flx = FlexibleIndexToken(ctx, token)
    solver = _solver_client(ctx)
    solver.get_solver()
    msg = solver.solver('accept_challenges', [flx.address])
    if msg:
        typer.echo(msg)


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


@ix_app.command('use', help="Use the token to challenge the task. (Get the MISP object, etc.")
def ix_use(ctx: typer.Context, token: str,
           seeker: str = typer.Option(
               '', help='Globally accessible url which seeker is listening. '
                        'This option overwrites --ngrok.'),
           ngrok: bool = typer.Option(
               True, help='Use ngrok public url bound up with seeker if launched.')):
    _ix_use(ctx, token, seeker, ngrok)


@common_logging
def _ix_use(ctx, token, seeker, ngrok):
    flx = FlexibleIndexToken(ctx, token)
    account = _load_account(ctx)
    operator = _load_operator(ctx)
    assert operator.address
    data = seeker if seeker else (NgrokMgr(APP_DIR).public_url or '') if ngrok else ''
    if not data:
        raise Exception('Seeker url is not specified')
    Token(account).get(flx.address).send(operator.address, amount=1, data=data)
    typer.echo(f'Started challenge with token({flx.address}).')


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
    account = _load_account(ctx)
    operator = _load_operator(ctx)
    raw_tasks = []
    limit_atonce = 16
    offset = 0
    while True:
        tmp = operator.history(ADDRESS0, account.eoa, limit_atonce, offset)
        raw_tasks.extend(tmp)
        if len(tmp) < limit_atonce:
            break
        offset += limit_atonce
    return raw_tasks


@ix_app.command('show', help="Show CTI tokens available.")
def ix_challenge_show(ctx: typer.Context,
                      done: bool = typer.Option(False, help='show finished and cancelled'),
                      mine_only: bool = typer.Option(True, help='show yours only')):
    _ix_challenge_show(ctx, done, mine_only)


@common_logging
def _ix_challenge_show(ctx, done, mine_only):
    account = _load_account(ctx)
    raw_tasks = _get_challenges(ctx)
    for (task_id, token, _, seeker, state) in reversed(raw_tasks):
        if mine_only and seeker != account.eoa:
            continue
        if not done and state in (2, 3):  # ('Finished', 'Cancelled')
            continue
        try:
            title = _find_token_info(ctx, token).title
        except Exception:
            title = '(no information found on current catalogs)'
        typer.echo(
            f'  {task_id}: {title}' + '\n'
            f'    ├ Token: {token}' + '\n'
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
                   private: bool = typer.Option(False, help='create a private catalog'),
                   activate: bool = typer.Option(False, help='activate created catalog')):
    _catalog_create(ctx, private, activate)


@common_logging
def _catalog_create(ctx, private, activate):
    _load_contract_libs(ctx)
    account = _load_account(ctx)
    catalog: Catalog = Catalog(account).new(private)
    typer.echo('deployed a new '
               f'{"private" if private else "public"} catalog. '
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


@misp_app.command("open")
def misp_open(ctx: typer.Context):
    logger = getLogger()
    try:
        misp_url = _load_config(ctx)['general']['misp_url']
        logger.info(f"Open MISP: {misp_url}")
        typer.echo(misp_url)
        typer.launch(misp_url)
    except KeyError as err:
        typer.echo(err, err=True)
        logger.error(err)


@app.command(help="Run the current intelligence workflow.")
def run(ctx: typer.Context):
    logger = getLogger()
    logger.info(f"Run command: kedro run")
    try:
        # TODO: check the existence of a CWD path
        cwd = _load_config(ctx)['general']['project']
        subprocess.run(['kedro', 'run'], check=True, cwd=cwd)
    except CalledProcessError as err:
        logger.exception(err)
        typer.echo(f'An error occurred while running the workflow. {err}')


@app.command(help="Validate the current intelligence cylcle")
def check(ctx: typer.Context, viz: bool = typer.Option(
        False, help='Show the visualized current workflow')):
    # TODO: check the available intelligece workflow
    # TODO: check available intelligece contents
    logger = getLogger()
    logger.info(f"Run command: kedro test")
    try:
        # TODO: check the existence of a CWD path
        cwd = _load_config(ctx)['general']['project']
        subprocess.run(['kedro', 'test'], check=True, cwd=cwd)
        if viz:
            logger.info(f"Run command: kedro viz")
            subprocess.run(['kedro', 'viz'], check=True, cwd=cwd)
    except CalledProcessError as err:
        logger.exception(err)
        typer.echo(f'An error occurred while testing the workflow. {err}')


@app.command(help="Deploy the CTI token to disseminate CTI.")
def publish(ctx: typer.Context, catalog: str,
            token_address: str, uuid: UUID, title: str, price: int):
    _publish(ctx, catalog, token_address, uuid, title, price)


@common_logging
def _publish(ctx, catalog, token_address, uuid, title, price):
    if len(title) == 0:
        raise Exception(f'Invalid(empty) title')
    if price < 0:
        raise Exception(f'Invalid price: {price}')
    account = _load_account(ctx)
    catalog = Catalog(account).get(FlexibleIndexCatalog(ctx, catalog).address)
    catalog.register_cti(cast(ChecksumAddress, token_address), uuid, title, price)
    typer.echo(f'registered token({token_address}) onto catalog({catalog.address}).')
    catalog.publish_cti(account.eoa, cast(ChecksumAddress, token_address))
    typer.echo(f'Token({token_address}) was published on catalog({catalog.address}).')


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
    print('Your new account is locked with a password. Please give a password.')
    acct = eth_account.Account.create('')

    # https://pages.nist.gov/800-63-3/sp800-63b.html
    # 5.1.1.1 Memorized Secret Authenticators
    # Memorized secrets SHALL be at least 8 characters in length if chosen by the subscriber.
    password = ''
    while len(password) < 8:
        print('Do not forget this password. The password must contain at least 8 characters.')
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
        _save_config(config)
        typer.echo('Update your config file.')


@config_app.command('show', help="Show your config file of metemctl")
def config_show(ctx: typer.Context,
                raw: bool = typer.Option(False, help='omit complementing system defaults.')):
    _config_show(ctx, raw)


@common_logging
def _config_show(ctx, raw):
    if raw:
        with open(CONFIG_FILE_PATH) as fin:
            typer.echo(fin.read())
    else:
        typer.echo(config2str(_load_config(ctx)))


@config_app.command('edit', help="Edit your config file of metemctl")
def config_edit(ctx: typer.Context,
                raw: bool = typer.Option(False, help='omit complementing system defaults.')):
    _config_edit(ctx, raw)


@common_logging
def _config_edit(ctx, raw):
    if raw:
        typer.edit(filename=CONFIG_FILE_PATH)
    else:
        contents = typer.edit(config2str(_load_config(ctx)))
        if contents:
            with open(CONFIG_FILE_PATH, 'w') as fout:
                fout.write(contents)
            if '~' in contents:
                config = _load_config(ctx)
                _save_config(config)  # expanduser


@app.command(help="Start an interactive intelligence cycle.")
def console():
    typer.echo(f"console")


@app.command(help="Show practical security services.")
def external_link():
    json_path = Path(__file__).with_name('external-links.json')
    with open(json_path) as fin:
        services = json.load(fin)
        for service in services:
            # https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
            hyperlink = f'\x1b]8;;{service["url"]}\x1b\\{service["name"]}\x1b]8;;\x1b\\'
            typer.echo(f"- {hyperlink}: {service['description']}")


def issues():
    typer.launch('https://github.com/nttcom/metemcyber/issues')


if __name__ == "__main__":
    app()
