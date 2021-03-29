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

import configparser
import json
import os
import subprocess
import uuid
from enum import Enum
from pathlib import Path
from shutil import copyfile
from subprocess import CalledProcessError
from typing import Callable, Dict, List, Optional, Tuple, Union, cast

import typer
import yaml
from eth_typing import ChecksumAddress

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.broker import Broker
from metemcyber.core.bc.catalog import Catalog, TokenInfo
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
from metemcyber.core.bc.operator import TASK_STATES, Operator
from metemcyber.core.bc.token import Token
from metemcyber.core.bc.util import ADDRESS0, decode_keyfile
from metemcyber.core.logger import get_logger
from metemcyber.core.multi_solver import MCSClient, MCSErrno, MCSError
from metemcyber.core.seeker import Seeker

APP_NAME = "metemcyber"
APP_DIR = typer.get_app_dir(APP_NAME)
CONFIG_FILE_NAME = "metemctl.ini"
CONFIG_FILE_PATH = Path(APP_DIR) / CONFIG_FILE_NAME
WORKFLOW_FILE_NAME = "workflow.yml"
DATA_FILE_NAME = "source_of_truth.yml"

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


def create_config(filepath: Path):
    logger = getLogger()
    logger.info(f"Create new config to {filepath}")

    typer.echo('You need the keyfile to connect the ethereum network.')
    path_text = typer.prompt('Input the path of your keyfile')

    # Allow the path that contain '~'
    keyfile_path = str(Path(path_text).expanduser())

    template = Path(__file__).with_name(f'{CONFIG_FILE_NAME}')
    config = read_config(template)
    if config.has_option('general', 'keyfile'):
        config.set('general', 'keyfile', keyfile_path)

    write_config(config, filepath)


def read_config(filepath: Path):
    logger = getLogger()
    logger.info(f"Load config file from {filepath}")
    config = configparser.ConfigParser()
    config.read(filepath)
    return config


def write_config(config: configparser.ConfigParser, filepath: Path):
    logger = getLogger()
    with open(filepath, 'w') as fout:
        try:
            config.write(fout)
        except OSError as err:
            logger.exception('Cannot write to file: %s', err)
    logger.debug(f'update config file: {filepath}')


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
    config = ctx.meta['config']
    ether = Ether(config['general']['endpoint_url'])
    eoa, pkey = decode_keyfile(config['general']['keyfile'], _get_keyfile_password)
    account = Account(ether, eoa, pkey)
    ctx.meta['account'] = account

    ctx.meta['xxx_pkey'] = pkey  # FIXME: TODO: XXX

    return account


def _load_metemcyber_util(ctx: typer.Context):
    account = _load_account(ctx)
    config = ctx.meta['config']
    if config.has_section('metemcyber_util'):
        util_addr = config['metemcyber_util'].get('address')
        util_ph = config['metemcyber_util'].get('placeholder')
    else:
        util_addr = util_ph = None
        config.add_section('metemcyber_util')
    if util_addr and util_ph:
        _ph = MetemcyberUtil.register_library(util_addr)
        assert _ph == util_ph
    else:
        util = MetemcyberUtil(account).new()
        util_ph = util.register_library(util.address)
        config.set('metemcyber_util', 'address', util.address)
        config.set('metemcyber_util', 'placeholder', util_ph)
        write_config(config, CONFIG_FILE_PATH)


def _load_catalog_manager(ctx: typer.Context) -> CatalogManager:
    if 'catalog_manager' in ctx.meta.keys():
        return ctx.meta['catalog_manager']
    account = _load_account(ctx)
    catalog_mgr = CatalogManager(account)
    config = ctx.meta['config']
    if config.has_section('catalog'):
        actives = config['catalog'].get('actives')
        if actives:
            catalog_mgr.add(actives.strip().split(','), activate=True)
        reserves = config['catalog'].get('reserves')
        if reserves:
            catalog_mgr.add(reserves.strip().split(','), activate=False)
    ctx.meta['catalog_manager'] = catalog_mgr
    return catalog_mgr


def _load_broker(ctx: typer.Context) -> Broker:
    if 'broker' in ctx.meta.keys():
        return ctx.meta['broker']
    account = _load_account(ctx)
    config = ctx.meta['config']
    try:
        broker_address = cast(ChecksumAddress, config['broker']['address'])
        assert(broker_address)
    except Exception as err:
        raise Exception('Broker is not yet configured') from err
    broker = Broker(account).get(broker_address)
    ctx.meta['broker'] = broker
    return broker


def _load_operator(ctx: typer.Context) -> Operator:
    if 'operator' in ctx.meta.keys():
        return ctx.meta['operator']
    account = _load_account(ctx)
    config = ctx.meta['config']
    try:
        operator_address = cast(ChecksumAddress, config['operator']['address'])
        assert operator_address
    except Exception as err:
        raise Exception('Operator is not yet configured') from err
    operator = Operator(account).get(operator_address)
    ctx.meta['operator'] = operator
    return operator


@app.callback()
def app_callback(ctx: typer.Context):
    if not os.path.exists(CONFIG_FILE_PATH):
        typer.echo(
            f'The {CONFIG_FILE_NAME} is missing. Try to create a new config file...')
        create_config(CONFIG_FILE_PATH)
    config = read_config(CONFIG_FILE_PATH)
    ctx.meta['config'] = config


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


@app.command(help="Create a new intelligence workflow.")
def new(
    event_uuid: uuid.UUID = typer.Option(
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
            'Input a new event_id(UUID)', str(uuid.uuid4()))

    logger.info(f"EventID: {event_id}")

    if contents:
        # allow index selector
        contents_list = list(IntelligenceContents)
        for i, content_type in enumerate(contents_list):
            typer.echo(f'{i}: {content_type}')
        items = typer.prompt('Choose contents to be include', "0,1")
        indices = [int(i) for i in items.split(',') if i.isdecimal()]
        for i in indices:
            if i <= len(contents_list):
                contents.append(IntelligenceContents(contents_list[i]))
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


def config_update_catalog(ctx: typer.Context):
    catalog_mgr = _load_catalog_manager(ctx)
    config = ctx.meta['config']
    if catalog_mgr is None:
        config.remove_section('catalog')
    else:
        if not config.has_section('catalog'):
            config.add_section('catalog')
        config.set('catalog', 'actives',
                   ','.join(catalog_mgr.active_catalogs.keys()))
        config.set('catalog', 'reserves',
                   ','.join(catalog_mgr.reserved_catalogs.keys()))
    write_config(config, CONFIG_FILE_PATH)
    del ctx.meta['catalog_manager']
    Catalog(_load_account(ctx)).uncache(entire=True)


def config_update_broker(ctx: typer.Context):
    config = ctx.meta['config']
    try:
        broker = _load_broker(ctx)
        if not config.has_section('broker'):
            config.add_section('broker')
        config.set('broker', 'address', broker.address)
    except Exception:
        config.remove_section('broker')
    write_config(config, CONFIG_FILE_PATH)


def config_update_operator(ctx: typer.Context):
    config = ctx.meta['config']
    try:
        operator = _load_operator(ctx)
        if not config.has_section('operator'):
            config.add_section('operator')
        config.set('operator', 'address', operator.address)
    except Exception:
        config.remove_section('operator')
    write_config(config, CONFIG_FILE_PATH)


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


def _ix_parse_token_index(ctx: typer.Context, token_index: str
                          ) -> Tuple[ChecksumAddress, ChecksumAddress]:
    try:
        catalog_part, token_part = token_index.split('-', 1)
        catalog_idx = int(catalog_part)
        token_idx = int(token_part)
    except Exception as err:
        raise Exception(f'Invalid index: {token_index}') from err
    account = _load_account(ctx)
    catalog_mgr = _load_catalog_manager(ctx)
    catalog_address = catalog_mgr.id2address(catalog_idx)
    token_address = Catalog(account).get(catalog_address).id2address(token_idx)
    return catalog_address, token_address


@ix_app.command('search', help="Show CTI tokens on the active list of CTI catalogs.")
def ix_search(ctx: typer.Context,
              mine: bool = typer.Option(True, help='show tokens published by you'),
              mine_only: bool = typer.Option(False),
              soldout: bool = typer.Option(False, help='show soldout tokens'),
              own: bool = typer.Option(True, help='show tokens you own'),
              own_only: bool = typer.Option(False)):
    logger = getLogger()
    try:
        if (mine_only and not mine) or (own_only and not own):
            typer.echo('contradictory options')
            return
        _ix_list_tokens(ctx, mine, mine_only, soldout, own, own_only)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_app.command('buy', help="Buy the CTI Token by index. (Check metemctl ix list)")
def ix_buy(ctx: typer.Context, token_index: str):
    logger = getLogger()
    try:
        account = _load_account(ctx)
        broker = _load_broker(ctx)
        catalog, token = _ix_parse_token_index(ctx, token_index)
        price = Catalog(account).get(catalog).get_tokeninfo(token).price
        broker.buy(catalog, token, price, allow_cheaper=False)
        typer.echo(f'bought token {token_index} for {price} pts.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_broker_app.command('serve', help="Pass your tokens to the broker for disseminate.")
def broker_serve(ctx: typer.Context, token_index: str, amount: int):
    logger = getLogger()
    try:
        if amount <= 0:
            raise Exception(f'Invalid amount: {amount}')
        account = _load_account(ctx)
        catalog_address, token_address = _ix_parse_token_index(ctx, token_index)
        tinfo = Catalog(account).get(catalog_address).get_tokeninfo(token_address)
        if tinfo.owner != account.eoa:
            raise Exception(f'Not a token published by you')
        balance = Token(account).get(token_address).balance_of(account.eoa)
        if balance < amount:
            raise Exception(f'transfer amount({amount}) exceeds balance({balance})')
        broker = _load_broker(ctx)
        broker.consign(catalog_address, token_address, amount)
        typer.echo(f'consigned {amount} of token({token_address}) to broker({broker.address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_token_app.command('create')
def token_create(ctx: typer.Context, initial_supply: int):
    logger = getLogger()
    try:
        _load_metemcyber_util(ctx)
        account = _load_account(ctx)
        if initial_supply <= 0:
            raise Exception(f'Invalid initial-supply: {initial_supply}')
        token = Token(account).new(initial_supply, [])
        typer.echo(f'created a new token. address is {token.address}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@seeker_app.command('status')
def seeker_status(_ctx: typer.Context):
    logger = getLogger()
    try:
        seeker = Seeker(APP_DIR)
        if seeker.pid == 0:
            typer.echo(f'not running.')
        else:
            typer.echo(f'running on pid {seeker.pid}, listening {seeker.address}:{seeker.port}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@seeker_app.command('start')
def seeker_start(_ctx: typer.Context,
                 config: Optional[str] = typer.Option(None, help='seeker config filepath')):
    logger = getLogger()
    try:
        seeker = Seeker(APP_DIR, config)
        seeker.start()
        typer.echo(f'seeker started on process {seeker.pid}, '
                   f'listening {seeker.address}:{seeker.port}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@seeker_app.command('stop')
def seeker_stop(_ctx: typer.Context):
    logger = getLogger()
    try:
        seeker = Seeker(APP_DIR)
        seeker.stop()
        typer.echo(f'seeker stopped.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


def _solver_client(ctx: typer.Context) -> MCSClient:
    if 'solver_client' in ctx.meta.keys():
        return ctx.meta['solver_client']
    account = _load_account(ctx)
    solver = MCSClient(account.eoa, ctx.meta.get('xxx_pkey'))
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
    logger = getLogger()
    try:
        _solver_client(ctx)
        typer.echo('Solver already running.')
        return
    except Exception:
        pass
    try:
        config = ctx.meta['config']
        endpoint_url = config['general']['endpoint_url']
    except Exception:
        typer.echo('Configuration error: missing general.endpoint_url.')
    try:
        subprocess.Popen(
            ['python3', 'metemcyber/core/multi_solver_cli.py', '-e', endpoint_url, '-m', 'server'],
            shell=False)
        typer.echo('Solver started as a subprocess.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@solver_app.command('stop',
                    help='Kill Solver process, all solver (not only yours) are killed.')
def solver_stop(ctx: typer.Context):
    logger = getLogger()
    try:
        solver = _solver_client(ctx)
        solver.shutdown()
        typer.echo('Solver shutted down.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@solver_app.command('enable',
                    help='Solver start running with operator you configured.')
def solver_enable(ctx: typer.Context,
                  plugin: Optional[str] = typer.Option(None, help='solver plugin filename'),
                  config: Optional[str] = typer.Option(None, help='solver config filepath')):
    logger = getLogger()
    try:
        operator = _load_operator(ctx)
        solver = _solver_client(ctx)
        applied = solver.new_solver(operator.address, pluginfile=plugin, configfile=config)
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
        solver.solver('accept_registered', token_addresses)
        acceptings = solver.solver('accepting_tokens')
        if acceptings:
            typer.echo(f'and accepting {len(acceptings)} token(s) already registered.')
        else:
            typer.echo(f'No token registered on this operator.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'accepting registerd tokens failed: {err}')


@solver_app.command('disable',
                    help='Solver will purge your operator, and keep running.')
def solver_disable(ctx: typer.Context):
    logger = getLogger()
    try:
        solver = _solver_client(ctx)
        solver.get_solver()
        solver.purge_solver()
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@solver_app.command('support',
                    help='Register token to accept challenge.')
def solver_support(ctx: typer.Context,
                   token_address: str):
    logger = getLogger()
    try:
        solver = _solver_client(ctx)
        solver.get_solver()
        solver.solver('accept_challenges', [cast(ChecksumAddress, token_address)])
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@solver_app.command('obsolete',
                    help='Unregister token not to accept challenge.')
def solver_obsolete(ctx: typer.Context,
                    token_address: str):
    logger = getLogger()
    try:
        solver = _solver_client(ctx)
        solver.get_solver()
        solver.solver('refuse_challenges', [cast(ChecksumAddress, token_address)])
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_app.command('use', help="Use the token to challenge the task. (Get the MISP object, etc.")
def ix_use(ctx: typer.Context, token_address: str, data: str = ''):
    logger = getLogger()
    try:
        account = _load_account(ctx)
        operator = _load_operator(ctx)
        assert operator.address
        Token(account).get(cast(ChecksumAddress, token_address)
                           ).send(operator.address, amount=1, data=data)
        typer.echo(f'Started challenge with token({token_address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


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
    limit_atonce = 16
    offset = 0
    while True:
        tmp = operator.history(ADDRESS0, limit_atonce, offset)
        raw_tasks.extend(tmp)
        if len(tmp) < limit_atonce:
            break
        offset += limit_atonce
    return raw_tasks


@ix_app.command('show', help="Show CTI tokens available.")
def ix_challenge_show(ctx: typer.Context,
                      done: bool = typer.Option(False, help='show finished and cancelled'),
                      mine_only: bool = typer.Option(True, help='show yours only')):
    logger = getLogger()
    try:
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
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_app.command('cancel', help="Abort the task in progress.")
def ix_cancel(ctx: typer.Context, challenge_id: int):
    logger = getLogger()
    try:
        operator = _load_operator(ctx)
        operator.cancel_challenge(challenge_id)
        typer.echo(f'cancelled challenge: {challenge_id}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_broker_app.command('show')
def broker_show(ctx: typer.Context):
    logger = getLogger()
    try:
        broker = _load_broker(ctx)
        if broker is None:
            typer.echo(f'Broker is not yet configured.')
        else:
            typer.echo(f'Broker address is {broker.address}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_broker_app.command('create')
def broker_create(ctx: typer.Context,
                  switch: bool = typer.Option(True, help='switch to deployed broker')):
    logger = getLogger()
    try:
        _load_metemcyber_util(ctx)
        account = _load_account(ctx)
        broker = Broker(account).new()
        typer.echo(f'deployed a new broker. address is {broker.address}.')
        if switch:
            ctx.meta['broker'] = broker
            config_update_broker(ctx)
            typer.echo('configured to use the broker above.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


# @contract_broker_app.command('set')
def broker_set(ctx: typer.Context, broker_address: str):
    logger = getLogger()
    try:
        account = _load_account(ctx)
        broker = Broker(account).get(cast(ChecksumAddress, broker_address))
        ctx.meta['broker'] = broker
        config_update_broker(ctx)
        typer.echo(f'configured to use broker({broker_address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_operator_app.command('show', help="Show the contract address of the operator.")
def operator_show(ctx: typer.Context):
    logger = getLogger()
    try:
        operator = _load_operator(ctx)
        if operator is None:
            typer.echo(f'Operator is not yet configured.')
        else:
            typer.echo(f'Operator address is {operator.address}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_operator_app.command('create')
def operator_create(ctx: typer.Context,
                    switch: bool = typer.Option(True, help='switch to deployed operator')):
    logger = getLogger()
    try:
        _load_metemcyber_util(ctx)
        account = _load_account(ctx)
        operator = Operator(account).new()
        typer.echo(f'deployed a new operator. address is {operator.address}.')
        if switch:
            ctx.meta['operator'] = operator
            config_update_operator(ctx)
            typer.echo('configured to use the operator above.')

            # TODO: need notify about plugin file.

    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


# @contract_operator_app.command('set')
def operator_set(ctx: typer.Context, operator_address: str):
    logger = getLogger()
    try:
        account = _load_account(ctx)
        operator = Operator(account).get(cast(ChecksumAddress, operator_address))
        ctx.meta['operator'] = operator
        config_update_operator(ctx)
        typer.echo(f'configured to use operator({operator_address}).')

        # TODO: need notify about plugin file.

    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_catalog_app.command('show', help="Show the list of CTI catalogs")
def catalog_show(ctx: typer.Context):
    catalog_mgr = _load_catalog_manager(ctx)
    typer.echo('Catalogs *:active')
    for caddr, cid in sorted(
            catalog_mgr.all_catalogs.items(), key=lambda x: x[1]):
        typer.echo(
            f'  {"*" if caddr in catalog_mgr.actives else " "}{cid} {caddr}')


# @contract_catalog_app.command('add', help="Add the CTI catalog to the list.")
def catalog_add(
    ctx: typer.Context,
    catalog_address: str,
    activate: bool = typer.Option(
        True,
        help='activate added catalog')):
    logger = getLogger()
    try:
        catalog_mgr = _load_catalog_manager(ctx)
        catalog_mgr.add([cast(ChecksumAddress, catalog_address)], activate=activate)
        config_update_catalog(ctx)
        catalog_show(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@contract_catalog_app.command('create', help="Create a new CTI catalog.")
def catalog_create(
    ctx: typer.Context,
    private: bool = typer.Option(
        False,
        help='create a private catalog'),
        activate: bool = typer.Option(
            False,
        help='activate created catalog')):
    logger = getLogger()
    try:
        _load_metemcyber_util(ctx)
        account = _load_account(ctx)
        catalog: Catalog = Catalog(account).new(private)
        typer.echo('deployed a new '
                   f'{"private" if private else "public"} catalog. '
                   f'address is {catalog.address}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')
        return
    catalog_add(ctx, str(catalog.address), activate)


def _catalog_ctrl(
        act: str, ctx: typer.Context, catalog_address: ChecksumAddress, by_id: bool):
    logger = getLogger()
    try:
        catalog_mgr = _load_catalog_manager(ctx)
        if by_id:
            catalog_address = catalog_mgr.id2address(int(catalog_address))
        if act not in ('remove', 'activate', 'deactivate'):
            raise Exception('Invalid act: ' + act)
        func: Callable[[List[ChecksumAddress]], None] = getattr(catalog_mgr, act)
        func([catalog_address])
        config_update_catalog(ctx)
        catalog_show(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


# @contract_catalog_app.command('remove', help="Remove the CTI catalog from the list.")
def catalog_remove(ctx: typer.Context, catalog_address: str,
                   by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('remove', ctx, cast(ChecksumAddress, catalog_address), by_id)


@ix_catalog_app.command('enable', help="Activate the CTI catalog on the list.")
def ix_catalog_enable(ctx: typer.Context, catalog_address: str,
                      by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('activate', ctx, cast(ChecksumAddress, catalog_address), by_id)


@ix_catalog_app.command('disable', help="Deactivate the CTI catalog on the list.")
def ix_catalog_desable(ctx: typer.Context, catalog_address: str,
                       by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('deactivate', ctx, cast(ChecksumAddress, catalog_address), by_id)


@app.command()
def misp():
    typer.echo(f"misp")


@misp_app.command("open")
def misp_open(ctx: typer.Context):
    logger = getLogger()
    try:
        misp_url = ctx.meta['config']['general']['misp_url']
        logger.info(f"Open MISP: {misp_url}")
        typer.echo(misp_url)
        typer.launch(misp_url)
    except KeyError as err:
        typer.echo(err, err=True)
        logger.error(err)


@app.command(help="Run the current intelligence workflow.")
def run():
    typer.echo(f"run")


@app.command(help="Validate the use of your CTIs")
def check():
    typer.echo(f"check")


@app.command(help="Deploy the CTI token to disseminate CTI.")
def publish(ctx: typer.Context, catalog_address: str, token_address: str,
            uuid_: uuid.UUID, title: str, price: int,
            by_id: bool = typer.Option(False, help='select catalog by id')):
    logger = getLogger()
    try:
        if len(title) == 0:
            raise Exception(f'Invalid(empty) title')
        if price < 0:
            raise Exception(f'Invalid price: {price}')
        account = _load_account(ctx)
        catalog_mgr = _load_catalog_manager(ctx)
        if by_id:
            catalog_address = catalog_mgr.id2address(int(catalog_address))
        catalog = Catalog(account).get(cast(ChecksumAddress, catalog_address))
        catalog.register_cti(cast(ChecksumAddress, token_address), uuid_, title, price)
        typer.echo(f'registered token({token_address}) onto catalog({catalog_address}).')
        producer = account.eoa
        catalog = Catalog(account).get(cast(ChecksumAddress, catalog_address))
        catalog.publish_cti(producer, cast(ChecksumAddress, token_address))
        typer.echo(f'Token({token_address}) was published on catalog({catalog.address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@account_app.command("show", help="Show the current account information.")
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


@config_app.command('show', help="Show your config file of metemctl")
def config_show():
    with open(CONFIG_FILE_PATH) as fin:
        typer.echo(fin.read())


@config_app.command('edit', help="Edit your config file of metemctl")
def config_edit():
    typer.edit(filename=CONFIG_FILE_PATH)


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
