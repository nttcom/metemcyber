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

import configparser
import json
import os
import uuid
from enum import Enum
from pathlib import Path
from subprocess import call
from typing import Callable, Dict, List, Optional, Tuple, Union, cast

import typer
import yaml
from eth_typing import ChecksumAddress
from web3 import Web3
from web3.auto import w3

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.broker import Broker
from metemcyber.core.bc.catalog import Catalog, TokenInfo
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
from metemcyber.core.bc.operator import TASK_STATES, Operator
from metemcyber.core.bc.token import Token
from metemcyber.core.logger import get_logger

APP_NAME = "metemcyber"
APP_DIR = typer.get_app_dir(APP_NAME)
CONFIG_FILE_NAME = "metemctl.ini"
CONFIG_FILE_PATH = Path(APP_DIR) / CONFIG_FILE_NAME
WORKFLOW_FILE_NAME = "workflow.yml"

app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp")

account_app = typer.Typer()
app.add_typer(account_app, name="account")

ix_app = typer.Typer()
app.add_typer(ix_app, name="ix")
ix_token_app = typer.Typer()
ix_app.add_typer(ix_token_app, name='token')
ix_broker_app = typer.Typer()
ix_app.add_typer(ix_broker_app, name='broker')
ix_operator_app = typer.Typer()
ix_app.add_typer(ix_operator_app, name='operator')
ix_challenge_app = typer.Typer()
ix_app.add_typer(ix_challenge_app, name='challenge')

catalog_app = typer.Typer()
app.add_typer(catalog_app, name="catalog")


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


def decode_keyfile(filepath: Path):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    logger = getLogger()
    try:
        logger.info(f"Decode ethereum key file: {filepath}")
        with open(filepath) as keyfile:
            enc_data = keyfile.read()
        address = Web3.toChecksumAddress(json.loads(enc_data)['address'])
        word = os.getenv('METEMCTL_KEYFILE_PASSWORD', "")
        if word == "":
            typer.echo('You can also use an env METEMCTL_KEYFILE_PASSWORD.')
            word = typer.prompt('Enter password for keyfile:', hide_input=True)

        private_key = w3.eth.account.decrypt(enc_data, word).hex()
        return address, private_key
    except Exception as err:
        typer.echo(f'ERROR:{err}')
        typer.echo(
            f'cannot decode keyfile:{os.path.basename(filepath)}', err=True)
        logger.error(f'Decode keyfile Error: {err}')
        logger.exception(f'test: {err}')
        raise typer.Exit(code=1)


def _load_metemcyber_util(ctx: typer.Context):
    account = ctx.meta['account']
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
        util = MetemcyberUtil(account.web3).new()
        util_ph = util.register_library(util.address)
        config.set('metemcyber_util', 'address', util.address)
        config.set('metemcyber_util', 'placeholder', util_ph)
        write_config(config, CONFIG_FILE_PATH)


def _load_catalog_manager(ctx: typer.Context) -> CatalogManager:
    if 'catalog_manager' in ctx.meta.keys():
        return ctx.meta['catalog_manager']
    account = ctx.meta['account']
    catalog_mgr = CatalogManager(account.web3)
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
    account = ctx.meta['account']
    config = ctx.meta['config']
    try:
        broker_address = cast(ChecksumAddress, config['broker']['address'])
    except KeyError as err:
        raise Exception('Broker is not yet configured') from err
    broker = Broker(account.web3).get(broker_address)
    ctx.meta['broker'] = broker
    return broker


def _load_operator(ctx: typer.Context) -> Operator:
    if 'operator' in ctx.meta.keys():
        return ctx.meta['operator']
    account = ctx.meta['account']
    config = ctx.meta['config']
    try:
        operator_address = cast(ChecksumAddress, config['operator']['address'])
    except KeyError as err:
        raise Exception('Operator is not yet configured') from err
    operator = Operator(account.web3).get(operator_address)
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

    ether = Ether(config['general']['endpoint_url'])
    eoa, pkey = decode_keyfile(config['general']['keyfile'])
    account = Account(ether.web3_with_signature(pkey), eoa)
    ctx.meta['account'] = account

    _load_metemcyber_util(ctx)


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
        call(['kedro', 'new', '--config', dist_yml_filepath])


@app.command()
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


def _ix_list_tokens(ctx: typer.Context, mine, mine_only, soldout, own, own_only):
    account = ctx.meta['account']
    for caddr, cid in sorted(
            _load_catalog_manager(ctx).active_catalogs.items(), key=lambda x: x[1], reverse=True):
        typer.echo(f'Catalog {cid}: {caddr}')
        token_infos = sorted(
            Catalog(account.web3).get(caddr).tokens.values(),
            key=lambda x: x.token_id,
            reverse=True)
        amounts = _load_broker(ctx).get_amounts(caddr, [token.address for token in token_infos])
        for idx, tinfo in enumerate(token_infos):
            if account.eoa == tinfo.owner:
                if not mine:
                    continue
            elif mine_only:
                continue
            if not soldout and amounts[idx] == 0:
                continue
            balance = Token(account.web3).get(tinfo.address).balance_of(account.eoa)
            if balance == 0:
                if own_only:
                    continue
            elif not own:
                continue

            typer.echo(
                f'  {cid}-{tinfo.token_id}: {tinfo.title}' + '\n'
                f'     ├ UUID : {tinfo.uuid}' + '\n'
                f'     ├ Addr : {tinfo.address}' + '\n'
                f'     └ Price: {tinfo.price} pts / {amounts[idx]} tokens left' +
                ('' if balance == 0 else f' (you have {balance})'))


def _ix_parse_token_index(ctx: typer.Context, token_index: str
                          ) -> Tuple[ChecksumAddress, ChecksumAddress]:
    try:
        catalog_part, token_part = token_index.split('-', 1)
        catalog_idx = int(catalog_part)
        token_idx = int(token_part)
    except Exception as err:
        raise Exception(f'Invalid index: {token_index}') from err
    account = ctx.meta['account']
    catalog_mgr = _load_catalog_manager(ctx)
    catalog_address = catalog_mgr.id2address(catalog_idx)
    token_address = Catalog(account.web3).get(catalog_address).id2address(token_idx)
    return catalog_address, token_address


@ix_app.command('list')
def ix_list(ctx: typer.Context,
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


@ix_app.command('buy')
def ix_buy(ctx: typer.Context, token_index: str):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        broker = _load_broker(ctx)
        catalog, token = _ix_parse_token_index(ctx, token_index)
        price = Catalog(account.web3).get(catalog).get_tokeninfo(token).price
        broker.buy(catalog, token, price, allow_cheaper=False)
        typer.echo(f'bought token {token_index} for {price} pts.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_app.command('consign')
def ix_consign(ctx: typer.Context, token_index: str, amount: int):
    logger = getLogger()
    try:
        if amount <= 0:
            raise Exception(f'Invalid amount: {amount}')
        account = ctx.meta['account']
        catalog_address, token_address = _ix_parse_token_index(ctx, token_index)
        tinfo = Catalog(account.web3).get(catalog_address).get_tokeninfo(token_address)
        if tinfo.owner != account.eoa:
            raise Exception(f'Not a token published by you')
        balance = Token(account.web3).get(token_address).balance_of(account.eoa)
        if balance < amount:
            raise Exception(f'transfer amount({amount}) exceeds balance({balance})')
        broker = _load_broker(ctx)
        broker.consign(catalog_address, token_address, amount)
        typer.echo(f'consigned {amount} of token({token_address}) to broker({broker.address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_token_app.command('create')
def ix_token_create(ctx: typer.Context, initial_supply: int):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        if initial_supply <= 0:
            raise Exception(f'Invalid initial-supply: {initial_supply}')
        token = Token(account.web3).new(initial_supply, [])
        typer.echo(f'created a new token. address is {token.address}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_challenge_app.command('token')
def ix_challenge_token(ctx: typer.Context, token_address: str, data: str = ''):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        operator = _load_operator(ctx)
        assert operator.address
        Token(account.web3).get(cast(ChecksumAddress, token_address)
                                ).send(operator.address, amount=1, data=data)
        typer.echo(f'Started challenge with token({token_address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


def _find_token_info(ctx: typer.Context, token_address: ChecksumAddress) -> TokenInfo:
    account = ctx.meta['account']
    catalog_mgr = _load_catalog_manager(ctx)
    for catalog_address in catalog_mgr.all_catalogs.keys():
        try:
            return Catalog(account.web3).get(catalog_address).get_tokeninfo(token_address)
        except Exception:
            pass
    raise Exception('No info found for token({token_address}) on registered catalogs')


def _get_challenges(ctx: typer.Context
                    ) -> List[Tuple[int, ChecksumAddress, ChecksumAddress, ChecksumAddress, int]]:
    operator = _load_operator(ctx)
    raw_tasks = []
    limit_atonce = 16
    offset = 0
    address0 = cast(ChecksumAddress, '0x{:040x}'.format(0))  # address(0): wildcard in history()
    while True:
        tmp = operator.history(address0, limit_atonce, offset)
        raw_tasks.extend(tmp)
        if len(tmp) < limit_atonce:
            break
        offset += limit_atonce
    return raw_tasks


@ix_challenge_app.command('list')
def ix_challenge_list(ctx: typer.Context,
                      done: bool = typer.Option(False, help='show finished and cancelled'),
                      mine_only: bool = typer.Option(True, help='show yours only')):
    logger = getLogger()
    try:
        account = ctx.meta['account']
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


@ix_challenge_app.command('cancel')
def ix_challenge_cancel(ctx: typer.Context, challenge_id: int):
    logger = getLogger()
    try:
        operator = _load_operator(ctx)
        operator.cancel_challenge(challenge_id)
        typer.echo(f'cancelled challenge: {challenge_id}.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_broker_app.command('show')
def ix_broker_show(ctx: typer.Context):
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


@ix_broker_app.command('new')
def ix_broker_new(ctx: typer.Context,
                  switch: bool = typer.Option(True, help='switch to deployed broker')):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        broker = Broker(account.web3).new()
        typer.echo(f'deployed a new broker. address is {broker.address}.')
        if switch:
            ctx.meta['broker'] = broker
            config_update_broker(ctx)
            typer.echo('configured to use the broker above.')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_broker_app.command('set')
def ix_broker_set(ctx: typer.Context, broker_address: str):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        broker = Broker(account.web3).get(cast(ChecksumAddress, broker_address))
        ctx.meta['broker'] = broker
        config_update_broker(ctx)
        typer.echo(f'configured to use broker({broker_address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_operator_app.command('show')
def ix_operator_show(ctx: typer.Context):
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


@catalog_app.command('list')
def catalog_list(ctx: typer.Context):
    catalog_mgr = _load_catalog_manager(ctx)
    typer.echo('Catalogs *:active')
    for caddr, cid in sorted(
            catalog_mgr.all_catalogs.items(), key=lambda x: x[1]):
        typer.echo(
            f'  {"*" if caddr in catalog_mgr.actives else " "}{cid} {caddr}')


@catalog_app.command('add')
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
        catalog_list(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@catalog_app.command('new')
def catalog_new(
    ctx: typer.Context,
    private: bool = typer.Option(
        False,
        help='create a private catalog'),
        activate: bool = typer.Option(
            False,
        help='activate created catalog')):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        catalog: Catalog = Catalog(account.web3).new(private)
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
        catalog_list(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@catalog_app.command('remove')
def catalog_remove(ctx: typer.Context, catalog_address: str,
                   by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('remove', ctx, cast(ChecksumAddress, catalog_address), by_id)


@catalog_app.command('activate')
def catalog_activate(ctx: typer.Context, catalog_address: str,
                     by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('activate', ctx, cast(ChecksumAddress, catalog_address), by_id)


@catalog_app.command('deactivate')
def catalog_deactivate(ctx: typer.Context, catalog_address: str,
                       by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('deactivate', ctx, cast(ChecksumAddress, catalog_address), by_id)


@catalog_app.command('register')
def catalog_register(ctx: typer.Context, catalog_address: str, token_address: str,
                     uuid_: uuid.UUID, title: str, price: int,
                     by_id: bool = typer.Option(False, help='select catalog by id')):
    logger = getLogger()
    try:
        if len(title) == 0:
            raise Exception(f'Invalid(empty) title')
        if price < 0:
            raise Exception(f'Invalid price: {price}')
        account = ctx.meta['account']
        catalog_mgr = _load_catalog_manager(ctx)
        if by_id:
            catalog_address = catalog_mgr.id2address(int(catalog_address))
        catalog = Catalog(account.web3).get(cast(ChecksumAddress, catalog_address))
        catalog.register_cti(cast(ChecksumAddress, token_address), uuid_, title, price)
        typer.echo(f'registered token({token_address}) onto catalog({catalog_address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@catalog_app.command('publish')
def catalog_publish(ctx: typer.Context, catalog_address: str, token_address: str,
                    by_id: bool = typer.Option(False, help='select catalog by id')):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        producer = account.eoa
        catalog_mgr = _load_catalog_manager(ctx)
        if by_id:
            catalog_address = catalog_mgr.id2address(int(catalog_address))
        catalog = Catalog(account.web3).get(cast(ChecksumAddress, catalog_address))
        catalog.publish_cti(producer, cast(ChecksumAddress, token_address))
        typer.echo(f'Token({token_address}) was published on catalog({catalog.address}).')
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


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


@app.command()
def run():
    typer.echo(f"run")


@app.command()
def check():
    typer.echo(f"check")


@app.command()
def publish():
    typer.echo(f"publish")


@account_app.command("info")
def account_info(ctx: typer.Context):
    account = ctx.meta['account']
    typer.echo(f'--------------------')
    typer.echo(f'Summary')
    typer.echo(f'  - EOA Address: {account.wallet.eoa}')
    typer.echo(f'  - Balance: {account.wallet.balance} Wei')
    typer.echo(f'--------------------')

    catalog_mgr = _load_catalog_manager(ctx)
    for caddr, cid in sorted(
            catalog_mgr.active_catalogs.items(), key=lambda x: x[1]):
        typer.echo(f'Catalog {cid}: {caddr}')
        catalog = Catalog(account.web3).get(caddr)
        if len(catalog.tokens) > 0:
            typer.echo('  Tokens <id, balance, address>')
            for taddr, tinfo in sorted(
                    catalog.tokens.items(), key=lambda x: x[1].token_id):
                token = Token(account.web3).get(taddr)
                balance = token.balance_of(account.eoa)
                if balance > 0:
                    typer.echo(f'  {tinfo.token_id}: {balance}: {taddr}')


@app.command('config')
def _config():
    typer.echo(f"config")


@app.command()
def contract():
    typer.echo(f"contract")


@app.command()
def console():
    typer.echo(f"console")


@app.command()
def external_links():
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
