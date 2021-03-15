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
from metemcyber.core.bc.catalog import Catalog
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
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
    config = ctx.meta.get('config')
    assert config
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


def _ix_list_tokens(ctx: typer.Context):
    account = ctx.meta['account']
    broker = _load_broker(ctx)
    catalog_mgr = _load_catalog_manager(ctx)
    for caddr, cid in sorted(
            catalog_mgr.active_catalogs.items(), key=lambda x: x[1], reverse=True):
        typer.echo(f'Catalog {cid}: {caddr}')
        catalog = Catalog(account.web3).get(caddr)
        if not catalog.tokens:
            continue
        token_infos = sorted(catalog.tokens.values(), key=lambda x: x.token_id, reverse=True)
        amounts = broker.get_amounts(caddr, [token.address for token in token_infos])
        for idx, tinfo in enumerate(token_infos):
            if amounts[idx] > 0:
                typer.echo(f'  {cid}-{tinfo.token_id}: {tinfo.title}')
                typer.echo(f'    ├ UUID : {tinfo.uuid}')
                typer.echo(f'    ├ Addr : {tinfo.address}')
                typer.echo(f'    └ Price: {tinfo.price} pts  /  {amounts[idx]} tokens left')


def _ix_parse_tokenid(ctx: typer.Context, token_id: str
                      ) -> Tuple[ChecksumAddress, ChecksumAddress]:
    try:
        catalog_part, token_part = token_id.split('-', 1)
        catalog_idx = int(catalog_part)
        token_idx = int(token_part)
    except Exception as err:
        raise Exception(f'Invalid ID: {token_id}') from err
    account = ctx.meta['account']
    catalog_mgr = _load_catalog_manager(ctx)
    catalog_address = catalog_mgr.id2address(catalog_idx)
    token_address = Catalog(account.web3).get(catalog_address).id2address(token_idx)
    return catalog_address, token_address


@ix_app.command('list')
def ix_list(ctx: typer.Context):
    logger = getLogger()
    try:
        _ix_list_tokens(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@ix_app.command('buy')
def ix_buy(ctx: typer.Context, token_id: str):
    logger = getLogger()
    try:
        account = ctx.meta['account']
        broker = _load_broker(ctx)
        catalog, token = _ix_parse_tokenid(ctx, token_id)
        price = Catalog(account.web3).get(catalog).get_tokeninfo(token).price
        broker.buy(catalog, token, price, allow_cheaper=False)
        typer.echo(f'bought token {token_id} for {price} pts.')
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
