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

import os
import json
import configparser
from pathlib import Path

from typing import List, Callable
import typer
from web3 import Web3
from web3.auto import w3

from metemcyber.core.bc.ether import Ether
from metemcyber.core.logger import get_logger
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.metemcyber_util import MetemcyberUtil
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.catalog import Catalog
from metemcyber.core.bc.token import Token

APP_NAME = "metemcyber"
APP_DIR = typer.get_app_dir(APP_NAME)
CONFIG_FILE_NAME = "metemctl.ini"
CONFIG_FILE_PATH = Path(APP_DIR) / CONFIG_FILE_NAME

app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp")

account_app = typer.Typer()
app.add_typer(account_app, name="account")

catalog_app = typer.Typer()
app.add_typer(catalog_app, name="catalog")


def getLogger(name='cli'):
    return get_logger(name=name, app_dir=APP_DIR, file_prefix='cli')


def create_config(filepath: Path):
    logger = getLogger()
    logger.info(f"Create new config to {filepath}")

    typer.echo('You need the keyfile to connect the ethereum network.')
    path_text = typer.prompt('Input the path of your keyfile')

    # Allow the path that contain '~'
    keyfile_path = str(Path(path_text).expanduser())

    template = Path(__file__).with_name(f'{CONFIG_FILE_NAME}.template')
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
        write_config(config)


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

    catalog_mgr = CatalogManager(account.web3)
    if config.has_section('catalog'):
        actives = config['catalog'].get('actives')
        if actives:
            catalog_mgr.add(actives.strip().split(','), activate=True)
        reserves = config['catalog'].get('reserves')
        if reserves:
            catalog_mgr.add(reserves.strip().split(','), activate=False)
    ctx.meta['catalog_manager'] = catalog_mgr


@app.command()
def new():
    typer.echo(f"new")


def config_update_catalog(ctx: typer.Context):
    catalog_mgr = ctx.meta.get('catalog_manager')
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


@catalog_app.command('list')
def catalog_list(ctx: typer.Context):
    catalog_mgr = ctx.meta['catalog_manager']
    typer.echo('Catalogs *:active')
    for caddr, cid in sorted(
            catalog_mgr.all_catalogs.items(), key=lambda x: x[1]):
        typer.echo(
            f'  {"*" if caddr in catalog_mgr.actives else " "}{cid} {caddr}')


@catalog_app.command('add')
def catalog_add(ctx: typer.Context, catalog_address: str,
                activate: bool = typer.Option(True, help='activate added catalog')):
    logger = getLogger()
    try:
        catalog_mgr = ctx.meta['catalog_manager']
        catalog_mgr.add([catalog_address], activate=activate)
        config_update_catalog(ctx)
        catalog_list(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@catalog_app.command('new')
def catalog_new(ctx: typer.Context,
                private: bool = typer.Option(
                    False, help='create a private catalog'),
                activate: bool = typer.Option(False, help='activate created catalog')):
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
        act: str, ctx: typer.Context, catalog_address: str, by_id: bool):
    logger = getLogger()
    try:
        catalog_mgr = ctx.meta['catalog_manager']
        if by_id:
            catalog_address = catalog_mgr.id2address(int(catalog_address))
        if act not in ('remove', 'activate', 'deactivate'):
            raise Exception('Invalid act: ' + act)
        # typer does not support eth_typing.ChecksumAddress
        func: Callable[[List[str]], None] = getattr(catalog_mgr, act)
        func([catalog_address])
        config_update_catalog(ctx)
        catalog_list(ctx)
    except Exception as err:
        logger.exception(err)
        typer.echo(f'failed operation: {err}')


@catalog_app.command('remove')
def catalog_remove(ctx: typer.Context, catalog_address: str,
                   by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('remove', ctx, catalog_address, by_id)


@catalog_app.command('activate')
def catalog_activate(ctx: typer.Context, catalog_address: str,
                     by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('activate', ctx, catalog_address, by_id)


@catalog_app.command('deactivate')
def catalog_deactivate(ctx: typer.Context, catalog_address: str,
                       by_id: bool = typer.Option(False, help='select by catalog id')):
    _catalog_ctrl('deactivate', ctx, catalog_address, by_id)


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
    except KeyError as e:
        typer.echo(e, err=True)
        logger.error(e)


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

    catalog_mgr = ctx.meta['catalog_manager']
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
    services = [
        {
            'name': 'CyberChef',
            'url': 'https://gchq.github.io/CyberChef/',
            'description': 'The Swiss Army Knife for cyber operations.'
        },
        {
            'name': 'VirusTotal',
            'url': 'https://www.virustotal.com/',
            'description': 'Analyze suspicious files and URLs to detect types of malware.'
        },
        {
            'name': 'UnpacMe',
            'url': 'https://www.unpac.me/feed',
            'description': 'An automated malware unpacking service.'
        },
        {
            'name': 'ANY.RUN',
            'url': 'https://app.any.run/submissions/',
            'description': 'Interactive online malware analysis service.'
        },
        {
            'name': 'ThreatFox',
            'url': 'https://threatfox.abuse.ch/browse/',
            'description': 'A platform of sharing IOCs associated with malware.'
        },
        {
            'name': 'Hatching Triage',
            'url': 'https://tria.ge/reports/public',
            'description': 'A malware analysis sandbox designed for cross-platform support.'
        },
        {
            'name': 'URLhaus',
            'url': 'https://urlhaus.abuse.ch/browse/',
            'description': 'A project of sharing malicious URLs that are being used for malware distribution.'
        },
        {
            'name': 'Open Threat Exchange',
            'url': 'https://otx.alienvault.com/browse/',
            'description': 'The world’s first and largest truly open threat intelligence community.'
        },
        {
            'name': 'ThreatMiner',
            'url': 'https://www.threatminer.org/',
            'description': 'A threat intelligence portal that provides information on IOCs.'
        },
        {
            'name': 'Grey Noise',
            'url': 'https://viz.greynoise.io/cheat-sheet/',
            'description': 'A cybersecurity platform that collects and analyzes Internet-wide scan and attack traffic.'
        },
        {
            'name': 'Bitcoin Abuse Database',
            'url': 'https://www.bitcoinabuse.com/reports',
            'description': 'Tracking bitcoin addresses used by ransomware, blackmailers, fraudsters, etc.'
        },
    ]

    for service in services:
        # See
        # https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
        hyperlink = f'\x1b]8;;{service["url"]}\x1b\\{service["name"]}\x1b]8;;\x1b\\'
        typer.echo(f"- {hyperlink}: {service['description']}")


def issues():
    typer.launch('https://github.com/nttcom/metemcyber/issues')


if __name__ == "__main__":
    app()
