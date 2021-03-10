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

import typer
from web3 import Web3
from web3.auto import w3

from metemcyber.core.bc.ether import Ether
from metemcyber.core.logger import get_logger
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.catalog_manager import CatalogManager
from metemcyber.core.bc.catalog import Catalog
from metemcyber.core.bc.token import Token

CONFIGFILEPATH = f'{os.getcwd()}/metemctl.ini'

app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp")

account_app = typer.Typer()
app.add_typer(account_app, name="account")

catalog_app = typer.Typer()
app.add_typer(catalog_app, name="catalog")


def getLogger(name='cli'):
    return get_logger(name=name, file_prefix='cli')


def read_config():
    logger = getLogger()
    logger.info(f"Load config file from {CONFIGFILEPATH}")
    config = configparser.ConfigParser()
    config.read(CONFIGFILEPATH)
    return config

def write_config(config: configparser.ConfigParser):
    logger = getLogger()
    with open(CONFIGFILEPATH, 'w') as fout:
        config.write(fout)
    logger.debug(f'update config file: {CONFIGFILEPATH}')

def decode_keyfile(filename):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    logger = getLogger()
    try:
        logger.info(f"Decode ethereum key file: {filename}")
        with open(filename) as keyfile:
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
            f'cannot decode keyfile:{os.path.basename(filename)}', err=True)
        logger.error(f'Decode keyfile Error: {err}')
        logger.exception(f'test: {err}')
        raise typer.Exit(code=1)


@app.callback()
def app_callback(ctx: typer.Context):
    config = read_config()
    ctx.meta['config'] = config

    ether = Ether(config['general']['endpoint_url'])
    eoa, pkey = decode_keyfile(config['general']['keyfile'])
    account = Account(ether.web3_with_signature(pkey), eoa)
    ctx.meta['account'] = account

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


@app.command()
def catalog():
    typer.echo(f"catallog")

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
    write_config(config)

@catalog_app.command('list')
def catalog_list(ctx: typer.Context):
    catalog_mgr = ctx.meta['catalog_manager']
    typer.echo('Catalogs *:active')
    for caddr, cid in sorted(
            catalog_mgr.all_catalogs.items(), key=lambda x:x[1]):
        typer.echo(
            f'  {"*" if caddr in catalog_mgr.actives else " "}{cid} {caddr}')

@catalog_app.command('add')
def catalog_add(ctx: typer.Context, catalog_address: str):
    logger = getLogger()
    try:
        catalog_mgr = ctx.meta['catalog_manager']
        catalog_mgr.add([catalog_address], activate=True)
        config_update_catalog(ctx)
        catalog_list(ctx)
    except Exception as err:
        typer.echo(f'failed operation: {err}')

def _catalog_ctrl(
        act: str, ctx: typer.Context, catalog_address: str, by_id: bool):
    logger = getLogger()
    try:
        catalog_mgr = ctx.meta['catalog_manager']
        if by_id:
            catalog_address = catalog_mgr.get_catalog_by_id(
                int(catalog_address))
        func = {
            'remove': catalog_mgr.remove,
            'activate': catalog_mgr.activate,
            'deactivate': catalog_mgr.deactivate,
            }.get(act)
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


@app.command()
def account():
    typer.echo(f"account")


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


@app.command()
def config():
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
        # See https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
        hyperlink = f'\x1b]8;;{service["url"]}\x1b\\{service["name"]}\x1b]8;;\x1b\\'
        typer.echo(f"- {hyperlink}: {service['description']}")


def issues():
    typer.launch('https://github.com/nttcom/metemcyber/issues')


if __name__ == "__main__":
    app()
