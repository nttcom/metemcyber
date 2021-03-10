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

import typer
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.ether import Ether
from web3 import Web3
from web3.auto import w3

app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp")

account_app = typer.Typer()
app.add_typer(account_app, name="account")


def read_config():
    filename = "metemctl.ini"
    config = configparser.ConfigParser()
    config.read(filename)
    return config


def decode_keyfile(filename):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    try:
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
        typer.echo('ERROR:', err)
        typer.echo('cannot decode keyfile:', os.path.basename(filename))
        typer.Exit(code=1)


@app.callback()
def app_callback(ctx: typer.Context):
    config = read_config()
    ctx.meta['config'] = config

    ether = Ether(config['general']['endpoint_url'])
    eoa, pkey = decode_keyfile(config['general']['keyfile'])
    ctx.meta['account'] = Account(ether.web3_with_signature(pkey), eoa)


@app.command()
def new():
    typer.echo(f"new")


@app.command()
def catalog():
    typer.echo(f"catallog")


@app.command()
def misp():
    typer.echo(f"misp")


@misp_app.command("open")
def misp_open(ctx: typer.Context):
    try:
        misp_url = ctx.meta['config']['general']['misp_url']
        typer.echo(misp_url)
        typer.launch(misp_url)
    except KeyError as e:
        typer.echo(e, err=True)


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
        hyperlink = f'\x1b]8;;{service["url"]}\x1b\\{service["name"]}\x1b]8;;\x1b\\'
        typer.echo(f"- {hyperlink}: {service['description']}")


if __name__ == "__main__":
    app()
