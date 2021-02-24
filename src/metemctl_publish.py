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

"""
usage:  metemctl publish
        metemctl publish <filename>
        metemctl publish [--dir <misp_json_dir>]

options:
    -h, --help
    -r, --dir <misp_json_dir>
    
"""

from docopt import docopt
import configparser
import json
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import geth_poa_middleware
from web3.middleware import construct_sign_and_send_raw_middleware
import os
import sys
from getpass import getpass
import glob
from pathlib import Path
import csv
import logging

LOGGER = logging.getLogger('common')

CONFIG_INI_FILEPATH = "metemctl.ini"
WORKSPACE_CONFIG_INI_FILEPATH = "./workspace/config.ini"
MISP_DATAFILE_PATH = os.getenv('MISP_DATAFILE_PATH', './fetched_misp_events')
MISP_INI_FILEPATH = './workspace/misp.ini'
REGISTERED_TOKEN_TSV = './workspace/registered_token.tsv'


def decode_keyfile(filename, w3):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    try:
        with open(filename) as keyfile:
            enc_data = keyfile.read()
        address = Web3.toChecksumAddress(json.loads(enc_data)['address'])
        word = os.getenv('METEMCTL_KEYFILE_PASSWORD', "")
        if word == "":
            print('You can also use an env METEMCTL_KEYFILE_PASSWORD.')
            word = getpass('Enter password for keyfile:')

        private_key = w3.eth.account.decrypt(enc_data, word).hex()
        return address, private_key
    except Exception as err:
        print('ERROR:', err)
        print('cannot decode keyfile:', os.path.basename(filename))
        sys.exit()


def list_token_uris(catalog_address):
    contract_path = './src/contracts_data/CTICatalog.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts']['CTICatalog.sol:CTICatalog']
    contract_metadata = json.loads(contract_json['metadata'])

    # Note: array contains "" which means unregistered.
    func = w3.eth.contract(address=catalog_address,
                           abi=contract_metadata['output']['abi']).functions.listTokenURIs()
    token_uris = func.call()

    # remove "" element
    return [uri for uri in token_uris if uri != '']


def get_cti_uuid(catalog_address, token_address):
    contract_path = './src/contracts_data/CTICatalog.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts']['CTICatalog.sol:CTICatalog']
    contract_metadata = json.loads(contract_json['metadata'])
    if token_address:
        func = w3.eth.contract(
            address=catalog_address, abi=contract_metadata['output']['abi']).functions.getCtiInfo(token_address)
        _, _, uuid, _, _, _, _ = func.call()
        return uuid
    else:
        return None


def deploy_CTItoken(w3, token_quantity, operators):
    # load compiled smartcontract
    contract_path = './src/contracts_data/CTIToken.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts']['CTIToken.sol:CTIToken']
    contract_metadata = json.loads(contract_json['metadata'])
    if contract_metadata and token_quantity and len(operators) > 0:
        tx_hash = w3.eth.contract(abi=contract_metadata['output']['abi'], bytecode=contract_json['bin']).constructor(
            token_quantity, operators).transact()
        # address = w3.eth.waitForTransactionReceipt(tx_hash)['contractAddress']
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        address = tx_receipt['contractAddress']
        # print(f'Deployed {contract_path} to: {address}\n')
        return address
    else:
        return None


def read_dir(misp_json_dir):
    if os.path.isdir(misp_json_dir):
        misp_json_path = os.path.join(misp_json_dir, '*.json')
        # get json file list by glob
        return glob.glob(misp_json_path)
    else:
        return None


def save_registered_token(cti_metadata):
    # cticatalog コントラクトに登録したtokenのmetadataを保存する
    fieldnames = ['uuid', 'tokenAddress',
                  'title', 'price', 'operator', 'quantity']

    is_empty = not os.path.isfile(REGISTERED_TOKEN_TSV)

    with open(REGISTERED_TOKEN_TSV, 'a', newline='') as tsvfile:
        writer = csv.DictWriter(
            tsvfile, fieldnames=fieldnames, extrasaction='ignore', delimiter='\t')
        if is_empty:
            writer.writeheader()
        writer.writerow(cti_metadata)


def fetch_registered_token():
    # 登録済みトークンのfetch
    registered_tokens = []
    try:
        with open(REGISTERED_TOKEN_TSV, newline='') as tsvfile:
            tsv = csv.DictReader(tsvfile, delimiter='\t')
            for row in tsv:
                registered_tokens.append(row)
            return registered_tokens
    except FileNotFoundError:
        pass
    except Exception as err:
        LOGGER.error(err)
    return registered_tokens


def create_metadata(misp_json_file, operators, misp_config):
    uuid = Path(misp_json_file).stem
    # 登録済みのtokenを取得 from tsvfile
    registered_token = fetch_registered_token()
    registered_uuid = [token.get('uuid') for token in registered_token]
    # if uuid in registered_uuid:
    #     return None
    metadata = {}
    with open(misp_json_file) as fin:
        misp = json.load(fin)
    metadata['uuid'] = uuid
    metadata['title'] = misp['Event']['info']
    metadata['price'] = misp_config['MISP']['defaultprice']
    metadata['operator'] = ','.join(operators)
    metadata['quantity'] = misp_config['MISP']['defaultquantity']

    return metadata


def register_cti(w3, catalog_address, token_address, uuid, title, price, operator, abi):
    func = w3.eth.contract(address=catalog_address, abi=abi).functions.registerCti(
        token_address, uuid, title, int(price), operator)
    tx_hash = func.transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt['status'] != 1:
        raise ValueError('register CTI: transaction failed.')


def publish_cti(w3, catalog_address, token_address, abi):
    func = w3.eth.contract(address=catalog_address, abi=abi).functions.publishCti(
        w3.eth.defaultAccount, token_address)
    tx_hash = func.transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt['status'] != 1:
        raise ValueError('publish CTI: transaction failed.')


def register_catalog(w3, catalog_address, token_address, cti_metadata):
    # トークンをカタログに登録
    cti_metadata['tokenAddress'] = token_address
    save_registered_token(cti_metadata)

    contract_path = './src/contracts_data/CTICatalog.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts']['CTICatalog.sol:CTICatalog']
    contract_metadata = json.loads(contract_json['metadata'])
    if contract_metadata:
        abi = contract_metadata['output']['abi']

        register_cti(
            w3,
            catalog_address,
            token_address,
            cti_metadata['uuid'],
            cti_metadata['title'],
            cti_metadata['price'],
            cti_metadata['operator'],
            abi)

        publish_cti(
            w3,
            catalog_address,
            token_address,
            abi)

#/Users/nishino/Projects/metemcyber/node_modules/@openzeppelin/contracts/token/ERC777/ERC777.sol:ERC777

def authorize_operator(token_address, broker_address):
    contract_path = './src/contracts_data/CTIToken.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts']['CTIToken.sol:CTIToken']
    contract_metadata = json.loads(contract_json['metadata'])
    if contract_metadata:
        abi = contract_metadata['output']['abi']

    func = w3.eth.contract(
        address=token_address, abi=abi).functions.authorizeOperator(broker_address)
    tx_hash = func.transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt['status'] != 1:
        raise ValueError('authorize operator: Transaction failed: ')


def consign_token(w3, broker_address, catalog_address, token_address, stock):
    contract_path = './src/contracts_data/CTIBroker.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts']['CTIBroker.sol:CTIBroker']
    contract_metadata = json.loads(contract_json['metadata'])
    if contract_metadata:
        abi = contract_metadata['output']['abi']

    func = w3.eth.contract(address=broker_address, abi=abi).functions.consignToken(
        catalog_address, token_address, int(stock))
    tx_hash = func.transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt['status'] != 1:
        raise ValueError('consign token: transaction failed.')


if __name__ == '__main__':

    args = docopt(__doc__)

    # load config
    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)

    workspace_config = configparser.ConfigParser()
    workspace_config.read(WORKSPACE_CONFIG_INI_FILEPATH)

    misp_config = configparser.ConfigParser()
    misp_config.read(MISP_INI_FILEPATH)

    # make json file list
    if args['--dir']:
        # read json directory
        misp_json_dir = args['--dir']
        misp_json_files = read_dir(misp_json_dir)
        if not misp_json_files:
            exit(f'Error. {misp_json_dir} is not a directory.')
    elif args['<filename>']:
        # read json file
        root, ext = os.path.splitext(args['<filename>'])
        if ext == '.json':
            misp_json_files = [args['<filename>']]
        else:
            exit(f"Error. {args['<filename>']} is not a json file.")
    else:
        # read default json directory
        misp_json_dir = config['general']['misp_json_dumpdir']
        misp_json_files = read_dir(misp_json_dir)
        if not misp_json_files:
            exit(f'Error. {misp_json_dir} is not a directory.')

    # set endpoint
    endpoint = config['general']['endpoint_url']
    w3 = Web3(Web3.HTTPProvider(endpoint))

    # set account
    keyfile_path = config['general']['keyfile']
    my_account_id, my_private_key = decode_keyfile(keyfile_path, w3)
    w3.eth.defaultAccount = my_account_id

    # set token quantity, operators, catalog address
    token_quantity = int(misp_config['MISP']['defaultquantity'])
    operators = workspace_config['operator']['address'].split(',')
    if workspace_config['operator']['address'] == "":
        operators = ['0xe338Eb236dDd7c5485f11DF4CA02522f208c715b']
    catalog_address = workspace_config['catalog']['address']
    if catalog_address == "":
        exit('Error. Failed to get catalog address.')

    # access catalog to get registered uuid list
    registered_uuids = []
    registered_token_uris = list_token_uris(catalog_address)
    for registered_token_uri in registered_token_uris:
        registered_uuid = get_cti_uuid(catalog_address, registered_token_uri)
        if registered_uuid:
            registered_uuids.append(registered_uuid)

    # check PoA
    if w3.isConnected():
        # PoA であれば geth_poa_middleware を利用
        try:
            w3.eth.getBlock('latest')
        except ExtraDataLengthError:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if my_private_key:
            w3.middleware_onion.add(
                construct_sign_and_send_raw_middleware(my_private_key)
            )

    # register json file in the catalog
    for misp_json_file in misp_json_files:
        # check json file
        if not os.path.isfile(misp_json_file):
            exit(f'{misp_json_file} is not a file.')
        else:
            root, ext = os.path.splitext(misp_json_file)
            if not ext == '.json':
                exit(f"{args['<filename>']} is not a json file.")

        # カタログに登録するための関数を実装する

        # create metadata
        cti_metadata = create_metadata(misp_json_file, operators, misp_config)
        # 元のカタログ 0x43402fbc73f7610D00e47060fB1Cae9bCC4fEC72

        if not cti_metadata:
            exit('Error. The CTI already exists in tsvfile.')
        # if cti_metadata['uuid'] in registered_uuids:
        #     exit('Error. The CTI already exists in catalog.')

        # deploy CTI token
        token_address = deploy_CTItoken(w3, token_quantity, operators)
        if not token_address:
            exit('Error. Failed to get token address.')

        register_catalog(w3, catalog_address, token_address, cti_metadata)

        broker_address = workspace_config['broker']['address']
        stock = misp_config['MISP']['default_num_consign']

        # Note: token owner should authorize me as operator in advance.
        authorize_operator(token_address, broker_address)

        consign_token(w3, broker_address, catalog_address,
                      token_address, stock)

        #TODO: brokerに委託する在庫数をオプションで指定できるようにする
