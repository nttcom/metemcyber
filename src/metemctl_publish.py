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
usage:  metemctl publish [options]
        metemctl publish <filename> [options]
        metemctl publish [--dir <misp_json_dir>] [options]

options:
    -h, --help                          Show this screen.
    -r, --dir <misp_json_dir>           Specify json directory.
    -p, --price <token_price>           Specify token price.
    -q, --quantity <token_quantity>     Specify token quantity.
    -s, --stock <token_stock>           Specify token stock.
    
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


def decode_keyfile(w3, filename):
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


def load_contract(contract_path, contract_key):
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())[
            'contracts'][contract_key]
    contract_metadata = json.loads(contract_json['metadata'])
    return contract_json, contract_metadata


def list_token_uris(w3, catalog_address):
    contract_path = './src/contracts_data/CTICatalog.combined.json'
    contract_key = 'CTICatalog.sol:CTICatalog'
    _, contract_metadata = load_contract(contract_path, contract_key)
    # Note: array contains "" which means unregistered.
    func = w3.eth.contract(address=catalog_address,
                           abi=contract_metadata['output']['abi']).functions.listTokenURIs()
    token_uris = func.call()

    # remove "" element
    return [uri for uri in token_uris if uri != '']


def get_cti_uuid(w3, catalog_address, token_address):
    contract_path = './src/contracts_data/CTICatalog.combined.json'
    contract_key = 'CTICatalog.sol:CTICatalog'
    _, contract_metadata = load_contract(contract_path, contract_key)
    if token_address:
        func = w3.eth.contract(
            address=catalog_address, abi=contract_metadata['output']['abi']).functions.getCtiInfo(token_address)
        _, _, uuid, _, _, _, _ = func.call()
        return uuid
    else:
        return None


def deploy_CTItoken(w3, token_quantity, operators):
    contract_path = './src/contracts_data/CTIToken.combined.json'
    contract_key = 'CTIToken.sol:CTIToken'
    contract_json, contract_metadata = load_contract(
        contract_path, contract_key)
    if contract_metadata and token_quantity and len(operators) > 0:
        func = w3.eth.contract(abi=contract_metadata['output']['abi'], bytecode=contract_json['bin']).constructor(
            token_quantity, operators)
        tx_hash = func.transact()
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        address = tx_receipt['contractAddress']
        # print(f'Deployed {contract_path} to: {address}\n')
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: deploy CTItoken')
        else:
            print('deploy  token: success')
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


def create_metadata(misp_json_file, operators, token_price, token_quantity):
    # get registered token info from "registered_token.tsv"
    registered_token = fetch_registered_token()
    registered_uuid = [token.get('uuid') for token in registered_token]
    metadata = {}
    with open(misp_json_file) as fin:
        misp = json.load(fin)
    uuid = misp['Event']['uuid']
    if uuid in registered_uuid:
        return None
    metadata['uuid'] = uuid
    metadata['title'] = misp['Event']['info']
    metadata['price'] = token_price
    metadata['operator'] = ','.join(operators)
    metadata['quantity'] = token_quantity
    return metadata


def register_cti(w3, catalog_address, token_address, uuid, title, price, operator, abi):
    func = w3.eth.contract(address=catalog_address, abi=abi).functions.registerCti(
        token_address, uuid, title, price, operator)
    tx_hash = func.transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt['status'] != 1:
        raise ValueError('Transaction failed: register CTI')
    else:
        print('register cti : success')


def publish_cti(w3, catalog_address, token_address, abi):
    func = w3.eth.contract(address=catalog_address, abi=abi).functions.publishCti(
        w3.eth.defaultAccount, token_address)
    tx_hash = func.transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt['status'] != 1:
        raise ValueError('Transaction failed: publish CTI')
    else:
        print('publish  cti : success')


def register_catalog(w3, catalog_address, token_address, cti_metadata):
    # register token with catalog
    cti_metadata['tokenAddress'] = token_address
    save_registered_token(cti_metadata)
    contract_path = './src/contracts_data/CTICatalog.combined.json'
    contract_key = 'CTICatalog.sol:CTICatalog'
    _, contract_metadata = load_contract(contract_path, contract_key)
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


def authorize_operator(w3, token_address, broker_address):
    contract_path = './src/contracts_data/CTIToken.combined.json'
    contract_key = 'CTIToken.sol:CTIToken'

    _, contract_metadata = load_contract(contract_path, contract_key)
    # with open(contract_path, 'r') as contract_file:
    #     contract_json = json.loads(contract_file.read())[
    #         'contracts']['CTIToken.sol:CTIToken']
    # contract_metadata = json.loads(contract_json['metadata'])
    if contract_metadata:
        abi = contract_metadata['output']['abi']

        func = w3.eth.contract(
            address=token_address, abi=abi).functions.authorizeOperator(broker_address)
        tx_hash = func.transact()
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: authorize operator')


def consign_token(w3, broker_address, catalog_address, token_address, stock):
    contract_path = './src/contracts_data/CTIBroker.combined.json'
    contract_key = 'CTIBroker.sol:CTIBroker'
    _, contract_metadata = load_contract(contract_path, contract_key)
    if contract_metadata:
        abi = contract_metadata['output']['abi']

        func = w3.eth.contract(address=broker_address, abi=abi).functions.consignToken(
            catalog_address, token_address, stock)
        tx_hash = func.transact()
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        if tx_receipt['status'] != 1:
            raise ValueError('Transaction failed: consign token')
        else:
            print('consign token: success')


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

    # set default price, quantity, stock
    token_price = int(misp_config['MISP']['defaultprice'])
    token_quantity = int(misp_config['MISP']['defaultquantity'])
    token_stock = int(misp_config['MISP']['default_num_consign'])

    if args['--price']:
        token_price = int(args['--price'])
    if args['--quantity']:
        token_quantity = int(args['--quantity'])
    if args['--stock']:
        token_stock = int(args['--stock'])

    output_price = 'token price   :' + str(token_price).rjust(8)
    output_quantity = 'token quantity:' + str(token_quantity).rjust(8)
    output_stock = 'token stock   :' + str(token_stock).rjust(8)

    print("-------------TOKEN INFO-------------")
    print(output_price if args['--price'] else output_price + " (default)")
    print(output_quantity if args['--quantity']
          else output_quantity + " (default)")
    print(output_stock if args['--stock'] else output_stock + " (default)")
    print("------------------------------------")

    # set endpoint
    endpoint = config['general']['endpoint_url']
    w3 = Web3(Web3.HTTPProvider(endpoint))

    # set account
    keyfile_path = config['general']['keyfile']
    if keyfile_path == "":
        exit('Error. Failed to get keyfile path.')
    my_account_id, my_private_key = decode_keyfile(w3, keyfile_path)
    w3.eth.defaultAccount = my_account_id

    # set operators, catalog address
    operators = workspace_config['operator']['address'].split(',')
    if workspace_config['operator']['address'] == "":
        operators = ['0xe338Eb236dDd7c5485f11DF4CA02522f208c715b']
    catalog_address = workspace_config['catalog']['address']
    if catalog_address == "":
        exit('Error. Failed to get catalog address.')

    # access catalog to get registered uuid list
    registered_uuids = []
    registered_token_uris = list_token_uris(w3, catalog_address)
    for registered_token_uri in registered_token_uris:
        registered_uuid = get_cti_uuid(w3, catalog_address, registered_token_uri)
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

    print('')
    print('---PUBLISH START---')
    publish_count = 0

    # register json file in the catalog
    for misp_json_file in misp_json_files:
        # check json file
        if not os.path.isfile(misp_json_file):
            print(f'Error. {misp_json_file} is not a file.')
            continue
        else:
            root, ext = os.path.splitext(misp_json_file)
            if not ext == '.json':
                print(f"Error. {args['<filename>']} is not a json file.")
                continue

        # create metadata
        cti_metadata = create_metadata(
            misp_json_file, operators, token_price, token_quantity)

        # if the CTI already exists, exit
        if not cti_metadata:
            print('Error. ' + 'uuid of the MISP EVENT(' + misp_json_file + ') already exists in "registered_token.tsv".')
            continue
        if cti_metadata['uuid'] in registered_uuids:
            print('Error. ' + 'uuid of the MISP EVENT(' + misp_json_file + ') already exists in the catalog.')
            continue

        print('MISP EVENT: "' +
              cti_metadata['title'] + '"(' + misp_json_file + ')' + ' loaded.')

        # deploy CTI token
        token_address = deploy_CTItoken(w3, token_quantity, operators)
        if not token_address:
            print('Error. Failed to get token address.')
            continue

        # register token with catalog
        register_catalog(w3, catalog_address, token_address, cti_metadata)

        broker_address = workspace_config['broker']['address']

        # broker should be authorized as operator in advance.
        # authorize broker as operator
        authorize_operator(w3, token_address, broker_address)

        # consign token
        consign_token(w3, broker_address, catalog_address,
                      token_address, token_stock)

        print('MISP EVENT: "' +
              cti_metadata['title'] + '"(' + misp_json_file + ')' + ' published.')
        print('')
        publish_count += 1

print('---PUBLISH FINISHED---')
print('')
if publish_count == 0:
    print('publish failed.')
elif publish_count == 1:
    print('1 event is published.')
else:
    print(publish_count + ' events are published.')
