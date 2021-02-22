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

CONFIG_INI_FILEPATH = "metemctl.ini"
WORKSPACE_CONFIG_INI_FILEPATH = "./workspace/config.ini"
MISP_DATAFILE_PATH = os.getenv('MISP_DATAFILE_PATH', './fetched_misp_events')

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

def deploy_CTItoken(w3, token_balance, operators):
    # load compiled smartcontract
    contract_path = './src/contracts_data/CTIToken.combined.json'
    with open(contract_path, 'r') as contract_file:
        contract_json = json.loads(contract_file.read())['contracts']['CTIToken.sol:CTIToken']
    contract_metadata = json.loads(contract_json['metadata'])
    if contract_metadata and token_balance and len(operators) > 0:
        tx_hash = w3.eth.contract(abi=contract_metadata['output']['abi'], bytecode=contract_json['bin']).constructor(token_balance, operators).transact()
        address = w3.eth.waitForTransactionReceipt(tx_hash)['contractAddress']
        print(f'Deployed {contract_path} to: {address}\n')
        return address
    else:
        return None

def read_dir(misp_json_dir):
    if os.path.isdir(misp_json_dir):
        misp_json_path = os.path.join(misp_json_dir, '*.json')
        # get json file list by glob
        return glob.glob(misp_json_path)
    else:
        exit(f'{misp_json_dir} is not a directory.')

if __name__ == '__main__':

    args = docopt(__doc__)

    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)
    
    workspace_config = configparser.ConfigParser()
    workspace_config.read(WORKSPACE_CONFIG_INI_FILEPATH)
    
    if args['--dir']:
        misp_json_dir = args['--dir']
        misp_json_files = read_dir(misp_json_dir)
        
    # get value from key
    elif args['<filename>']:
        misp_json_files = [args['<filename>']]
    else:
        misp_json_dir = config['misp_json_dumpdir']
        misp_json_files = read_dir(misp_json_dir)
    
    # set provider
    endpoint = config['general']['endpoint_url']
    w3 = Web3(Web3.HTTPProvider(endpoint))
    
    # set account
    keyfile_path = config['general']['keyfile']
    my_account_id, my_private_key = decode_keyfile(keyfile_path, w3)
    w3.eth.defaultAccount = my_account_id

    # submit the transaction that deploy the smartcontract
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
    
    for misp_json_file in misp_json_files:
        if not os.path.isfile(misp_json_file):
            exit(f'{misp_json_file} is not a file.')
        #set token_balance and operators
        token_balance = 100
        operators = workspace_config['operator']['address'].split(',')
        if workspace_config['operator']['address'] == "":
            operators = ['0xe338Eb236dDd7c5485f11DF4CA02522f208c715b']
        token_address = deploy_CTItoken(w3, token_balance, operators)
        if not token_address:
            exit('Error. Failed to get token address.')
        
        #TODO: カタログに登録するための関数を実装する
        # register_catalog(catalog_address, token_address, cti_metadata)
        
        




        
        
        
