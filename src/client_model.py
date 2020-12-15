#
#    Copyright 2020, NTT Communications Corp.
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

import csv
import json
import logging
import os
from pathlib import Path
from urllib.request import Request, urlopen
import configparser

from requests.exceptions import HTTPError
from eth_utils.exceptions import ValidationError
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import geth_poa_middleware
from web3.middleware import construct_sign_and_send_raw_middleware

from contract import Contracts
from metemcyberutil import MetemcyberUtil
from ctitoken import CTIToken
from cticatalog import CTICatalog
from ctibroker import CTIBroker
from ctioperator import CTIOperator
from seeker import Seeker
from wallet import Wallet
from inventory import Inventory
from plugin import PluginManager
from eventlistener import BasicEventListener

LOGGER = logging.getLogger('common')
GASLOG = logging.getLogger('gaslog')

BROKER_ACCOUNT_ID = os.getenv('BROKER_ACCOUNT_ID', 'broker@test')
CREATOR_ACCOUNT_ID = os.getenv('CREATOR_ACCOUNT_ID', 'creator@test')
OPERATOR_ACCOUNT_ID = os.getenv('OPERATOR_ACCOUNT_ID', 'operator@test')

## MISP_DATAFILE_PATH should be same with JSON_DUMPDIR in fetch_misp_events.sh.
MISP_DATAFILE_PATH = os.getenv(
    'MISP_DATAFILE_PATH', './fetched_misp_events')
## FILESERVER_ASSETS_PATH should be a directory file server controls.
FILESERVER_ASSETS_PATH = os.getenv(
    'FILESERVER_ASSETS_PATH', './workspace/dissemination')
## DOWNLOADED_CTI_PATH should be different from MISP_DATAFILE_PATH.
DOWNLOADED_CTI_PATH = os.getenv(
    'DOWNLOADED_CTI_PATH', './download')
## the directory where plugins are placed
PLUGINS_PATH = os.getenv('PLUGINS_PATH', './src/plugins')

ERC1820_RAW_TX_FILEPATH = './src/erc1820.tx.raw'
CONFIG_INI_FILEPATH = './workspace/config.ini'
MISP_INI_FILEPATH = './workspace/misp.ini'
TRUSTED_USERS_TSV = './workspace/trusted_users.tsv'
REGISTERED_TOKEN_TSV = './workspace/registered_token.tsv'
MAX_HISTORY_NUM = 5


def uuid_formatter(unformatted_uuid):
    if len(unformatted_uuid) != 32:
        return ''
    return unformatted_uuid[0:8] + '-' + unformatted_uuid[8:12] + '-' + \
        unformatted_uuid[12:16] + '-' + \
        unformatted_uuid[16:20] + '-' + unformatted_uuid[20:]


def uuid_to_asset_id(formatted_uuid):
    if len(formatted_uuid) != 36:
        raise ValueError("The uuid cannot translation.")
    return formatted_uuid.replace('-', '')+'#test'


class Player():

    def __init__(self, account_id, private_key, provider, dev=False):
        self.plugin = PluginManager()
        self.plugin.load(PLUGINS_PATH)
        self.plugin.set_default_solverclass('gcs_solver.py')

        self.dev = dev
        self.account_id = account_id
        self.web3 = Web3(provider)
        self.interest = ''
        self.trusted_users = []
        self.web3.eth.defaultAccount = account_id

        # PoA であれば geth_poa_middleware を利用
        try:
            self.web3.eth.getBlock("latest")
        except ExtraDataLengthError:
            self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        if private_key:
            self.web3.middleware_onion.add(
                construct_sign_and_send_raw_middleware(private_key))
        self.deploy_erc1820()

        self.__observer = None
        self.__state = None
        self.assets = None
        # Wallet の情報
        self.wallet = Wallet(self.web3, self.account_id)

        # オペレータ(トークンの交換などを担当)のコントラクト
        self.operator_address = None
        self.load_config()

        self.operator_address = self._fix_config_address(
            self.config['operator']['address'])
        if self.config['operator']['solver_pluginfile']:
            self.plugin.set_solverclass(
                self.operator_address,
                self.config['operator']['solver_pluginfile'])

        self.contracts = Contracts(self.web3)
        self.deploy_metemcyberutil()

        self.fetch_trusted_users()

        self.event_listener = BasicEventListener('')
        self.event_listener.start()

        # inventory (トークン・カタログの管理)のインスタンス生成
        catalog_address = self._fix_config_address(
            self.config['catalog']['address'])
        broker_address = self._fix_config_address(
            self.config['broker']['address'])
        self.inventory = Inventory(
            self.contracts, self.account_id,
            self.event_listener, catalog_address, broker_address)

        # Seeker (チャレンジの依頼者)のインスタンス
        self.seeker = Seeker(self.contracts)

        # Solver (チャレンジの受領者)としてのインスタンス
        if self.operator_address:
            solverclass = self.plugin.get_solverclass(self.operator_address)
            self.solver = solverclass(
                self.contracts, self.account_id, self.operator_address)
        else:
            self.solver = None

        # MISP設定のinsert
        self.load_misp_config(MISP_INI_FILEPATH)

    def deploy_erc1820(self):
        # ERC777を利用するにはERC1820が必要
        # https://github.com/ConsenSys/ERC1400/blob/master/migrations/2_erc1820_registry.js
        deployer_address = '0xa990077c3205cbDf861e17Fa532eeB069cE9fF96'
        contract_address = Web3.toChecksumAddress(
            '0x1820a4b7618bde71dce8cdc73aab6c95905fad24')
        code = self.web3.eth.getCode(contract_address)
        LOGGER.debug('erc1820_address has %s', code)

        if code:
            return

        try:
            #指定のアドレスへ送金
            tx_hash = self.web3.eth.sendTransaction({
                'from': self.account_id,
                'to': deployer_address,
                'value': self.web3.toWei('0.1', 'ether')})
            tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
            GASLOG.info(
                'erc1820.sendTransaction: gasUsed=%d', tx_receipt['gasUsed'])
            if tx_receipt['status'] != 1:
                raise ValueError('erc1820.sendTransaction failed')
            LOGGER.debug(tx_receipt)
        except (HTTPError, ValueError, ValidationError) as err:
            LOGGER.error(err)
            raise ValueError('Sending Ether for ERC1820 failed') from err

        try:
            #ERC1820のデプロイ
            with open(ERC1820_RAW_TX_FILEPATH, 'r') as fin:
                raw_tx = fin.read().strip()
            tx_hash = self.web3.eth.sendRawTransaction(raw_tx)
            tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
            GASLOG.info(
                'erc1820.sendRawTransaction: gasUsed=%d',
                tx_receipt['gasUsed'])
            if tx_receipt['status'] != 1:
                raise ValueError('erc1820.sendRawTransaction failed')
            LOGGER.debug(tx_receipt)
        except (HTTPError, ValueError, ValidationError) as err:
            LOGGER.error(err)
            raise ValueError('Sending ERC1820 raw transaction failed') from err

    def deploy_metemcyberutil(self):
        metemcyber_util = self.contracts.accept(MetemcyberUtil())
        if not self.config['metemcyber_util']['address']:
            self.config['metemcyber_util']['address'] = \
                metemcyber_util.new().contract_address
        placeholder = metemcyber_util.register_library(
            self.config['metemcyber_util']['address'],
            self.config['metemcyber_util']['placeholder'])
        if placeholder != self.config['metemcyber_util']['placeholder']:
            self.config['metemcyber_util']['placeholder'] = placeholder
            self.save_config()

    def _fix_config_address(self, target):
        if self.web3.isChecksumAddress(target):
            return target
        if self.web3.isAddress(target):
            return self.web3.toChecksumAddress(target)
        return None

    def load_config(self):
        # コントラクトのアドレスを設定ファイルから読み込む
        fname = CONFIG_INI_FILEPATH
        config = configparser.ConfigParser()
        config.add_section('catalog')
        config.set('catalog', 'address', '')
        config.add_section('broker')
        config.set('broker', 'address', '')
        config.add_section('operator')
        config.set('operator', 'address', '')
        config.set('operator', 'owner', '')
        config.set('operator', 'solver_pluginfile', '')
        config.add_section('metemcyber_util')
        config.set('metemcyber_util', 'address', '')
        config.set('metemcyber_util', 'placeholder', '')
        if not os.path.exists(fname):
            self.config = config
            return

        config.read(fname)
        self.config = config
        LOGGER.info('[load config]')
        LOGGER.info('catalog address: %s', config['catalog']['address'])

    def save_config(self):
        if hasattr(self, 'inventory') and self.inventory:
            catalog = 'catalog'
            if not self.config.has_section(catalog):
                self.config.add_section(catalog)
            self.config.set(
                catalog, 'address', self.inventory.catalog_address)

            broker = 'broker'
            if not self.config.has_section(broker):
                self.config.add_section(broker)
            self.config.set(
                broker, 'address', self.inventory.broker_address)

        operator = 'operator'
        if not self.config.has_section(operator):
            self.config.add_section(operator)
        self.config.set(
            operator, 'address',
            self.operator_address if self.operator_address else '')
        self.config.set(
            operator, 'owner', self.account_id if self.account_id else '')
        if self.plugin and self.operator_address:
            fname = self.plugin.get_plugin_filename(self.operator_address)
            self.config.set(
                operator, 'solver_pluginfile', fname if fname else '')

        with open(CONFIG_INI_FILEPATH, 'w') as fout:
            self.config.write(fout)
            LOGGER.info('update config.')

    def load_misp_config(self, fname):
        # MISPに関する設定を設定ファイルから読み取る
        self.default_price = -1
        self.default_quantity = -1
        self.default_num_consign = -1
        self.default_auto_accept = False
        if not os.path.exists(fname):
            return
        config = configparser.ConfigParser()
        config.read(fname)
        try:
            self.default_price = config["MISP"].getint("defaultprice")
            self.default_quantity = config["MISP"].getint("defaultquantity")
            self.default_num_consign = config["MISP"].getint(
                "default_num_consign")
            self.default_auto_accept = config['MISP'].getboolean(
                'default_auto_accept')
            LOGGER.info('[load MISP config]')
        except KeyError as err:
            LOGGER.warning('MISP configファイルの読み込みに失敗しました')
            LOGGER.warning(err)

    @staticmethod
    def uuid_to_filepath(uuid):
        return os.path.abspath('{}/{}.json'.format(MISP_DATAFILE_PATH, uuid))

    @staticmethod
    def tokenaddress_to_filepath(address):
        return os.path.abspath('{}/{}'.format(FILESERVER_ASSETS_PATH, address))

    def add_observer(self, observer):
        self.__observer = observer

    def notify_observer(self):
        self.__observer.update(self)

    @property
    def state(self):
        return self.__state

    @state.setter
    def state(self, state):
        self.__state = state
        # Stateと同じ名前の関数があれば自動実行
        if state in dir(self):
            getattr(self, state)()
        self.notify_observer()

    def setup_inventory(
            self, catalog_address='', broker_address='', is_private=False):
        if catalog_address == '':
            catalog_address = self.contracts.accept(CTICatalog()).\
                new(is_private).contract_address
            LOGGER.info('deployed CTICatalog. address: %s', catalog_address)
        if broker_address == '':
            broker_address = self.contracts.accept(CTIBroker()).\
                new().contract_address
            LOGGER.info('deployed CTIBroker. address: %s', broker_address)

        if self.inventory:
            self.inventory.switch_catalog(catalog_address)
            self.inventory.switch_broker(broker_address)
        else:
            # inventory インスタンスの作成
            self.inventory = Inventory(
                self.contracts, self.account_id, catalog_address,
                broker_address)

        self.save_config()

    def create_token(self, initial_supply, default_operators=None):
        # CTIトークンとなるERC777トークンの発行
        ctitoken = self.contracts.accept(CTIToken()).new(
            initial_supply, default_operators if default_operators else [])
        return ctitoken.contract_address

    def accept_as_solver(self, view=None):
        LOGGER.info('accept as solver')
        if not self.inventory or not self.solver:
            return
        own_tokens = self.inventory.list_own_tokens(self.account_id)
        if len(own_tokens) == 0:
            return
        self.solver.accept_challenges(own_tokens, view=view)
        self.solver.reemit_pending_tasks()

    def setup_operator(
            self, operator_address='', solver_pluginfile='', view=None):
        if operator_address == self.operator_address:
            return

        if solver_pluginfile and \
                not self.plugin.is_pluginfile(solver_pluginfile):
            raise Exception('invalid plugin file: ' + solver_pluginfile)

        old_operator_address = self.operator_address
        if operator_address == '':
            # オペレータのデプロイ
            ctioperator = self.contracts.accept(CTIOperator())
            operator_address = ctioperator.new().contract_address
            ctioperator.set_recipient()

        if solver_pluginfile:
            self.plugin.set_solverclass(operator_address, solver_pluginfile)

        if operator_address != old_operator_address:
            if self.solver:
                self.solver.destroy()
            if operator_address:
                solverclass = self.plugin.get_solverclass(operator_address)
                self.solver = solverclass(
                    self.contracts, self.account_id, operator_address)
            else:
                self.solver = None

        self.operator_address = operator_address
        self.save_config()

        if self.solver:
            self.accept_as_solver(view)

    def buy(self, token_address):
        # トークンの購買処理の実装
        self.inventory.buy(token_address, allow_cheaper=True)

    def disseminate_token_from_mispdata(
            self, default_pirce, default_quantity, default_num_consign,
            default_auto_accept, view):
        # mispオブジェクトファイルの一覧をtokenとして公開する

        # 登録済みのtokenを取得
        registered_token = self.fetch_registered_token()
        registered_uuid = [token.get('uuid') for token in registered_token]
        for obj_path in Path(MISP_DATAFILE_PATH).glob("./*.json"):
            # UUID (ファイル名から拡張子を省いた部分) を取得
            uuid = obj_path.stem
            if uuid in registered_uuid:
                continue
            metadata = {}
            with open(obj_path) as fin:
                misp = json.load(fin)
            try:
                view.vio.print(
                    'disseminating CTI: \n'
                    '  UUID: ' + uuid + '\n'
                    '  TITLE: ' + misp['Event']['info'] + '\n'
                    )
                metadata['uuid'] = uuid
                metadata['title'] = misp['Event']['info']
                metadata['price'] = default_pirce
                metadata['operator'] = self.operator_address
                metadata['quantity'] = default_quantity
                token_address = self.disseminate_new_token(
                    metadata, default_num_consign)
                if default_auto_accept:
                    self.accept_challenge(token_address, view)
            except KeyError:
                LOGGER.warning('There is no Event info in %s', misp)

    def disseminate_new_token(self, cti_metadata, num_consign=0):
        # ERC20/777 トークンを、独自トークンとして発行する
        # CTIトークンを作成
        token_address = self.create_token(cti_metadata['quantity'])

        # カタログに登録して詳細をアップデート
        self.disseminate_token(token_address, cti_metadata)

        if num_consign > 0:
            self.inventory.consign(token_address, num_consign)

        return token_address

    def disseminate_token(self, token_address, cti_metadata):
        # トークンをカタログに登録

        cti_metadata['tokenAddress'] = token_address
        self.create_asset_content(cti_metadata)
        self.register_catalog(token_address, cti_metadata)
        self.save_registered_token(cti_metadata)

    def create_asset_content(self, cti_metadata):
        misp_filepath = self.uuid_to_filepath(cti_metadata['uuid'])
        dist_linkpath = self.tokenaddress_to_filepath(
            cti_metadata['tokenAddress'])

        ## create a simple placeholder if MISP file does not exist.
        if not os.path.isfile(misp_filepath):
            LOGGER.warning('MISP file does not exist: %s', misp_filepath)
            os.makedirs(os.path.dirname(misp_filepath), exist_ok=True)
            ## simple placeholder with title. is this redundant?
            j = json.loads('{"Event":{"info": ""}}')
            j['Event']['info'] = cti_metadata['title']
            with open(misp_filepath, 'w') as fout:
                json.dump(j, fout, indent=2, ensure_ascii=False)
            LOGGER.warning(
                'created a simple placeholder. '
                'please overwrite the file above.')

        dist_dir = os.path.dirname(dist_linkpath)
        if not os.path.isdir(dist_dir):
            os.makedirs(dist_dir)
            LOGGER.warning(
                'created missing directory for disseminate: %s', dist_dir)
        try:
            os.symlink(misp_filepath, dist_linkpath)
        except FileExistsError:
            LOGGER.error('disseminate link already exists: %s', dist_linkpath)

    def register_catalog(self, token_address, cti_metadata):
        self.inventory.register_token(
            self.account_id, token_address, cti_metadata)

    def unregister_catalog(self, token_address):
        self.inventory.unregister_token(token_address)

    def update_catalog(self, token_address, cti_metadata):
        self.inventory.modify_token(token_address, cti_metadata)

    @staticmethod
    def save_registered_token(cti_metadata):
        # cticatalog コントラクトに登録したtokenのmetadataを保存する
        fieldnames = [
            'uuid', 'tokenAddress', 'title', 'price', 'operator', 'quantity']

        is_empty = not os.path.isfile(REGISTERED_TOKEN_TSV)

        with open(REGISTERED_TOKEN_TSV, 'a', newline='') as tsvfile:
            writer = csv.DictWriter(
                tsvfile, fieldnames=fieldnames, extrasaction='ignore',
                delimiter='\t')
            if is_empty:
                writer.writeheader()
            writer.writerow(cti_metadata)

    @staticmethod
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

    def consign(self, token_address, amount):
        self.inventory.consign(token_address, amount)

    def takeback(self, token_address, amount):
        self.inventory.takeback(token_address, amount)

    def watch_token_start(self, token_address, callback):
        ctitoken = self.contracts.accept(CTIToken()).get(token_address)
        argument_filters = dict()
        argument_filters['from'] = self.operator_address
        argument_filters['to'] = self.account_id
        event_filter = ctitoken.event_filter(
            'Sent', fromBlock='latest', argument_filters=argument_filters)
        self.event_listener.add_event_filter(
            'Sent:'+token_address, event_filter, callback)

    def watch_token_stop(self, token_address):
        self.event_listener.remove_event_filter_in_callback(
            'Sent:'+token_address)

    def request_challenge(self, token_address, data=''):
        # token_address のトークンに対してチャレンジを実行
        if self.seeker.challenge(
                self.operator_address, token_address, data=data):
            # トークン送付したので情報更新する
            self.inventory.update_balanceof_myself(token_address)

    def receive_challenge_answer(self, data):
        try:
            # data is generated at Solver.webhook().
            download_url = data['download_url']
            token_address = data['token_address']
            if len(download_url) == 0 or len(token_address) == 0:
                raise Exception('received empty data')
        except:
            msg = '受信データの解析不能: ' + str(data)
            return False, msg

        msg = ''
        msg += '受信 URL: ' + download_url + '\n'
        msg += 'トークン: ' + token_address + '\n'

        try:
            request = Request(download_url, method="GET")
            with urlopen(request) as response:
                rdata = response.read()
        except Exception as err:
            LOGGER.error(err)
            msg += \
                'チャレンジ結果を受信しましたが、受信URLからの' + \
                'ダウンロードに失敗しました: ' + str(err) + '\n'
            msg += '手動でダウンロードしてください\n'
            msg += '\n'
            msg += self._save_download_url(token_address, download_url)
            return True, msg

        try:
            jdata = json.loads(rdata)
            title = jdata['Event']['info']
        except:
            title = '（解析できませんでした）'
        msg += '取得データタイトル: ' + title + '\n'

        try:
            if not os.path.isdir(DOWNLOADED_CTI_PATH):
                os.makedirs(DOWNLOADED_CTI_PATH)
            filepath = '{}/{}.json'.format(DOWNLOADED_CTI_PATH, token_address)
            with open(filepath, 'wb') as fout:
                fout.write(rdata)
            msg += '取得データを保存しました: ' + filepath + '\n'
        except Exception as err:
            msg += '取得データの保存に失敗しました: ' + str(err) + '\n'
            msg += '手動で再取得してください\n'
            msg += '\n'
            msg += self._save_download_url(token_address, download_url)
        return True, msg

    @staticmethod
    def _save_download_url(token_address, download_url):
        try:
            if not os.path.isdir(DOWNLOADED_CTI_PATH):
                os.makedirs(DOWNLOADED_CTI_PATH)
            filepath = '{}/{}.url'.format(
                DOWNLOADED_CTI_PATH, token_address)
            with open(filepath, 'w') as fout:
                fout.write(download_url)
            msg = 'ダウンロードURLを保存しました: ' + filepath + '\n'
        except Exception as err:
            msg = 'ダウンロードURLの保存に失敗しました: ' + str(err) + '\n'
        return msg

    def cancel_challenge(self, task_id):
        assert self.operator_address
        self.seeker.cancel_challenge(self.operator_address, task_id)

    def fetch_task_id(self, token_address):
        token_related_task = self.contracts.accept(CTIOperator()).\
            get(self.operator_address).history(token_address, MAX_HISTORY_NUM)
        # 最新の一つのみを表示
        task_id = token_related_task[0]
        return task_id

    def fetch_trusted_users(self):
        # 信頼済みユーザのfetch
        trusted_users = []
        try:
            with open(TRUSTED_USERS_TSV, newline='') as tsvfile:
                tsv = csv.DictReader(tsvfile, delimiter='\t')
                for row in tsv:
                    try:
                        row['id'] = Web3.toChecksumAddress(row['id'])
                    except:
                        continue
                    if row['id'] == self.account_id:
                        continue
                    trusted_users.append(row['id'])
                self.trusted_users = trusted_users
        except FileNotFoundError:
            pass
        except Exception as err:
            LOGGER.error(err)

    def interest_assets(self):
        if not self.interest:
            return self.inventory.catalog_tokens

        filtered_assets = filter(
            lambda x: self.interest in x[1]['title'],
            self.inventory.catalog_tokens.items())

        return dict(filtered_assets)

    def accept_challenge(self, token_address, view=None):
        LOGGER.info('accept_challenge token: %s', token_address)
        self.solver.accept_challenges([token_address], view=view)

    def refuse_challenge(self, token_address):
        LOGGER.info('refuse_challenge token: %s', token_address)
        self.solver.refuse_challenges([token_address])

    def like_cti(self, token_address):
        assert self.inventory
        self.inventory.like_cti(token_address)

    def get_like_users(self):
        try:
            return self.inventory.like_users
        except:
            return dict()

    def send_token(self, token_address, target_address, amount):
        assert token_address and target_address and amount > 0
        self.contracts.accept(CTIToken()).get(token_address).\
            send_token(target_address, amount=amount, data='')
        # ブローカー経由でないためイベントは飛ばない。手動で反映する。
        self.inventory.update_balanceof_myself(token_address)

    def burn_token(self, token_address, amount, data=''):
        assert token_address and amount > 0
        self.contracts.accept(CTIToken()).get(token_address).\
            burn_token(amount, data)
        # Burned イベントが飛ぶがキャッチしていない。手動で反映する。
        self.inventory.update_balanceof_myself(token_address)
