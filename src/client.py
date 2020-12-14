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

import argparse
import logging
import os
import sys
import signal
import atexit
import json
from getpass import getpass
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from web3.providers.rpc import HTTPProvider
from web3.auto import w3
from eth_utils.exceptions import ValidationError
from eth_tester import PyEVMBackend, EthereumTester
from requests.exceptions import HTTPError
from webhook import WebhookReceiver

from client_model import Player
from client_ui import SimpleCUI, ViewerIO

if sys.version_info[0] < 3:
    raise Exception('Python 3 or a more recent version is required.')

## following defaults are valid (maybe only) with EthereumTesterProvider.
ALICE_ACCOUNT_ID = Web3.toChecksumAddress(os.getenv(
    'ALICE_EOA_ADDRESS', '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf'))
BOB_ACCOUNT_ID = Web3.toChecksumAddress(os.getenv(
    'BOB_EOA_ADDRESS', '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF'))
CAROL_ACCOUNT_ID = Web3.toChecksumAddress(os.getenv(
    'CAROL_EOA_ADDRESS', '0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69'))
ALICE_PRIVATE_KEY = os.getenv('ALICE_PRIVATE_KEY', '{:064x}'.format(1))
BOB_PRIVATE_KEY = os.getenv('BOB_PRIVATE_KEY', '{:064x}'.format(2))
CAROL_PRIVATE_KEY = os.getenv('CAROL_PRIVATE_KEY', '{:064x}'.format(3))

GAS_LOGGING_FILEPATH_FORMAT = './workspace/gasUsed.{user}.log'
GASLOG = logging.getLogger('gaslog')
LOGGER = logging.getLogger('common')

GENERIC_CAUTION = \
    'Make sure the EOA address and private key pair is correct ' \
    'and you have enough Ether to operate. ' \
    'You can check your Ether balance from the menu [1].'
PRIVATE_CATALOG_CAUTION = \
    'To buy tokens from private catalog, make sure you ' \
    'have been authorized by the catalog owner.'


class FileViewerIO(ViewerIO):
    def __init__(self, input_file=None, output_file=None):
        if input_file:
            self.infile = open(input_file, 'r')
            atexit.register(print, 'closing input file', input_file)
            atexit.register(self.infile.close)
        else:
            self.infile = sys.stdin
        if output_file:
            self.outfile = open(output_file, 'w')
            atexit.register(print, 'closing output file', output_file)
            atexit.register(self.outfile.close)
        else:
            self.outfile = sys.stdout

    def print(self, *args, **kwargs):
        if 'file' in kwargs.keys():
            del kwargs['file']
        print(*args, **kwargs, file=self.outfile)

    def pager_reset(self):
        pass

    def pager_cancel_quit(self):
        pass

    def pager_print(self, *args, **kwargs):
        return self.print(*args, **kwargs)

    def input(self):
        if self.infile == sys.stdin:
            return input()
        pycommand_prefix = '#:pycode:'
        while True:
            command = self.infile.readline().rstrip('\n\r')
            if command.startswith(pycommand_prefix):
                try:
                    pycode = command[len(pycommand_prefix):]
                    exec(pycode)
                except Exception as err:
                    LOGGER.error('ERROR pycode failed: %s: %s', pycode, err)
                continue
            return command


class Controller():
    def __init__(
            self, account_id, private_key, provider, dev=False, vio=None,
            hookurl=None):
        self.view = SimpleCUI(vio)
        self.dev = dev
        self.provider = provider
        self.state = None
        self.hookurl = hookurl

        self.view.vio.print(
            '\n'
            'connecting to Ethereum Blockchain...\n'
            'Endpoint: ' + str(provider) + '\n'
            'EoA address: ' + account_id)

        try:
            self.model = Player(
                account_id, private_key, self.provider, dev=dev)
        except (HTTPError, ValueError, ValidationError) as err:
            LOGGER.error(err)
            self.view.vio.print(
                'Initialization failed. '
                'Make sure the EOA address and private key pair is correct '
                'and you have enough Ether to operate.')
            sys.exit(255)

        self.model.add_observer(self.view)

        # observerに通知してセットアップ
        self.model.state = 'initalize'

        self.model.accept_as_solver(self.view)

    def menu(self, command=None):
        if command:
            self.state = self.view.num_command(command)
        else:
            self.state = self.view.menu_selector()

        if self.state == 'exit':
            signal.raise_signal(signal.SIGINT)

        try:
            self.model.state = self.state

            if hasattr(self, self.state):
                getattr(self, self.state)()
            elif self.state not in {
                    None, 'initialize', 'exit', 'account_info'}:
                LOGGER.warning('cannot find attr for state: %s', self.state)
        except HTTPError as err:
            LOGGER.error(err)
            errmsg = str(err)
            if errmsg.startswith('400 Client Error: Bad Request for url: '):
                self.view.vio.print('Operation failed. ' + GENERIC_CAUTION)
            else:
                self.view.vio.print(
                    'HTTP error occurred. Check the network conditions.')
        except (ValueError, ValidationError) as err:
            # short of Ether, permission denied, or reverted. maybe...
            LOGGER.error(err)
            self.view.vio.print('Operation failed. ' + GENERIC_CAUTION)

    def exit_handler(self, _signum, __):
        LOGGER.info('exiting process')
        if self.model and self.model.solver:
            self.model.solver.destroy()
        if self.model and self.model.inventory:
            self.model.inventory.destroy()

        sys.exit(os.EX_OK)

    def shopping(self):
        while True:
            address, asset = self.view.token_selector(mode='catalog')
            if not address:
                return
            if not self.view.confirm(asset):
                continue

            caution = 'Operation failed.'
            try:
                self.model.buy(address)
                continue

            except HTTPError as err:
                LOGGER.error(err)
                emsg = str(err)
                if emsg.startswith('400 Client Error: Bad Request for url: '):
                    caution += ' ' + GENERIC_CAUTION
                    caution += self._private_catalog_caution()
                else:
                    caution = \
                        'HTTP error occurred. Check the network conditions.'
            except ValueError as err:
                LOGGER.error(err)
                caution += ' ' + GENERIC_CAUTION
                caution += self._private_catalog_caution()
            self.view.vio.print(caution)
            break

    def _private_catalog_caution(self):
        try:
            if self.model.inventory.is_catalog_private():
                return '\n' +\
                    'In addition, connecting catalog is private mode. ' +\
                    PRIVATE_CATALOG_CAUTION
        except:
            pass  # in this case, authentication may not be the error reason.
        return ''

    def dissemination(self):
        if not self.model.inventory.catalog_address:
            self.view.missing_screen('カタログ')
            return
        if not self.model.inventory.broker_address:
            self.view.missing_screen('ブローカー')
            return
        if not self.model.operator_address:
            self.view.missing_screen('オペレータ')
            return
        context, num_consign = self.view.new_asset()
        accept_now = self.view.select_yes_no_screen(
            hint='チャレンジ受付を開始しますか？')

        assert context
        token_address = self.model.disseminate_new_token(context, num_consign)
        self.view.vio.print('CTIトークンを発行しました: ' + token_address)
        if accept_now:
            self.model.accept_challenge(token_address, view=self.view)
        else:
            self.view.vio.print(
                'チャレンジ受付を開始するには client の再起動、もしくは'
                'メニューから「チャレンジの受付」を実行してください')

    def broker(self):
        catalog_address = self.view.input_address_screen(
            'カタログコントラクトアドレス', hint='新規作成')
        if catalog_address is None:
            return
        broker_address = self.view.input_address_screen(
            'ブローカーコントラクトアドレス', hint='新規作成')
        if broker_address is None:
            return
        is_private = self.view.select_yes_no_screen(
            hint='プライベートカタログとして作成しますか？')
        self.model.setup_inventory(catalog_address, broker_address, is_private)
        self.view.setup_broker_done(
            self.model.inventory.catalog_address,
            self.model.inventory.broker_address)

    def challenge(self):
        address, _asset = self.view.token_selector(mode='token_holder')
        if not address:
            return

        # webhook受付時のcallbackの指定
        WebhookReceiver.set_callback(self.webhook_callback)
        if self.hookurl:
            hookurl = self.hookurl
        else:
            hookurl = WebhookReceiver.get_url(address)

        self.model.watch_token_start(address, self.token_returned)
        self.model.request_challenge(address, data=hookurl)
        result = self.model.fetch_task_id(address)
        self.view.start_challenge(result)

    def token_returned(self, event):
        assert self.model.inventory
        token_address = event['address']
        self.view.vio.print(
            'チャレンジトークンが返還されました: ' + token_address)
        if event['args']['data']:
            self.view.vio.print(
                'メッセージが添付されています: ' +
                event['args']['data'].decode('utf-8'))
        self.model.inventory.update_balanceof_myself(token_address)
        self.model.watch_token_stop(token_address)

    def webhook_callback(self, data):
        judge, msg = self.model.receive_challenge_answer(data)
        if judge:
            self.view.challenge_successful(msg)
        else:
            self.view.challenge_failed(msg)

    def challenge_acception(self):
        address, _asset = self.view.token_selector(mode='token_publisher')
        if not address:
            return
        action = self.view.challenge_action_selector()
        if not action:
            return
        if action == 'accept_challenge':
            self.model.accept_challenge(address, view=self.view)
        elif action == 'refuse_challenge':
            self.model.refuse_challenge(address)
        else:
            raise Exception('Internal Error')

    def like(self):
        while True:
            address, _asset = self.view.token_selector(mode='like')
            if address:
                self.model.like_cti(address)
                continue
            break

    def init_like_users(self):
        search_blocks = self.view.init_like_users_screen()
        if search_blocks is None:
            return
        self.model.inventory.init_like_users(search_blocks=search_blocks)

    def disseminate_mispdata(self):
        err = None
        if self.model.default_price < 0 \
                or self.model.default_quantity < 0 \
                or self.model.default_num_consign < 0:
            err = '設定値（価格・発行数・委託数）が不正です'
        elif not (self.model.inventory and
                  self.model.inventory.catalog and
                  self.model.inventory.broker):
            err = 'カタログ・ブローカーが未設定です'
        elif not self.model.operator_address:
            err = 'オペレータが未設定です'
        if err is not None:
            self.view.vio.print(
                err + '\n'
                'CTI の自動発行に失敗しました')
            return
        self.model.disseminate_token_from_mispdata(
            self.model.default_price, self.model.default_quantity,
            self.model.default_num_consign, self.view)

    def publish_misp(self):
        if not self.model.inventory:
            self.view.missing_screen('インベントリ')
            return
        if not self.model.inventory.catalog_address:
            self.view.missing_screen('カタログ')
            return
        if not self.model.inventory.broker_address:
            self.view.missing_screen('ブローカー')
            return
        if not self.model.operator_address:
            self.view.missing_screen('オペレータ')
            return

        price, quantity, num_consign = self.view.publish_misp_param()
        if price is not None and price >= 0 and quantity > 0:
            self.model.disseminate_token_from_mispdata(
                price, quantity, num_consign, self.view)

    ## temporal func to hide 'send' from menu.
    def burn_own_token(self):
        hook = lambda: self.view.vio.pager_print(
            '廃棄するトークンを選択してください')
        token_address, asset = self.view.token_selector(
            mode='token_holder', hook=hook)
        if not token_address:
            return
        amount = self.view.input_int_screen(
            minimum=1, maximum=asset['balanceOfUser'])
        if amount is None:
            return
        self.model.burn_token(token_address, amount)

    ## currently unused. we don't permit send token.
    def treat_own_token(self):
        hook = lambda: self.view.vio.pager_print(
            '操作するトークンを選択してください')
        token_address, asset = self.view.token_selector(
            mode='token_holder', hook=hook)
        if not token_address:
            return
        act = self.view.select_token_act_screen()
        if not act:
            return
        amount = self.view.input_int_screen(
            minimum=1, maximum=asset['balanceOfUser'])
        if amount is None:
            return
        if act == 'send':
            target = self.view.input_address_screen()
            if not target:
                return
            self.model.send_token(token_address, target, amount)
        elif act == 'burn':
            self.model.burn_token(token_address, amount)
        else:
            raise Exception('Internal Error')

    def dealing(self):
        hook = lambda: self.view.vio.pager_print(
            '取引するトークンを選択してください')
        token_address, asset = self.view.token_selector(
            mode='token_publisher', hook=hook)
        if not token_address:
            return
        act = self.view.select_dealing_act_screen()
        if not act:
            return
        if act == 'unregister':
            self.model.refuse_challenge(token_address)
            self.model.unregister_catalog(token_address)
            return
        if act == 'consign':
            max_amount = asset['balanceOfUser']
            deal_func = self.model.consign
        elif act == 'takeback':
            max_amount = asset['quantity']
            deal_func = self.model.takeback
        amount = self.view.input_int_screen(minimum=1, maximum=max_amount)
        if amount is None:
            return
        deal_func(token_address, amount)

    def modify_asset(self):
        hook = lambda: self.view.vio.pager_print(
            'パラメータ変更するトークンを選択してください')
        token_address, asset = self.view.token_selector(
            mode='token_publisher', hook=hook)
        if not token_address:
            return
        new_asset = self.view.modify_asset_screen(token_address, asset)
        if new_asset is None:
            return
        self.model.update_catalog(token_address, new_asset)

    def cancel_task(self):
        if not self.model.operator_address:
            self.view.missing_screen('オペレータ')
            return
        tasks = self.model.seeker.list_tasks(
            self.model.operator_address, self.model.inventory.catalog_tokens)
        task_id = self.view.task_selector(tasks, state={'Pending'})
        if task_id is None:
            return
        try:
            self.model.cancel_challenge(task_id)
            self.view.cancel_challenge_done(task_id)
        except:
            self.view.common_failed(
                ext_msg='操作中にタスクの状態が変化した可能性があります')

    def list_all_tasks(self):
        if not self.model.operator_address:
            self.view.missing_screen('オペレータ')
            return
        tasks = self.model.seeker.list_tasks(
            self.model.operator_address, self.model.inventory.catalog_tokens)
        _task_id = self.view.task_selector(tasks)
        ## do nothing

    def operator(self):
        operator_address = self.view.input_address_screen(
            'オペレータコントラクトアドレス', hint='新規作成',
            ext_delimiter='@')
        if operator_address is None:
            return

        # FIXME: plugin 管理はもう少しちゃんとやろう
        tmp = operator_address.split('@', 1)
        if len(tmp) == 2:
            [operator_address, solver_pluginfile] = tmp
        else:
            solver_pluginfile = ''
        try:
            self.model.setup_operator(
                operator_address, solver_pluginfile, self.view)
            self.view.setup_operator_done(self.model.operator_address)
        except Exception as err:
            self.view.common_failed(str(err))

    def restore_disseminate(self):
        if not self.model.inventory:
            self.view.missing_screen('インベントリ')
            return
        if not self.model.inventory.catalog_address:
            self.view.missing_screen('カタログ')
            return
        callback = self.model.create_asset_content
        self.model.inventory.restore_disseminate(
            self.model.account_id, callback, view=self.view)

    def catalog_settings(self):
        if not self.model.inventory:
            self.view.missing_screen('インベントリ')
            return
        if not self.model.inventory.is_catalog_owner:
            self.view.vio.print('カタログのオーナーではありません')
            return

        settings = self.view.select_catalog_settings_screen()
        if not settings:
            return
        if settings == 'private':
            self.model.inventory.set_private()
        elif settings == 'public':
            self.model.inventory.set_public()

    def authorize_user(self):
        if not self.model.inventory:
            self.view.missing_screen('インベントリ')
            return
        if not self.model.inventory.is_catalog_owner:
            self.view.vio.print('カタログのオーナーではありません')
            return

        act = self.view.select_authorize_act_screen()
        if act == 'authorize':
            address = self.view.input_address_screen()
            self.model.inventory.authorize_user(address)
            return
        if act == 'revoke':
            address_list = self.model.inventory.show_authorized_users()
            address = self.view.revoke_user_selector(address_list)
            if address:
                self.model.inventory.revoke_user(address)
            return
        if act == 'show':
            address_list = self.model.inventory.show_authorized_users()
            self.view.vio.print('アドレスリスト:')
            for address in address_list:
                self.view.vio.print(address)
            return

def decode_keyfile(filename):
    # https://web3py.readthedocs.io/en/stable/web3.eth.account.html#extract-private-key-from-geth-keyfile
    try:
        with open(filename) as keyfile:
            enc_data = keyfile.read()
        address = Web3.toChecksumAddress(json.loads(enc_data)['address'])
        word = getpass('Enter password for keyfile:')
        private_key = w3.eth.account.decrypt(enc_data, word).hex()
        return address, private_key
    except Exception as err:
        print('ERROR:', err)
        print('cannot decode keyfile:', os.path.basename(filename))
        sys.exit()

# ログイン処理
def login(input_user_name, input_private_key):
    if not input_user_name:
        print('ユーザIDを入力してください')
        input_user_name = str(input())

    my_account_id = ''
    my_private_key = ''
    if input_user_name == 'alice':
        my_account_id = ALICE_ACCOUNT_ID
        my_private_key = ALICE_PRIVATE_KEY
    elif input_user_name == 'bob':
        my_account_id = BOB_ACCOUNT_ID
        my_private_key = BOB_PRIVATE_KEY
    elif input_user_name == 'carol':
        my_account_id = CAROL_ACCOUNT_ID
        my_private_key = CAROL_PRIVATE_KEY
    else:
        try:
            my_account_id = Web3.toChecksumAddress(input_user_name)
        except:
            print('ユーザIDが正しくありません')
            sys.exit()
        if input_private_key:
            my_private_key = input_private_key
    return my_account_id, my_private_key

def main(args):
    # logging.WARNING=30
    level = logging.WARNING - args.verbose * 10
    common_handler = logging.StreamHandler()
    common_handler.setFormatter(
        logging.Formatter('<%(levelname)s>: %(message)s'))
    LOGGER.addHandler(common_handler)
    LOGGER.setLevel(level)

    my_account_id, my_private_key = \
        decode_keyfile(args.keyfile) if args.keyfile \
        else login(args.name, args.pkey)

    gas_handler = logging.FileHandler(
        GAS_LOGGING_FILEPATH_FORMAT.format(user=my_account_id))
    gas_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    GASLOG.addHandler(gas_handler)
    GASLOG.setLevel(logging.DEBUG if args.gaslog else logging.WARNING)

    if args.endpoint_uri:
        provider = HTTPProvider(args.endpoint_uri)
    else:
        # GASリミットの上限をデフォルトより大きく設定
        provider = EthereumTesterProvider(
            ethereum_tester=EthereumTester(
                backend=PyEVMBackend(
                    genesis_parameters=PyEVMBackend._generate_genesis_params(
                        overrides={'gas_limit': 4500000}))))

    viewer_io = None
    if args.input or args.output:
        viewer_io = FileViewerIO(args.input, args.output)

    controller = Controller(
        my_account_id, my_private_key, provider, dev=args.dev, vio=viewer_io,
        hookurl=args.webhook)

    # webhookを待ち受けるサーバアドレスがあれば起動
    if args.server:
        try:
            WebhookReceiver().start(args.server)
        except ValueError as err:
            LOGGER.error('failed to parse url: %s', err)

    # MISPのオプションが指定されていれば、MISPのtokenの発行
    if args.misp:
        controller.disseminate_mispdata()

    signal.signal(signal.SIGINT, controller.exit_handler)
    if args.command:
        try:
            controller.menu(args.command)
        except EOFError:
            pass
        signal.raise_signal(signal.SIGINT)
    while True:
        try:
            controller.menu()
        except EOFError:
            continue  # keep on going


OPTIONS = [
    ('-v', '--verbose', {'action':'count', 'default':0,
                         'help':'詳細メッセージ'}),
    ('-f', '--keyfile', {'action':'store', 'dest':'keyfile',
                         'help':'キーファイル'}),
    ('-u', '--user', {'action':'store', 'dest':'name',
                      'help':'ログインユーザ'}),
    ('-k', '--privatekey', {'action':'store', 'dest':'pkey',
                            'help':'プライベートキー'}),
    ('-p', '--provider', {'action':'store', 'dest':'endpoint_uri',
                          'help':'Ethereumプロバイダーendpoint_uri '
                                 '-p http://127.0.0.1:8545'}),
    ('-c', '--command', {'action':'store', 'help':'単発実行コマンド番号'}),
    ('-d', '--dev', {'action':'store_true', 'help':'開発モード'}),
    ('-s', '--server', {'action':'store', 'default':'http://127.0.0.1:12345',
                        'help':'webhook待ち受けURL '
                               '-s http://127.0.0.1:12345'}),
    ('-w', '--webhook', {'action':'store',
                         'help':'Solverに通知するwebhook待ち受けURL.'
                                '未指定時はSERVERの値が通知される'}),
    ('-g', '--gaslog', {'action':'store_true', 'help':'GAS 消費量ロギング'}),
    ('-m', '--misp', {'action':'store_true', 'help':'MISP token自動発行'}),
    ('-i', '--input', {'action':'store', 'help':'操作入力ファイル'}),
    ('-o', '--output', {'action':'store', 'help':'出力ファイル'}),
    ]

if __name__ == '__main__':

    PARSER = argparse.ArgumentParser()
    for sname, lname, etc_opts in OPTIONS:
        PARSER.add_argument(sname, lname, **etc_opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
