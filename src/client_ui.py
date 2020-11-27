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

import uuid
import json
import shutil
import math
import unicodedata
from io import StringIO
from abc import ABCMeta, abstractmethod

try:
    from msvcrt import getch
except ImportError:
    import sys
    import tty
    import termios
    def getch():
        fd0 = sys.stdin.fileno()
        old = termios.tcgetattr(fd0)
        try:
            tty.setraw(fd0)
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd0, termios.TCSADRAIN, old)

PTS_RATE = 10**18  # 1pts = PTS_RATE wei.


class ViewerIO(metaclass=ABCMeta):

    @abstractmethod
    def print(self, *args, **kwargs):
        pass

    @abstractmethod
    def pager_reset(self):
        pass

    @abstractmethod
    def pager_cancel_quit(self):
        pass

    @abstractmethod
    def pager_print(self, *args, **kwargs):
        pass

    @abstractmethod
    def input(self):
        pass


class StandardViewerIO(ViewerIO):

    def __init__(self):
        self.pager = dict()
        self.pager_reset()

    def print(self, *args, **kwargs):
        print(*args, **kwargs)

    def pager_reset(self):
        self.pager['columns'], self.pager['lines'] = shutil.get_terminal_size()
        self.pager['filled'] = 0
        self.pager['quitting'] = False

    def pager_cancel_quit(self):
        self.pager['quitting'] = False

    def pager_print(self, *objects, **kwargs):
        if 'file' in kwargs: # file 指定があるケースはサポート外
            print(*objects, **kwargs)
            return
        if self.pager['quitting']:
            return
        with StringIO() as sio:
            if 'end' not in kwargs:
                kwargs['end'] = ''
            print(*objects, **kwargs, file=sio)
            str_line = sio.getvalue()
            for line in str_line.splitlines():
                line_len = 0
                for char in line:
                    if unicodedata.east_asian_width(char) in 'FWA':
                        line_len += 2
                    else:
                        line_len += 1
                num_lines = math.ceil(line_len / self.pager['columns'])
                # 入力された内容を表示すると溢れる場合、表示を中断する
                if self.pager['filled'] + num_lines + 1 > self.pager['lines']:
                    print('--More-- (hit any key to continue, or q to quit) ',
                        end='', flush=True)
                    self.pager['filled'] = 0
                    cmd = getch()
                    if cmd == 'q':
                        # 'q' が入力された場合、リセットされるまで表示を割愛する
                        self.pager['quitting'] = True
                        return
                print(line)
                self.pager['filled'] += num_lines

    def input(self):
        return input()


class SimpleCUI():
    def __init__(self, vio=None):
        self.display_assets = []
        self.catalog = dict()
        self.model = None
        self.select_asset = None
        self.menu = dict()
        self.vio = vio if vio else StandardViewerIO()

    def update(self, model):
        self.model = model
        self.init_menu()
        # Stateと同じ名前の関数があれば自動実行
        if model.state in dir(self):
            getattr(self, model.state)()

    def num_input(self, parse_method=None):
        if not parse_method:
            parse_method = self.parse_default

        while True:
            num = self.vio.input()
            try:
                input_command = int(num)
                return parse_method(input_command)
            except:
                self.vio.print('不正な値です')

    def num_command(self, command):
        try:
            return self.menu[int(command)]['state']
        except:
            self.vio.print('不正な値です')
        return None

    @staticmethod
    def parse_default(command):
        return command

    def init_menu(self):
        self.menu = dict() # {command: {state:x, hint:x}}
        menu = [
            (0, 'exit', '終了'),
            (1, 'account_info', 'アカウント・保有トークン情報'),

            (10, 'shopping', 'CTIトークンの購入'),
            (11, 'challenge', 'チャレンジの実行'),
            (12, 'cancel_task', 'タスク(チャレンジ)のキャンセル'),
            (13, 'burn_own_token', '保有トークンの廃棄'),

            (20, 'dissemination', '新規CTIトークンの配布'),
            (21, 'challenge_acception', 'チャレンジの受付開始・解除'),
            (22, 'dealing', '発行トークンの追加委託・引取・登録取消'),
            (23, 'publish_misp', 'ローカルMISPデータからのCTIトークン自動配布'),
            ]
        if self.model.dev:
            menu.extend([
                (901, 'broker', 'カタログ・ブローカーの作成・変更'),
                (902, 'operator', 'オペレータの作成・変更'),
                (903, 'list_all_tasks', 'タスク一覧表示'),
                (904, 'like', 'CTIトークンのLike'),
                (905, 'init_like_users', 'Liked情報の初期化'),
                (906, 'restore_disseminate', 'disseminate link再構成'),
                ])
        for num, state, hint in menu:
            self.menu[num] = {'state': state, 'hint': hint}

    def menu_selector(self):
        hook = lambda: self.vio.print('コマンドを入力してください')
        self.vio.pager_cancel_quit()
        self.vio.pager_print('--------------------')
        return self.number_selector(self.menu, pager=True, hook=hook)

    def number_selector(self, items, pager=False, hook=None):
        output = self.vio.pager_print if pager else self.vio.print
        for key in sorted(items.keys()):
            output('[{}]:{}'.format(key, items[key]['hint']))
        if pager:
            self.vio.pager_reset()
        if hook:
            hook()
        while True:
            num = self.vio.input().strip()
            try:
                return items[int(num)]['state']
            except:
                pass
            self.vio.print('入力値が不正です')

    def account_info(self):
        num_own = len([v for v \
            in self.model.inventory.catalog_tokens.values() \
                if v['balanceOfUser'] > 0])
        num_published = len([v for v \
            in self.model.inventory.catalog_tokens.values() \
                if v['owner'] == self.model.account_id])
        catalog_address = self.model.inventory.catalog_address
        broker_address = self.model.inventory.broker_address
        operator_address = self.model.operator_address \
            if self.model.operator_address else ''
        eth = str(self.model.wallet.balance)
        if len(eth) > 18: # ether, gwei, wei
            eth = eth[:-18] + ',' + eth[:-9][-9:] + ',' + eth[-9:]
        elif len(eth) > 9:
            eth = eth[:-9][-9:] + ',' + eth[-9:]
        self.vio.pager_reset()
        pout = self.vio.pager_print
        pout('--------------------')
        pout('アカウント情報')
        pout('■ サマリー')
        pout(' - EoAアドレス: {}'.format(self.model.account_id))
        pout(' - 所持ETH: {} Wei'.format(eth))
        pout('■ コントラクト')
        pout(' - カタログアドレス: {}'.format(catalog_address))
        pout(' - ブローカーアドレス: {}'.format(broker_address))
        pout(' - オペレータアドレス: {}'.format(operator_address))
        pout('■ カタログ')
        pout(' - 所持ユニークCTIトークン数: {}'.format(num_own))
        pout(' - CTIトークン発行回数: {}'.format(num_published))
        pout('■ CTIトークン')
        for address, asset in self.model.inventory.catalog_tokens.items():
            if asset['balanceOfUser'] > 0:
                pout('ID:{tokenId} 数量:{balance} - {uri}'.format(
                    tokenId=asset['tokenId'],
                    balance=asset['balanceOfUser'],
                    uri=address))

    def _token_selector_list(self, mode='catalog'):
        self.display_assets = []

        if self.model.interest:
            base_assets = dict(filter(
                lambda x: self.model.interest in x[1]['title'],
                self.model.inventory.catalog_tokens.items()))
            self.vio.pager_print(
                '(検索中のキーワード:', self.model.interest, ')')
        else:
            base_assets = self.model.inventory.catalog_tokens

        if mode in {'catalog', 'like'}: ## shopping catalog
            # tokens listed in catalog.
            assets = base_assets
            balance_key = 'quantity'
            min_balance = 1 if mode == 'catalog' else 0

        elif mode == 'token_publisher': ## acceptable as solver
            # tokens which owner is me - published by me.
            assets = {
                k: v for k, v in base_assets.items() \
                    if v['owner'] == self.model.account_id}
            balance_key = 'balanceOfUser'
            min_balance = 0

        elif mode == 'token_holder': ## challengeable
            # tokens i have.
            assets = base_assets
            balance_key = 'balanceOfUser'
            min_balance = 1

        else:
            raise Exception('Internal Error')

        for address, asset in assets.items():
            try:
                if asset[balance_key] >= min_balance:
                    self.display_assets.append((address, asset))
            except:
                continue

        # Ctiごとのlike情報を取得
        like_users = self.model.get_like_users()
        for address, asset in self.display_assets:
            liked_prefix = '   '
            if address in like_users.keys():
                if len(like_users[address]) == 0:
                    continue
                liked_myself = liked_someone = liked_trusted = False
                for user in like_users[address]:
                    if user == self.model.account_id:
                        liked_myself = True
                    elif user in self.model.trusted_users:
                        liked_trusted = True
                    else:
                        liked_someone = True
                liked_prefix = \
                    ('+' if liked_myself else ' ') + \
                    ('+' if liked_someone else ' ') + \
                    ('+' if liked_trusted else ' ')
            id_prefix = '{}:'.format(asset['tokenId'])
            self.vio.pager_print(liked_prefix, id_prefix, asset['title'])
            self.vio.pager_print(
                '   ', ' ', '├', 'Addr :', address)
            self.vio.pager_print(
                '   ', ' ', '├', 'UUID :', asset['uuid'],
                '(' + asset['operator'] + ')')
            self.vio.pager_print(
                '   ', ' ', '└', 'Price:', asset['price'], 'pts', ' / ',
                asset[balance_key], 'tokens left')

    def _token_selector_input(self):

        self.vio.pager_cancel_quit()

        if len(self.display_assets) > 0:
            self.vio.pager_print('[ ]インデックスを入力して選択する')
        else:
            self.vio.pager_print('選択できるアイテムがありません')
        self.vio.pager_print('[s]アイテムを検索する')
        if self.model.interest:
            self.vio.pager_print('[a]検索キーワードを解除する')
        self.vio.pager_print('[b]メニューに戻る')

        self.vio.pager_reset()

        while True:
            command = self.vio.input().strip()

            if command == 'a':
                return ('search', '')
            if command == 's':
                keyword = self.search()
                return ('search', keyword)
            if command == 'b':
                return ('back', None)
            try:
                token = int(command)
                address, asset = [(k, v) for k, v \
                    in self.display_assets if v['tokenId'] == token][0]
                return 'select', (address, asset)
            except:
                pass
            self.vio.print('入力値が不正です')

    def token_selector(self, mode='catalog', hook=None):

        if not hook:
            str_tgt = '購入' if mode == 'catalog' else \
                'Like' if mode == 'like' else \
                'チャレンジ' if mode == 'token_holder' else \
                'チャレンジ受付・解除' if mode == 'token_publisher' else \
                None
            assert str_tgt
            hook = lambda: self.vio.pager_print(
                '{}するアイテムを選択してください (1pts = {}ETH)'.\
                format(str_tgt, float(PTS_RATE/(10**18))))

        while True:
            self.vio.pager_reset()
            if hook:
                hook()
            self._token_selector_list(mode)
            act, target = self._token_selector_input()
            if act == 'select':
                address, asset = target
                return address, asset
            if act == 'back':
                return None, None
            if act == 'search':
                self.model.interest = target
                continue
            return None, None

    def _task_selector_list(self, tasks, state=None):

        if self.model.interest:
            base_tasks = dict(filter(
                lambda x: self.model.interest in x[1]['title'], tasks.items()))
            self.vio.pager_print(
                '(検索中のキーワード:', self.model.interest, ')')
        else:
            base_tasks = tasks

        if state:
            display_tasks = dict(filter(
                lambda x: x[1]['state'] in state, base_tasks.items()))
        else:
            display_tasks = base_tasks

        for task_id in display_tasks.keys():
            task = display_tasks[task_id]
            id_prefix = '   {}:'.format(task_id)
            self.vio.pager_print(id_prefix, task['title'])
            self.vio.pager_print('   ', ' ', '├', 'Addr :', task['token'])
            self.vio.pager_print('   ', ' ', '└', 'State:', task['state'])
        return display_tasks

    def _task_selector_input(self, tasks):
        self.vio.pager_cancel_quit()
        if len(tasks) > 0:
            self.vio.pager_print('[ ]インデックスを入力して選択する')
        else:
            self.vio.pager_print('選択できるアイテムがありません')
        self.vio.pager_print('[s]アイテムを検索する')
        if self.model.interest:
            self.vio.pager_print('[a]検索キーワードを解除する')
        self.vio.pager_print('[b]メニューに戻る')

        self.vio.pager_reset()

        while True:
            command = self.vio.input().strip()
            if command == 'a':
                return 'search', ''
            if command == 's':
                keyword = self.search()
                return 'search', keyword
            if command == 'b':
                return 'back', None
            try:
                tid = int(command)
                if tid in tasks.keys():
                    return 'select', tid
            except:
                pass
            self.vio.print('入力値が不正です')

    def task_selector(self, tasks, state=None, hook=None):
        while True:
            self.vio.pager_reset()
            if hook:
                hook()
            display_tasks = self._task_selector_list(tasks, state)
            act, target = self._task_selector_input(display_tasks)
            if act == 'select':
                return target
            if act == 'back':
                return None
            if act == 'search':
                self.model.interest = target
                continue
            return None

    def search(self):
        self.vio.print('タイトルを検索:')
        return self.vio.input().strip()

    def confirm(self, asset):
        self.vio.print('{}を購入しますか'.format(asset['title']))
        self.vio.print('[1]購入する')
        self.vio.print('[2]キャンセル')
        return self.num_input(self.parse_confirm)

    def parse_confirm(self, command):
        if command == 1:
            return True
        if command == 2:
            self.vio.print('購入をキャンセルしました')
            return False

        raise ValueError

    def missing_screen(self, what='アドレス'):
        self.vio.print('{}がセットされていません'.format(what))

    def new_asset(self):
        self.vio.print('----新規CTIトークンを発行します----')

        self.vio.print('UUIDを入力してください(空文字列でデモ用ランダム生成)')
        tmp_uuid = self.vio.input().strip()

        tmp_title = None
        if tmp_uuid and len(tmp_uuid) > 0:
            # load title as default from specified MISP file.
            jsonfile = self.model.uuid_to_filepath(tmp_uuid)
            try:
                with open(jsonfile) as fin:
                    misp = json.load(fin)
                    tmp_title = misp['Event']['info']
            except FileNotFoundError:
                self.vio.print(
                    'MISP ファイルがありません(疑似ファイルを生成します): {}'.\
                        format(jsonfile))
            except json.decoder.JSONDecodeError:
                # broken json? it's none of our business.
                pass
            except KeyError:
                # data does not have Event.info, it's ok.
                pass
        if not tmp_uuid or len(tmp_uuid) == 0:
            tmp_uuid = str(uuid.uuid4())

        self.vio.print('タイトルを入力してください')
        if tmp_title and len(tmp_title) > 0:
            self.vio.print("(空文字列でデフォルト: '{}')".format(tmp_title))
        asset_title = self.vio.input().strip()
        if tmp_title and len(tmp_title) > 0 and len(asset_title) == 0:
            asset_title = tmp_title

        asset_price = self.input_int_screen(name='価格', minimum=0)
        if asset_price is None:
            return None, None

        asset_quantity = self.input_int_screen(name='発行数', minimum=1)
        if asset_quantity is None:
            return None, None

        self.vio.print('オペレータを入力してください')
        operator_id = self.vio.input().strip()

        num_consign = self.input_int_screen(
            name='カタログ登録数', minimum=0, maximum=asset_quantity)
        if num_consign is None:
            return None, None

        self.vio.print('--[確認]--')
        self.vio.print('      UUID: {}'.format(tmp_uuid))
        self.vio.print('  タイトル: "{}"'.format(asset_title))
        self.vio.print('      価格: {}'.format(asset_price))
        self.vio.print('    発行数: {}'.format(asset_quantity))
        self.vio.print('オペレータ: {}'.format(operator_id))
        self.vio.print('カタログ登録数: {}'.format(num_consign))
        self.vio.print('----')
        self.vio.print('この内容でCTIトークンを発行しますか？ [y/N]')
        confirm = self.vio.input().strip()
        if confirm not in {'y', 'Y'}:
            return None, None

        asset = dict()
        asset['uuid'] = tmp_uuid
        asset['title'] = asset_title
        asset['price'] = asset_price
        asset['quantity'] = asset_quantity
        asset['operator'] = operator_id
        return asset, num_consign

    def start_challenge(self, task_id):
        self.vio.print('--------------------')
        self.vio.print('チャレンジの処理を開始しました')
        self.vio.print('--------------------')
        self.vio.print('TaskID:', task_id)

    def challenge_successful(self, result):
        self.vio.print('--------------------')
        self.vio.print('チャレンジに成功しました！！！')
        self.vio.print('--------------------')
        self.vio.print(result)

    def challenge_failed(self, result):
        self.vio.print('--------------------')
        self.vio.print('チャレンジに失敗しました！！！')
        self.vio.print('--------------------')
        if result:
            self.vio.print(result)

    def cancel_challenge_done(self, task_id):
        self.vio.print('チャレンジをキャンセルしました')
        self.vio.print('TaskID:', task_id)

    def common_successful(self, ext_msg=None):
        self.vio.print('操作に成功しました')
        if ext_msg:
            self.vio.print(ext_msg)

    def common_failed(self, ext_msg=None):
        self.vio.print('操作に失敗しました')
        if ext_msg:
            self.vio.print(ext_msg)

    def challenge_action_selector(self):
        self.vio.print('操作を選択してください')
        items = dict()
        items[0] = {
            'state': None, 'hint': 'キャンセル'}
        items[1] = {
            'state': 'accept_challenge', 'hint': 'チャレンジ受付する'}
        items[2] = {
            'state': 'refuse_challenge', 'hint': 'チャレンジ受付解除する'}
        return self.number_selector(items)

    def setup_broker_done(self, catalog, broker):
        self.vio.print('作成/変更を完了しました')
        self.vio.print('カタログアドレス:', catalog)
        self.vio.print('ブローカーアドレス:', broker)

    def setup_operator_done(self, operator):
        self.vio.print('作成/変更を完了しました')
        self.vio.print('オペレータアドレス:', operator)

    def init_like_users_screen(self):
        self.vio.print('初期化で検索するブロック数は？（空白で 172800: 約2日）')
        self.vio.print(
            '現在のブロック番号: {}'.format(self.model.web3.eth.blockNumber))
        while True:
            num = self.vio.input().strip()
            if not num or len(num) == 0:
                return 172800
            try:
                num = int(num)
                if num < 0:
                    raise Exception
                return num
            except:
                pass
            self.vio.print('不正な値です')

    def publish_misp_param(self):
        self.vio.print('未配布のMISPデータをCTIトークンとして自動配布します')

        default = self.model.default_price \
            if self.model.default_price >= 0 else None
        price = self.input_int_screen('価格', minimum=0, default=default)
        if price is None:
            return None, None, None

        default = self.model.default_quantity \
            if self.model.default_quantity > 0 else None
        quantity = self.input_int_screen('発行数', minimum=1, default=default)
        if quantity is None:
            return None, None, None

        default = self.model.default_num_consign \
            if self.model.default_num_consign > 0 else None
        num_consign = self.input_int_screen(
            'カタログ登録数', minimum=0, default=default)
        if num_consign is None:
            return None, None, None

        return price, quantity, num_consign

    def select_token_act_screen(self):
        self.vio.print('操作内容を選択してください')
        items = dict()
        items[0] = {'state': None, 'hint': 'キャンセル'}
        items[1] = {'state': 'send', 'hint': 'トークンの送付（譲渡）'}
        items[2] = {'state': 'burn', 'hint': 'トークンの廃棄'}
        return self.number_selector(items)

    def select_dealing_act_screen(self):
        self.vio.print('取引内容を選択してください')
        items = dict()
        items[0] = {'state': None, 'hint': 'キャンセル'}
        items[1] = {'state': 'consign', 'hint': '発行トークンの委託'}
        items[2] = {'state': 'takeback', 'hint': '委託トークンの引き取り'}
        items[3] = {'state': 'unregister', 'hint': 'トークンの登録取り消し'}
        return self.number_selector(items)

    def input_address_screen(
        self, target_hint=None, default=None, hint=None, ext_delimiter=None):
        while True:
            self.vio.print(
                '{}を入力してください'.format(
                    target_hint if target_hint else 'アドレス'))
            if hint or default:
                if default:
                    self.vio.print('(空白で{}: {})'.format(
                        hint if hint else 'デフォルト', default))
                else:
                    self.vio.print('(空白で{})'.format(hint))
            target = self.vio.input().strip()

            ext_str = ''
            if ext_delimiter:
                tmp = target.split(ext_delimiter, 1)
                if len(tmp) == 2:
                    target, ext = tmp
                else:
                    ext = ''
                ext_str = ext_delimiter + ext

            if target == '':
                if default:
                    return default + ext_str
                return '' + ext_str

            if not self.model.web3.isAddress(target.lower()):
                self.vio.print('正しいアドレスではありません')
                continue
            return self.model.web3.toChecksumAddress(target) + ext_str

    def input_int_screen(
            self, name='数量', minimum=None, maximum=None, default=None):
        hint = ''
        if minimum is not None \
                and maximum is not None \
                and int(minimum) > int(maximum):
            self.vio.print('選択できる範囲がありません')
            return None
        if minimum is not None or maximum is not None:
            hint = ': {} 〜 {}'.format(
                int(minimum) if minimum is not None else '',
                int(maximum) if maximum is not None else '')
        while True:
            self.vio.print(
                '{name}を入力してください{hint}'.format(name=name, hint=hint))
            if default is not None:
                self.vio.print('(空白でデフォルト: {})'.format(default))
            amount = self.vio.input().strip()
            if default is not None and amount == '':
                return default
            try:
                amount = int(amount)
            except:
                self.vio.print('入力値が不正です')
                continue
            if minimum is not None and minimum > amount:
                self.vio.print('入力値が小さ過ぎます')
                continue
            if maximum is not None and maximum < amount:
                self.vio.print('入力値が大き過ぎます')
                continue
            return amount

    def select_blocknumber_screen(
            self, title='ブロック番号',
            allow_future=False, allow_negative=False):
        while True:
            maxblock = self.model.web3.eth.blockNumber
            if allow_future:
                maxblock += 1
            self.vio.print(
                '{}を入力してください (空白で最新ブロック:{})'.format(
                    title, maxblock))
            if allow_negative:
                self.vio.print('（負数 -N で、最新の N ブロック前）')
            num = self.vio.input().strip()
            if not num or len(num) == 0:
                return maxblock
            try:
                num = int(num)
                if allow_negative and num < 0:
                    return max(0, maxblock+num)
                if num < 0 or maxblock < num:
                    raise Exception
                return num
            except:
                pass
            self.vio.print('不正な値です')

    def select_yes_no_screen(self, hint=None):
        self.vio.print('{} [y/N]'.format(hint if hint else '選択？'))
        confirm = self.vio.input().strip()
        if confirm not in {'y', 'Y'}:
            return False
        return True
