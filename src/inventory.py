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

import logging
import time
import inspect
import copy
from web3 import Web3
from ens.constants import EMPTY_ADDR_HEX
from ctibroker import CTIBroker
from cticatalog import CTICatalog
from ctitoken import CTIToken
from client_ui import PTS_RATE

LOGGER = logging.getLogger('common')
CATALOG_ID_BIAS = 1000  # XXX temporal value


def catalog_tokens_key(catalog, token):
    return '{token}:{catalog}'.format(token=token, catalog=catalog)

def divide_token_key(token_key):
    token, catalog = token_key.split(':', 1)
    assert Web3.isChecksumAddress(catalog)
    assert Web3.isChecksumAddress(token)
    return catalog, token


class Inventory:
    def __init__(
            self, contracts, account_id, event_listener, broker_address=None):
        self.contracts = contracts
        self.account_id = account_id
        self.event_listener = event_listener
        self.catalog_list = CatalogList(contracts, account_id, event_listener)

        self.broker = None
        self.switch_broker(broker_address)

    def catalog_ctrl(self, actions, addresses):
        assert self.catalog_list
        if not isinstance(actions, list):
            actions = [actions]
        if not isinstance(addresses, list):
            addresses = [addresses]
        for action in actions:
            assert action in {'add', 'remove', 'activate', 'deactivate'}
            func = getattr(self.catalog_list, action)
            for address in addresses:
                func(address)
                if action in {'add'}:
                    self.fill_quantity(address)

    @property
    def catalog_addresses(self):
        return self.catalog_list.catalog_addresses

    def list_catalogs(self, active):
        assert self.catalog_list
        return self.catalog_list.get_list(active)

    @property
    def broker_address(self):
        return self.broker.broker_address if self.broker else ''

    @property
    def catalog_tokens(self):
        return self.catalog_list.catalog_tokens

    def is_catalog_owner(self, address):
        return self.catalog_list.is_owner(address)

    @property
    def like_users(self):
        return self.catalog_list.like_users

    def init_like_users(self, **kwargs):
        self.catalog_list.init_like_users(**kwargs)

    def destroy(self):
        if self.catalog_list:
            self.catalog_list.destroy()
            self.catalog_list = None
        if self.broker:
            self.broker.destroy()
            self.broker = None

    def switch_broker(self, broker_address):
        if self.broker:
            if self.broker.broker_address == broker_address:
                return
            self.broker.destroy()
            self.broker = None
        if not broker_address:
            return
        self.broker = Broker(
            self.contracts, broker_address, self.amountchanged_callback,
            self.event_listener)
        self.fill_quantity()

    def fill_quantity(self, catalog_address=None):
        if not self.catalog_list or not self.broker:
            return
        self.catalog_list.fill_quantity(
            self.broker.get_amounts, catalog_address)

    def amountchanged_callback(self, event):
        item = event['args']
        if not self.catalog_list:
            return
        if item['catalog'] not in self.catalog_addresses:
            # 自身のカタログには無関係なので無視
            return
        self.catalog_list.update_quantity(
            item['catalog'], item['token'], item['amount'])

    def list_own_tokens(self, account_id):
        if not self.catalog_list:
            return []
        tokens = [v['token_address'] for v
            in self.catalog_tokens.values() if v['owner'] == account_id]
        return tokens

    def update_balanceof_myself(self, token_address, catalog_address=None):
        if not self.catalog_list:
            return
        self.catalog_list.update_balanceof_myself(
            token_address, catalog_address)

    def restore_disseminate(self, *args, **kwargs):
        assert self.catalog_list
        self.catalog_list.restore_disseminate(*args, **kwargs)

    def register_token(
            self, catalog_address, producer_address, token_address, metadata):
        assert self.catalog_list
        self.catalog_list.register_token(
            catalog_address, producer_address, token_address, metadata)

    def unregister_token(self, catalog_address, token_address):
        assert self.catalog_list and self.broker
        key = catalog_tokens_key(catalog_address, token_address)
        amount = self.catalog_tokens[key]['quantity']
        if amount > 0:
            self.broker.takeback(catalog_address, token_address, amount)
            # すぐに catalog_token から抹消されるので amount 更新は割愛
        self.catalog_list.unregister_token(catalog_address, token_address)

    def modify_token(self, catalog_address, token_address, metadata):
        assert self.catalog_list
        self.catalog_list.modify_token(
            catalog_address, token_address, metadata)

    def like_cti(self, token_address, catalog_address=None):
        assert self.catalog_list
        self.catalog_list.like_cti(token_address, catalog_address)

    def consign(self, catalog_address, token_address, amount):
        assert self.catalog_list and self.broker
        self.broker.consign(catalog_address, token_address, amount)
        self.catalog_list.update_balanceof_myself(
            token_address, catalog_address)

    def takeback(self, catalog_address, token_address, amount):
        assert self.catalog_list and self.broker
        self.broker.takeback(catalog_address, token_address, amount)
        self.catalog_list.update_balanceof_myself(
            token_address, catalog_address)

    def buy(self, catalog_address, token_address, allow_cheaper=False):
        assert self.catalog_list and self.broker
        key = catalog_tokens_key(catalog_address, token_address)
        price = self.catalog_tokens[key]['price']
        self.broker.buy(catalog_address, token_address, price, allow_cheaper)
        self.catalog_list.update_balanceof_myself(
            token_address, catalog_address)

    def is_catalog_private(self, catalog_address):
        assert self.catalog_list
        return self.catalog_list.is_private(catalog_address)

    def set_private(self, catalog_address):
        assert self.catalog_list
        self.catalog_list.set_private(catalog_address)

    def set_public(self, catalog_address):
        assert self.catalog_list
        self.catalog_list.set_public(catalog_address)

    def authorize_user(self, catalog_address, eoa_address):
        assert self.catalog_list
        self.catalog_list.authorize_user(catalog_address, eoa_address)

    def revoke_user(self, catalog_address, eoa_address):
        assert self.catalog_list
        self.catalog_list.revoke_user(catalog_address, eoa_address)

    def show_authorized_users(self, catalog_address):
        assert self.catalog_list
        return self.catalog_list.show_authorized_users(catalog_address)


class CatalogList:
    def __init__(self, contracts, catalog_user, event_listener):
        self.contracts = contracts
        self.catalog_user = catalog_user
        self.event_listener = event_listener
        self.catalogs = {}  # {addr: {index, active, catalog}}

    def passthrough(self, catalog_address, *args, **kwargs):
        # Note:
        #   This method calls the same name method in Catalog class.
        #   See Catalog class for details of arguments.
        catalog = self.catalogs.get(catalog_address)
        if not catalog:
            return None
        finfo = inspect.getframeinfo(inspect.stack()[1][0])
        func = getattr(catalog['catalog'], finfo.function)
        if not callable(func):  # maybe a property
            return func
        return func(*args, **kwargs)

    def destroy(self):
        for catalog in self.catalogs.values():
            catalog['catalog'].destroy()

    @property
    def catalog_addresses(self):
        return [k for k, v in self.catalogs.items() if v['active']]

    def get_list(self, active):
        return [
            (k, v['index'], v['active'])
            for k, v in self.catalogs.items()
            if active is None or v['active'] == active]

    def add(self, address):
        if address in self.catalogs.keys():
            return self.catalogs[address]['index']
        idx = 0 if not self.catalogs \
            else max([x['index'] for x in self.catalogs.values()]) + 1
        catalog = Catalog(
            self.contracts, address, self.catalog_user, self.event_listener)
        self.catalogs[address] = {
            'index': idx,
            'active': False,
            'catalog': catalog,
            }
        return idx

    def remove(self, address):
        if address not in self.catalogs.keys():
            return
        self.catalogs[address]['catalog'].destroy()
        del self.catalogs[address]

    def activate(self, address):
        assert address in self.catalogs.keys()
        self.catalogs[address]['active'] = True

    def deactivate(self, address):
        assert address in self.catalogs.keys()
        self.catalogs[address]['active'] = False

    def update_quantity(self, catalog_address, *args, **kwargs):
        self.passthrough(catalog_address, *args, **kwargs)

    def fill_quantity(self, get_amounts_func, catalog_address=None):
        if catalog_address:
            self.passthrough(catalog_address, get_amounts_func)
            return
        for catalog in self.catalogs.values():
            catalog['catalog'].fill_quantity(get_amounts_func)

    def update_balanceof_myself(self, token_address, catalog_address=None):
        if catalog_address:
            self.passthrough(catalog_address, token_address)
            return
        for catalog in self.catalogs.values():
            catalog['catalog'].update_balanceof_myself(token_address)

#    def _index_to_address(self, index):
#        tgt = [k for k, v in self.catalogs.items() if v['index'] == index]
#        return tgt[0] if tgt else None

    @property
    def catalog_tokens(self):
        return self.fixed_tokens(active=True)

    def fixed_tokens(self, addresses=None, active=None):
        if not addresses:
            addresses = self.catalogs.keys()
        fixed = dict()
        for addr, val in self.catalogs.items():
            if addr not in addresses:
                continue
            if active is not None and active != val['active']:
                continue
            tokens = copy.deepcopy(val['catalog'].catalog_tokens)
            for token, metadata in tokens.items():
                metadata['token_address'] = token
                metadata['catalog_address'] = addr
                metadata['tokenId'] += val['index'] * CATALOG_ID_BIAS  # overwr

                key = catalog_tokens_key(addr, token)
                fixed[key] = metadata
        return fixed

    def is_owner(self, catalog_address):
        return self.passthrough(catalog_address)

    @property
    def like_users(self):
        ret = dict()
        for catalog in self.catalogs.values():
            ret.update(catalog['catalog'].like_users)  #FIXME key may conflict
        return ret

    def init_like_users(self, **kwargs):
        for catalog in self.catalogs.values():
            catalog['catalog'].init_like_users(**kwargs)

    def restore_disseminate(self, *args, **kwargs):
        for catalog in self.catalogs.values():
            catalog['catalog'].restore_disseminate(*args, **kwargs)

    def register_token(self, catalog_address, *args, **kwargs):
        self.passthrough(catalog_address, *args, **kwargs)

    def unregister_token(self, catalog_address, *args, **kwargs):
        self.passthrough(catalog_address, *args, **kwargs)

    def modify_token(self, catalog_address, *args, **kwargs):
        self.passthrough(catalog_address, *args, **kwargs)

    def like_cti(self, token_address, catalog_address=None):
        if catalog_address:
            self.passthrough(catalog_address, token_address)
            return
        for catalog in self.catalogs.values():
            catalog['catalog'].like_cti(token_address)

    def is_private(self, catalog_address):
        return self.passthrough(catalog_address)

    def set_private(self, catalog_address):
        self.passthrough(catalog_address)

    def set_public(self, catalog_address):
        self.passthrough(catalog_address)

    def authorize_user(self, catalog_address, *args, **kwargs):
        self.passthrough(catalog_address, *args, **kwargs)

    def revoke_user(self, catalog_address, *args, **kwargs):
        self.passthrough(catalog_address, *args, **kwargs)

    def show_authorized_users(self, catalog_address, *args, **kwargs):
        return self.passthrough(catalog_address, *args, **kwargs)


class Catalog:
    def __init__(
            self, contracts, catalog_address, catalog_user, event_listener):
        self.contracts = contracts
        self.catalog_address = catalog_address
        self.cticatalog = contracts.accept(CTICatalog()).get(catalog_address)
        self.catalog_owner = self.cticatalog.get_owner()
        self.catalog_user = catalog_user
        self.is_owner = (self.catalog_owner == self.catalog_user)

        event_filter = self.cticatalog.event_filter(
            'CtiInfo', fromBlock='latest')
        event_listener.add_event_filter(
            'CtiInfo:'+catalog_address, event_filter, self.ctiinfo_callback)
        event_filter = self.cticatalog.event_filter(
            'CtiLiked', fromBlock='latest')
        event_listener.add_event_filter(
            'CtiLiked:'+catalog_address, event_filter, self.liked_callback)
        event_listener.start()
        self.event_listener = event_listener

        self.init_catalog()
        self.init_like_users(search_blocks=172800)

    @property
    def is_private(self):
        # カタログがプライベートかを確認する
        return self.cticatalog.is_private()

    def destroy(self):
        LOGGER.info('Catalog: destructing %s', self.catalog_address)
        self.event_listener.remove_event_filter(
            'CtiInfo:'+self.catalog_address)
        self.event_listener.remove_event_filter(
            'CtiLiked:'+self.catalog_address)

    def init_like_users(self, **kwargs):
        self.like_users = dict()
        like_events = self.cticatalog.get_like_event(**kwargs)
        for event in like_events:
            self.liked_callback(event)

    def liked_callback(self, event):
        item = event['args']
        token_address = item['tokenURI']
        user = item['likeuser']
        if not(token_address and user):
            return

        if token_address in self.like_users.keys():
            self.like_users[token_address].add(user)
        else:
            self.like_users[token_address] = set([user])

    def ctiinfo_callback(self, event):
        cti = event['args']

        if len(cti['uuid']) == 0:
            # removed
            del self.catalog_tokens[cti['tokenURI']]
            LOGGER.info('CTI removed: %s: %s', cti['title'], cti['tokenURI'])
            return

        if cti['tokenURI'] in self.catalog_tokens.keys():
            # modified
            target = self.catalog_tokens[cti['tokenURI']]
            assert target['tokenId'] == cti['tokenId']
            assert target['owner'] == cti['owner']
            assert target['uuid'] == cti['uuid']
            LOGGER.info('CTI modified: %s: %s', cti['title'], cti['tokenURI'])
        else:
            # new cti
            target = dict()
            self.catalog_tokens[cti['tokenURI']] = target
            target['tokenId'] = cti['tokenId']
            target['owner'] = cti['owner']
            target['uuid'] = cti['uuid']
            target['quantity'] = 0
            LOGGER.info('CTI published: %s: %s', cti['title'], cti['tokenURI'])
        target['title'] = cti['title']
        target['price'] = cti['price']
        target['operator'] = cti['operator']

        self.update_balanceof_myself(cti['tokenURI'])

    def init_catalog(self):
        # カタログ情報をfetchする
        catalog = dict()

        tokens = self.cticatalog.list_token_uris()
        for token_address in tokens:
            if token_address == '': # removed cti
                continue
            token_id, owner, uuid, title, price, operator, likecount = \
                self.cticatalog.get_cti_info(token_address)

            if token_id == 0: # registered, but not yet published
                continue
            catalog[token_address] = dict()
            catalog[token_address]['uuid'] = uuid
            catalog[token_address]['tokenId'] = token_id
            catalog[token_address]['owner'] = owner
            catalog[token_address]['title'] = title
            catalog[token_address]['price'] = price
            catalog[token_address]['quantity'] = 0
            catalog[token_address]['operator'] = operator
            catalog[token_address]['like'] = likecount

        self.catalog_tokens = catalog

        for token_address in tokens:
            self.update_balanceof_myself(token_address)

    def fill_quantity(self, get_amounts_func):
        token_addresses = list(self.catalog_tokens.keys())
        amounts = get_amounts_func(self.catalog_address, token_addresses)
        for i, token_address in enumerate(token_addresses):
            self.catalog_tokens[token_address]['quantity'] = amounts[i]

    def restore_disseminate(self, account_id, callback, view=None):
        for token in self.cticatalog.list_token_uris():
            if token == '':
                continue
            _id, owner, uuid, title, _price, _ope, _like = \
                self.cticatalog.get_cti_info(token)
            if account_id != owner:
                continue
            metadata = {}
            metadata['uuid'] = uuid
            metadata['title'] = title
            metadata['tokenAddress'] = token
            if view:
                view.vio.print('restoring token:{} with uuid:{}'.format(
                    token, uuid))
            callback(metadata)

    def safe_get_token(self, token_address, retry=10):
        while True:
            try:
                return self.catalog_tokens[token_address]
            except KeyError:
                if retry > 0:
                    time.sleep(1)
                    retry -= 1
                    continue
            break
        return None

    def update_quantity(self, token_address, quantity):
        try:
            token = self.safe_get_token(token_address, 5)
            if token is None:
                if quantity == 0:  # maybe unregistered
                    return
                raise Exception('not found on catalog, token: '+token_address)
            if token['tokenId'] > 0:
                token['quantity'] = quantity
        except Exception as err:
            LOGGER.error(err)

    def update_balanceof_myself(self, token_address):
        target = self.safe_get_token(token_address)
        if target is None:  # maybe unregistered
            return
        LOGGER.info(
            'CTI token (%s) calls balanceOf(%s)',
            token_address, self.catalog_user)
        ctitoken = self.contracts.accept(CTIToken()).get(token_address)
        target['balanceOfUser'] = ctitoken.balance_of(self.catalog_user)

    def register_token(self, producer_address, token_address, metadata):
        self.cticatalog.register_cti(
            token_address,
            metadata['uuid'],
            metadata['title'],
            metadata['price'],
            metadata['operator'])
        self.cticatalog.publish_cti(producer_address, token_address)

    def unregister_token(self, token_address):
        self.cticatalog.unregister_cti(token_address)

    def modify_token(self, token_address, metadata):
        self.cticatalog.modify_cti(
            token_address,
            metadata['uuid'],
            metadata['title'],
            metadata['price'],
            metadata['operator'])

    def list_token_uris(self):
        return self.cticatalog.list_token_uris()

    def get_cti_info(self, token_address):
        return self.cticatalog.get_cti_info(token_address)

    def like_cti(self, token_address):
        self.cticatalog.like_cti(token_address)

    def set_private(self):
         # カタログオーナーのみ実施可能 カタログをプライベートにする
        assert self.is_owner
        self.cticatalog.set_private()

    def set_public(self):
         # カタログオーナーのみ実施可能 カタログをパブリックにする
        assert self.is_owner
        self.cticatalog.set_public()

    def authorize_user(self, eoa_address):
        # カタログオーナーのみ実施可能 指定ユーザをカタログから購買可能にする
        assert self.is_owner
        self.cticatalog.authorize_user(eoa_address)

    def revoke_user(self, eoa_address):
        # カタログオーナーのみ実施可能 指定したユーザの購買許可を取り消す
        assert self.is_owner
        self.cticatalog.revoke_user(eoa_address)

    def show_authorized_users(self):
        # カタログオーナーのみ実施可能 指定したユーザの購買許可を取り消す
        assert self.is_owner
        authorized_users = self.cticatalog.show_authorized_users()
        authorized_actual_users = [address for address in authorized_users
                                   if address != EMPTY_ADDR_HEX]
        return authorized_actual_users


class Broker:
    def __init__(
            self, contracts, broker_address, amountchanged_callback,
            event_listener):
        self.contracts = contracts
        self.broker_address = broker_address
        self.ctibroker = contracts.accept(CTIBroker()).get(broker_address)

        event_filter = self.ctibroker.event_filter(
            'AmountChanged', fromBlock='latest')
        event_listener.add_event_filter(
            'AmountChanged:'+broker_address,
            event_filter, amountchanged_callback)
        event_listener.start()
        self.event_listener = event_listener

    def destroy(self):
        LOGGER.info('Broker: destructing %s', self.broker_address)
        self.event_listener.remove_event_filter(
            'AmountChanged:'+self.broker_address)

    def get_amounts(self, catalog_address, token_addresses):
        return self.ctibroker.get_amounts(catalog_address, token_addresses)

    def consign(self, catalog_address, token_address, amount):
        ctitoken = self.contracts.accept(CTIToken()).get(token_address)
        ctitoken.authorize_operator(self.broker_address)
        self.ctibroker.consign_token(catalog_address, token_address, amount)
        ctitoken.revoke_operator(self.broker_address)

    def takeback(self, catalog_address, token_address, amount):
        self.ctibroker.takeback_token(catalog_address, token_address, amount)

    def buy(self, catalog_address, token_address, price, allow_cheaper=False):
        wei = price * PTS_RATE
        self.ctibroker.buy_token(
            catalog_address, token_address, wei, allow_cheaper)
