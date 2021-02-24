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
import json
from urllib.request import Request, urlopen
from requests.exceptions import HTTPError
from eth_utils.exceptions import ValidationError

from ctioperator import CTIOperator
from eventlistener import BasicEventListener

LOGGER = logging.getLogger('common')


class ChallengeListener(BasicEventListener):

    def __init__(self, solver, event_name):
        self.accepting = dict()
        ctioperator = solver.ctioperator
        event_filter = ctioperator.event_filter(event_name, fromBlock='latest')
        super().__init__(self)
        self.add_event_filter(
            event_name+':'+solver.operator_address,
            event_filter, self.dispatch_callback)

    def dispatch_callback(self, event):
        token_address = event['args']['token']
        if token_address in self.accepting.keys():
            callback = self.accepting[token_address]
            callback(token_address, event)

    def accept_tokens(self, token_addresses, callback):
        for address in token_addresses:
            self.accepting[address] = callback

    def refuse_tokens(self, token_addresses):
        for address in token_addresses:
            if address in self.accepting.keys():
                del self.accepting[address]

    def list_accepting(self):
        return list(self.accepting.keys())


class BaseSolver:

    def __init__(self, contracts, account_id, operator_address):
        LOGGER.info(
            'initializing solver %s for %s', self, operator_address)
        self.contracts = contracts
        self.account_id = account_id
        self.operator_address = operator_address
        self.ctioperator = \
            self.contracts.accept(CTIOperator()).get(operator_address)
        self.listener = None

    def destroy(self):
        LOGGER.info(
            'destructing solver %s for %s', self, self.operator_address)
        if self.listener:
            self.listener.destroy()
            self.listener = None

    @staticmethod  # should be overwritten by subclass
    def notify_first_accept():
        return None

    def accepting_tokens(self):
        return self.listener.list_accepting() if self.listener else []

    def accept_registered(self, tokens):
        LOGGER.info('accept_registered candidates: %s', tokens)
        registered = self.ctioperator.check_registered(tokens)
        accepting = self.accepting_tokens()
        targets = [
            token for i, token in enumerate(tokens)
            if registered[i] and token not in accepting]
        if targets:
            LOGGER.info('newly accepted: %s', targets)
            msg = self._accept(targets, force_register=False)
            self.reemit_pending_tasks(targets)
            return msg
        return None

    def accept_challenges(self, tokens):
        LOGGER.info('BaseSolver: accept tokens: %s', tokens)
        accepting = self.accepting_tokens()
        targets = [token for token in tokens if token not in accepting]
        if targets:
            msg = self._accept(targets, force_register=True)
            self.reemit_pending_tasks(targets)
            return msg
        return None

    def _accept(self, token_addresses, force_register=False):
        if len(token_addresses) == 0:
            return None
        need_notify = \
            self.listener is None or len(self.listener.accepting) == 0
        if not self.listener:
            self.listener = ChallengeListener(self, 'TokensReceivedCalled')
            self.listener.start()
        self.listener.accept_tokens(token_addresses, self.process_challenge)
        if force_register:
            self.ctioperator.register_tokens(token_addresses)
        return self.notify_first_accept() if need_notify else None

    def refuse_challenges(self, token_addresses):
        LOGGER.info('BaseSolver: refuse: %s', token_addresses)
        if self.listener:
            self.listener.refuse_tokens(token_addresses)
        self.ctioperator.unregister_tokens(token_addresses)

    def accept_task(self, task_id):
        try:
            self.ctioperator.accept_task(task_id)
            return True
        except (HTTPError, ValueError, ValidationError) as err:
            # another solver may accept faster than me.
            LOGGER.error(err)
            return False

    def finish_task(self, task_id, data=''):
        self.ctioperator.finish_task(task_id, data)

    def reemit_pending_tasks(self, tokens):
        self.ctioperator.reemit_pending_tasks(tokens)

    @staticmethod
    def process_challenge(_token_address, _event):
        print('チャレンジの実装、または設定がありません')

        # need your code as a plug-in. see plugins/*solver.py as examples.
        # 1. preparation if needed.
        # 2. accept_task. task_id is given in event['args']['taskId'].
        # 3. your own process to solve request.
        # 4. return result via webhook.
        #    url can be gotten by Web3.toText(event['args']['data'].
        # 5. finish_task.

    @staticmethod
    def webhook(url, download_url, token_address):
        headers = {"Content-Type" : "application/json"}
        data_obj = {
            "download_url": download_url,
            "token_address": token_address
            }
        data = json.dumps(data_obj).encode("utf-8")
        # Note: this data is parsed at Controller.webhook_callback().

        # httpリクエストを準備してPOST
        request = Request(url, data=data, method="POST", headers=headers)
        with urlopen(request) as response:
            LOGGER.info(response.getcode())
            LOGGER.debug(response.info())
