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

import json
from collections import deque
from threading import Condition, Thread
from time import sleep
from typing import Callable, Dict, List, Optional
from urllib.request import Request, urlopen

from eth_typing import ChecksumAddress
from eth_utils.exceptions import ValidationError
from omegaconf.dictconfig import DictConfig
from requests.exceptions import HTTPError
from web3.datastructures import AttributeDict

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_operator import CTIOperator
from metemcyber.core.bc.eventlistener import BasicEventListener
from metemcyber.core.logger import get_logger

SIGNATURE_HEADER = 'Metemcyber-Signature'
QUEUE_DELAY_SEC = 2

LOGGER = get_logger(name='solver', file_prefix='core.bc')


class QueuedExecutor:
    queue: deque

    def __init__(self):
        self.queue = deque()  # deque is thread-safe
        self.cond = Condition()
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def destroy(self):
        self.queue = None
        self.cond.acquire()
        self.cond.notify_all()
        self.cond.release()

    def enqueue(self, callback, *args, **kwargs) -> None:
        self.cond.acquire()
        self.queue.append((callback, args, kwargs))
        self.cond.notify()
        self.cond.release()

    def run(self):
        LOGGER.info(f'starting {self.__class__.__name__}.')
        while True:
            try:
                callback, args, kwargs = self.queue.popleft()
                callback(*args, **kwargs)
                sleep(QUEUE_DELAY_SEC)
                continue
            except IndexError:
                pass
            except Exception as err:
                LOGGER.exception(err)
                continue
            self.cond.acquire()
            self.cond.wait()
            self.cond.release()
            if self.queue is None:
                break
        LOGGER.info(f'destructing {self.__class__.__name__}.')


class ChallengeListener(BasicEventListener):
    def __init__(self, account: Account, operator: ChecksumAddress, event_name: str) -> None:
        super().__init__(str(self))
        #                    token_address:   callback(token_address,    event)
        self.executor = QueuedExecutor()
        self.accepting: Dict[ChecksumAddress, Callable[[ChecksumAddress, AttributeDict],
                                                       None]] = {}
        event_filter = CTIOperator(account).get(
            operator).event_filter(event_name, fromBlock='latest')
        self.add_event_filter(f'{event_name}:{operator}', event_filter, self.dispatch_callback)

    def destroy(self):
        super().destroy()
        self.executor.destroy()

    def dispatch_callback(self, event: AttributeDict) -> None:
        token_address = event['args']['token']
        if token_address in self.accepting:
            callback = self.accepting[token_address]
            self.executor.enqueue(callback, token_address, event)

    def accept_tokens(self, token_addresses: List[ChecksumAddress],
                      callback: Callable[[ChecksumAddress, AttributeDict], None]) -> None:
        for address in token_addresses:
            self.accepting[address] = callback

    def refuse_tokens(self, token_addresses: List[ChecksumAddress]) -> None:
        for address in token_addresses:
            self.accepting.pop(address, None)

    def list_accepting(self) -> List[ChecksumAddress]:
        return list(self.accepting.keys())


class BaseSolver:
    account: Account
    listener: Optional[ChallengeListener]
    config: DictConfig

    def __init__(self, account: Account, config: DictConfig):
        LOGGER.info('initializing solver %s for EOA %s', self, account.eoa)
        self.account = account
        self.listener = None
        self.config = config

    def destroy(self):
        LOGGER.info('destructing solver %s for EOA %s', self, self.account.eoa)
        if self.listener:
            self.listener.destroy()
            self.listener = None

    @staticmethod  # should be overwritten by subclass
    def notify_first_accept():
        return None

    def accepting_tokens(self):
        return self.listener.list_accepting() if self.listener else []

    def accept_registered(self, tokens: Optional[List[ChecksumAddress]]):
        LOGGER.info('accept_registered candidates: %s', tokens)
        accepting = self.accepting_tokens()
        cti_operator = CTIOperator(self.account).get(self.config.workspace.operator.address)
        if tokens is None:  # auto detect mode
            targets = cti_operator.list_registered(self.account.eoa)
        else:
            registered = cti_operator.check_registered(tokens)
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
            self.listener = ChallengeListener(
                self.account, self.config.workspace.operator.address, 'TokensReceivedCalled')
            self.listener.start()
        self.listener.accept_tokens(token_addresses, self.process_challenge)
        if force_register:
            cti_operator = CTIOperator(self.account).get(self.config.workspace.operator.address)
            cti_operator.register_tokens(token_addresses)
        return self.notify_first_accept() if need_notify else None

    def refuse_challenges(self, tokens: List[ChecksumAddress]):
        LOGGER.info('BaseSolver: refuse: %s', tokens)
        targets = [t for t in tokens if t in self.accepting_tokens()]
        if targets:
            assert self.listener
            self.listener.refuse_tokens(targets)
            cti_operator = CTIOperator(self.account).get(self.config.workspace.operator.address)
            cti_operator.unregister_tokens(targets)

    def accept_task(self, task_id):
        try:
            cti_operator = CTIOperator(self.account).get(self.config.workspace.operator.address)
            cti_operator.accept_task(task_id)
            return True
        except (HTTPError, ValueError, ValidationError) as err:
            # another solver may accept faster than me.
            LOGGER.error(err)
            return False

    def finish_task(self, task_id, data=''):
        cti_operator = CTIOperator(self.account).get(self.config.workspace.operator.address)
        cti_operator.finish_task(task_id, data)

    def reemit_pending_tasks(self, tokens):
        cti_operator = CTIOperator(self.account).get(self.config.workspace.operator.address)
        cti_operator.reemit_pending_tasks(tokens)

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

    def webhook(self, webhook_url: str, download_url: str,
                seeker: ChecksumAddress, task_id: int, token_address: ChecksumAddress
                ) -> None:
        data_obj = {
            "solver": self.account.eoa,
            "seeker": seeker,
            "task_id": task_id,
            "token_address": token_address,
            "download_url": download_url,
        }
        data = json.dumps(data_obj, sort_keys=True)
        sign = self.account.sign_message(str(data))
        headers = {"Content-Type": "application/json",
                   SIGNATURE_HEADER: sign}
        # httpリクエストを準備してPOST
        request = Request(webhook_url, data=data.encode('utf-8'), method="POST", headers=headers)
        with urlopen(request) as response:
            LOGGER.info(response.getcode())
            LOGGER.debug(response.info())
