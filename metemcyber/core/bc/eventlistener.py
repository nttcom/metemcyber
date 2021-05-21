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

import time
from threading import Lock, Thread
from typing import Any, Callable, Dict, List, Optional

from requests.exceptions import ConnectionError as ConnError
from requests.exceptions import HTTPError
from web3._utils.filters import LogFilter
from web3.datastructures import AttributeDict

from ..logger import get_logger

LOGGER = get_logger(name='event', file_prefix='core.bc')

EVENT_POLLING_INTERVAL_SEC = 2
LISTENER_JOIN_TIMEOUT_SEC = 30


class BasicEventListener:

    def __init__(self, identity: str) -> None:
        self.__thread: Optional[Thread] = None
        self.__identity: str = identity
        self.__stopping: bool = True
        self.__prefix: str = self.__class__.__name__
        #                          key: {filter:x, count:x, callback:x}
        self.__event_filters: Dict[str, Dict[str, Any]] = {}
        self.__lock: Lock = Lock()
        #                           {key:x, filter:x, callback:x}
        self.__pending_filters: List[Dict[str, Any]] = list()
        self.__pending_lock: Lock = Lock()

    def destroy(self) -> None:
        self.stop()

    def add_event_filter(self, key: str, event_filter: LogFilter,
                         callback: Callable[[AttributeDict], None]) -> None:
        with self.__lock:
            if key in self.__event_filters.keys():
                assert self.__event_filters[key]['callback'] == callback
                self.__event_filters[key]['count'] += 1
            else:
                self.__event_filters[key] = {
                    'filter': event_filter, 'callback': callback, 'count': 1}
                LOGGER.debug('start watching: %s', key)
        if not self.__stopping:
            self.start()

    def remove_event_filter(self, key: str) -> None:
        with self.__lock:
            self.__event_filters[key]['count'] -= 1
            if self.__event_filters[key]['count'] <= 0:
                del self.__event_filters[key]
                LOGGER.debug('remove watching: %s', key)
        # auto-stopped in __run() if __event_filters is empty.

    def add_event_filter_in_callback(self, key: str, event_filter: LogFilter,
                                     callback: Callable[[AttributeDict], None]) -> None:
        with self.__pending_lock:
            self.__pending_filters.append(
                {'key': key, 'filter': event_filter, 'callback': callback})

    def remove_event_filter_in_callback(self, key: str) -> None:
        with self.__pending_lock:
            self.__pending_filters.append({'key': key, 'filter': None})

    def start(self) -> None:
        if self.__thread:
            return
        self.__stopping = False
        if len(self.__event_filters) == 0:
            return
        self.__thread = Thread(target=self.__run, daemon=True)
        self.__thread.start()

    def stop(self) -> None:
        if not self.__thread:
            return
        LOGGER.info('%s: stopping %s', self.__prefix, self.__identity)
        self.__stopping = True
        self.__thread.join(timeout=LISTENER_JOIN_TIMEOUT_SEC)
        if self.__thread and self.__thread.is_alive():
            LOGGER.error('failed stopping listener: %s', self.__identity)
            return
        self.__event_filters.clear()
        self.__pending_filters.clear()
        self.__thread = None

    def __run(self) -> None:
        LOGGER.info('%s: starting %s', self.__prefix, self.__identity)
        while True:
            if len(self.__event_filters) == 0:
                break

            with self.__lock:
                for value in self.__event_filters.values():
                    try:
                        events = value['filter'].get_new_entries()
                    except (ConnError, HTTPError) as err:
                        LOGGER.warning(
                            'could not connect to ethereum network: %s', err)
                        break  # retry on next time

                    for event in events:
                        if self.__stopping:
                            break
                        LOGGER.info(
                            'event %s: address=%s args=%s',
                            event['event'], event['address'], event['args'])

                        Thread(target=value['callback'], args=[event]).start()

                    if self.__stopping:
                        break

            if self.__stopping:
                break
            time.sleep(EVENT_POLLING_INTERVAL_SEC)

            with self.__pending_lock:
                for item in self.__pending_filters:
                    if item['filter']:
                        self.add_event_filter(
                            item['key'], item['filter'], item['callback'])
                    else:
                        self.remove_event_filter(item['key'])
                self.__pending_filters.clear()

        LOGGER.info('%s: thread exiting: %s', self.__prefix, self.__identity)
        self.__thread = None
