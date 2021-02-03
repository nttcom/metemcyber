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
from threading import Thread, Lock
from requests.exceptions import ConnectionError as ConnError, HTTPError

LOGGER = logging.getLogger('common')


EVENT_POLLING_INTERVAL_SEC = 2
LISTENER_JOIN_TIMEOUT_SEC = 30


class BasicEventListener:

    def __init__(self, identity):
        self.__thread = None
        self.__identity = identity
        self.__stopping = True
        self.__prefix = self.__class__.__name__
        self.__event_filters = dict() # {key: {filter:x, count:x, callback:x}}
        self.__lock = Lock()
        self.__pending_filters = list() # {key:x, filter:x, callback:x}
        self.__pending_lock = Lock()

    def add_event_filter(self, key, event_filter, callback):
        self.__lock.acquire()
        if key in self.__event_filters.keys():
            assert self.__event_filters[key]['callback'] == callback
            self.__event_filters[key]['count'] += 1
        else:
            self.__event_filters[key] = {
                'filter':event_filter, 'callback': callback, 'count': 1}
            LOGGER.debug('start watching: %s', key)
        self.__lock.release()
        if not self.__stopping:
            self.start()

    def remove_event_filter(self, key):
        self.__lock.acquire()
        self.__event_filters[key]['count'] -= 1
        if self.__event_filters[key]['count'] <= 0:
            del self.__event_filters[key]
            LOGGER.debug('remove watching: %s', key)
        self.__lock.release()
        ## auto-stopped in __run() if __event_filters is empty.

    def add_event_filter_in_callback(self, key, event_filter, callback):
        self.__pending_lock.acquire()
        self.__pending_filters.append(
            {'key': key, 'filter': event_filter, 'callback': callback})
        self.__pending_lock.release()

    def remove_event_filter_in_callback(self, key):
        self.__pending_lock.acquire()
        self.__pending_filters.append({'key': key, 'filter': None})
        self.__pending_lock.release()

    def start(self):
        if self.__thread:
            return
        self.__stopping = False
        if len(self.__event_filters) == 0:
            return
        self.__thread = Thread(target=self.__run, daemon=True)
        self.__thread.start()

    def stop(self):
        if not self.__thread:
            return
        LOGGER.info('%s: stopping %s', self.__prefix, self.__identity)
        self.__stopping = True
        self.__thread.join(timeout=LISTENER_JOIN_TIMEOUT_SEC)
        if self.__thread and self.__thread.is_alive():
            LOGGER.error('failed stopping listener: %s', self.__identity)
            return
        self.__thread = None

    def __run(self):
        LOGGER.info('%s: starting %s', self.__prefix, self.__identity)
        while True:
            if len(self.__event_filters) == 0:
                break

            self.__lock.acquire()
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
            self.__lock.release()

            if self.__stopping:
                break
            time.sleep(EVENT_POLLING_INTERVAL_SEC)

            self.__pending_lock.acquire()
            for item in self.__pending_filters:
                if item['filter']:
                    self.add_event_filter(
                        item['key'], item['filter'], item['callback'])
                else:
                    self.remove_event_filter(item['key'])
            self.__pending_filters.clear()
            self.__pending_lock.release()

        LOGGER.info('%s: thread exiting: %s', self.__prefix, self.__identity)
        self.__thread = None
