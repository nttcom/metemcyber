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

import atexit
import os
import shelve
from shelve import DbfilenameShelf as Shelf
from time import sleep
from typing import Any, Callable, List, Optional

from web3.exceptions import BlockNotFound


class TransactionDB:
    filepath: str
    shelf: Optional[Shelf]
    earliest: int

    def __init__(self, endpoint: Optional[str], filepath: str):
        self.filepath = filepath
        self.shelf = None  # for keep-connection mode
        if os.path.exists(filepath):
            saved = self.get('endpoint')
            if not saved:
                raise Exception(f'Endpoint is not saved in this dbfile: {filepath}')
            if endpoint and saved != endpoint:
                raise Exception(f'Endpoint mismatch (Saved endpoint is {saved})')
        else:
            if not endpoint:
                raise Exception('Missing endpoint')
            self.open(readonly=False)
            self.update('endpoint', endpoint)
            self.close()
        self.earliest = self._shelf_wrapper(True, self._load_earliest)

    def open(self, readonly=False):
        assert self.filepath
        if self.shelf:
            raise Exception('already opened')
        flag = 'r' if readonly else 'cu'  # flag 'u' requires python3-gdbm
        self.shelf = shelve.open(self.filepath, flag)
        atexit.register(self.close)

    def close(self, allow_redundant=False):
        if self.shelf is None:
            if allow_redundant:
                return
            raise Exception('not opened')
        self.shelf.close()
        self.shelf = None  # switch out from keep-alive mode
        atexit.unregister(self.close)

    def _shelf_wrapper(self, readonly: bool, callback: Callable, *args, **kwargs):
        if self.shelf:
            return callback(self.shelf, *args, **kwargs)
        flag = 'r' if readonly else 'cu'
        with shelve.open(self.filepath, flag) as shelf:
            return callback(shelf, *args, **kwargs)

    def stored_blocks(self, *args, **kwargs) -> List[int]:
        return self._shelf_wrapper(True, self._stored_blocks, *args, **kwargs)

    @staticmethod
    def _stored_blocks(shelf: Shelf, minimum: Optional[int] = None, maximum: Optional[int] = None
                       ) -> List[int]:
        return sorted([int(key) for key in list(shelf.keys())
                       if key.isdecimal() and
                          (minimum is None or int(key) >= minimum) and
                          (maximum is None or int(key) < maximum)])

    def get(self, *args, **kwargs):
        return self._shelf_wrapper(True, self._get, *args, **kwargs)

    @staticmethod
    def _get(shelf: Shelf, key: str):
        return shelf.get(key)

    @property
    def latest(self) -> int:
        return self._shelf_wrapper(True, self._load_latest)

    def update(self, *args, **kwargs):
        self._shelf_wrapper(False, self._update, *args, **kwargs)

    @staticmethod
    def _update(shelf: Shelf, key: str, value: Any):
        shelf[key] = value

    def update_latest(self, *args, **kwargs):
        self._shelf_wrapper(False, self._update_latest, *args, **kwargs)

    @staticmethod
    def _update_latest(shelf: Shelf, latest: int, allow_shrink: bool = False):
        if 'latest' not in shelf.keys():
            shelf['latest'] = latest
            return
        if shelf['latest'] == latest:
            return
        if shelf['latest'] > latest and not allow_shrink:
            return
        shelf['latest'] = latest

    @staticmethod
    def _load_earliest(shelf: Shelf) -> int:
        val = shelf.get('earliest')
        if val is not None:
            return val
        return min([int(x) for x in shelf.keys() if x.isdecimal()] + [0])

    @staticmethod
    def _load_latest(shelf: Shelf) -> int:
        val = shelf.get('latest')
        if val:
            return val
        return max([int(x) for x in shelf.keys() if x.isdecimal()] + [0])

    def load(self, *args, **kwargs) -> List[dict]:
        return self._shelf_wrapper(True, self._load, *args, **kwargs)

    @staticmethod
    def _load(shelf: Shelf, block: int, index: Optional[int] = None) -> List[dict]:
        retry = 10
        while retry > 0:
            try:
                if block > shelf['latest']:
                    raise BlockNotFound('Block not found')
                break
            except KeyError:  # may conflict with storing process
                sleep(1)
                retry -= 1
        if retry <= 0:
            raise Exception('Cannot get latest')
        tmp: List = shelf.get(str(block), [])
        return ([] if not tmp else  # no tx
                tmp if index is None else  # all tx in block
                tmp[index:index + 1])  # specified tx only

    def store(self, *args, **kwargs):
        self._shelf_wrapper(False, self._store, *args, **kwargs)

    def _store(self, shelf: Shelf, block: int, index: int, tx0: dict,
               hardlimit=None, softlimit=None):
        txs = shelf.get(str(block)) or []
        assert index == 0 or len(txs) >= index
        if len(txs) == index:
            txs.append(tx0)
        else:
            txs[index] = tx0  # overwrite
        shelf[str(block)] = txs  # {block: [tx0, tx1, ...]}

        if shelf.get('earliest') is None or self.earliest > block:
            shelf['earliest'] = self.earliest = block
        if block > shelf.get('latest', 0):
            shelf['latest'] = block

        if hardlimit:
            if softlimit is None:
                softlimit = hardlimit
            self._shrink_by_amount(shelf, hardlimit, softlimit)

    def _shrink_by_amount(self, shelf: Shelf, hardlimit: int, softlimit: int):
        # shrink down to softlimit if exceeds hardlimit.
        assert softlimit > 0
        assert hardlimit >= softlimit
        keys = [x for x in shelf.keys() if x.isdecimal()]
        if len(keys) <= hardlimit:
            return
        victims = sorted(keys, key=int)[:-softlimit]
        shelf['earliest'] = self.earliest = int(victims[-1]) + 1
        for key in victims:
            try:
                del shelf[key]
            except Exception:
                pass  # may be deleted by another proc.

    def shrink_by_blocknumber(self, *args, **kwargs):
        self._shelf_wrapper(False, self._shrink_by_blocknumber, *args, **kwargs)

    def _shrink_by_blocknumber(self, shelf: Shelf, shrink_before: int):
        for key in [x for x in shelf.keys() if x.isdecimal() and int(x) < shrink_before]:
            try:
                del shelf[key]
            except Exception:
                pass  # may be deleted by another proc.
        shelf['earliest'] = self.earliest = shrink_before
