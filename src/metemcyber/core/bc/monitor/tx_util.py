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

from typing import Any, List, Optional


def safe_inc(base: Optional[dict], keys: List[str]) -> dict:
    tgt = base if base is not None else {}
    tmp = tgt
    for key in keys[:-1]:  # fix branches
        if key not in tmp.keys():
            tmp[key] = {}
        tmp = tmp[key]
    if keys[-1] not in tmp.keys():  # fix leaf
        tmp[keys[-1]] = 0
    tmp[keys[-1]] += 1
    return tgt


def safe_set(base: Optional[dict], keys: List[str], val: Any) -> dict:
    tgt = base if base is not None else {}
    tmp = tgt
    for key in keys[:-1]:
        if key not in tmp.keys():
            tmp[key] = {}
        tmp = tmp[key]
    tmp[keys[-1]] = val
    return tgt


def safe_dec(base: Optional[dict], keys: List[str]) -> dict:
    if base is None:
        return {}
    tgt = base
    tmp = tgt
    for key in keys[:-1]:
        if key not in tmp.keys():  # no such leaf to decrement.
            return tgt
        tmp = tmp[key]
    if keys[-1] not in tmp.keys():  # no such leaf to decrement.
        return tgt
    if tmp[keys[-1]] > 1:
        tmp[keys[-1]] -= 1
        return tgt
    _recursive_delete(tgt, keys, 0)
    return tgt


def _recursive_delete(base: dict, keys: List[str], depth: int):
    if depth == len(keys):
        del base[keys[depth]]  # delete leaf
        return
    _recursive_delete(base[keys[depth]], keys, depth + 1)
    if not base[keys[depth]]:
        del base[keys[depth]]  # delete if the branch comes to be empty.
