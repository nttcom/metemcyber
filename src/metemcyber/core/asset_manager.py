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
import os
import sys
from datetime import datetime
from signal import SIGINT
from time import sleep
from typing import Dict, List, Optional, Tuple, Union
from urllib.request import Request, urlopen

import uvicorn
from eth_typing import ChecksumAddress
from fastapi import FastAPI, HTTPException
from psutil import Process
# pylint: disable=no-name-in-module
from pydantic import BaseModel
from web3 import Web3

from metemcyber.cli.constants import APP_DIR
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_token import CTIToken
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.multi_solver import MCSClient, MCSErrno, MCSError

#CTX: typer.Context = typer.Context(Command('_fake_command_'))
PIDFILEPATH = f'{APP_DIR}/assetmgr.pid'
VALID_TIMESTAMP_RANGE = 12 * 3600  # 12 hours in sec
SERVERLOG = get_logger(name='asset_mgr', file_prefix='core')
CLIENTLOG = get_logger(name='asset_client', file_prefix='core')

URLPATH_INFO = 'info'
URLPATH_MISP = 'misp_object'
URLPATH_SOLVER = 'solver'

CONFIG_SECTION = 'asset_manager'
DEFAULT_CONFIGS = {
    CONFIG_SECTION: {
        'url': 'http://localhost:48000',  # used by client
        'listen_address': '0.0.0.0',
        'listen_port': '48000',
    }
}


class GetInfoRequest(BaseModel):
    address: ChecksumAddress


class SignedRequest(BaseModel):
    timestamp: int
    nonce: int
    data: str
    signature: str

    @property
    def string_to_sign(self) -> str:
        return f'{self.timestamp}:{self.nonce}:{self.data}'

    @property
    def signer(self) -> ChecksumAddress:
        return verify_message(self.string_to_sign, self.signature)

    def sign(self, account: Account):
        self.signature = account.sign_message(self.string_to_sign)


class RequestWithTokenAddress(SignedRequest):
    token_address: ChecksumAddress


class PostMispRequest(RequestWithTokenAddress):
    auto_support: bool = False


class DeleteMispRequest(RequestWithTokenAddress):
    pass


class AssetManager:
    listen_address: str
    listen_port: int
    anonymous: Account
    solver_account: Account
    operator_address: ChecksumAddress
    assets_rootpath: str
    nonce_map: Dict[ChecksumAddress, int]
    app: FastAPI

    def __init__(self,
                 listen_address: str,
                 listen_port: int,
                 endpoint_url: str,
                 solver_account: Account,
                 operator_address: ChecksumAddress,
                 assets_rootpath: str):
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.anonymous = Account(Ether(endpoint_url))
        self.solver_account = solver_account
        self.operator_address = operator_address
        self.assets_rootpath = assets_rootpath
        self.nonce_map = {}
        try:
            self._get_solver()
        except Exception as err:
            raise Exception(f'Solver must be running and enabled: {err}') from err

        self.app = FastAPI()
        self.app.get(f'/{URLPATH_INFO}')(self._get_info)
        self.app.post(f'/{URLPATH_INFO}')(self._get_info)
        self.app.post(f'/{URLPATH_MISP}')(self._post_asset)
        self.app.delete(f'/{URLPATH_MISP}')(self._delete_asset)
        # self.app.get(f'/{URLPATH_SOLVER}')(self._get_accepting)
        # self.app.post(f'/{URLPATH_SOLVER}')(self._post_accepting)
        # self.app.delete(f'/{URLPATH_SOLVER}')(self._delete_accepting)

    def _get_solver(self) -> MCSClient:  # CAUTION: do not cache client.
        solver = MCSClient(self.solver_account, APP_DIR)
        solver.connect()
        solver.login()
        try:
            addr = solver.get_solver()
        except MCSError as err:
            if err.code == MCSErrno.ENOENT:
                msg = f'Solver is running, but not yet enabled'
            else:
                msg = str(err)
            raise Exception(msg) from err
        if addr != self.operator_address:
            raise Exception(
                f'Solver is running with different operator({addr}) '
                f'from configured({self.operator_address})')
        return solver

    async def _get_info(self, request: Optional[GetInfoRequest] = None) -> dict:
        if request:
            if not Web3.isChecksumAddress(request.address):
                raise HTTPException(400, 'Not a checksum address')
            nonce = self.nonce_map.get(request.address)
            if not nonce:
                nonce = int(datetime.now().timestamp() * 1000000)
                self.nonce_map[request.address] = nonce
        else:
            nonce = None
        try:
            self._get_solver()
            solver_status = 'running'
        except Exception as err:
            SERVERLOG.error(err)
            solver_status = str(err)
        ret: Dict[str, Union[str, int]] = {
            'solver_address': self.solver_account.eoa,
            'operator_address': self.operator_address,
            'solver_status': solver_status,
        }
        if nonce:
            ret['nonce'] = nonce
        return ret

    def _check_signed_request(self, request: RequestWithTokenAddress):
        ts_now = int(datetime.now().timestamp())
        ts_diff = abs(ts_now - request.timestamp)
        if ts_diff > VALID_TIMESTAMP_RANGE:
            raise HTTPException(400,
                                'RequestTimeTooSkewed: The difference between '
                                'the request time and the current time is too large')
        try:
            signer = request.signer
            SERVERLOG.debug(f'signer: {signer}')
        except Exception as err:
            raise HTTPException(400, f'Wrong Signature: {err}') from err
        if request.nonce != self.nonce_map.get(signer, 'xxx_fake'):
            raise HTTPException(400, 'Nonce mismatch')
        del self.nonce_map[signer]
        try:
            cti_token = CTIToken(self.anonymous).get(request.token_address)
        except Exception as err:
            raise HTTPException(400, f'Invalid token address: {err}') from err
        if signer != cti_token.publisher:
            raise HTTPException(403, 'Not a token publisher')
        if not cti_token.is_operator(self.solver_account.eoa, signer):
            raise HTTPException(401, 'Solver is not authorized')
        # TODO
        # apply whitelist and/or blacklist for access control

    def _asset_filepath(self, token_address: ChecksumAddress) -> str:
        assert Web3.isChecksumAddress(token_address)
        return f'{self.assets_rootpath}/{token_address}'

    async def _post_asset(self, request: PostMispRequest) -> dict:
        try:
            self._check_signed_request(request)
            filepath = self._asset_filepath(request.token_address)
            if os.path.exists(filepath):
                os.unlink(filepath)  # for the case target already exists as a symlink.
            with open(filepath, 'w') as fout:
                fout.write(request.data)
        except HTTPException as err:
            SERVERLOG.exception(err)
            raise
        except Exception as err:
            SERVERLOG.exception(err)
            raise HTTPException(500, f'{err.__class__.__name__}: {err}') from err
        SERVERLOG.info(f'saved asset file for token: {request.token_address}.')
        if request.auto_support:
            try:
                self._get_solver().solver('accept_challenges', [request.token_address])
                SERVERLOG.info(f'let solver accept token: {request.token_address}.')
            except Exception as err:
                SERVERLOG.exception(err)
                return {
                    'result': f'uploading file succeeded, but solver control failed: {err}'}
        return {'result': 'ok'}

    async def _delete_asset(self, request: DeleteMispRequest) -> dict:
        self._check_signed_request(request)
        filepath = self._asset_filepath(request.token_address)
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
                SERVERLOG.info(f'removed asset file for token: {request.token_address}.')
                ret = {'result': 'ok'}
            else:
                ret = {'result': 'asset file does not exist.'}
        except Exception as err:
            SERVERLOG.exception(err)
            raise HTTPException(500, f'{err.__class__.__name__}: str(err)') from err
        try:
            self._get_solver().solver('refuse_challenges', [request.token_address])
            SERVERLOG.info(f'let solver refuse token: {request.token_address}.')
        except Exception as err:
            SERVERLOG.exception(err)
            return {
                'result': f'removing file succeeded, but solver control failed: {err}'}
        return ret

    def run(self):
        uvicorn.run(self.app, host=self.listen_address, port=self.listen_port, log_level='trace')


class AssetManagerController:
    def __init__(self):
        self.expected_cmd_args = ['asset_manager', 'start']
        self.pid, self.listen_address, self.listen_port = self.get_running_params()

    def get_running_params(self) -> Tuple[int, str, int]:  # pid, addr, port
        try:
            with open(PIDFILEPATH, 'r') as fin:
                str_data = fin.readline().strip()
            str_pid, str_addr, str_port = str_data.split('\t', 2)
        except Exception:
            return 0, '', 0
        try:
            proc = Process(int(str_pid))
            cmdline: List = proc.cmdline()
            if len(cmdline) - 2 == len(self.expected_cmd_args):  # cut leading 'python'&'metemctl'
                for idx, arg in enumerate(self.expected_cmd_args):
                    assert cmdline[2 + idx] == arg
                return int(str_pid), str_addr, int(str_port)
        except Exception:
            pass
        if os.path.exists(PIDFILEPATH):
            os.unlink(PIDFILEPATH)  # remove defunct pidfile.
        return 0, '', 0

    def start(self,
              listen_address: str,
              listen_port: int,
              endpoint_url: str,
              solver_account: Account,
              operator_address: ChecksumAddress,
              assets_rootpath: str) -> int:
        if self.pid > 0:
            raise Exception(f'Already running on pid: {self.pid}')

        pid = os.fork()
        if pid > 0:  # parent
            for _cnt in range(3):
                sleep(1)
                if self.get_running_params()[0] != pid:
                    continue  # wait again
                return pid
            raise Exception('Cannot start AssetManager')

        # child
        try:
            mgr = AssetManager(listen_address,
                               listen_port,
                               endpoint_url,
                               solver_account,
                               operator_address,
                               assets_rootpath)
            with open(PIDFILEPATH, 'w') as fout:
                fout.write(f'{os.getpid()}\t{listen_address}\t{listen_port}\n')
            mgr.run()
        except KeyboardInterrupt:
            pass
        finally:
            if os.path.exists(PIDFILEPATH):
                os.unlink(PIDFILEPATH)
        sys.exit(0)
        return 0  # not reached

    def stop(self):
        if self.pid <= 0:
            raise Exception('Not running')
        try:
            os.kill(self.pid, SIGINT)
            self.pid = 0
        except Exception as err:
            raise Exception(f'Cannot stop AssetManager(pid={self.pid})') from err


class AssetManagerClient:
    base_url: str
    common_headers: dict

    def __init__(self, url: str):
        self.base_url = url
        self.common_headers = {'Content-Type': 'application/json'}

    def get_info(self, address: Optional[ChecksumAddress] = None) -> dict:
        url = f'{self.base_url}/{URLPATH_INFO}'
        pdata = GetInfoRequest(address=address).json().encode('utf-8') if address else None

        request = Request(url, method='POST', headers=self.common_headers, data=pdata)
        with urlopen(request) as response:
            rdata = response.read()
            if isinstance(rdata, bytes):
                rdata = rdata.decode()
        jdata = json.loads(rdata)
        keys = set({
            'solver_address',
            'operator_address',
            'solver_status',
        })
        assert set(jdata.keys()).intersection(keys) == keys
        assert not address or 'nonce' in jdata.keys()
        return jdata

    def post_asset(self, account: Account, token_address: ChecksumAddress, filepath: str,
                   auto_support: bool = False) -> str:
        info = self.get_info(address=account.eoa)
        url = f'{self.base_url}/{URLPATH_MISP}'
        request_data = PostMispRequest(timestamp=int(datetime.now().timestamp()),
                                       nonce=info['nonce'],
                                       token_address=token_address,
                                       data='',
                                       signature='',
                                       auto_support=auto_support)
        with open(filepath, 'r') as fin:
            request_data.data = fin.read()
        request_data.sign(account)

        jdata = request_data.json().encode('utf-8')
        request = Request(url, method='POST', headers=self.common_headers, data=jdata)
        with urlopen(request) as response:
            detail = json.loads(response.read().decode())['result']
            return detail

    def delete_asset(self, account: Account, token_address: ChecksumAddress) -> str:
        info = self.get_info(address=account.eoa)
        url = f'{self.base_url}/{URLPATH_MISP}'
        request_data = DeleteMispRequest(timestamp=int(datetime.now().timestamp()),
                                         nonce=info['nonce'],
                                         token_address=token_address,
                                         data='',
                                         signature='')
        request_data.sign(account)

        jdata = request_data.json().encode('utf-8')
        request = Request(url, method='DELETE', headers=self.common_headers, data=jdata)
        with urlopen(request) as response:
            detail = json.loads(response.read().decode())['result']
            return detail
