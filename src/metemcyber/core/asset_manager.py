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
from fastapi.middleware.cors import CORSMiddleware
from omegaconf.dictconfig import DictConfig
from psutil import Process
# pylint: disable=no-name-in-module
from pydantic import BaseModel
from web3 import Web3

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_token import CTIToken
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import ADDRESS0, verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.solver_server import SolverClient, SolverController

VALID_TIMESTAMP_RANGE = 12 * 3600  # 12 hours in sec
SERVERLOG = get_logger(name='asset_mgr', file_prefix='core')
CLIENTLOG = get_logger(name='asset_client', file_prefix='core')

URLPATH_PREFIX = 'solver/api'
URLPATH_INFO = f'{URLPATH_PREFIX}/info'
URLPATH_MISP = f'{URLPATH_PREFIX}/misp_object'
URLPATH_LIST = f'{URLPATH_PREFIX}/list_tokens'
URLPATH_ACCEPT = f'{URLPATH_PREFIX}/accept_tokens'


class GetInfoRequest(BaseModel):
    address: ChecksumAddress


class SignedRequest(BaseModel):
    nonce: int
    timestamp: int = 0
    signature: str = ''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.timestamp == 0:
            self.timestamp = int(datetime.now().timestamp())

    @property
    def string_to_sign(self) -> str:
        return f'{self.timestamp}:{self.nonce}'

    @property
    def signer(self) -> ChecksumAddress:
        return verify_message(self.string_to_sign, self.signature)

    def sign(self, account: Account):
        self.signature = account.sign_message(self.string_to_sign)


class RequestWithTokenAddress(SignedRequest):
    token_address: ChecksumAddress


class PostMispRequest(RequestWithTokenAddress):
    data: str = ''
    auto_support: bool = False


class DeleteMispRequest(RequestWithTokenAddress):
    pass


class AcceptingRequest(SignedRequest):
    token_addresses: List[ChecksumAddress]


class AnonymousAcceptingRequest(BaseModel):
    token_addresses: List[ChecksumAddress]


class AssetManager:
    config: DictConfig
    anonymous: Account
    solver_account: Account
    nonce_map: Dict[ChecksumAddress, int]
    listen_address: str
    listen_port: int
    app: FastAPI

    def __init__(self, solver_account: Account, config: DictConfig):
        self.config = config
        self.anonymous = Account(Ether(config.workspace.endpoint_url))
        self.solver_account = solver_account
        self.nonce_map = {}
        self.listen_address = config.workspace.assetmanager.listen_address
        self.listen_port = config.workspace.assetmanager.listen_port

        ctrl = self._solver_ctrl()
        if ctrl.pid <= 0:
            raise Exception(f'Solver looks down (must be running)')
        if ctrl.solver_eoaa != self.solver_account.eoa:
            raise Exception(f'Solver is running with different EOA({ctrl.solver_eoaa})')
        if ctrl.operator_address != self.config.workspace.operator.address:
            raise Exception(f'Solver is running with different operator({ctrl.operator_address})')
        try:
            solver = self._get_solver()
            solver.disconnect()
        except Exception as err:
            raise Exception(f'Cannot connect to solver: {err}') from err

        self.app = FastAPI()
        self.app.get(f'/{URLPATH_INFO}')(self._get_info)
        self.app.post(f'/{URLPATH_INFO}')(self._get_info)
        self.app.post(f'/{URLPATH_MISP}')(self._post_asset)
        self.app.delete(f'/{URLPATH_MISP}')(self._delete_asset)
        self.app.post(f'/{URLPATH_LIST}')(self._list_accepting)
        self.app.post(f'/{URLPATH_ACCEPT}')(self._post_accepting)
        self.app.delete(f'/{URLPATH_ACCEPT}')(self._delete_accepting)

        # Enable Cross-Origin Resource Sharing with localhost
        origins = [
            'http://localhost:3000'  # webpotal-api
        ]
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_headers=['*'],
            allow_methods=['DELETE', 'GET', 'OPTION', 'POST']
        )

    def _solver_ctrl(self) -> SolverController:
        return SolverController(self.solver_account, self.config)

    def _get_solver(self) -> SolverClient:  # CAUTION: do not cache client.
        client = SolverClient(self.solver_account, self.config)
        client.connect()
        return client

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
        ret: Dict[str, Union[ChecksumAddress, str, int]] = {
            'solver_address': ADDRESS0,
            'operator_address': ADDRESS0,
            'solver_status': 'running',
        }
        try:
            ctrl = self._solver_ctrl()
            ret['solver_address'] = ctrl.solver_eoaa
            ret['operator_address'] = ctrl.operator_address
            ret['solver_status'] = 'running' if ctrl.pid > 0 else 'not running'
        except Exception as err:
            SERVERLOG.error(err)
            ret['solver_status'] = str(err)
        if nonce:
            ret['nonce'] = nonce
        return ret

    def _check_signed_request(self, request: SignedRequest):
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
        if request.nonce != self.nonce_map.get(signer, -ts_now):
            raise HTTPException(400, 'Nonce mismatch')
        del self.nonce_map[signer]  # remove used nonce
        # TODO
        # apply whitelist and/or blacklist for access control

    def _check_request_with_token(self, request: RequestWithTokenAddress,
                                  check_authorized: bool = False):
        try:
            cti_token = CTIToken(self.anonymous).get(request.token_address)
        except Exception as err:
            raise HTTPException(400, f'Invalid token address: {err}') from err
        if request.signer != cti_token.publisher:
            raise HTTPException(403, 'Not a token publisher')
        if check_authorized:
            if not cti_token.is_operator(self.solver_account.eoa, cti_token.publisher):
                raise HTTPException(401, 'Solver is not authorized')

    def _asset_filepath(self, token_address: ChecksumAddress) -> str:
        if not Web3.isChecksumAddress(token_address):
            raise HTTPException(400, 'Not a checksum address')
        return f'{self.config.runtime.asset_filepath}/{token_address}'

    async def _post_asset(self, request: PostMispRequest) -> dict:
        try:
            self._check_signed_request(request)
            self._check_request_with_token(request, check_authorized=True)
            filepath = self._asset_filepath(request.token_address)
            if os.path.exists(filepath):
                os.unlink(filepath)  # for the case target already exists as a symlink.
            with open(filepath, 'w', encoding='utf-8') as fout:
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
                solver = self._get_solver()
                solver.solver('accept_challenges', [request.token_address])
                SERVERLOG.info(f'let solver accept token: {request.token_address}.')
            except Exception as err:
                SERVERLOG.exception(err)
                return {
                    'result': f'uploading file succeeded, but solver control failed: {err}'}
            finally:
                if solver:
                    solver.disconnect()
        return {'result': 'ok'}

    async def _delete_asset(self, request: DeleteMispRequest) -> dict:
        try:
            self._check_signed_request(request)
            self._check_request_with_token(request)
            filepath = self._asset_filepath(request.token_address)
            if os.path.exists(filepath):
                os.unlink(filepath)
                SERVERLOG.info(f'removed asset file for token: {request.token_address}.')
                ret = {'result': 'ok'}
            else:
                ret = {'result': 'asset file does not exist.'}
        except HTTPException as err:
            SERVERLOG.exception(err)
            raise
        except Exception as err:
            SERVERLOG.exception(err)
            raise HTTPException(500, f'{err.__class__.__name__}: str(err)') from err
        try:
            solver = self._get_solver()
            solver.solver('refuse_challenges', [request.token_address])
            SERVERLOG.info(f'let solver refuse token: {request.token_address}.')
        except Exception as err:
            SERVERLOG.exception(err)
            return {
                'result': f'removing file succeeded, but solver control failed: {err}'}
        finally:
            if solver:
                solver.disconnect()
        return ret

    def _check_request_for_accepting(self, request: AcceptingRequest,
                                     check_authorized: bool = False,
                                     check_assetfile: bool = False):
        signer = request.signer
        for address in request.token_addresses:
            try:
                cti_token = CTIToken(self.anonymous).get(address)
            except Exception as err:
                raise HTTPException(400, f'Bad Request: {err}') from err
            if cti_token.publisher != signer:
                raise HTTPException(403, 'Not a token publisher')
            if check_authorized:
                if not cti_token.is_operator(self.solver_account.eoa, cti_token.publisher):
                    raise HTTPException(401, 'Solver is not authorized')
            if check_assetfile:
                if not os.path.exists(self._asset_filepath(address)):
                    raise HTTPException(404, 'Asset file not yet uploaded')

    async def _list_accepting(self, request: AnonymousAcceptingRequest) -> dict:
        try:
            solver = self._get_solver()
            acceptings = solver.solver('accepting_tokens')
        except Exception as err:
            SERVERLOG.exception(err)
            raise HTTPException(500, f'Cannot connect to solver: {err}') from err
        finally:
            if solver:
                solver.disconnect()
        return {'result': list(set(acceptings).intersection(set(request.token_addresses)))}

    def _acception_control(self, request: AcceptingRequest, method: str) -> dict:
        if method not in {'POST', 'DELETE'}:
            raise HTTPException(500, f'InternalError: unexpected method: {method}')
        try:
            self._check_signed_request(request)
            flg = (method == 'POST')
            self._check_request_for_accepting(request, check_authorized=flg, check_assetfile=flg)
        except HTTPException as err:
            SERVERLOG.exception(err)
            raise
        try:
            solver = self._get_solver()
            solver.solver(
                'accept_challenges' if method == 'POST' else 'refuse_challenges',
                request.token_addresses)
        except Exception as err:
            SERVERLOG.exception(err)
            raise HTTPException(500, f'{err.__class__.__name__}: {str(err)}') from err
        finally:
            if solver:
                solver.disconnect()
        return {'result': 'ok'}

    async def _post_accepting(self, request: AcceptingRequest) -> dict:
        return self._acception_control(request, 'POST')

    async def _delete_accepting(self, request: AcceptingRequest) -> dict:
        return self._acception_control(request, 'DELETE')

    def run(self):
        uvicorn.run(self.app, host=self.listen_address, port=self.listen_port, log_level='info')


class AssetManagerController:
    account: Account
    config: DictConfig
    pid: int
    listen_address: str
    listen_port: int

    def __init__(self, account: Account, config: DictConfig):
        self.account = account
        self.config = config
        self.pid, self.listen_address, self.listen_port = self.get_running_params()

    def get_running_params(self) -> Tuple[int, str, int]:  # pid, addr, port
        try:
            with open(self.config.runtime.assetmanager_pid_filepath, 'r', encoding='utf-8') as fin:
                str_data = fin.readline().strip()
                str_args = fin.readline().strip()
            str_pid, str_addr, str_port = str_data.split('\t', 2)
            expected_cmd_args = str_args.split('\t')
            pid = int(str_pid)
            cmdline = Process(pid).cmdline()
            if cmdline != expected_cmd_args:
                raise Exception(f'command args mismatch')
            return int(str_pid), str_addr, int(str_port)
        except Exception:
            pass
            # FALLTHROUGH
        if os.path.exists(self.config.runtime.assetmanager_pid_filepath):
            os.unlink(self.config.runtime.assetmanager_pid_filepath)  # remove defunct pidfile.
        return 0, '', 0

    def start(self):
        if self.pid > 0:
            raise Exception(f'Already running on pid: {self.pid}')

        pid = os.fork()
        if pid > 0:  # parent
            for _cnt in range(3):
                sleep(1)
                running = self.get_running_params()
                if running[0] != pid:
                    continue  # wait again
                self.pid, self.listen_address, self.listen_port = running
                return
            raise Exception('Cannot start AssetManager')

        # child
        try:
            os.setsid()
            mgr = AssetManager(self.account, self.config)
            pid = os.getpid()
            str_cmdline = '\t'.join(Process(pid).cmdline())
            with open(self.config.runtime.assetmanager_pid_filepath, 'w', encoding='utf-8') as fout:
                fout.write(f'{pid}\t{mgr.listen_address}\t{mgr.listen_port}\n')
                fout.write(f'{str_cmdline}\n')
            mgr.run()
        except KeyboardInterrupt:
            pass
        finally:
            if os.path.exists(self.config.runtime.assetmanager_pid_filepath):
                os.unlink(self.config.runtime.assetmanager_pid_filepath)
        sys.exit(0)

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
                   auto_support: bool = False, nonce: Optional[int] = None) -> str:
        nonce = nonce if nonce else self.get_info(address=account.eoa)['nonce']
        url = f'{self.base_url}/{URLPATH_MISP}'
        request_data = PostMispRequest(nonce=nonce,
                                       token_address=token_address,
                                       auto_support=auto_support)
        with open(filepath, 'r', encoding='utf-8') as fin:
            request_data.data = fin.read()
        request_data.sign(account)

        jdata = request_data.json().encode('utf-8')
        request = Request(url, method='POST', headers=self.common_headers, data=jdata)
        with urlopen(request) as response:
            detail = json.loads(response.read().decode())['result']
            return detail

    def delete_asset(self, account: Account, token_address: ChecksumAddress,
                     nonce: Optional[int] = None) -> str:
        nonce = nonce if nonce else self.get_info(address=account.eoa)['nonce']
        url = f'{self.base_url}/{URLPATH_MISP}'
        request_data = DeleteMispRequest(nonce=nonce,
                                         token_address=token_address)
        request_data.sign(account)

        jdata = request_data.json().encode('utf-8')
        request = Request(url, method='DELETE', headers=self.common_headers, data=jdata)
        with urlopen(request) as response:
            detail = json.loads(response.read().decode())['result']
            return detail

    def list_accepting(self, token_addresses: List[ChecksumAddress]) -> List[ChecksumAddress]:
        url = f'{self.base_url}/{URLPATH_LIST}'
        request_data = AnonymousAcceptingRequest(token_addresses=token_addresses)

        jdata = request_data.json().encode('utf-8')
        request = Request(url, method='POST', headers=self.common_headers, data=jdata)
        with urlopen(request) as response:
            tokens = json.loads(response.read().decode())['result']
            return tokens

    def _acception_control(self, account: Account, token_addresses: List[ChecksumAddress],
                           method: str, nonce: Optional[int] = None) -> str:
        assert method in {'POST', 'DELETE'}
        nonce = nonce if nonce else self.get_info(address=account.eoa)['nonce']
        url = f'{self.base_url}/{URLPATH_ACCEPT}'
        request_data = AcceptingRequest(nonce=nonce,
                                        token_addresses=token_addresses)
        request_data.sign(account)

        jdata = request_data.json().encode('utf-8')
        request = Request(url, method=method, headers=self.common_headers, data=jdata)
        with urlopen(request) as response:
            detail = json.loads(response.read().decode())['result']
            return detail

    def post_accepting(self, account: Account, token_addresses: List[ChecksumAddress],
                       nonce: Optional[int] = None) -> str:
        return self._acception_control(account, token_addresses, 'POST', nonce=nonce)

    def delete_accepting(self, account: Account, token_addresses: List[ChecksumAddress],
                         nonce: Optional[int] = None) -> str:
        return self._acception_control(account, token_addresses, 'DELETE', nonce=nonce)
