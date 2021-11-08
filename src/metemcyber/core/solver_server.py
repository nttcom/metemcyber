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

from __future__ import annotations

import argparse
import inspect
import json
import os
import select
import signal
import socket
import sys
from enum import IntEnum, auto
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, cast

from cryptography.fernet import Fernet
from eth_typing import ChecksumAddress
from omegaconf import OmegaConf
from omegaconf.dictconfig import DictConfig
from psutil import Process

from metemcyber.cli.config import decode_keyfile, load_config
from metemcyber.core.bc.account import Account
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import ADDRESS0, verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.plugin import PluginManager
from metemcyber.core.solver import BaseSolver

SERVERLOG = get_logger(name='solv_server', file_prefix='core')
CLIENTLOG = get_logger(name='solv_client', file_prefix='core')

INHERIT_PW_ENV_NAME = '_SOLVER_INHERIT_FOR_KEYFILE_'
POLL_SHUTDOWN_INTERVAL_SEC = 1
KEEPALIVE_TIMEOUT_SEC = 10
BUFSIZ = 4096

ARGS_DELIMITER = '\t'   # for command line input
EOM = '\v'  # End of Message


def tracelog(logger, *args, **kwargs):
    stacks = inspect.stack()
    assert len(stacks) > 1
    finfo = inspect.getframeinfo(stacks[1][0])
    filename = os.path.basename(finfo.filename)
    lineno = finfo.lineno
    funcname = finfo.function
    pref = f'{filename}:{lineno} {funcname}'
    if len(args) > 0:
        logger.debug(pref + ': ' + args[0], *args[1:], **kwargs)
    else:
        logger.debug(pref, **kwargs)


class DataPack:
    def __init__(self, code, eoaa, *args, **kwargs):
        self.code: Union[str, int] = code  # SolverErrno or function
        self.eoaa: Optional[ChecksumAddress] = eoaa
        self.args: Tuple[Any, ...] = args
        self.kwargs: Dict[str, Any] = kwargs
        self.sign: Optional[str] = None

    @classmethod
    def from_string(cls, str_data: str) -> DataPack:
        jdata = json.loads(str_data)
        inst = cls(
            jdata.get('code'),
            jdata.get('eoaa'),
            *jdata.get('args', []),
            **jdata.get('kwargs', {}))
        inst.sign = jdata.get('sign')
        return inst

    def __str__(self):  # sign is not included
        return json.dumps({
            'code': self.code,
            'eoaa': self.eoaa,
            'args': self.args,
            'kwargs': self.kwargs,
        })

    @property
    def signed_string(self):  # include sign
        return json.dumps({
            'code': self.code,
            'eoaa': self.eoaa,
            'args': self.args,
            'kwargs': self.kwargs,
            'sign': self.sign,
        })

    def sign_message(self, sign_func: Callable[[str], str]) -> DataPack:
        self.sign = sign_func(str(self))
        return self  # for DataPack(...).sign_message(pkey).send(conn)

    def verify(self) -> bool:
        if self.eoaa and self.sign:
            return verify_message(str(self), self.sign) == self.eoaa
        return False

    def send(self, sock):
        msg = (self.signed_string + EOM).encode()
        total = 0
        while total < len(msg):
            if hasattr(socket, 'SOCK_NONBLOCK'):
                # SOCK_NONBLOCK is available only on Linux.
                # pylint pylint: disable=E1101
                tmp = sock.send(msg[total:], socket.SOCK_NONBLOCK)
            else:
                tmp = sock.send(msg[total:])
            if tmp == 0:
                raise Exception('Disconnected by peer')
            total += tmp


class SolverErrno(IntEnum):
    OK = 0xE000
    EPROTO = auto()
    EINVAL = auto()
    ENOP = auto()
    EALREADY = auto()
    ENOENT = auto()
    EINTERNAL = auto()
    EUNKNOWN = auto()


class SolverError(Exception):
    def __init__(self, code: SolverErrno, msg: Optional[str] = None):
        super().__init__(self)
        self.code = code
        self.msg = msg if msg else {
            SolverErrno.OK: 'OK',
            SolverErrno.EPROTO: 'Protocol Error',
            SolverErrno.EINVAL: 'Invalid Parameter',
            SolverErrno.ENOP: 'Nothing to Operate',
            SolverErrno.EALREADY: 'Already Exists',
            SolverErrno.ENOENT: 'No Such Entry',
        }.get(code, 'Unknown Error')

    def __str__(self):
        return f'{self.code:04X}: {self.msg:s}'


class SolverServer:
    account: Account
    config: DictConfig
    sock = None
    shutdown: bool = False
    solver: BaseSolver
    fernet_key: Optional[bytes] = None

    def __init__(self, account: Account, config: DictConfig):
        self.account = account
        self.config = config
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.solver = self._setup_solver_instance()
        self.solver.accept_registered(None)

    def _setup_solver_instance(self) -> BaseSolver:
        pmgr = PluginManager()
        pmgr.load()
        pmgr.set_default_solverclass(self.config.workspace.solver.plugin or 'gcs_solver.py')
        solverclass = pmgr.get_solverclass(self.config.workspace.operator.address)
        return solverclass(self.account, self.config)

    def _signal_handler(self, signum, _):
        if signum not in {signal.SIGINT}:
            SERVERLOG.warning(f'caught un-expected signal: {signum}')
            return
        tracelog(SERVERLOG, 'caught SIGINT')
        self.shutdown = True

    def accept_loop(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        try:
            self.sock.bind(self.config.runtime.solver_socket_filepath)
            self.sock.listen()
            self.sock.settimeout(POLL_SHUTDOWN_INTERVAL_SEC)
            while True:
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    if self.shutdown:
                        break
                    continue
                self._communicate(conn, addr)
        finally:
            self.solver.destroy()
            os.unlink(self.config.runtime.solver_socket_filepath)
        tracelog(SERVERLOG, 'SolverServer shutted down.')

    def _communicate(self, conn, _addr):
        tracelog(SERVERLOG, 'start communication')
        self.fernet_key = None  # reset key
        disconnect = False
        msg = ''
        while not disconnect:
            timeout = KEEPALIVE_TIMEOUT_SEC
            while True:
                rfds, _, _ = select.select([conn], [], [], POLL_SHUTDOWN_INTERVAL_SEC)
                if rfds or self.shutdown:
                    break
                timeout -= POLL_SHUTDOWN_INTERVAL_SEC
                if timeout < 0:
                    tracelog(SERVERLOG, 'timeout')
                    disconnect = True
                    break
            if self.shutdown or disconnect:
                break
            tmp = conn.recv(BUFSIZ).decode()
            if len(tmp) == 0:  # disconnected
                break
            msg += tmp
            queries = msg.split(EOM)
            for query in queries[:-1]:
                tracelog(SERVERLOG, 'query: %s', query)

                brk, discon = self._treat_one_query(query, conn)

                disconnect |= discon
                if brk:
                    break
            msg = queries[-1]  # empty or incomplete msg
        tracelog(SERVERLOG, 'disconnecting')
        conn.close()

    def _treat_one_query(self, query, conn) -> Tuple[bool, bool]:  # [break, disconnect]
        try:
            dpk = DataPack.from_string(query)
            if dpk.code != 'ping':  # need sign expect ping
                if not dpk.verify():
                    raise SolverError(SolverErrno.EINVAL, 'Verify signature failed')
                if dpk.eoaa != self.account.eoa:
                    raise SolverError(SolverErrno.EINVAL, 'EOA address mismatch')
                if dpk.code == 'shutdown':
                    signal.raise_signal(signal.SIGINT)
                    return True, False
                if dpk.code == 'disconnect':
                    return True, True

            resp = self._get_callback(dpk.code)(dpk)

        except SolverError as err:
            resp = DataPack(err.code, None, data=err.msg)
        except Exception as err:
            SERVERLOG.exception(err)
            resp = DataPack(SolverErrno.EINTERNAL, None, data=str(err))

        tracelog(SERVERLOG, 'retval: %X, %s, %s', resp.code, resp.args, resp.kwargs)
        try:
            resp.send(conn)
        except Exception as err:
            tracelog(SERVERLOG, 'send error: %s', err)
        return False, False

    def _get_callback(self, func) -> Callable[[DataPack], DataPack]:
        if func == 'ping':
            return lambda *args, **kwargs: DataPack(SolverErrno.OK, None, data='pong')
        if func == 'get_fernet_key':
            return self._get_fernet_key
        if func == 'solver':
            return self._solver_wrapper
        raise SolverError(SolverErrno.EINVAL, 'No such method')

    def _solver_wrapper(self, dpk: DataPack) -> DataPack:
        if len(dpk.args) < 1:
            raise SolverError(SolverErrno.EINVAL, 'Missing function')
        data = getattr(self.solver, dpk.args[0])(*dpk.args[1:], **dpk.kwargs)
        return DataPack(SolverErrno.OK, None, data=data)

    def _get_fernet_key(self, _dpk: DataPack) -> DataPack:
        if not self.fernet_key:
            self.fernet_key = Fernet.generate_key()
            assert self.fernet_key
        return DataPack(SolverErrno.OK, None, data=self.fernet_key.decode())


class SolverController:
    config: DictConfig
    pid: int
    solver_eoaa: ChecksumAddress
    operator_address: ChecksumAddress

    def __init__(self, config: DictConfig):
        self.config = config
        self.pid, self.solver_eoaa, self.operator_address = self._get_running_params()

    def _get_running_params(self) -> Tuple[int, ChecksumAddress, ChecksumAddress]:
        try:
            with open(self.config.runtime.solver_pid_filepath, 'r', encoding='utf-8') as fin:
                str_pid, eoaa, addr = fin.readline().strip().split('\t', 2)
                expected_cmd_args = fin.readline().strip().split('\t')
            pid = int(str_pid)
            cmdline = Process(pid).cmdline()
            if cmdline != expected_cmd_args:
                raise Exception(f'command args mismatch')
            return pid, cast(ChecksumAddress, eoaa), cast(ChecksumAddress, addr)
        except Exception:
            pass  # FALLTHROUGH
        if os.path.exists(self.config.runtime.solver_pid_filepath):
            os.unlink(self.config.runtime.solver_pid_filepath)  # remove defunct pidfile.
        return 0, ADDRESS0, ADDRESS0

    def start(self):
        if self.pid > 0:
            raise Exception(f'Already running on pid: {self.pid}')
        if not self.config.workspace.operator.address:
            raise Exception('Missing configuration: workspace.operator.address')
        tmp_config = self.config.copy()
        OmegaConf.set_readonly(tmp_config, False)
        OmegaConf.resolve(tmp_config)
        if not tmp_config.workspace.solver.keyfile_password:
            _eoaa, _pkey, pword = decode_keyfile(tmp_config.workspace.solver.keyfile, '')
            os.environ[INHERIT_PW_ENV_NAME] = pword  # pass to child process

        pid = os.fork()
        if pid > 0:  # parent
            os.environ.pop(INHERIT_PW_ENV_NAME, None)
            for _cnt in range(3):
                sleep(1)
                if self._get_running_params()[0] != pid:
                    continue  # wait again
                self.pid = pid
                return
            raise Exception('Cannot start SolverServer')

        # child
        args = ['python3', __file__, 'server']
        os.execvpe(args[0], args, os.environ)

    def stop(self):
        if self.pid <= 0:
            raise Exception('Not running')
        try:
            os.kill(self.pid, signal.SIGINT)
            self.pid = 0
        except Exception as err:
            raise Exception(f'Cannot stop SolverServer(pid={self.pid})') from err


class SolverClient():
    """ Class as a client
    """

    def __init__(self, account: Account, config: DictConfig):
        self.account = account
        self.config = config
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.disconnecting = False
        self.buffer = ''
        tracelog(CLIENTLOG, 'initialized %s', self)

    def destroy(self):
        self.disconnect()

    def connect(self):
        try:
            self.sock.connect(self.config.runtime.solver_socket_filepath)
        except FileNotFoundError as err:
            raise Exception('Solver not running') from err
        except OSError as err:
            if err.errno != 106:  # ignore EISCONN (already connected)
                raise
        self.ping()  # check connected

    def disconnect(self):
        self.disconnecting = True
        try:
            self.send_query('disconnect')
        finally:
            self.sock.close()
        self.sock = None

    def shutdown(self):
        self.send_query('shutdown')
        # may disconnected by server

    def send_query(self, func, *args, **kwargs):
        dpk = DataPack(func, self.account.eoa, *args, **kwargs)
        dpk.sign_message(self.account.sign_message)
        tracelog(CLIENTLOG, str(dpk))
        if dpk.send(self.sock) == 0:
            self.disconnecting = True

    def wait_response(self) -> DataPack:
        resp = self.buffer
        assert len(resp) == 0  # XXX Uhmm how to control msg drived by peer...
        while EOM not in resp:
            tmp = self.sock.recv(BUFSIZ).decode()
            if len(tmp) == 0:  # disconnected
                self.disconnecting = True
                raise Exception('Disconnected by peer')
            resp += tmp
        resp, left = resp.split(EOM, 1)
        dpk = DataPack.from_string(resp)
        tracelog(CLIENTLOG, '%X, %s, %s', dpk.code, dpk.args, dpk.kwargs)
        self.buffer = left  # maybe no left message
        return dpk

    def _simple_query(self, query) -> Optional[Any]:
        self.send_query(query)
        resp = self.wait_response()
        if resp.code == SolverErrno.OK:
            return resp.kwargs.get('data')
        raise Exception(f'Received error: {resp.code:X} {resp.kwargs.get("data")}')

    def ping(self):
        return self._simple_query('ping')

    def _get_fernet_key(self) -> bytes:
        self.send_query('get_fernet_key')
        resp = self.wait_response()
        if resp.code == SolverErrno.OK:
            return resp.kwargs['data'].encode('utf-8')
        raise SolverError(code=cast(SolverErrno, resp.code), msg=resp.kwargs.get('data'))

    def solver(self, *args, **kwargs) -> Any:
        assert len(args) > 0
        self.send_query('solver', *args, **kwargs)
        resp = self.wait_response()
        if resp.code == SolverErrno.OK:
            return resp.kwargs.get('data')
        raise SolverError(code=cast(SolverErrno, resp.code), msg=resp.kwargs.get('data'))


def mcs_console(account, config):
    """ Simple CUI to use SolverClient
    """

    client = SolverClient(account, config)
    try:
        client.connect()
    except Exception as err:
        raise Exception('cannot connect to solver daemon') from err
    sock = client.sock
    msg = ''
    while not client.disconnecting:

        print('query? ', end='')

        sys.stdout.flush()
        try:
            rfds, _, _ = select.select([sock, sys.stdin], [], [])

            if sock in rfds:  # received message from peer
                tmp = sock.recv(BUFSIZ).decode()
                if len(tmp) == 0:  # disconnected
                    break
                msg += tmp
                tracelog(CLIENTLOG, 'received: %s', tmp.strip())
                queries = msg.split(EOM)
                for query in queries[:-1]:
                    if query in {'SHUTDOWN', 'DISCONNECT'}:
                        client.disconnecting = True
                        break  # immediately
                msg = queries[-1]  # empty or incomplete msg
                if client.disconnecting:
                    break

            if sys.stdin in rfds:  # got query from stdin
                # input format:
                #   query? <func_name>
                # or
                #   query? <func_name><tab><args and|or kwargs>
                # format of <args and|or kwargs>:
                #   {"args":["arg0", ...], "kwargs":{"key0":"val0",...}}
                #
                tokens = sys.stdin.readline().strip().split(ARGS_DELIMITER, 1)
                func = tokens[0]
                jval = json.loads(tokens[1] if len(tokens) > 1 else '{}')
                try:
                    resp = getattr(client, func)(
                        *jval.get('args', []),
                        **jval.get('kwargs', {}))
                    print(resp)
                    if func in {'shutdown', 'disconnect'}:
                        break
                except Exception as err:
                    CLIENTLOG.exception(err)
                    print(err)

        except KeyboardInterrupt:
            break
    if sock:
        sock.close()


def main(args):
    config = load_config()
    OmegaConf.set_readonly(config, False)
    OmegaConf.resolve(config)
    if not config.workspace.solver.keyfile_password and os.environ.get(INHERIT_PW_ENV_NAME):
        config.workspace.solver.keyfile_password = os.environ.pop(INHERIT_PW_ENV_NAME)
    eoaa, pkey, _ = decode_keyfile(config.workspace.solver.keyfile,
                                   config.workspace.solver.keyfile_password)
    account = Account(Ether(config.workspace.endpoint_url), eoaa, pkey)

    if args.mode == 'server':
        try:
            server = SolverServer(account, config)
            pid = os.getpid()
            str_cmdline = '\t'.join(Process(pid).cmdline())
            with open(config.runtime.solver_pid_filepath, 'w', encoding='utf-8') as fout:
                fout.write(f'{pid}\t'
                           f'{account.eoa}\t'
                           f'{config.workspace.operator.address}\n')
                fout.write(f'{str_cmdline}\n')

            server.accept_loop()

        except KeyboardInterrupt:
            pass
        finally:
            if os.path.exists(config.runtime.solver_pid_filepath):
                os.unlink(config.runtime.solver_pid_filepath)

    else:
        mcs_console(account, config)


OPTIONS: List[Tuple[str, str, dict]] = [
]
ARGUMENTS: List[Tuple[str, dict]] = [
    ('mode', dict(choices=['server', 'client'])),
]

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    for sname, lname, etc_opts in OPTIONS:
        PARSER.add_argument(sname, lname, **etc_opts)
    for name, etc_opts in ARGUMENTS:
        PARSER.add_argument(name, **etc_opts)
    ARGS = PARSER.parse_args()
    main(ARGS)
