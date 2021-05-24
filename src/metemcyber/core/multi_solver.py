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

import inspect
import json
import os
import select
import signal
import socket
import sys
from enum import IntEnum, auto
from threading import Condition, Thread
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, cast

from cryptography.fernet import Fernet
from eth_typing import ChecksumAddress
from web3 import Web3

from metemcyber.core.bc.account import Account
from metemcyber.core.bc.cti_operator import CTIOperator
from metemcyber.core.bc.ether import Ether
from metemcyber.core.bc.util import verify_message
from metemcyber.core.logger import get_logger
from metemcyber.core.plugin import PluginManager
from metemcyber.core.solver import BaseSolver

SERVERLOG = get_logger(name='solv_server', file_prefix='core')
CLIENTLOG = get_logger(name='solv_client', file_prefix='core')

NUM_THREADS = 4
BUFSIZ = 4096

ARGS_DELIMITER = '\t'   # for command line input
EOM = '\v'  # End of Message


def socket_filepath(work_dir: str) -> str:
    return f'{work_dir}/mcs.sock'


def tracelog(logger, *args, **kwargs):
    stacks = inspect.stack()
    assert len(stacks) > 1
    finfo = inspect.getframeinfo(stacks[1][0])
    pref = '{}:{} {}'.format(
        os.path.basename(finfo.filename),
        finfo.lineno, finfo.function)
    if len(args) > 0:
        logger.debug(pref + ': ' + args[0], *args[1:], **kwargs)
    else:
        logger.debug(pref, **kwargs)


class DataPack:
    def __init__(self, code, eoaa, *args, **kwargs):
        self.code: Union[str, int] = code  # MCSErrno or function
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


class MCSErrno(IntEnum):
    OK = 0xE000
    EPROTO = auto()
    EINVAL = auto()
    ENOP = auto()
    EALREADY = auto()
    ENOENT = auto()
    EINTERNAL = auto()
    EUNKNOWN = auto()


class MCSError(Exception):
    def __init__(self, code: MCSErrno, msg: Optional[str] = None):
        super().__init__(self)
        self.code = code
        self.msg = msg if msg else {
            MCSErrno.OK: 'OK',
            MCSErrno.EPROTO: 'Protocol Error',
            MCSErrno.EINVAL: 'Invalid Parameter',
            MCSErrno.ENOP: 'Nothing to Operate',
            MCSErrno.EALREADY: 'Already Exists',
            MCSErrno.ENOENT: 'No Such Entry',
        }.get(code, 'Unknown Error')

    def __str__(self):
        return '{:04X}: {:s}'.format(self.code, self.msg)


class SolverManager():
    """ Class to manage Solver instances
    """

    def __init__(self, endpoint_url: str) -> None:
        self.endpoint_url = endpoint_url
        self.plugin = PluginManager()
        self.plugin.load()
        self.plugin.set_default_solverclass('gcs_solver.py')
        #                  eoaa:            {account: x, solver: x}
        self.solvers: Dict[ChecksumAddress, Dict[str, Any]] = {}

    def destroy(self):
        for solver in [v['solver'] for v in self.solvers.values()]:
            if solver:
                solver.destroy()
        self.solvers = {}

    def new_solver(self, eoaa: ChecksumAddress,
                   encrypted_pkey: str,
                   operator_address: Optional[ChecksumAddress],
                   solver_plugin: Optional[str] = None,
                   solver_config: Optional[str] = None,
                   ) -> BaseSolver:
        cache = self.solvers.get(eoaa)
        if not cache or not cache['fernet_key']:
            raise MCSError(MCSErrno.EPROTO, 'Protocol error1')
        if cache['solver']:
            raise MCSError(MCSErrno.EALREADY, 'Already exists for this EOA')
        if not encrypted_pkey:
            raise MCSError(MCSErrno.EINVAL, 'Missing privatekey')
        if solver_plugin and not self.plugin.is_pluginfile(solver_plugin):
            raise MCSError(MCSErrno.EINVAL, 'Invalid pluginfile')

        fnt_key = cache['fernet_key']
        cache['fernet_key'] = None  # remove immediately
        with open(encrypted_pkey, 'rb') as fin:
            pkey: str = Fernet(fnt_key).decrypt(fin.read()).decode()
        account = Account(Ether(self.endpoint_url), eoaa, pkey)

        if not operator_address:  # deploy a new contract
            cti_operator = CTIOperator(account).new()
            operator_address = cti_operator.address
            cti_operator.set_recipient()
        assert operator_address
        if solver_plugin:
            self.plugin.set_solverclass(operator_address, solver_plugin)
        solverclass = self.plugin.get_solverclass(operator_address)
        solver = solverclass(account, operator_address, solver_config)

        cache['solver'] = solver
        cache['account'] = account

        tracelog(SERVERLOG, 'added solver: %s', cache)
        return cache['solver']

    def get_fernet_key(self, dpk: DataPack) -> DataPack:
        assert dpk.eoaa
        cache = self.solvers.get(dpk.eoaa)
        if not cache:
            cache = {
                'account': None,
                'solver': None,
                'fernet_key': Fernet.generate_key(),
            }
            self.solvers[dpk.eoaa] = cache
        if not cache['fernet_key']:
            cache['fernet_key'] = Fernet.generate_key()
        return DataPack(MCSErrno.OK, None, data=cache['fernet_key'].decode())

    def _solver_control(self, eoaa: ChecksumAddress, act: str) -> Optional[BaseSolver]:
        cache = self.solvers.get(eoaa)
        if not cache or not cache['solver']:
            raise MCSError(MCSErrno.ENOENT, 'Not found')
        if not Web3.isChecksumAddress(eoaa):
            raise MCSError(MCSErrno.EINVAL, 'Not a checksum address')

        if act == 'get':
            return cache['solver']

        # act == 'purge'
        tracelog(SERVERLOG, 'purge solver: %s', str(cache['solver']))
        self.solvers[eoaa]['solver'].destroy()
        del self.solvers[eoaa]
        return None

    def get_solver(self, eoaa):
        return self._solver_control(eoaa, act='get')

    def purge_solver(self, eoaa):
        return self._solver_control(eoaa, act='purge')


class SolverThread():
    """ Class to deal with one connection
    """

    def __init__(self, pool, index, mgr):
        self.mgr = mgr
        self.pool = pool
        self.index = index
        self.shutdown = False
        self.conn = self.addr = None
        self.solver = None
        self.eoaa: Optional[ChecksumAddress] = None
        self.cond = Condition()
        self.thread = Thread(target=self.run, daemon=False)
        self.thread.start()
        tracelog(SERVERLOG, '%d: initialized thread', index)

    def destroy(self):
        self.stop()

    def stop(self):
        if not self.thread:
            return
        tracelog(SERVERLOG, '%d: stopping thread', self.index)
        self.shutdown = True
        if self.cond and self.cond.acquire(timeout=1):
            # got lock. thread may be waiting with cond.acquire().
            self.cond.notify_all()
            self.cond.release()
        if self.thread:
            tracelog(SERVERLOG, '%d: joinning thread', self.index)
            self.thread.join()
        self.thread = None
        tracelog(SERVERLOG, '%d: thread stopped', self.index)

    def apply_client(self, conn, addr):
        assert self.conn is None
        self.cond.acquire()
        self.conn = conn
        self.addr = addr
        self.solver = None
        self.eoaa = None
        self.cond.notify()
        tracelog(SERVERLOG, '%d: cond notify', self.index)
        self.cond.release()

    def _get_callback(self, func) -> Callable[[DataPack], DataPack]:
        if func == 'ping':
            return lambda *args, **kwargs: DataPack(MCSErrno.OK, None, data='pong')
        if func == 'login':
            return self._login

        # following functions need login(eoaa).
        if not self.eoaa:
            raise MCSError(MCSErrno.EPROTO, 'Protocol error2')
        if func in ('new_solver', 'get_solver', 'purge_solver'):
            return self._solver_mgr_wrapper
        if func == 'get_fernet_key':
            return self.mgr.get_fernet_key
        if func == 'solver':
            return self._solver_wrapper

        raise MCSError(MCSErrno.EINVAL, 'No such method')

    def _login(self, dpk: DataPack) -> DataPack:
        if self.eoaa:
            raise MCSError(MCSErrno.EPROTO, 'Protocol error3')
        if not Web3.isChecksumAddress(dpk.eoaa):
            raise MCSError(MCSErrno.EINVAL, 'Not a ChecksumAddress')
        self.eoaa = dpk.eoaa
        return DataPack(MCSErrno.OK, None)

    def _solver_mgr_wrapper(self, dpk: DataPack) -> DataPack:
        assert dpk.code in ('new_solver', 'get_solver', 'purge_solver')

        if dpk.code == 'get_solver' and self.solver:
            pass
        elif (self.solver is None) == (dpk.code == 'purge_solver'):
            raise MCSError(MCSErrno.EPROTO, 'Protocol error4')
        else:
            self.solver = getattr(self.mgr, cast(str, dpk.code))(self.eoaa, *dpk.args, **dpk.kwargs)
        if self.solver is None:
            return DataPack(MCSErrno.OK, None)
        return DataPack(MCSErrno.OK, None,
                        operator_address=self.solver.operator_address,
                        solver_class=str(self.solver))

    def _solver_wrapper(self, dpk: DataPack) -> DataPack:
        if not self.solver:
            raise MCSError(MCSErrno.EPROTO, 'Protocol error5')
        if len(dpk.args) < 1:
            raise MCSError(MCSErrno.EINVAL, 'Missing function')
        func = getattr(self.solver, dpk.args[0])
        return DataPack(MCSErrno.OK, None, data=func(*dpk.args[1:], **dpk.kwargs))

    def _treat_one_query(self, query: str, conn) -> Tuple[bool, bool]:  # (break, disconnect)
        try:
            dpk = DataPack.from_string(query)
            if dpk.code != 'ping':  # need sign except ping
                if not dpk.verify():
                    raise MCSError(MCSErrno.EINVAL, 'Verify signature failed')
                if self.eoaa and self.eoaa != dpk.eoaa:
                    raise MCSError(MCSErrno.EINVAL, 'EOA address mismatch')
            if dpk.code == 'shutdown':
                signal.raise_signal(signal.SIGINT)
                return True, False
            if dpk.code == 'disconnect':
                return True, True

            resp = self._get_callback(dpk.code)(dpk)

        except MCSError as err:
            resp = DataPack(err.code, None, data=err.msg)
        except Exception as err:
            SERVERLOG.exception(err)
            resp = DataPack(MCSErrno.EINTERNAL, None, data=str(err))

        tracelog(SERVERLOG, 'retval: %X, %s, %s', resp.code, resp.args, resp.kwargs)
        try:
            resp.send(conn)
        except Exception as err:
            tracelog(SERVERLOG, '%d: send error: %s', self.index, err)
        return False, False

    def communicate(self, conn, _addr):
        tracelog(SERVERLOG, '%d: communicate with %s', self.index, conn)
        disconnect = False
        msg = ''
        while not disconnect:
            while True:
                rfds, _, _ = select.select([conn], [], [], 1.0)
                if rfds or self.shutdown:
                    break
            if self.shutdown:
                disconnect = True
                tracelog(SERVERLOG, '%d: self.shutdown', self.index)
                try:
                    DataPack('SHUTDOWN', None).send(conn)
                except Exception as err:
                    tracelog(SERVERLOG, '%d: send error: %s', self.index, err)
                break
            tmp = conn.recv(BUFSIZ).decode()
            if len(tmp) == 0:  # disconnected
                tracelog(SERVERLOG, '%d: len == 0 (disconnect)', self.index)
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
        tracelog(SERVERLOG, '%d: disconnecting', self.index)
        tracelog(SERVERLOG, '%d: closing %s', self.index, conn)
        conn.close()

    def run(self):
        tracelog(SERVERLOG, '%d: start thread', self.index)
        self.cond.acquire()
        while True:
            tracelog(SERVERLOG, '%d: cond waiting', self.index)
            self.cond.wait()
            tracelog(SERVERLOG, '%d: cond awaken', self.index)
            if self.shutdown:
                break
            assert self.conn

            self.communicate(self.conn, self.addr)

            self.conn = self.addr = None
            if self.shutdown:
                break
            self.pool.append(self)
            tracelog(SERVERLOG, '%d: released', self.index)
        tracelog(SERVERLOG, '%d: shuttting down', self.index)


class MCSServer():
    """ Class as a service
    """

    def __init__(self, mgr: SolverManager, work_dir: str):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.mgr = mgr
        self.work_dir = work_dir
        self.threadlist: List[SolverThread] = []  # all threads
        self.threadpool: List[SolverThread] = []  # non-active threads
        self.shutdown = False
        signal.signal(signal.SIGINT, self.signal_handler)
        for idx in range(NUM_THREADS):
            sol_thr = SolverThread(self.threadpool, idx, mgr)
            self.threadlist.append(sol_thr)
            self.threadpool.append(sol_thr)

    def signal_handler(self, signum, __):
        if signum not in {signal.SIGINT}:
            SERVERLOG.warning('caught un-expected signal: %d', signum)
            return
        tracelog(SERVERLOG, 'caught SIGINT')
        self.shutdown = True
        self.threadpool.clear()  # accept no more

    def run(self):
        socket_file = socket_filepath(self.work_dir)
        try:
            self.sock.bind(socket_file)
            self.sock.listen()
            self.sock.settimeout(1)
            while True:
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    if self.shutdown:
                        break
                    continue
                if len(self.threadpool) == 0:
                    tracelog(SERVERLOG, 'too many connections')
                    conn.close()
                    continue
                tracelog(SERVERLOG, 'accepted')
                sol_thr = self.threadpool.pop()
                sol_thr.apply_client(conn, addr)
        finally:
            for sol_thr in self.threadlist:
                sol_thr.destroy()
            if self.mgr:
                self.mgr.destroy()
            os.remove(socket_file)
        tracelog(SERVERLOG, 'MCSServer shutted down')


class MCSClient():
    """ Class as a client
    """

    def __init__(self, account: Account, work_dir: str):
        self.account = account
        self.work_dir = work_dir
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.operator_address: Optional[ChecksumAddress] = None
        self.solver_class = None
        self.disconnecting = False
        self.buffer = ''
        tracelog(CLIENTLOG, 'initialized %s', self)

    def destroy(self):
        self.disconnect()

    def connect(self):
        try:
            self.sock.connect(socket_filepath(self.work_dir))
        except FileNotFoundError as err:
            raise Exception('Socket not found. Solver daemon may be down.') from err
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

    def _simple_query(self, query):
        self.send_query(query)
        resp = self.wait_response()
        if resp.code == MCSErrno.OK:
            return
        raise Exception('Received error: {:X} {}'.format(resp.code, resp.kwargs.get('data')))

    def ping(self):
        self._simple_query('ping')

    def login(self):
        self._simple_query('login')

    def new_solver(self, operator_address: ChecksumAddress, pkey: str,
                   pluginfile: Optional[str] = None, configfile: Optional[str] = None,
                   ) -> ChecksumAddress:
        fnt_key = self._get_fernet_key()
        tmp_filepath = f'{self.work_dir}/{fnt_key.decode()}'
        if os.path.exists(tmp_filepath):
            raise Exception(f'temporal filepath already exists: {tmp_filepath}')
        try:
            with open(tmp_filepath, 'wb') as fout:
                fout.write(Fernet(fnt_key).encrypt(pkey.encode('utf-8')))
            kwargs = {
                'encrypted_pkey': tmp_filepath,
                'operator_address': operator_address,
                'solver_plugin': pluginfile,
                'solver_config': configfile,
            }
            self.send_query('new_solver', **kwargs)
            resp = self.wait_response()
        finally:
            os.unlink(tmp_filepath)
        if resp.code == MCSErrno.OK:
            assert operator_address == resp.kwargs['operator_address']
            self.operator_address = operator_address
            self.solver_class = resp.kwargs['solver_class']
            return self.operator_address
        raise MCSError(code=cast(MCSErrno, resp.code), msg=resp.kwargs.get('data'))

    def _get_fernet_key(self) -> bytes:
        self.send_query('get_fernet_key')
        resp = self.wait_response()
        if resp.code == MCSErrno.OK:
            return resp.kwargs['data'].encode('utf-8')
        raise MCSError(code=cast(MCSErrno, resp.code), msg=resp.kwargs.get('data'))

    def _solver_control(self, act) -> Optional[ChecksumAddress]:
        assert act in ('get_solver', 'purge_solver')
        self.send_query(act)
        resp = self.wait_response()
        if resp.code == MCSErrno.OK:
            if act == 'get_solver':
                self.operator_address = resp.kwargs.get('operator_address')
                self.solver_class = resp.kwargs.get('solver_class')
                return self.operator_address
            self.operator_address = None
            self.solver_class = None
            return None
        raise MCSError(code=cast(MCSErrno, resp.code), msg=resp.kwargs.get('data'))

    def get_solver(self) -> ChecksumAddress:
        ret = self._solver_control('get_solver')
        return cast(ChecksumAddress, ret)

    def purge_solver(self):
        self._solver_control('purge_solver')

    def solver(self, *args, **kwargs) -> Any:
        assert len(args) > 0
        self.send_query('solver', *args, **kwargs)
        resp = self.wait_response()
        if resp.code == MCSErrno.OK:
            return resp.kwargs.get('data')
        raise MCSError(code=cast(MCSErrno, resp.code), msg=resp.kwargs.get('data'))


def mcs_console(account, work_dir):
    """ Simple CUI to use MCSClient
    """

    client = MCSClient(account, work_dir)
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
