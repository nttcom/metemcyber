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

import os
import sys
import inspect
import json
import select
import signal
import socket
import logging
import crypt
import secrets

from threading import Thread, Condition
from hmac import compare_digest
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware import (
    geth_poa_middleware,
    construct_sign_and_send_raw_middleware)

from contract import Contracts
from ctioperator import CTIOperator
from plugin import PluginManager
from solver import BaseSolver

#logging.basicConfig(format='[%(levelname)s]: %(message)s')
LOGGER = logging.getLogger('common')

SOCKET_FILE = 'workspace/mcs.sock'
NUM_THREADS = 4
BUFSIZ = 4096

ARGS_DELIMITER = '\t'   # for command line input
EOM = '\v'  # End of Message


def TRACELOG(*args, **kwargs):
    stacks = inspect.stack()
    assert len(stacks) > 1
    finfo = inspect.getframeinfo(stacks[1][0])
    #pref = '{}: line {}, in {}'.format(
    pref = '{}:{} {}'.format(
        os.path.basename(finfo.filename),
        finfo.lineno, finfo.function)
    if len(args) > 0:
        LOGGER.info(pref+': '+args[0], *args[1:], **kwargs)
    else:
        LOGGER.info(pref, **kwargs)

def encode_msg(cmd, *args, **kwargs):
    pack = {
        'cmd': cmd,
        'args': args,
        'kwargs': kwargs,
        }
    return json.dumps(pack)

def decode_msg(packed_json):
    pack = json.loads(packed_json)
    return pack.get('cmd'), pack.get('args'), pack.get('kwargs')

def send_encoded(sock, msg):
    if not msg.endswith(EOM):
        msg += EOM
    enc_msg = msg.encode()
    total = 0
    while total < len(enc_msg):
        tmp = sock.send(enc_msg[total:], socket.SOCK_NONBLOCK)
        if tmp == 0:  # disconnected
            return 0
        total += tmp
    return total


class MCSError(Exception):
    OK =        0xE000
    EPROTO =    0xE001  # protocol error
    EINVAL =    0xE002  # invalid parameter
    ENOP =      0xE003  # nothing to operate
    EALREADY =  0xE004  # already exists
    ENOENT =    0xE005  # not found

    EINTERNAL = 0xEEEE  # internal error
    EUNKNOWN =  0xEFFF

    def __init__(self, code=EUNKNOWN, msg=None):
        super().__init__()
        self.code = code
        self.msg = msg
        if not self.msg:
            self.msg = {
                self.OK:     'OK',
                self.EPROTO: 'Protocol Error',
                self.EINVAL: 'Invalid Parameter',
                self.ENOP:   'Nothing to Operate',
                self.EALREADY: 'Already Exists',
                self.ENOENT: 'No Such Entry',
                }.get(code)

    def __str__(self):
        return '{:04X}: {:s}'.format(self.code, self.msg)


class MCSolver():
    def __init__(self, provider, eoaa, pkey, operator_address, pluginfile):
        assert provider
        self.provider = provider
        self.plugin = PluginManager()
        self.plugin.load()
        self.plugin.set_default_solverclass('gcs_solver.py')
        self.random_once = None
        self.solvers = dict()  # {eoa: {...}}

        if eoaa and operator_address:
            self.new_solver(eoaa, pkey, operator_address, pluginfile)

    def destroy(self):
        for solver in [v['solver'] for v in self.solvers.values()]:
            solver.destroy()

    @staticmethod
    def ping():
        return 'pong'

    def new_solver(self, eoaa, pkey, operator_address, solver_plugin=None):
        try:
            account_id = Web3.toChecksumAddress(eoaa)
        except Exception as err:
            raise MCSError(MCSError.EINVAL, 'invalid address') from err
        if not pkey:
            raise MCSError(MCSError.EINVAL, 'missing privatekey')
        if account_id in self.solvers.keys():
            raise MCSError(MCSError.EALREADY, 'already exists for this EOA')
        if solver_plugin and \
                not self.plugin.is_pluginfile(solver_plugin):
            raise MCSError(MCSError.EINVAL, 'invalid pluginfile')

        web3 = Web3(self.provider)
        web3.eth.defaultAccount = account_id
        try:
            web3.eth.getBlock('latest')
        except ExtraDataLengthError:
            web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        web3.middleware_onion.add(construct_sign_and_send_raw_middleware(pkey))
        contracts = Contracts(web3)
        if not operator_address:  # deploy a new contract
            ctioperator = contracts.accept(CTIOperator())
            operator_address = ctioperator.new().contract_address
            ctioperator.set_recipient()
        if solver_plugin:
            self.plugin.set_solverclass(operator_address, solver_plugin)
        solverclass = self.plugin.get_solverclass(operator_address)
        solver = solverclass(contracts, account_id, operator_address)

        self.solvers[account_id] = {
            'pkey': pkey,
            'web3': web3,
            'contracts': contracts,
            'solver': solver,
        }
        TRACELOG('added solver: %s', str(self.solvers))
        return solver

    def get_random(self):
        if not self.random_once:
            self.random_once = secrets.token_hex(secrets.randbelow(16)+16)
        return self.random_once

    def _solver_control(self, eoaa, pkey_hash, act):
        if not self.random_once:
            raise MCSError(MCSError.EPROTO, 'protocol error')
        try:
            account_id = Web3.toChecksumAddress(eoaa)
        except Exception as err:
            raise MCSError(MCSError.EINVAL, 'invalid address') from err
        wrapper = self.solvers.get(account_id)
        if not wrapper:
            raise MCSError(MCSError.ENOENT, 'not found')
        if not compare_digest(
                pkey_hash,
                crypt.crypt(
                    self.random_once + wrapper.get('pkey'), pkey_hash)):
            raise MCSError(MCSError.EINVAL, 'pkey_hash mismatch')
        self.random_once = None  # reset random token

        if act == 'get':
            return wrapper.get('solver')
        # act == 'purge'
        TRACELOG('purge solver: %s', str(wrapper['solver']))
        self.solvers[account_id]['solver'].destroy()
        del self.solvers[account_id]
        return None

    def get_solver(self, eoaa, pkey_hash):
        return self._solver_control(eoaa, pkey_hash, act='get')

    def purge_solver(self, eoaa, pkey_hash):
        return self._solver_control(eoaa, pkey_hash, act='purge')


class SolverThread():
    def __init__(self, pool, index, mcs):
        self.mcs = mcs
        self.pool = pool
        self.index = index
        self.shutdown = False
        self.conn = self.addr = None
        self.solver = None
        self.cond = Condition()
        self.thread = Thread(target=self.run, daemon=False)
        self.thread.start()
        TRACELOG('%d: initialized thread', index)

    def destroy(self):
        self.stop()

    def stop(self):
        if not self.thread:
            return
        TRACELOG('%d: stopping thread', self.index)
        self.shutdown = True
        if self.cond and self.cond.acquire(timeout=1):
            # got lock. thread may be waiting with cond.acquire().
            self.cond.notify_all()
            self.cond.release()
        if self.thread:
            TRACELOG('%d: joinning thread', self.index)
            self.thread.join()
        self.thread = None
        TRACELOG('%d: thread stopped', self.index)

    def apply_client(self, conn, addr):
        assert self.conn is None
        self.cond.acquire()
        self.conn = conn
        self.addr = addr
        self.solver = None
        self.cond.notify()
        TRACELOG('%d: cond notify', self.index)
        self.cond.release()

    def communicate(self, conn, _addr):
        TRACELOG('%d: communicate with %s', self.index, conn)
        disconnect = False
        msg = ''
        while not disconnect:
            while True:
                rfds, _, _ = select.select([conn], [], [], 1.0)
                if rfds or self.shutdown:
                    break
            if self.shutdown:
                disconnect = True
                TRACELOG('%d: self.shutdown', self.index)
                try:
                    send_encoded(conn, 'SHUTDOWN')
                except Exception as err:
                    TRACELOG('%d: send error: %s', self.index, err)
                break

            tmp = conn.recv(BUFSIZ).decode()
            if len(tmp) == 0:  # disconnected
                TRACELOG('%d: len == 0 (disconnect)', self.index)
                break
            msg += tmp
            TRACELOG('received: ' + tmp.strip())
            queries = msg.split(EOM)
            TRACELOG('current queries: ' + str(queries))
            for query in queries[:-1]:
                func, args, kwargs = decode_msg(query)
                if func == 'shutdown':
                    signal.raise_signal(signal.SIGINT)
                    break
                if func == 'disconnect':
                    disconnect = True
                    break
                try:
                    # TODO FIXME XXX check method strictly!
                    target = self.mcs
                    if func == 'solver':
                        # operation with solver
                        if len(args) == 0:
                            raise MCSError(MCSError.EINVAL, 'wrong arg')
                        if not self.solver:
                            raise MCSError(MCSError.EPROTO, 'solver not set')
                        target = self.solver
                        func = args[0]
                        args = [] if len(args) == 1 else args[1:]
                    if not hasattr(target, func):
                        raise MCSError(MCSError.EINVAL, "no such method")

                    data = getattr(target, func)(*args, **kwargs)

                    resp = None
                    if target == self.mcs:
                        if func in {'new_solver', 'get_solver'}:
                            assert not self.solver
                            assert isinstance(data, BaseSolver)
                            self.solver = data
                            TRACELOG(
                                '%d: set solver: %s', self.index, self.solver)
                            resp = encode_msg(
                                MCSError.OK,
                                operator_address=self.solver.operator_address,
                                solver_class=str(self.solver))
                        elif func == 'purge_solver':
                            TRACELOG(
                                '%d: purged solver: %s',
                                self.index, self.solver)
                            self.solver = None
                            resp = encode_msg(MCSError.OK)
                    if resp is None:
                        resp = encode_msg(MCSError.OK, data=data)
                except MCSError as err:
                    resp = encode_msg(err.code, data=err.msg)
                except TypeError as err:
                    LOGGER.exception(err)
                    resp = encode_msg(MCSError.EINVAL, data=str(err))
                except Exception as err:
                    LOGGER.exception(err)
                    resp = encode_msg(MCSError.EINTERNAL, data=str(err))

                code, args, kwargs = decode_msg(resp)
                TRACELOG('retval: %X, %s, %s', code, args, kwargs)
                try:
                    if send_encoded(conn, resp) == 0:
                        break
                except Exception as err:
                    TRACELOG('%d: send error: %s', self.index, err)
            msg = queries[-1]  # empty or incomplete msg

        TRACELOG('%d: disconnecting', self.index)
        TRACELOG('%d: closing %s', self.index, conn)
        conn.close()

    def run(self):
        TRACELOG('%d: start thread', self.index)
        self.cond.acquire()
        while True:
            TRACELOG('%d: cond waiting', self.index)
            self.cond.wait()
            TRACELOG('%d: cond awaken', self.index)
            if self.shutdown:
                break
            assert self.conn

            self.communicate(self.conn, self.addr)

            self.conn = self.addr = None
            if self.shutdown:
                break
            self.pool.append(self)
            TRACELOG('%d: released', self.index)
        TRACELOG('%d: shuttting down', self.index)


class MCSServer():
    def __init__(self, mcs):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.mcs = mcs
        self.threadlist = []  # all threads
        self.threadpool = []  # non-active threads
        self.shutdown = False
        signal.signal(signal.SIGINT, self.signal_handler)
        for idx in range(NUM_THREADS):
            sol_thr = SolverThread(self.threadpool, idx, mcs)
            self.threadlist.append(sol_thr)
            self.threadpool.append(sol_thr)

    def signal_handler(self, signum, __):
        if signum not in {signal.SIGINT}:
            LOGGER.warning('caught un-expected signal: %d', signum)
            return
        TRACELOG('caught SIGINT')
        self.shutdown = True
        self.threadpool.clear()  # accept no more

    def run(self):
        try:
            self.sock.bind(SOCKET_FILE)
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
                    TRACELOG('too many connections')
                    conn.close()
                    continue
                TRACELOG('accepted')
                sol_thr = self.threadpool.pop()
                sol_thr.apply_client(conn, addr)
        finally:
            for sol_thr in self.threadlist:
                sol_thr.destroy()
            if self.mcs:
                self.mcs.destroy()
            os.remove(SOCKET_FILE)
        TRACELOG('MCSServer shutted down')


class MCSClient():
    def __init__(self, eoaa, pkey):
        self.eoaa = eoaa
        self.pkey = pkey
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.operator_address = None
        self.solver_class = None
        self.disconnecting = False
        self.buffer = ''
        TRACELOG('initialized %s', self)

    def destroy(self):
        self.disconnect()

    def connect(self):
        try:
            self.sock.connect(SOCKET_FILE)
        except FileNotFoundError as err:
            raise Exception('Socket not found. Solver daemon may be down.') \
                from err
        except OSError as err:
            if err.errno != 106:  # ignore EISCONN (already connected)
                raise
        return self.ping()  # check connected

    def disconnect(self):
        self.disconnecting = True
        try:
            self.send_query(encode_msg('disconnect'))
            self.sock.close()
        except:
            pass
        self.sock = None

    def shutdown(self):
        self.send_query(encode_msg('shutdown'))

    def send_query(self, query):
        TRACELOG(query.strip())  # strip EOM
        if send_encoded(self.sock, query) == 0:
            self.disconnecting = True

    def wait_response(self):
        resp = self.buffer
        assert len(resp) == 0  # XXX Uhmm how to control msg drived by peer...
        while EOM not in resp:
            tmp = self.sock.recv(BUFSIZ).decode()
            if len(tmp) == 0:  # disconnected
                self.disconnecting = True
                return None, [], {}
            resp += tmp
        resp, left = resp.split(EOM, 1)
        code, args, kwargs = decode_msg(resp)
        TRACELOG('%X, %s, %s', code, args, kwargs)
        self.buffer = left  # maybe no left message
        return code, args, kwargs

    def ping(self):
        query = encode_msg('ping')
        try:
            self.send_query(query)
            code, _, _ = self.wait_response()
            if code == MCSError.OK:
                return True
        except Exception as err:
            TRACELOG('failed: %s', err)
        return False

    def new_solver(self, operator_address='', pluginfile=None):
        kwargs = {
            'eoaa': self.eoaa,
            'pkey': self.pkey,
            'operator_address': operator_address,
            'solver_plugin': pluginfile,
            }
        self.send_query(encode_msg('new_solver', **kwargs))
        code, _, kwargs = self.wait_response()
        if code == MCSError.OK:
            self.operator_address = kwargs.get('operator_address')
            self.solver_class = kwargs.get('solver_class')
            return self.operator_address
        raise MCSError(code=code, msg=kwargs.get('data'))

    def _get_random(self):
        self.send_query(encode_msg('get_random'))
        code, _, kwargs = self.wait_response()
        if code == MCSError.OK:
            return kwargs.get('data')
        raise MCSError(code=code, msg=kwargs.get('data'))

    def _solver_control(self, act):
        assert self.eoaa and self.pkey
        random_once = self._get_random()
        pkey_hash = crypt.crypt(random_once+self.pkey, crypt.METHOD_SHA512)
        kwargs = {
            'eoaa': self.eoaa,
            'pkey_hash': pkey_hash,
            }
        self.send_query(encode_msg(act, **kwargs))
        code, _, kwargs = self.wait_response()
        if code == MCSError.OK:
            if act == 'get_solver':
                self.operator_address = kwargs.get('operator_address')
                self.solver_class = kwargs.get('solver_class')
                return self.operator_address
            return True
        if code == MCSError.ENOENT:
            return None
        raise Exception(code=code, msg=kwargs.get('data'))

    def get_solver(self):
        return self._solver_control('get_solver')

    def purge_solver(self):
        return self._solver_control('purge_solver')

    def solver(self, *args, **kwargs):
        assert self.solver
        assert len(args) > 0
        try:
            self.send_query(encode_msg('solver', *args, **kwargs))
            code, _, kwargs = self.wait_response()
            if code == MCSError.OK:
                return kwargs.get('data')
            raise MCSError(code=code, msg=kwargs.get('data'))
        except OSError as err:
            if err.errno == 32:  # Broken pipe
                LOGGER.error('%s failed: %s', args[0], err)
                return None
            raise


def mcs_client(eoaa, pkey):
    client = MCSClient(eoaa, pkey)
    if not client.connect():
        raise Exception('cannot connect to solver daemon')
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
                TRACELOG('received: %s', tmp.strip())
                queries = msg.split(EOM)
                for query in queries[:-1]:
                    if query in {'SHUTDOWN', 'DISCONNECT'}:
                        client.disconnecting = True
                        break  # immediately
                msg = queries[-1]  # empty or incomplete msg
                if client.disconnecting:
                    break

            if sys.stdin in rfds:  # got query from stdin
                ## input format:
                ##   query? <func_name>
                ## or
                ##   query? <func_name><tab><args and|or kwargs>
                ## format of <args and|or kwargs>:
                ##   {"args":["arg0", ...], "kwargs":{"key0":"val0",...}}
                ##
                tokens = sys.stdin.readline().strip().split(ARGS_DELIMITER, 1)
                func = tokens[0]
                args = []
                kwargs = {}
                if len(tokens) > 1:
                    try:
                        jval = json.loads(tokens[1])
                    except Exception as err:
                        print(err.__class__.__name__, err)
                        continue
                    args = jval.get('args') if jval.get('args') else []
                    kwargs = jval.get('kwargs') if jval.get('kwargs') else {}
                try:
                    getattr(client, func)(*args, **kwargs)
                    if func in {'shutdown', 'disconnect'}:
                        break
                except Exception as err:
                    print(err)

        except KeyboardInterrupt:
            break
    if sock:
        sock.close()
