import logging
import inspect
from multi_solver import MCSClient

LOGGER = logging.getLogger('common')


class SolverWrapper():
    def __init__(
            self, eoaa, pkey, contracts, plugin, operator_address=None,
            pluginfile=None, use_daemon=False):
        assert eoaa and pkey
        self.eoaa = eoaa
        self.pkey = pkey
        self.contracts = contracts
        self.plugin = plugin
        self.operator_address = operator_address
        self.pluginfile = pluginfile
        self.use_daemon = use_daemon
        self.solver = None
        self.client = None
        if self.operator_address:
            if self.use_daemon:
                try:
                    self.resume_client()
                except Exception as err:
                    LOGGER.error(
                        'cannot resume connection to solver daemon: %s',
                        str(err))
            try:
                self.setup_solver(operator_address, pluginfile)
            except Exception as err:
                LOGGER.error('setup solver failed: %s', str(err))

    def destroy(self):
        if self.solver:
            self.solver.destroy()
        if self.client:
            self.client.destroy()

    def try_client_connection(self):
        if self.client:
            self.client.connect()
        else:
            client = MCSClient(None, None)
            client.connect()
            client.destroy()

    def resume_client(self):
        assert self.operator_address
        assert self.use_daemon
        assert self.client is None
        try:
            self.client = MCSClient(self.eoaa, self.pkey)
            self.client.connect()
            addr = self.client.get_solver()
            if addr is None:  # not found. reset client for setup.
                self.client.destroy()
                self.client = None
                return
            if self.operator_address != addr:
                raise Exception(
                    'solver daemon running with another operator: ' + addr)
        except:
            self.client.destroy()
            self.client = None
            raise

#    def switch_wrapper(self, use_daemon):
#        if use_daemon == self.use_daemon:
#            return
#        self.setup_solver(
#            self.operator_address, self.pluginfile, use_daemon)

    def setup_solver(self, operator_address, pluginfile, use_daemon=None):
        if use_daemon is None:
            use_daemon = self.use_daemon
        if self.operator_address == operator_address and \
                self.pluginfile == pluginfile and \
                ((use_daemon and self.client) or \
                 (not use_daemon and self.solver)):
            return

        if self.operator_address:  # destroy current
            if self.solver:
                self.solver.destroy()
                self.solver = None
            elif self.client:
                self.client.connect()
                self.client.purge_solver()
                self.client.destroy()
                self.client = None

## deploying contract is solver's business?
#        if not operator_address:  # deploy new contract
#            ctiopertor = self.contracts.accept(CTIOperator())
#            operator_address = ctioperator.new().contract_address
#            ctioperator.set_recipient()
#            if pluginfile:
#                self.plugin.set_solverclass(operator_address, pluginfile)
        self.operator_address = operator_address
        self.pluginfile = pluginfile
        self.use_daemon = use_daemon

        if self.use_daemon:
            try:
                self.client = MCSClient(self.eoaa, self.pkey)
                self.client.connect()
                self.client.purge_solver()
                self.client.new_solver(
                    operator_address=self.operator_address,
                    pluginfile=self.pluginfile)
            except:
                self.client.destroy()
                self.client = None
                raise
        else:
            solverclass = self.plugin.get_solverclass(self.operator_address)
            self.solver = solverclass(
                self.contracts, self.eoaa, self.operator_address)

    def _passthrough(self, *args, **kwargs):
        funcname = inspect.getframeinfo(inspect.stack()[1][0]).function
        if self.solver:
            return getattr(self.solver, funcname)(*args, **kwargs)
        if self.client:
            return self.client.solver(funcname, *args, **kwargs)
        raise Exception('missing solver')

    def accept_challenges(self, tokens):
        return self._passthrough(tokens)

    def refuse_challenges(self, tokens):
        self._passthrough(tokens)

    def accepting_tokens(self):
        ret = self._passthrough()
        return [] if ret is None else ret

    def reemit_pending_tasks(self):
        self._passthrough()
