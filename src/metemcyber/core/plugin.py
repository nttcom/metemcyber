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
from importlib import import_module
from typing import Any, Dict, Optional, Tuple, Type

from eth_typing import ChecksumAddress

from .bc.util import ADDRESS0
from .logger import get_logger
from .solver import BaseSolver

LOGGER = get_logger(name='plugin', file_prefix='core')
# the directory where plugins are placed
PLUGINS_PATH = os.getenv('PLUGINS_PATH', os.path.dirname(__file__) + '/../plugins')
SOLVER_CLASSNAME = 'Solver'


class PluginManager():

    def __new__(cls, *_args, **_kwargs):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        #                   filename: module
        self._modules: Dict[str, Any] = {}
        #                   operator_address:     (solver_class,     filename)
        self._solvers: Dict[ChecksumAddress, Tuple[Type[BaseSolver], str]] = {}

    def load(self, path: str = PLUGINS_PATH) -> None:
        if self._modules:
            LOGGER.debug('Plugin: already loaded')
            return

        # prepare for import_module
        sys.path.insert(0, path)

        for fname in os.listdir(path):
            filepath = '{}/{}'.format(path, fname)
            if not (os.path.isfile(filepath) and fname.endswith('.py')):
                continue
            try:
                mod_name = os.path.splitext(fname)[0]
                mod = import_module(mod_name)
                if hasattr(mod, SOLVER_CLASSNAME):
                    self._modules[fname] = mod
                    LOGGER.info('loaded %s from %s', SOLVER_CLASSNAME, fname)
            except Exception as err:
                LOGGER.exception(err)

        sys.path.remove(path)
        LOGGER.debug(self._modules)

    def set_default_solverclass(self, plugin_filename: str) -> None:
        self.set_solverclass(ADDRESS0, plugin_filename)

    def set_solverclass(self, operator_address: ChecksumAddress, plugin_filename: str) -> None:
        if plugin_filename not in self._modules.keys():
            raise Exception('No such plugin loaded: ' + plugin_filename)
        mod = self._modules[plugin_filename]
        if not hasattr(self._modules[plugin_filename], SOLVER_CLASSNAME):
            raise Exception('Not a solver: ' + plugin_filename)
        solver = getattr(self._modules[plugin_filename], SOLVER_CLASSNAME)
        self._solvers[operator_address] = (solver, plugin_filename)
        LOGGER.info(
            'Set solverclass %s.%s for operator %s',
            mod.__name__, solver.__name__, operator_address)

    def get_solverclass(self, operator_address: ChecksumAddress) -> Type[BaseSolver]:
        if operator_address in self._solvers.keys():
            return self._solvers[operator_address][0]
        if ADDRESS0 in self._solvers.keys():
            # return default if set.
            return self._solvers[ADDRESS0][0]
        return BaseSolver

    def get_plugin_filename(self, operator_address: ChecksumAddress) -> Optional[str]:
        if operator_address in self._solvers.keys():
            return self._solvers[operator_address][1]
        return None

    def is_pluginfile(self, filename: str) -> bool:
        return filename in self._modules.keys()
