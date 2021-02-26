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

import sys
import os
import logging
from importlib import import_module

from solver import BaseSolver

LOGGER = logging.getLogger('common')

## the directory where plugins are placed
PLUGINS_PATH = os.getenv('PLUGINS_PATH', './src/plugins')


SOLVER_CLASSNAME = 'Solver'


class PluginManager():

    def __new__(cls, *_args, **_kwargs):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self._modules = dict()  ## {filename : module}
        self._solvers = dict()  ## {operator_address: (solver_class, filename)}

    def load(self, path=PLUGINS_PATH):
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
                self._modules[fname] = mod
                if hasattr(mod, SOLVER_CLASSNAME):
                    LOGGER.info(
                        'Plugin: loaded %s from %s', SOLVER_CLASSNAME, fname)
            except Exception as err:
                LOGGER.exception(err)

        sys.path.remove(path)
        LOGGER.debug(self._modules)

    def set_default_solverclass(self, plugin_filename):
        self.set_solverclass(0, plugin_filename)

    def set_solverclass(self, operator_address, plugin_filename):
        if not plugin_filename in self._modules.keys():
            raise Exception(
                'Plugin: no such plugin loaded: ' + plugin_filename)
        mod = self._modules[plugin_filename]
        if not hasattr(self._modules[plugin_filename], SOLVER_CLASSNAME):
            raise Exception('Plugin: not a solver: ' + plugin_filename)
        solver = getattr(self._modules[plugin_filename], SOLVER_CLASSNAME)
        self._solvers[operator_address] = (solver, plugin_filename)
        LOGGER.info(
            'Plugin: set solverclass %s.%s for operator %s',
            mod.__name__, solver.__name__, operator_address)

    def get_solverclass(self, operator_address):
        if operator_address in self._solvers.keys():
            return self._solvers[operator_address][0]
        if 0 in self._solvers.keys():
            # return default if set.
            return self._solvers[0][0]
        return BaseSolver

    def get_plugin_filename(self, operator_address):
        if operator_address in self._solvers.keys():
            return self._solvers[operator_address][1]
        return None

    def is_pluginfile(self, filename):
        return filename in self._modules.keys()
