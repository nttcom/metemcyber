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

"""
usage: metemctl [--version]
                <command> [<args>...]

options:
   -h, --help

The most commonly used metmctl commands are:
   new        Create a new workflow
   config     Operate the config of metemctl

See 'metemctl help <command>' for more information on a specific command.

"""
from subprocess import call
from docopt import docopt


if __name__ == '__main__':

    args = docopt(__doc__,
                  version='matemctl 0.0.1.0',
                  options_first=True)

    argv = [args['<command>']] + args['<args>']

    #サブコマンドのリストを追加
    if args['<command>'] in 'new config'.split():
        exit(call(['python', 'src/metemctl_%s.py' % args['<command>']] + argv))
    elif args['<command>'] in ['help', None]:
        exit(call(['python', 'src/metemctl.py', '--help']))
    else:
        exit("%r is not a metemctl.py command. See 'metemctl help'." % args['<command>'])
