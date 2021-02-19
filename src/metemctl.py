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

The most commonly used metemctl commands are:
   new        Create a new workflow
   config     Operate the config of metemctl
   misp       
   account

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
    valid_commands = 'new config misp account'.split()
    if args['<command>'] in valid_commands:
        exit(call(['python', 'src/metemctl_%s.py' % args['<command>']] + argv))
    elif args['<command>'] in ['help', None]:
        exit(call(['python', 'src/metemctl.py', '--help']))
    else:
        display_command_list = " ".join(["<{0}>".format(command) for command in valid_commands])
        exit("'{0}' is not a metemctl command. You can use {1} command. See 'metemctl help'.".format(args['<command>'], display_command_list))
