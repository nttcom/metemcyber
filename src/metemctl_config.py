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
usage: metemctl config [options] [<key>] [<value>]

    -h, --help
    -l, --list      Print option values within the general section

"""
from docopt import docopt
import configparser

CONFIG_INI_FILEPATH = "metemctl.ini"


if __name__ == '__main__':

    args = docopt(__doc__, help=True)
        
    config = configparser.ConfigParser()
    config.add_section('general')
    config.read(CONFIG_INI_FILEPATH)

    # get key
    if args['<key>']:
        print(config['general'][args['<key>']])
    # set key=value
    elif args['<key>'] and args['<value>']:
        config.set('general', args['<key>'], args['<value>'])
        with open(CONFIG_INI_FILEPATH, 'w') as fout:
            config.write(fout)
            print('update config.')
    # print all option values
    elif args['--list']:
        for option in config['general']:
            print(option, ":", config['general'][option])
    else:
        exit("%r is not valid in the config command. See 'metemctl config --help'.")