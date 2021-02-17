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
usage:  metemctl misp
        metemctl misp open [--url <misp-location>]

options:
   -h, --help
   -l, --url <misp-location>

"""
from docopt import docopt
import configparser
from subprocess import call

CONFIG_INI_FILEPATH = 'metemctl.ini'

if __name__ == '__main__':

    args = docopt(__doc__)
    print(args)
    
    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)
    
    if args['open']:
        browser = config['general']['browser_path']
        url = config['general']['misp_url']
        if args['--url']:
            url = args['--url']
        exit(call([browser, url]))
    else:
        exit("Invalid command. See 'metemctl misp --help'.")
