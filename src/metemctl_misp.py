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
        metemctl misp fetch

options:
   -h, --help
   -l, --url <misp-location>

"""
from docopt import docopt
import configparser
from subprocess import call
import pymisp
import re
import os
import json
import urllib3

CONFIG_INI_FILEPATH = 'metemctl.ini'

class MISPClient():
    def __init__(self, url, key, ssl=2):
        self.url = url
        self.key = key
        self.ssl = ssl
        if ssl == 0:
            urllib3.disable_warnings()
        self.misp = pymisp.PyMISP(url, key, ssl == 2)

    def get_event(self, event_id):
        return self.misp.get_event(event_id)

    def search(self, **kwargs):
        return self.misp.search(**kwargs)

    def search_index(self, **kwargs):
        return self.misp.search_index(**kwargs)

    def add_event(self, event_obj):
        return self.misp.add_event(event_obj)

    def update_event(self, event_obj):
        return self.misp.update_event(event_obj)

def dump_json(data, dumpdir, force=False, indent=None):
    try:
        uuid = data['Event']['uuid']
        if len(uuid) == 0:
            raise Exception('Empty UUID')
    except Exception as err:
        raise Exception('Unexpected data: missing Event or UUID') from err

    fpath = dumpdir + '/' + uuid + '.json'
    if os.path.isfile(fpath) and not force:
        raise Exception('already exists: ' + fpath)
    with open(fpath, 'w') as fout:
        json.dump(data, fout, indent=indent, ensure_ascii=False)

    return fpath


if __name__ == '__main__':

    args = docopt(__doc__)
    
    config = configparser.ConfigParser()
    config.read(CONFIG_INI_FILEPATH)

    url = config['general']['misp_url']
    
    # open MISP in your browser
    if args['open']:
        browser = config['general']['browser_path']
        if args['--url']:
            url = args['--url']
        exit(call([browser, url]))

    # fetch your MISP Events
    elif args['fetch']:
        # MISP Client Settings
        auth_key = config['general']['misp_auth_key']
        ssl_cert = config['general']['misp_ssl_cert']
        json_dumpdir = config['general']['misp_json_dumpdir']

        # MISP Client instance
        client = MISPClient(url, auth_key, ssl_cert)

        # build query
        basequery = "search"
        query_string = basequery + " limit=100 page=1"
        query = re.split(r'\s+', query_string)
        qname = query[0]
        qargs = query[1:]
        indent = 2
        query = dict()
        for token in qargs:
            key, val = token.split('=')
            query[key] = val

        # send query
        result = getattr(client, qname)(**query)

        # separate json data
        results = result if isinstance(result, list) else [result]

        # store json file
        for val in results:
            try:
                fpath = dump_json(val, json_dumpdir, True, indent)
                print('dumped to ' + fpath)
            except Exception as err:
                print(err)
    else:
        exit("Invalid command. See 'metemctl misp --help'.")
