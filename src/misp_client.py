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

import os
import sys
import re
import json
import argparse
from pathlib import Path
import urllib3
import pymisp

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


def insert_json(client, event_dict):
    #event_id = event_dict.get('Event', {}).get('id')
    uuid = event_dict.get('Event', {}).get('uuid')
    if uuid:
        event_obj = pymisp.MISPEvent()
        event_obj.from_dict(**event_dict)

        result = client.search(uuid=uuid)
        if len(result) > 0:
            client.update_event(event_obj)
        else:
            client.add_event(event_obj)
    else:
        raise Exception('There is no uuid in json')


def bulk_insert_json(client, insertdir):
    for obj_path in Path(insertdir).glob("./*.json"):
        try:
            event_dict = json.loads(open(obj_path).read())
            insert_json(client, event_dict)
        except json.decoder.JSONDecodeError:
            print('%s: Unparsable data', obj_path)
        except Exception as err:
            print('%s: %s',obj_path, err)


def main(args):
    client = MISPClient(args.url, args.key, args.ssl)

    if args.insertpath:
        if os.path.isdir(args.insertpath):
            bulk_insert_json(client, args.insertpath)
        else:
            event_dict = json.loads(open(args.insertpath).read())
            insert_json(client, event_dict)
    else:
        qname, qargs = re.split(r'\s+', args.query, 1)
        indent = 2 if args.pretty else None

        result = {}
        if qname == 'get_event':
            # ex) -q "get_event 1"
            result = client.get_event(qargs[0])
        elif qname in {'search', 'search_index'}:
            # ex) -q "search date_from=2019-05-10 date_to=2019-05-10"
            query = dict()
            for token in qargs:
                key, val = token.split('=')
                query[key] = val
            result = getattr(client, qname)(**query)
        else:
            raise Exception('Unsupported query: {}'.format(qname))

        if not args.dumppath:
            print(json.dumps(result, indent=indent, ensure_ascii=False))
            sys.exit()

        results = result if isinstance(result, list) else [result]
        for val in results:
            try:
                fpath = dump_json(val, args.dumppath, args.force, indent)
                print('dumped to ' + fpath)
            except Exception as err:
                print(err)


if __name__ == '__main__':

    # to use proxy, set environment variable HTTP_PROXY or HTTPS_PROXY.
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument(
        '-u', '--url', dest='url', action='store',
        help='MISP ReST API URL')
    PARSER.add_argument(
        '-k', '--key', dest='key', action='store',
        help='AuthKey to connect MISP instance')
    PARSER.add_argument(
        '-s', '--ssl', dest='ssl', action='store', type=int, default=2,
        help='2:enable, 1:disable with warnings, 0:disable without warnings')
    PARSER.add_argument(
        '-q', '--query', dest='query', action='store',
        help='<QueryFuncName> [Arguments...]')
    PARSER.add_argument(
        '-d', '--dump', dest='dumppath', action='store', default=None,
        help='dump to files named with its uuid under specified directory')
    PARSER.add_argument(
        '-i', '--insert', dest='insertpath', action='store', default=None,
        help='insert misp event from json file or directory')
    PARSER.add_argument(
        '-f', '--force', dest='force', action='store_true',
        help='overwrite dump files')
    PARSER.add_argument(
        '-p', '--pretty', dest='pretty', action='store_true',
        help='output pretty formatted JSON')

    ARGS = PARSER.parse_args()
    main(ARGS)
