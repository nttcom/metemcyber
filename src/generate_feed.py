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
import json
import glob
import time
import pathlib
import argparse
from threading import Thread
from socketserver import TCPServer
from http.server import SimpleHTTPRequestHandler
from pymisp import MISPEvent


def save_event(outputdir, event):
    try:
        with open(os.path.join(outputdir, f'{event["Event"]["uuid"]}.json'), 'w') as f:
            json.dump(event, f, indent=2)
    except Exception as e:
        print(e)
        sys.exit('Could not create the event dump.')


def save_manifest(outputdir, manifest):
    try:
        manifestFile = open(os.path.join(outputdir, 'manifest.json'), 'w')
        manifestFile.write(json.dumps(manifest))
        manifestFile.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the manifest file.')


def save_hashes(outputdir, hashes):
    try:
        with open(os.path.join(outputdir, 'hashes.csv'), 'w') as hashFile:
            for element in hashes:
                hashFile.write('{},{}\n'.format(element[0], element[1]))
    except Exception as e:
        print(e)
        sys.exit('Could not create the quick hash lookup file.')


def generate_feed(inputdir, outputdir):
    manifest = {}
    hashes = []
    for file in glob.glob(os.path.join(inputdir, '*.json')):
        print(file)
        event = MISPEvent()
        event.from_json(open(file).read())
        event_feed = event.to_feed(with_meta=True)
        
        hashes += [[h, event.uuid] for h in event_feed['Event'].pop('_hashes')]
        manifest.update(event_feed['Event'].pop('_manifest'))
        save_event(outputdir, event_feed)

    save_manifest(outputdir, manifest)
    save_hashes(outputdir, hashes)

def run_server(port):
    with TCPServer(("", port), SimpleHTTPRequestHandler) as httpd:
        httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-i', '--input', dest='inputdir', action='store', default=None,
        help='Input directory where MISP json exists')
    parser.add_argument(
        '-o', '--output', dest='outputdir', action='store', default=None,
        help='Output directory you want to store feed files')
    parser.add_argument(
        '-s', '--server', action='store_true',
        help='If set, run as feed server')
    parser.add_argument(
        '-p', '--port', action='store', type=int, default=8080,
        help='Port number of feed server')
    args = parser.parse_args()

    # convert to abs path
    input_rel = pathlib.Path(args.inputdir)
    input_abs = input_rel.resolve()

    output_rel = pathlib.Path(args.outputdir)
    output_abs = output_rel.resolve()

    generate_feed(input_abs, output_abs)

    if args.server:
        os.chdir(output_abs)
        thread = Thread(target=run_server, args=(args.port,), daemon=True)
        thread.start()

        event_files = set(os.listdir(input_abs))
        while True:
            current_files = set(os.listdir(input_abs))
            if event_files != current_files:
                generate_feed(input_abs, output_abs)
                event_files = current_files
            time.sleep(5)
            pass
