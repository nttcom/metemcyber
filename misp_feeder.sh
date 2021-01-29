#! /bin/bash

# Directory to store downloaded MISP event files.
# should be same with DOWNLOADED_CTI_PATH in src/client_model.py.
DOWNLOAD_DIR=./download

# Directory to store feed file for MISP.
MISP_FEEDDIR=./misp_feed

# PORT number which accepts http access for MISP feed
PORT=8080

workdir=`cd \`dirname $0\` && pwd`

[ ! -f "${workdir}/venv/bin/activate" ] \
    && echo "python-venv is not ready." \
    && exit 255

args="-i '${DOWNLOAD_DIR}' -o '${MISP_FEEDDIR}' -s -p ${PORT}"
source venv/bin/activate || exit 255
cmd="python3 src/generate_feed.py ${args}"
echo >&2 $cmd
eval $cmd