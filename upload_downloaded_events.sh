#! /bin/bash

# Directory to store downloaded MISP event files.
# should be same with MISP_DATAFILE_PATH in src/client_model.py.
DOWNLOAD_DIR=./download

### params for misp_client.py
# URL of MISP ReST API.
MISP_URL=
# AuthKey to connect MISP instance.
AUTH_KEY=
# set to 0 if certification error occurred.
SSL_CERT=0


required_params="DOWNLOAD_DIR MISP_URL AUTH_KEY"
for key in ${required_params}; do
    cmd="test -z \"\${$key}\""
    eval ${cmd} \
        && echo >&2 "specify ${key} in $0" \
        && exit 255
done

workdir=`cd \`dirname $0\` && pwd`

[ ! -f "${workdir}/venv/bin/activate" ] \
    && echo "python-venv is not ready." \
    && exit 255

DOWNLOAD_DIR=`cd ${DOWNLOAD_DIR} && pwd`

cd "${workdir}" || exit 255
source venv/bin/activate || exit 255

echo >&2 "Upload misp events in:${DOWNLOAD_DIR}"
args="--url '${MISP_URL}' --key '${AUTH_KEY}' --ssl ${SSL_CERT} --insert ${DOWNLOAD_DIR}"
cmd="python3 src/misp_client.py ${args}"
echo >&2 $cmd
eval $cmd

echo "successfully finished."
