#! /bin/bash

# Directory to store downloaded MISP event files.
# should be same with MISP_DATAFILE_PATH in src/client_model.py.
JSON_DUMPDIR=./fetched_misp_events

### params for misp_client.py
# URL of MISP ReST API.
MISP_URL=
# AuthKey to connect MISP instance.
AUTH_KEY=
# set to 0 if certification error occurred.
SSL_CERT=2


required_params="JSON_DUMPDIR MISP_URL AUTH_KEY"
for key in ${required_params}; do
    cmd="test -z \"\${$key}\""
    eval ${cmd} \
        && echo >&2 "specify ${key} in $0" \
        && exit 255
done

type jq >/dev/null 2>&1
[ $? -ne 0 ] && echo "command 'jq' is required." && exit 255

# max number of events to fetch at once in loop.
LIMIT_ATONCE=100


progname=`basename $0`
workdir=`cd \`dirname $0\` && pwd`

[ ! -f "${workdir}/venv/bin/activate" ] \
    && echo "python-venv is not ready." \
    && exit 255

pidfile="${workdir}/.${progname}.pid"
stampfile="${workdir}/.${progname}.timestamp"
running=`cat ${pidfile} 2>/dev/null`

[ -n "${running}" ] \
    && ps xww -q ${running} 2>/dev/null | grep -qw "${progname}" \
    && echo >&2 "another process is running." \
    && exit 255
echo $$ > "${pidfile}"
trap "rm -f '${pidfile}'" EXIT QUIT TERM INT HUP

mkdir -p "${JSON_DUMPDIR}" || exit 255
JSON_DUMPDIR=`cd ${JSON_DUMPDIR} && pwd`

function dump_mispobjects() {
    cd "${workdir}" || exit 255
    source venv/bin/activate || exit 255
    [ -f "${stampfile}" ] && source "${stampfile}"
    if [ -n "${lasttimestamp}" ]; then
        strdate=`date -R --date=@${lasttimestamp}`
        echo >&2 "fetching MISP events which timestamp is newer than ${lasttimestamp} (${strdate})"
        basequery="search timestamp=${lasttimestamp}"
    else
        echo >&2 "fetching all MISP events."
        basequery="search"
    fi
    baseargs="--url '${MISP_URL}' --key '${AUTH_KEY}' --ssl ${SSL_CERT}"
    baseargs+=" --dump '${JSON_DUMPDIR}' --force --pretty"

    page=1
    newest=0
    while [ 1 ]; do
        query="${basequery} limit=${LIMIT_ATONCE} page=${page}"
        args="${baseargs} --query '${query}'"

        cmd="python3 src/misp_client.py ${args}"
        echo >&2 $cmd
        candidate=`eval $cmd \
            | grep "^dumped to " \
            | cut -d\  -f3 \
            | xargs jq -r .Event.timestamp \
            | sort -n \
            | tail -1 \
            ; exit ${PIPESTATUS[0]} `
        [ $? -ne 0 ] && echo >&2 "error occurred." && exit 255

        [ -z ${candidate} ] && break ## nothing fetched, end of loop.
        [ ${candidate} -gt ${newest} ] && newest=${candidate}
        page=`expr ${page} + 1`
    done

    echo ${newest}
}

lasttimestamp=`dump_mispobjects`
[ $? -ne 0 ] && exit 255
[ -n "${lasttimestamp}" ] \
    && [ ${lasttimestamp} -gt 0 ] \
    && savetimestamp=`expr ${lasttimestamp} + 1` \
    && echo "lasttimestamp=${savetimestamp}" > "${stampfile}"

echo "successfully finished."
