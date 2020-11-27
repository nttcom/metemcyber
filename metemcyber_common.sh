

function wait_provider_ready() {
    uri=$1
    [ -z "${uri}" ] && return 0
    timeout=${2:- 15} ## default 15 count
    cmd="curl -sI '${uri}' -o /dev/null -w %{http_code} | grep -sq '000'"
    count=0
    if eval "${cmd}"; then
        while eval "${cmd}"; do
            count=`expr ${count} + 1`
            [ ${count} -gt ${timeout} ] && echo "timeout." && return 1
            echo 'wait JSON-RPC HTTP service...'
            sleep 1
        done
        # 起動時のトランザクションがなぜか反映されない場合はこの待ち時間を長くする
        echo 'wait Ethereum warm up...'
        sleep 10
    fi
    echo 'connection ok.'
}

function container_is_running() {
    image=$1
    name=$2
    [ -z "${image}" ] \
        && echo >&2 "internal error ${FUNCNAME[1]}:${FUNCNAME[0]}" \
        && exit 255
    if [ -n "${name}" ]; then
        docker ps | grep " ${image} " | grep -q " ${name}$"
    else
        docker ps | grep -q " ${image} "
    fi
    return $?
}

function get_mtime() {
    tgt=$1
    cat <<EOD | sed -e "s/^    //" | python3
    import os
    try:
        print(int(os.stat('${tgt}').st_mtime))
    except:
        print('0')
EOD
}

function datestr_to_sec() {
    datestr=$1
    cat <<EOD | sed -e "s/^    //" | python3
    from dateutil.parser import parse
    try:
        print(int(parse('${datestr}', fuzzy=True).timestamp()))
    except:
        print('0')
EOD
}
