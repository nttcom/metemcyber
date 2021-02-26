#! /usr/bin/sh
cd `dirname $0`
workdir=`pwd`
cmd="docker run -it --rm --network metemcyber-pricom --env-file ./workspace/docker.env -v ${workdir}:/usr/src/myapp -w /usr/src/myapp --name multi_solver metemcyber-python:latest  python3 src/multi_solver_cli.py -p https://rpc.metemcyber.ntt.com -m server"
echo $cmd
exec $cmd
