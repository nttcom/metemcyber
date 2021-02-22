#! /usr/bin/sh
cd `dirname $0`
workdir=`pwd`
cmd="docker run -i --rm --network metemcyber-pricom --env-file ./workspace/docker.env -v ${workdir}:/usr/src/myapp -w /usr/src/myapp --name multi_solver_client metemcyber-python:latest  python3 src/multi_solver_cli.py -m client"
echo $cmd
echo "shutdown" | exec $cmd
