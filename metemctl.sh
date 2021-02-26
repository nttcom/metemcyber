#! /bin/bash

# TODO: 暫定的にvenv環境を使うが、将来的に変更する可能性あり
. ./venv/bin/activate
exec python -O ./src/metemctl.py "$@"