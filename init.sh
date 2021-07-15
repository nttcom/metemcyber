#!/bin/sh -ex
export PIPENV_VENV_IN_PROJECT=true
pipenv --python 3.8
pipenv run python -m pip install -U pip
pipenv install