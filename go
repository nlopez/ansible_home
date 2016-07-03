#!/usr/bin/env bash
if ! hash virtualenv 2>/dev/null; then
  echo "Can't proceed without virtualenv"
  exit 1
fi

readonly venv="venv/ansible-home"
readonly here="$(dirname "$0")"
cd "$here" || exit
virtualenv -q "$venv" >/dev/null 2>&1
source "$here/$venv/bin/activate"
pip -q install -r requirements.txt >/dev/null 2>&1

echo "source $here/$venv/bin/activate"

exit 0
