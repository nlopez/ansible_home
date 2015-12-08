#!/usr/bin/env bash
if ! hash virtualenv 2>/dev/null; then
  echo "Can't proceed without virtualenv"
  exit 1
fi

here="$(dirname "$0")"
cd "$here" || exit
virtualenv -q venv >/dev/null 2>&1
pip -q install -r requirements.txt >/dev/null 2>&1

echo "source $here/venv/bin/activate"

exit 0
