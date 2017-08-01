#!/bin/bash
cleanup() {
  if [ -f /tmp/odrobian-s905.list ]; then
    mv -v /tmp/odrobian-s905.list /etc/apt/sources.list.d/odrobian-s905.list
  fi
}

trap cleanup EXIT

if ! dpkg --status apt-transport-https >/dev/null 2>&1; then
  if [ -f /etc/apt/sources.list.d/odrobian-s905.list ]; then
    mv -v /etc/apt/sources.list.d/odrobian-s905.list /tmp/odrobian-s905.list
  fi
  apt-get update
  apt-get install -y apt-transport-https
  cleanup
  apt-get update
else
  echo "apt-transport-https already installed"
fi

if ! dpkg --status python >/dev/null 2>&1; then
  apt-get install -y python
else
  echo "python already installed"
fi
