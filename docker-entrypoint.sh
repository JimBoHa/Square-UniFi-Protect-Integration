#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
    data_uid=$(stat -c %u /data)
    data_gid=$(stat -c %g /data)
    if [ "$data_uid" = "0" ]; then
        chown -R square-protect:square-protect /data
        data_uid=10001
        data_gid=10001
    fi
    exec gosu "$data_uid:$data_gid" "$@"
fi

exec "$@"
