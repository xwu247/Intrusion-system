#!/bin/bash

db_source='https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'

z=$(basename -- "$0")

if [ -z "$MANUFDB" ]; then
    MANUFDB=~/.cache/manuf.db
fi
db=$MANUFDB

if [ X"$*" = Xupdate ]; then
    dir=$(dirname -- "$db")
    [ -d "$dir" ] || mkdir -p -- "$dir"
    [ -f "$db" ] && mv "$db" "$db".old
    curl -o "$db" "$db_source"
    [ -n "$PAGER" ] || PAGER=less
    ( echo 'manuf db changes:'; echo; diff -uN -- "$db.old" "$db" ) | $PAGER
else
    if ! [ -f "$db" ]; then
	echo "$z: no db. run $z update" >&2
	exit 1 
	fi
    grep -i "$@" "$db"
fi