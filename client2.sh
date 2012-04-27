#!/bin/sh
./invpn -k conf/client2.key -c conf/client2.crt -a conf/ca.crt -s conf/client2.db -fd -t '00:50:56:00:00:01@127.0.0.1:59051'
