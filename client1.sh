#!/bin/sh
./invpn -k conf/client1.key -c conf/client1.crt -a conf/ca.crt -s conf/client1.db -fd -p 59051
echo $?
