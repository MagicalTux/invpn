#!/bin/sh

# make CA cert
if [ ! -f ca.crt ]; then
	openssl req -config tibanne.cnf -batch -newkey rsa:4096 -nodes -keyout ca.key -out ca.req
	openssl x509 -req -signkey ca.key -extfile tibanne.cnf -set_serial 0 -extensions v3_ca -days 6000 -in ca.req -out ca.crt
fi

# make client certs
if [ ! -f client1.crt ]; then
	openssl req -config tibanne.cnf -batch -subj "/C=JP/ST=Tokyo/L=Shibuya/O=Tibanne Co. Ltd./OU=VPN/CN=00:50:56:00:00:01" -newkey rsa:4096 -nodes -keyout client1.key -out client1.req
	openssl x509 -req -CA ca.crt -CAkey ca.key -extfile tibanne.cnf -set_serial 1 -extensions v3_notca -days 365 -in client1.req -out client1.crt
fi

if [ ! -f client2.crt ]; then
	openssl req -config tibanne.cnf -batch -subj "/C=JP/ST=Tokyo/L=Shibuya/O=Tibanne Co. Ltd./OU=VPN/CN=00:50:56:00:00:02" -newkey rsa:4096 -nodes -keyout client2.key -out client2.req
	openssl x509 -req -CA ca.crt -CAkey ca.key -extfile tibanne.cnf -set_serial 2 -extensions v3_notca -days 365 -in client2.req -out client2.crt
fi

