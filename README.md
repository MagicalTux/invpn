invpn
=====

VPN server written in C++ (Qt)

Concept
-------

The goal of this VPN system is to provide fully decentralized VPN service
between servers in various places.

Each node will connect to at least two other nodes, and accept connections from
any node on the network. Each connected node will broadcast to all its
neighboors details such as its own MAC address, and forward broadcasts from any
of its neightboors. It will also keep track of received broadcast messages from
other nodes including from which connection that broadcast was received first, in
order to know where to route packets to that node.

All connections are established via TCP/IP sockets with SSL encryption. A common
CA is used to recognize nodes from the same group, and prevent unauthorized
access to the VPN network. Each node must have its own certificate issued by the
CA with Common Name set to the node's MAC address.

History
-------

The idea behind InVPN was born after I've been using another similar VPN
software for a while. I used to use CloudVPN, and liked it, except for the part
where I had to tell it how to connect to the other nodes.

A long time later, I finally wrote a first version in C, but never had time to
finish it. More time later, I rewrote it in C++ using Qt, and within 24 hours I
was able to get packets to go through this.

Installation
------------

Please read the INSTALL file.

Packet types
------------

* 0: initial info broadcast. 1 byte version (default=1), 8 bytes id, 6 bytes MAC addr, 2 bytes port
* 1: info broadcast. 1 byte version (default=1), 8 bytes id, 6 bytes mac, 2 bytes port, 1 byte type (ipv4/ipv6), n bytes ip
* 2: admin health status request: 1 byte version (default=1), 8 bytes id, 6 bytes mac, n bytes traceroute (each node routing this packet appends its own mac)
* 3: admin health response: 1 byte version (default=1), 6 bytes dest mac, 6 bytes origin mac, 8 bytes original id, 2 bytes (nconn), n bytes conn info (mac addr of each connection), 2 bytes (n routes), n bytes route info (target mac addr, router mac addr), 2 bytes traceroute len, n bytes traceroute, n bytes reverse traceroute (each node routing this packet appends its own mac)
* 80: targetted packet. 6 bytes dst, 6 bytes src, data
* 81: broadcast. 8 bytes id, 6 bytes src, data

Each packet is made of 2 bytes for the length (big endian), then 1 byte type.
The length is not counted as part of the packet when computing its length.
