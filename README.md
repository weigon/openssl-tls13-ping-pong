# TLS 1.3 + TCP Fast Open

## Build Requirements

- cmake 3.4 or later
- C++14 capable compiler
- Openssl 1.1.1
- Linux 4.11 or later

## building

    $ cmake
    $ make

## running

1. Start server in one terminal (binds to port 3308)

    $ ./tls13_ping_pong_server

2. run the client in another terminal

    $ ./tls13_ping_pong_client

## Tracing packets

Start server as before, but add tcpdump:

    $ sudo tcpdump -w tls13.pcap -i lo 'port 3308'
    $ SSLKEYLOGFILE=keys.txt ./tls13_ping_pong_client
    $ editcap --inject-secrets tls,keys.txt tls13.pcap tls13-with-keys-dsb.pcapng
    $ wireshark tls13-with-keys-dsb.pcapng
