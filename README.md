# TLS 1.3 + TCP Fast Open

1. [TCP Fast Open] added support to send data in the first packet of the TCP handshake.
2. [TLS 1.3] added support for 0-RTT,
allowing to send application data in the first packet of the TLS handshake.

which makes it possible to establish a encrypted connection and
send the application over TCP in one packet.

[TCP Fast Open]: https://tools.ietf.org/html/rfc7413
[TLS 1.3]: https://tools.ietf.org/html/rfc8446

## TL;DR

1. using TLS 1.3 instead of TLS 1.2 saves a round-trip in the full handshake
2. session resumption saves about 5-8ms
3. TLS 1.3 0-RTT saves another round-trip
4. TCP Fast Open saves another round-trip

### Scenario

A simple use case

1. establish connection
2. send PING
3. receive PONG
4. close connection

over a network with a round-trip-time (RTT) of

- 200ms (between DCs, different region)
- 20ms (between DCs, same region)
- 2ms (in a DC)
- 0.2ms (LAN)
- 0.02ms (loopback)

#### RTT 200ms

| TLS Version       | Full Handshake | Full Handshake + TFO | Resumption | Resumption + TFO |
| ----------------- | --------------:| --------------------:| ----------:| ----------------:|
| TLS 1.0, 1.1, 1.2 |       809.50ms |             609.20ms |   704.90ms |         504.80ms |
| TLS 1.3           |       609.30ms |             409.40ms |   602.60ms |         402.50ms |

#### RTT 20ms

| TLS Version       | Full Handshake | Full Handshake + TFO | Resumption | Resumption + TFO |
| ----------------- | --------------:| --------------------:| ----------:| ----------------:|
| TLS 1.0, 1.1, 1.2 |        88.92ms |              69.13ms |    74.88ms |          54.82ms |
| TLS 1.3           |        69.20ms |              49.17ms |    62.52ms |          42.53ms |

*Note*: `TFO` is TCP Fast Open.

#### RTT 2ms

| TLS Version       | Full Handshake | Full Handshake + TFO | Resumption | Resumption + TFO |
| ----------------- | --------------:| --------------------:| ----------:| ----------------:|
| TLS 1.0, 1.1, 1.2 |        15.26ms |              13.67ms |    11.51ms |           9.93ms |
| TLS 1.3           |        13.07ms |              11.30ms |     8.28ms |           6.27ms |

#### RTT 0.2ms

| TLS Version       | Full Handshake | Full Handshake + TFO | Resumption | Resumption + TFO |
| ----------------- | --------------:| --------------------:| ----------:| ----------------:|
| TLS 1.0, 1.1, 1.2 |         5.92ms |               6.03ms |     3.59ms |           3.68ms |
| TLS 1.3           |         6.56ms |               6.28ms |     2.58ms |           2.47ms |


# Examples

## Build Requirements

- cmake 3.4 or later
- C++14 capable compiler
- Openssl 1.1.1
- Operating Systems
  - Linux 4.11 or later
  - FreeBSD 12 or later
  - MacOSX 10.11 or later
  - Windows 10

## building

Configure the build:

    $ cmake

Run the build with:

    $ cmake --build .

Note: `cmake --build .` runs the build. On Unix it will run "make",
on windows it will run "msbuild".

### MacOS X/Windows

On MacOS X and Windows you need to pass `-DOPENSSL_ROOT_DIR=`
to `cmake`:

    $ cmake -DOPENSSL_ROOT_DIR=<path-to-openssl-binary-directory>
    $ cmake --build .

Note: On MacOS X it is needed as linking against the systems openssl will fail.

## running

1. Start server in one terminal

       $ ./src/tls13_ping_pong_server --port=3308

2. run the client in another terminal

       $ ./src/tls13_ping_pong_client --port=3308

## Tracing packets

Start server as before, but add tcpdump:

    $ sudo tcpdump -w tls13.pcap -i lo 'port 3308'
    $ ./src/tls13_ping_pong_client --port=3308
    $ wireshark tls13.pcap

*Note*: On FreeBSD and MacOS X use `lo0` as name for the loopback interface.

### Let wireshark decrypt the TLS packets automatically

Wireshark 3.x allows to add the session keys that were used for the connection
into the pcap file:

    $ sudo tcpdump -w tls13.pcap -i lo 'port 3308'
    $ SSLKEYLOGFILE=keys.txt ./src/tls13_ping_pong_client --port=3308
    $ editcap --inject-secrets tls,keys.txt tls13.pcap tls13-with-keys-dsb.pcapng
    $ wireshark tls13-with-keys-dsb.pcapng

### Adding latency

On Linux, to simulate real-life network delays all packets from and to port 3308
were delayed by 10ms by using the [netem] network emulator of [tc].

    $ sudo tc qdisc add dev lo root handle 1: prio
    $ sudo tc qdisc add dev lo parent  1:3 handle 30: netem delay 10ms
    $ sudo tc filter add dev lo parent 1:0 protocol ip u32 match ip dport 3308 0xffff flowid 1:3
    $ sudo tc filter add dev lo parent 1:0 protocol ip u32 match ip sport 3308 0xffff flowid 1:3

[netem]: http://man7.org/linux/man-pages/man8/tc-netem.8.html
[tc]: http://man7.org/linux/man-pages/man8/tc.8.html
