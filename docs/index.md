# TLS 1.3 + TCP Fast Open

1. [TCP Fast Open] added support to send data in the first packet of the TLS handshake.
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

## TLS Connection

- TCP handshake
- TLS handshake
- Application data exchange
- TLS shutdown
- TCP shutdown

For example, a full TLS 1.3 handshake looks like:

![TCP TLS Handshake](/images/tcp-tls-handshake.svg)

### TLS 1.0-TLS.1.2 - Full Handshake

![TLS-1.2 Full Handshake](/images/tls-1.2-fullhandshake.svg)

*Note*: Between the `[ACK]` of the clients `Hello` the server spends ~8ms
generating the `Server Hello`.

### TLS 1.3 - Full Handshake

TLS 1.3 improves full handshake to require one roundtrip less.

![TLS-1.3 Full Handshake](/images/tls-1.3-fullhandshake.svg)

### TLS 1.3 - Session Resumption

TLS 1.3 supports a abbreveated handshake if

- client connected to the server previously and
- the previous connection was shutdown properly

With session resumption, the `Server Hello` is about 7-8ms faster.

...

### TLS 1.3 - 0-RTT data

TLS 1.3 supports the sending Application Data in the Client hello packet

- if a SSL session can be resumed
- server announced it supports early data

The packet flow:

![TLS-1.3 0-RTT](/images/tls-1.3-early-data.svg)

## TCP Fast Open

If

- TCP Fast Open is supported by the OS and
- enabled on both client and server and
- client established a connected to the server before

it can send data in the first packet of the TCP handshake:

![TLS-1.3 0-RTT](/images/tcp-fast-open.svg)

which allows the server to send a response earlier.

### TLS 1.3 Full Handshake + TCP Fast Open

TCP Fast Open and TLS 1.3 can be combined

![TLS-1.3 Full Handshake + TCP Fast Open](/images/tls-1.3-fullhandshake-tfo.svg)

### TLS 1.3 Session Resumption + TCP Fast Open

...

### TLS 1.3 0-RTT + TCP Fast Open

TCP Fast Open and TLS 1.3 0-RTT can be combined too:

![TLS-1.3 0-RTT + TCP Fast Open](/images/tls-1.3-early-data-tfo.svg)

### Cost of TLS handshake

Tracking the time spent of the TCP/TLS handshake over the loopback interface
(10us latency) allows to measure the duration of each stage.

| stage          | full handshake | resumption |
| -------------- | --------------:| ----------:|
| client hello   |          0.4ms |      0.4ms |
| server hello   |      **6.0ms** |      0.5ms |
| client finish  |      **1.0ms** |      0.7ms |
| data + latency |          0.1ms |      0.1ms |
| **TOTAL**      |          7.5ms |      1.7ms |


# API usage

OpenSSL 1.1.1 added the necessary APIs to use TLS 1.3 session resumption
and 0-RTT.

## TLS Session Resumption

The client MUST cache the session tickets the server sends to allow reuse:

```c++
std::unique_ptr<SSL_SESSION, void (*)(SSL_SESSION *)> last_session(
    nullptr, &SSL_SESSION_free);

static int new_session_cb(SSL *s, SSL_SESSION *sess) {
  // store session in cache.
  last_session.reset(sess);

  return 1;
}

  //...
  // enable the session cache to allow session resumption
  SSL_CTX_set_session_cache_mode(
    ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
  // ...
```

The `new_session_cb` will be called whenever the server sent a new
session (e.h. `New Session Ticket`). It can be used on the next SSL
connection to the same server.

```c++
  if (last_session) {
    SSL_set_session(ssl.get(), last_session.release());
  }
```

## TLS 1.3 0-RTT

If the current SSL connection has a resumed session and the server
announced it supports `early data`, the client can send data as part
of the handshake by using `SSL_write_early_data()` before `SSL_connect()`.

```c++
  if (SSL_get0_session(ssl)) != nullptr &&
      SSL_SESSION_get_max_early_data(SSL_get0_session(ssl)) > 0) {
    size_t written;
    auto ssl_res = SSL_write_early_data(ssl, transfer_buf.data(),
                                        transfer_buf.size(), &written);
    if (ssl_res != 1) {
      // handle error
    } else {
      // success
    }
  }

  // SSL_connect() ...
```

The TLS connection must properly signal a shutdown to make the session
resumable:

```c++
  // ...

  SSL_shutdown(ssl);
```

## TCP Fast Open

TCP Fast Open is supported on:

- Linux 3.x
- Windows 10
- FreeBSD 12
- MacOSX 10.11

### kernel side support

#### Linux

Linux requires enabling the server side support for TCP Fast Open
via `sysctl`.

See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt

> `tcp_fastopen` - INTEGER
>  - `0x01` - client (enabled by default)
>  - `0x02` - server (disabled by default)

```sh
# current value
$ cat /proc/sys/net/ipv4/tcp_fastopen
1
# enable client and server
$ echo "3" | sudo tee /proc/sys/net/ipv4/tcp_fastopen
```

#### FreeBSD

On FreeBSD:

```sh
$ sysctl net.inet.tcp.fastopen.server_enable
0
$ sysctl net.inet.tcp.fastopen.client_enable
1
```

#### MacOS X

MacOS X has client and server support for TCP Fast Open enabled by default.

```sh
$ sysctl net.inet.tcp.fastopen
3
```

#### Windows

```sh
> netsh interface tcp show global
Querying active state...

TCP Global Parameters
-----
...
Fast Open : disabled
Fast Open Fallback : disabled
...
> netsh interface tcp  set global fastopen=enabled
```

### server side support

If the kernel support is enabled, the server application can active
support for TCP Fast Open via a `setsockopt()`:

```c++
int on = 1;
setsockopt(server_sock, IPPROTO_TCP, TCP_FASTOPEN, &on, sizeof on);
```

*Note*: On MacOSX the socket must be in listening mode already
for the `setsockopt()` to succeed.

### client side support

Different API styles exist to enable sending application data
at connect time

- delay connect until first write
- use sendto()
- use new API

The `delay connect until first write` style allows easy integration
with existing socket abstractions like the one in OpenSSL.

#### delay connect until first write

Linux and FreeBSD allow to delay the connect until the first write
and use the existing socket APIs by enable the socket option with
`setsockopt()`.

On Linux:

```c++
int on = 1;
setsockopt(client_sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
  &on, sizeof on);
```

On MacOSX and FreeBSD:

```c++
int on = 1;
setsockopt(client_sock, IPPROTO_TCP, TCP_FASTOPEN,
  &on, sizeof on);
```

The `connect()` afterwards will succeed and the `send()` will return
the errors like `EINPROGRESS` that would otherwise happen with `connect()`.

```c++
// no op
connect(client_sock, addr, addr_len);

// SYN + data.
send(client_sock, data, data_len);
```

#### use sendto() to connect with data

On Linux `sendto()` can be used to established a connection and send data
in the first packet by setting the `MSG_FASTOPEN` flag:

```c++
sendto(sock, data, datalen, MSG_FASTOPEN, addr, addrlen);
```

It replaces the `connect()` + `send()`.

#### use a new API to connect with data

- Windows has `ConnectEx()`
- MacOSX has `connectx()`

# Examples

## Build Requirements

- cmake 3.4 or later
- C++14 capable compiler
- Openssl 1.1.1
- Operating Systems
  - Linux 4.11 or later
  - FreeBSD 12 or later
  - MacOSX 10.11 or later

## building

    $ cmake
    $ make

*Note*: On MacOS X you need to pass `-DOPENSSL_ROOT_DIR=<path-to-openssl-binary-directory>`
to `cmake` as linking against the systems openssl will fail.

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
