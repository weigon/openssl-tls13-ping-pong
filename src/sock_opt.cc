#ifndef WIN32
#include <arpa/inet.h>    // IPPROTO_TCP
#include <netinet/tcp.h>  // TCP_FASTOPEN
#include <sys/socket.h>   // setsockopt
#else
#include <ws2tcpip.h>  //  TCP_FASTOPEN
#endif
#include "sock_err.h"
#include "sock_opt.h"

void set_tcp_fast_open_server(native_handle_type sock, int qlen,
                              std::error_code &ec) {
  ec.clear();
#ifndef WIN32
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof qlen)) {
    ec = last_error_code();
  }
#else
  if (0 !=
      setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, (char *)&qlen, sizeof qlen)) {
    ec = last_error_code();
  }
#endif  // ! WIN32
}

void set_tcp_fast_open_client(native_handle_type sock, int on,
                              std::error_code &ec) {
  ec.clear();

#if defined(__FreeBSD__)
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &on, sizeof on)) {
    ec = last_error_code();
  }
#elif defined(__linux__)
  if (0 !=
      setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &on, sizeof on)) {
    ec = last_error_code();
  }
#elif defined(WIN32)
  if (0 !=
      setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, (char *)&on, sizeof on)) {
    ec = last_error_code();
  }
#endif
}

void set_reuse_address(native_handle_type sock, int on, std::error_code &ec) {
  ec.clear();
#ifndef WIN32
  if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on)) {
    ec = last_error_code();
  }
#else
  if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on)) {
    ec = last_error_code();
  }
#endif
}

void set_tcp_nodelay(native_handle_type sock, int on, std::error_code &ec) {
  ec.clear();
#ifndef WIN32
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on)) {
    ec = last_error_code();
  }
#else
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof on)) {
    ec = last_error_code();
  }
#endif
}
