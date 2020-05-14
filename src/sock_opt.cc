#ifndef WIN32
#include <arpa/inet.h>    // IPPROTO_TCP
#include <netinet/tcp.h>  // TCP_FASTOPEN
#include <sys/socket.h>   // setsockopt
#else
#endif
#include "sock_err.h"
#include "sock_opt.h"

void set_tcp_fast_open_server(int sock, int qlen, std::error_code &ec) {
  ec.clear();
#ifndef WIN32
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof qlen)) {
    ec = last_error_code();
  }
#else
#endif  // ! WIN32
}

void set_tcp_fast_open_client(int sock, int on, std::error_code &ec) {
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
#endif
}

void set_reuse_address(int sock, int on, std::error_code &ec) {
  ec.clear();
#ifndef WIN32
  if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on)) {
    ec = last_error_code();
  }
#else
#endif
}

void set_tcp_nodelay(int sock, int on, std::error_code &ec) {
  ec.clear();
#ifndef WIN32
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on)) {
    ec = last_error_code();
  }
#else
#endif
}
