#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>    // IPPROTO_TCP
#include <netinet/tcp.h>  // TCP_FASTOPEN
#include <sys/socket.h>   // setsockopt
#endif

#include "sock_err.h"
#include "sock_opt.h"

#if defined(_WIN32)
using opt_type = const char *;
#else
using opt_type = void *;
#endif

void set_tcp_fast_open_server(int sock, int qlen, std::error_code &ec) {
  ec.clear();
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN,
                      reinterpret_cast<opt_type>(&qlen), sizeof qlen)) {
    ec = last_error_code();
  }
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
#endif
}

void set_reuse_address(int sock, int on, std::error_code &ec) {
  ec.clear();
  if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<opt_type>(&on), sizeof on)) {
    ec = last_error_code();
  }
}

void set_tcp_nodelay(int sock, int on, std::error_code &ec) {
  ec.clear();
  if (0 != setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<opt_type>(&on), sizeof on)) {
    ec = last_error_code();
  }
}
