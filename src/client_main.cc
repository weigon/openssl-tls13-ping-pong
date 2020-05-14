/*
 * Copyright 2020 Jan Kneschke <jan@kneschke.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include <array>
#include <chrono>
#include <csignal>   // signal
#include <cstdlib>   // EXIT_SUCCESS
#include <fstream>   // ofstream
#include <ios>       // ios_base
#include <iostream>  // cerr
#include <map>
#include <memory>  // unique_ptr
#include <string>
#include <system_error>  // error_code
#include <vector>
#ifndef WIN32
#include <netdb.h>        // getaddrinfo
#include <netinet/in.h>   // sockaddr_in
#include <netinet/tcp.h>  // SOL_TCP
#include <openssl/tls1.h>
#include <sys/socket.h>  // SOL_SOCKET
#include <unistd.h>      // close
#else
/* clang-format off */
#include <signal.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <MSWSock.h>
/* clang-format on */
#endif

#include <openssl/err.h>  // ERR_get_error
#include <openssl/ssl.h>  // SSL_CTX_new
#include <openssl/bio.h>

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error at least openssl 1.1.1 is required.
#endif

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
// we are good to go.
#elif WIN32
#define SHUT_WR SD_SEND
#else
#error unsupported OS
#endif

#include "file_descriptor.h"
#include "resolver.h"
#include "sock_err.h"
#include "sock_opt.h"
#include "ssl_err.h"

// remember the last session to assign it to another connection to the same host
std::unique_ptr<SSL_SESSION, void (*)(SSL_SESSION *)> last_session(
    nullptr, &SSL_SESSION_free);

/**
 * store a session ticket in a cache.
 */
static int new_session_cb(SSL *s, SSL_SESSION *sess) {
#if 0
  if (SSL_version(s) == TLS1_3_VERSION) {
    SSL_SESSION_print_fp(stdout, sess);
  }
#endif

  last_session.reset(sess);

  return 1;
}

namespace {

template <class T>
struct Deleter;

template <>
struct Deleter<SSL_CTX> {
  void operator()(SSL_CTX *p) const { SSL_CTX_free(p); }
};
template <>
struct Deleter<SSL> {
  void operator()(SSL *p) const { SSL_free(p); }
};
template <>
struct Deleter<BIO> {
  void operator()(BIO *p) const { BIO_free(p); }
};
template <>
struct Deleter<BIO_METHOD> {
  void operator()(BIO_METHOD *p) const { BIO_meth_free(p); }
};

#ifdef WIN32
bool is_first_time = true;
sockaddr name;
LPFN_CONNECTEX connect_ex_ptr = nullptr;

static int ping_write(BIO *bio, const char *buf, int len) {
  int ret = 0;
  auto desc = BIO_get_fd(bio, nullptr);
  WSASetLastError(0);
  if (is_first_time) {
    is_first_time = false;
    LPOVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    if (connect_ex_ptr(desc, &name, sizeof name, (PVOID *)buf, len,
                       (LPDWORD)&ret, overlapped) == FALSE)
      return SOCKET_ERROR;
  } else {
    ret = send(desc, buf, len, MSG_OOB);
    if (ret == SOCKET_ERROR) {
      return SOCKET_ERROR;
    }
  }
  return ret;
}
#endif
}  // namespace

/**
 * run one connection.
 *
 * @param with_fast_open if TCP Fast Open shall be enabled.
 * @param with_session_resumption if TLS session resumption should be resumed.
 * @param early_data send data as part of the resmed session
 * @returns a std::error_code with the last error (or 0 on success)
 */
std::error_code do_one(SSL_CTX *ssl_ctx, const char *hostname,
                       const char *service, bool with_fast_open,
                       bool with_session_resumption, bool early_data,
                       const std::string &data, int verbosity) {
  auto ssl_mem = std::unique_ptr<SSL, Deleter<SSL>>(SSL_new(ssl_ctx));
  SSL *ssl = ssl_mem.get();
  std::unique_ptr<BIO_METHOD, Deleter<BIO_METHOD>> bio_method_mem;
  std::unique_ptr<BIO, Deleter<BIO>> bio_mem;

  if (verbosity > 1) {
    std::cout << "// TLS "
              << (with_session_resumption ? "session resumption"
                                          : "full handshake")
              << (with_fast_open ? ", TCP Fast Open" : "")
              << (early_data ? ", 0-RTT" : "") << std::endl;
  }

  std::error_code ec;

  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;

  auto ai = address_info(hostname, service, &hints, ec);
  name = *(ai->ai_addr);
  if (ec) {
    return ec;
  }

  // using a FD class which closes the FD automatically at destruction and can't
  // be copied
  FileDescriptor sock;

  sock.assign(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
  if (!sock.is_open()) {
    return last_error_code();
  }

  set_tcp_nodelay(sock.native_handle(), 1, ec);
  if (ec) {
    std::cerr << __LINE__ << ": setsockopt(" << sock.native_handle()
              << ", IPPROTO_TCP, TCP_NODELAY): " << ec << std::endl;
    return ec;
  }

  if (with_fast_open) {
#if defined(__FreeBSD__) || defined(__linux__)
    set_tcp_fast_open_client(sock.native_handle(), 1, ec);
    if (ec) return ec;

    if (0 != connect(sock.native_handle(), ai->ai_addr, ai->ai_addrlen)) {
      return last_error_code();
    }
#elif defined(__APPLE__)
    sa_endpoints_t endpoints{};

    endpoints.sae_dstaddr = ai->ai_addr;
    endpoints.sae_dstaddrlen = ai->ai_addrlen;

    if (0 != connectx(sock.native_handle(), &endpoints, SAE_ASSOCID_ANY,
                      CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                      NULL, 0, NULL, NULL)) {
      return last_error_code();
    }
#elif defined(WIN32)
    DWORD numBytes = 0;
    GUID guid = WSAID_CONNECTEX;
    if (WSAIoctl(sock.native_handle(), SIO_GET_EXTENSION_FUNCTION_POINTER,
                 (void *)&guid, sizeof(guid), (void *)&connect_ex_ptr,
                 sizeof(connect_ex_ptr), &numBytes, NULL, NULL) == SOCKET_ERROR)
      return last_error_code();

    bio_method_mem.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "ping_write"));
    BIO_METHOD *bio_method = bio_method_mem.get();
    BIO_meth_set_write(bio_method, ping_write);

    bio_mem.reset(BIO_new(bio_method));
    BIO *bio = bio_mem.get();
    BIO_set_fd(bio, (int)sock.native_handle(), BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
#endif
  } else {
    if (0 != connect(sock.native_handle(), ai->ai_addr, ai->ai_addrlen)) {
      return last_error_code();
    }
  }

  SSL_set_fd(ssl, sock.native_handle());
  if (last_session && with_session_resumption) {
    SSL_set_session(ssl, last_session.release());
  }
  SSL_set_connect_state(ssl);

  std::string transfer_buf(data);

  if (early_data && SSL_get0_session(ssl) != nullptr &&
      SSL_SESSION_get_max_early_data(SSL_get0_session(ssl)) > 0) {
    size_t written;
    auto ssl_res = SSL_write_early_data(ssl, transfer_buf.data(),
                                        transfer_buf.size(), &written);
    if (ssl_res != 1) {
      auto ec = last_ssl_error_code(ssl, ssl_res);
      std::cerr << ec.message() << std::endl;
      return ec;
    } else {
      std::cerr << "c -> s: " << transfer_buf.data() << std::endl;
    }
  }

  {
    auto ssl_res = SSL_connect(ssl);
    if (ssl_res != 1) {
      auto ec = last_ssl_error_code(ssl, ssl_res);

      return ec;
    } else if (ssl_res > 0) {
      if (verbosity > 1) {
        std::cout << "c -> s: "
                  << "// established: " << SSL_get_version(ssl) << " using "
                  << SSL_get_cipher(ssl) << " session reused? "
                  << (SSL_session_reused(ssl) ? "yes" : "no") << std::endl;
      }
    }
  }

  if (SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED) {
    auto ssl_res = SSL_write(ssl, transfer_buf.data(), transfer_buf.size());
    if (ssl_res < 0) {
      auto ec = last_ssl_error_code(ssl, ssl_res);

      return ec;
    } else if (ssl_res > 0) {
      if (verbosity > 1) {
        std::cout << "c -> s: " << transfer_buf.data() << std::endl;
      }
    }
  }

  {
    std::string transfer_buf;
    transfer_buf.resize(128);
    size_t transfered;
    auto ssl_res = SSL_read_ex(ssl, &transfer_buf.front(), transfer_buf.size(),
                               &transfered);
    if (ssl_res <= 0) {
      auto ec = last_ssl_error_code(ssl, ssl_res);

      return ec;
    } else {
      transfer_buf.resize(transfered);
      if (verbosity > 1) {
        std::cout << "c <- s: " << transfer_buf.data() << std::endl;
      }
    }
  }

  {
    auto ssl_res = SSL_shutdown(ssl);
    if (ssl_res == 0) {
      // not finished yet
      //
      // but we'll close the connection anyway.
      if (verbosity > 1) {
        std::cout << "c -> s: shutdown in-progress" << std::endl;
      }
    } else if (ssl_res == 1) {
      // finished
      if (verbosity > 1) {
        std::cout << "c -> s: shutdown finished" << std::endl;
      }
    } else if (ssl_res == -1) {
      auto ec = last_sslerr_error_code();

      std::cerr << __LINE__ << ": ssl: " << ec.message() << std::endl;

      return ec;
    }
  }

  if (verbosity > 1) {
    std::cout << "c -x s: // shutdown" << std::endl;
  }
  shutdown(sock.native_handle(), SHUT_WR);

  {
    auto ssl_res = SSL_shutdown(ssl);
    if (ssl_res == 0) {
      // not finished yet
      //
      // but we'll close the connection anyway.
      if (verbosity > 1) {
        std::cout << "c -> s: shutdown in-progress" << std::endl;
      }
    } else if (ssl_res == 1) {
      // finished
      if (verbosity > 1) {
        std::cout << "c -> s: shutdown finished" << std::endl;
      }
    } else if (ssl_res == -1) {
      std::cerr << __LINE__ << ": ssl: " << ec.message() << std::endl;

      return ec;
    }
  }

  if (verbosity > 1) {
    std::cout << "c -x s: // closed" << std::endl;
  }
  return {};
}

int main(int argc, char **argv) {
#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
#else
  WSADATA wsaData;
  // Initialize Winsock
  auto iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    printf("WSAStartup failed with error: %d\n", iResult);
    return EXIT_FAILURE;
  }
#endif

  std::map<std::string, std::string> args{
      {"hostname", "127.0.0.1"},
      {"port", "3308"},
      {"tls-max-proto", "tls1.3"},
      {"tls-resumption", "1"},
      {"tcp-fast-open", "1"},
      {"tls-early-data", ""},
      {"data", "PING"},
      {"rounds", "1"},
      {"verbosity", "0"},
      {"cmd", "run"},
      {"curves", ""},
  };
  for (int ndx = 1; ndx < argc; ++ndx) {
    std::string arg(argv[ndx]);

    if (arg.substr(0, 2) == "--") {
      arg.erase(0, 2);

      auto eq_pos = arg.find('=');
      if (eq_pos == std::string::npos) {
        return cleanup(EXIT_FAILURE);
      }
      auto key = arg.substr(0, eq_pos);
      auto value = arg.substr(eq_pos + 1);

      auto it = args.find(key);
      if (it == args.end()) {
        std::cerr << "unsupported option: " << key << std::endl;
        return cleanup(EXIT_FAILURE);
      }

      it->second = value;
    } else if (arg.substr(0, 1) == "-") {
      if (arg.substr(1) == "?") {
        args.at("cmd") = "help";
      } else {
        std::cerr << "unsupport arg: " << arg << std::endl;
        return cleanup(EXIT_FAILURE);
      }
    } else {
      std::cerr << "unsupport arg: " << arg << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  if (args.at("cmd") == "help") {
    return cleanup(EXIT_SUCCESS);
  }

  const char *hostname = args.at("hostname").c_str();
  const char *service = args.at("port").c_str();

  int max_proto_version{};
  auto arg_it = args.find("tls-max-proto");
  if (arg_it != args.end()) {
    auto arg = arg_it->second;
    if (arg == "tls1") {
      max_proto_version = TLS1_VERSION;
    } else if (arg == "tls1.1") {
      max_proto_version = TLS1_1_VERSION;
    } else if (arg == "tls1.2") {
      max_proto_version = TLS1_2_VERSION;
    } else if (arg == "tls1.3") {
      max_proto_version = TLS1_3_VERSION;
    } else {
      std::cerr << "unknown max SSL protocol version: " << arg << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  if (argc >= 5) {
    std::string arg(argv[4]);
  }

  // build SSL context
  auto ssl_ctx_mem = std::unique_ptr<SSL_CTX, Deleter<SSL_CTX>>(
      SSL_CTX_new(TLS_client_method()));

  SSL_CTX *ssl_ctx = ssl_ctx_mem.get();

  // set tmp DH keys
  auto dh_2048_mem =
      std::unique_ptr<DH, void (*)(DH *)>(DH_get_2048_256(), &DH_free);
  DH *dh_2048 = dh_2048_mem.get();

  SSL_CTX_set_tmp_dh(ssl_ctx, dh_2048);

  // set the elliptic curves lists
  {
    auto arg = args.at("curves");
    if (!arg.empty()) {
      SSL_CTX_set1_groups_list(ssl_ctx, arg.c_str());
    }
  }

  // enable the session cache to allow session resumption
  SSL_CTX_set_session_cache_mode(
      ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);

  // enable the keylog to get better traces with wireshark
  SSL_CTX_set_keylog_callback(ssl_ctx, [](const SSL *ssl, const char *line) {
    const char *ssl_keylogfile = getenv("SSLKEYLOGFILE");
    if (ssl_keylogfile) {
      std::ofstream(ssl_keylogfile, std::ios_base::out | std::ios_base::app)
          << line << "\n";
    }
  });

  SSL_CTX_set_max_proto_version(ssl_ctx, max_proto_version);

  bool tls_resumption = args.at("tls-resumption") == "1";
  bool tls_early_data = args.at("tls-early-data") == "1";
  bool tcp_fast_open = args.at("tcp-fast-open") == "1";
  auto rounds = std::stol(args.at("rounds"));
  auto verbosity = std::stol(args.at("verbosity"));
  const auto data = args.at("data");

  if (tcp_fast_open || tls_resumption) {
    auto ec = do_one(ssl_ctx, hostname, service, false, false, false, data,
                     verbosity);
    if (ec) {
      std::cerr << ec.message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  // warmup
  for (size_t round = 0; round < rounds; ++round) {
    auto ec = do_one(ssl_ctx, hostname, service, tcp_fast_open, tls_resumption,
                     tls_early_data, data, verbosity);
    if (ec) {
      std::cerr << ec.message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  // bench
  auto start = std::chrono::system_clock::now();
  for (size_t round = 0; round < rounds; ++round) {
    auto ec = do_one(ssl_ctx, hostname, service, tcp_fast_open, tls_resumption,
                     tls_early_data, data, verbosity);
    if (ec) {
      std::cerr << ec.message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }
  auto now = std::chrono::system_clock::now();

  std::cout << "rounds: " << rounds << std::endl;
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start)
                .count();
  std::cout << "runtime: " << ms << "ms" << std::endl;
  std::cout << "round-time: " << ms / rounds << "ms" << std::endl;

  return cleanup(EXIT_SUCCESS);
}
