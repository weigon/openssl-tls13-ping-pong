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
#include <csignal>       // signal
#include <cstdlib>       // EXIT_SUCCESS
#include <fstream>       // ofstream
#include <ios>           // ios_base
#include <iostream>      // cerr
#include <memory>        // unique_ptr
#include <system_error>  // error_code

#include <netdb.h>        // getaddrinfo
#include <netinet/in.h>   // sockaddr_in
#include <netinet/tcp.h>  // SOL_TCP
#include <sys/socket.h>   // SOL_SOCKET
#include <unistd.h>       // close

#include <openssl/err.h>  // ERR_get_error
#include <openssl/ssl.h>  // SSL_CTX_new

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error at least openssl 1.1.1 is required.
#endif

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
// we are good to go.
#else
#error unsupported OS
#endif

#include "file_descriptor.h"

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

/**
 * get last socket error-code.
 */
std::error_code last_error_code() { return {errno, std::generic_category()}; }

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
                       bool with_session_resumption, bool early_data) {
  auto ssl_mem =
      std::unique_ptr<SSL, void (*)(SSL *)>(SSL_new(ssl_ctx), &SSL_free);
  SSL *ssl = ssl_mem.get();

  addrinfo *ai_raw{};
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  auto ai_res = getaddrinfo(hostname, service, &hints, &ai_raw);
  if (ai_res != 0) {
    return last_error_code();
  }
  auto ai =
      std::unique_ptr<addrinfo, void (*)(addrinfo *)>(ai_raw, &freeaddrinfo);

  FileDescriptor sock;

  sock.assign(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
  if (!sock.is_open()) {
    return last_error_code();
  }

  {
    int on = 1;
    if (0 != setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_NODELAY, &on,
                        sizeof on)) {
      std::cerr << __LINE__ << ": setsockopt(" << sock.native_handle()
                << ", IPPROTO_TCP, TCP_NODELAY): "
                << last_error_code().message() << std::endl;
      return last_error_code();
    }
  }

  if (with_fast_open) {
#if defined(__FreeBSD__)
    int on{1};
    if (0 != setsockopt(sock.native_handle(), IPPROTO_TCP, TCP_FASTOPEN, &on,
                        sizeof on)) {
      return last_error_code();
    }

    if (0 != connect(sock.native_handle(), ai->ai_addr, ai->ai_addrlen)) {
      return last_error_code();
    }
#elif defined(__linux__)
    int on{1};
    if (0 != setsockopt(sock.native_handle(), SOL_TCP, TCP_FASTOPEN_CONNECT,
                        &on, sizeof on)) {
      return last_error_code();
    }
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

  std::string transfer_buf("PING");

  if (early_data && SSL_get0_session(ssl) != nullptr &&
      SSL_SESSION_get_max_early_data(SSL_get0_session(ssl)) > 0) {
    size_t written;
    auto ssl_res = SSL_write_early_data(ssl, transfer_buf.data(),
                                        transfer_buf.size(), &written);
    if (ssl_res != 1) {
      switch (SSL_get_error(ssl, ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << __LINE__ << ": none" << std::endl;
          break;
        case SSL_ERROR_SYSCALL:
          return last_error_code();
        case SSL_ERROR_SSL: {
          std::array<char, 120> errbuf;
          std::cerr << "ssl: "
                    << ERR_error_string(ERR_get_error(), errbuf.data())
                    << std::endl;
          break;
        }
      }
    } else {
      std::cerr << "c -> s: " << transfer_buf.data() << std::endl;
    }
  }

  {
    auto ssl_res = SSL_connect(ssl);
    if (ssl_res != 1) {
      switch (SSL_get_error(ssl, ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << __LINE__ << ": none" << std::endl;
          break;
        case SSL_ERROR_SSL: {
          std::array<char, 120> errbuf;
          std::cerr << __LINE__ << ": ssl: "
                    << ERR_error_string(ERR_get_error(), errbuf.data())
                    << std::endl;

          break;
        }
        case SSL_ERROR_SYSCALL:
          return last_error_code();
        default:
          std::cerr << __LINE__ << ": ??? " << ssl_res << std::endl;
          break;
      }
    } else if (ssl_res > 0) {
      std::cout << "c -> s: "
                << "// established" << std::endl;
    }
  }

  if (SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED) {
    auto ssl_res = SSL_write(ssl, transfer_buf.data(), transfer_buf.size());
    if (ssl_res < 0) {
      switch (SSL_get_error(ssl, ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << __LINE__ << ": none" << std::endl;
          break;
        case SSL_ERROR_SSL: {
          std::array<char, 120> errbuf;
          std::cerr << __LINE__ << ": ssl: "
                    << ERR_error_string(ERR_get_error(), errbuf.data())
                    << std::endl;

          break;
        }
        case SSL_ERROR_SYSCALL:
          return last_error_code();
        default:
          std::cerr << __LINE__ << ": ??? " << ssl_res << std::endl;
          break;
      }
    } else if (ssl_res > 0) {
      std::cout << "c -> s: " << transfer_buf.data() << std::endl;
    }
  }

  {
    std::string transfer_buf;
    transfer_buf.resize(128);
    size_t transfered;
    auto ssl_res = SSL_read_ex(ssl, &transfer_buf.front(), transfer_buf.size(),
                               &transfered);
    if (ssl_res <= 0) {
      switch (SSL_get_error(ssl, ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << __LINE__ << ": none" << std::endl;
          break;
        case SSL_ERROR_SSL: {
          std::array<char, 120> errbuf;
          std::cerr << __LINE__ << ": ssl: "
                    << ERR_error_string(ERR_get_error(), errbuf.data())
                    << std::endl;
          break;
        }
      }
    } else {
      transfer_buf.resize(transfered);
      std::cerr << "c <- s: " << transfer_buf.data() << std::endl;
    }
  }

  {
    auto ssl_res = SSL_shutdown(ssl);
    if (ssl_res == 0) {
      // not finished yet
      //
      // but we'll close the connection anyway.
      std::cout << "c -> s: shutdown in-progress" << std::endl;
    } else if (ssl_res == 1) {
      // finished
      std::cout << "c -> s: shutdown finished" << std::endl;
    } else if (ssl_res == -1) {
      std::array<char, 120> errbuf;
      std::cerr << __LINE__
                << ": ssl: " << ERR_error_string(ERR_get_error(), errbuf.data())
                << std::endl;
    }
  }

  std::cout << "c -x s: // shutdown" << std::endl;
  shutdown(sock.native_handle(), SHUT_WR);

  {
    auto ssl_res = SSL_shutdown(ssl);
    if (ssl_res == 0) {
      // not finished yet
      //
      // but we'll close the connection anyway.
      std::cout << "c -> s: shutdown in-progress" << std::endl;
    } else if (ssl_res == 1) {
      // finished
      std::cout << "c -> s: shutdown finished" << std::endl;
    } else if (ssl_res == -1) {
      std::array<char, 120> errbuf;
      std::cerr << __LINE__
                << ": ssl: " << ERR_error_string(ERR_get_error(), errbuf.data())
                << std::endl;
    }
  }

  std::cout << "c -x s: // closed" << std::endl;
  return {};
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  const char default_hostname[] = "127.0.0.1";
  const char default_service[] = "3308";

  const char *hostname = argc < 2 ? default_hostname : argv[1];
  const char *service = argc < 3 ? default_service : argv[2];

  // build SSL context
  auto ssl_ctx_mem = std::unique_ptr<SSL_CTX, void (*)(SSL_CTX *)>(
      SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);

  SSL_CTX *ssl_ctx = ssl_ctx_mem.get();

  // set tmp DH keys
  auto dh_2048_mem =
      std::unique_ptr<DH, void (*)(DH *)>(DH_get_2048_256(), &DH_free);
  DH *dh_2048 = dh_2048_mem.get();

  SSL_CTX_set_tmp_dh(ssl_ctx, dh_2048);

  // set the elliptic curves lists
  SSL_CTX_set1_groups_list(ssl_ctx, "P-521:P-384:P-256:X25519");

  // enable the session cache to allow session resumption
  SSL_CTX_set_session_cache_mode(
      ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);

  {
    const char *ssl_keylogfile = getenv("SSLKEYLOGFILE");
    if (ssl_keylogfile) {
      // truncate the file as later the code will append to it.
      std::ofstream ofs(ssl_keylogfile,
                        std::ios_base::out | std::ios_base::trunc);
    }
  }
  // enable the keylog to get better traces with wireshark
  SSL_CTX_set_keylog_callback(ssl_ctx, [](const SSL *ssl, const char *line) {
    const char *ssl_keylogfile = getenv("SSLKEYLOGFILE");
    if (ssl_keylogfile) {
      std::ofstream(ssl_keylogfile, std::ios_base::out | std::ios_base::app)
          << line << "\n";
    }
  });

  std::cout << "// TLS1.3 full handshake" << std::endl;
  auto ec = do_one(ssl_ctx, hostname, service, false, false, false);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "// TLS1.3 resumption" << std::endl;
  ec = do_one(ssl_ctx, hostname, service, false, true, false);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "// TLS1.3 0-RTT" << std::endl;
  ec = do_one(ssl_ctx, hostname, service, false, true, true);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "// TCP-Fast Open, TLS1.3 full handshake" << std::endl;
  ec = do_one(ssl_ctx, hostname, service, true, false, false);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "// TCP-Fast Open, TLS1.3 resumption" << std::endl;
  ec = do_one(ssl_ctx, hostname, service, true, true, false);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "// TCP-Fast Open, TLS1.3 0-RTT" << std::endl;
  ec = do_one(ssl_ctx, hostname, service, true, true, true);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
