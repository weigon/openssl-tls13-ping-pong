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

#if defined(__linux__)
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
 * @returns a std::error_code with the last error (or 0 on success)
 */
std::error_code do_one(SSL_CTX *ssl_ctx, bool with_fast_open,
                       bool with_session_resumption) {
  auto ssl = std::unique_ptr<SSL, void (*)(SSL *)>(SSL_new(ssl_ctx), &SSL_free);

  addrinfo *ai_raw{};
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AI_NUMERICHOST | AI_NUMERICSERV;
  auto ai_res = getaddrinfo("127.0.0.1", "3308", nullptr, &ai_raw);
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

  if (with_fast_open) {
    int on{1};
    setsockopt(sock.native_handle(), SOL_TCP, TCP_FASTOPEN_CONNECT, &on,
               sizeof on);
  }

  {
    int on = 1;
    setsockopt(sock.native_handle(), SOL_TCP, TCP_NODELAY, &on, sizeof on);
  }

  if (0 != connect(sock.native_handle(), ai->ai_addr, ai->ai_addrlen)) {
    return last_error_code();
  }

  SSL_set_fd(ssl.get(), sock.native_handle());
  if (last_session && with_session_resumption) {
    SSL_set_session(ssl.get(), last_session.release());
  }
  SSL_set_connect_state(ssl.get());

  std::array<char, 5> transfer_buf = {"PING"};
  if (SSL_get0_session(ssl.get()) != nullptr &&
      SSL_SESSION_get_max_early_data(SSL_get0_session(ssl.get())) > 0) {
    size_t written;
    auto ssl_res = SSL_write_early_data(ssl.get(), transfer_buf.data(),
                                        transfer_buf.size(), &written);
    if (ssl_res != 1) {
      switch (SSL_get_error(ssl.get(), ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << "none" << std::endl;
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
      std::cerr << __LINE__ << ": PING (early)" << std::endl;
    }
  }

  {
    auto ssl_res = SSL_connect(ssl.get());
    if (ssl_res != 1) {
      switch (SSL_get_error(ssl.get(), ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << "none" << std::endl;
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
      std::cerr << __LINE__ << ": connected" << std::endl;
    }
  }
  std::cerr << __LINE__ << ": " << SSL_get_early_data_status(ssl.get())
            << std::endl;

  if (SSL_get_early_data_status(ssl.get()) != SSL_EARLY_DATA_ACCEPTED) {
    auto ssl_res =
        SSL_write(ssl.get(), transfer_buf.data(), transfer_buf.size());
    if (ssl_res < 0) {
      switch (SSL_get_error(ssl.get(), ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << "none" << std::endl;
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
      std::cerr << __LINE__ << ": PING" << std::endl;
    }
  }

  {
    std::array<char, 128> read_buf;
    auto ssl_res = SSL_read(ssl.get(), read_buf.data(), read_buf.size());
    if (ssl_res != 1) {
      switch (SSL_get_error(ssl.get(), ssl_res)) {
        case SSL_ERROR_NONE:
          std::cerr << "none" << std::endl;
          break;
        case SSL_ERROR_SSL: {
          std::array<char, 120> errbuf;
          std::cerr << __LINE__ << ": ssl: "
                    << ERR_error_string(ERR_get_error(), errbuf.data())
                    << std::endl;
          break;
        }
      }
    } else if (ssl_res > 0) {
      std::cerr << "read" << std::endl;
    }
  }

  // shutdown the SSL session to
  SSL_shutdown(ssl.get());

  shutdown(sock.native_handle(), SHUT_WR);

  {
    std::array<char, 128> read_buf;
    // wait for the close from the other side
    read(sock.native_handle(), read_buf.data(), read_buf.size());
  }

  return {};
}

int main() {
  signal(SIGPIPE, SIG_IGN);

  // build SSL context
  auto ssl_ctx = std::unique_ptr<SSL_CTX, void (*)(SSL_CTX *)>(
      SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);

  // set tmp DH keys
  auto dh_2048 =
      std::unique_ptr<DH, void (*)(DH *)>(DH_get_2048_256(), &DH_free);
  SSL_CTX_set_tmp_dh(ssl_ctx.get(), dh_2048.get());

  // set the elliptic curves lists
  SSL_CTX_set1_groups_list(ssl_ctx.get(), "P-521:P-384:P-256:X25519");

  // enable the session cache to allow session resumption
  SSL_CTX_set_session_cache_mode(
      ssl_ctx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(ssl_ctx.get(), new_session_cb);

  {
    const char *ssl_keylogfile = getenv("SSLKEYLOGFILE");
    if (ssl_keylogfile) {
      // truncate the file as later the code will append to it.
      std::ofstream ofs(ssl_keylogfile,
                        std::ios_base::out | std::ios_base::trunc);
    }
  }
  // enable the keylog to get better traces with wireshark
  SSL_CTX_set_keylog_callback(
      ssl_ctx.get(), [](const SSL *ssl, const char *line) {
        const char *ssl_keylogfile = getenv("SSLKEYLOGFILE");
        if (ssl_keylogfile) {
          std::ofstream(ssl_keylogfile, std::ios_base::out | std::ios_base::app)
              << line << "\n";
        }
      });

  // 1st round without TCP Fast Open, no session resumption
  auto ec = do_one(ssl_ctx.get(), false, false);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  // 2nd round with TCP Fast Open.
  ec = do_one(ssl_ctx.get(), false, true);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  // 3rd round with TCP Fast Open, without session resumption
  ec = do_one(ssl_ctx.get(), true, false);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  // 4th round with TCP Fast Open, and session resumption
  ec = do_one(ssl_ctx.get(), true, true);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
