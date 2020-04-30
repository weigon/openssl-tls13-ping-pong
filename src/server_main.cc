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
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <system_error>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "file_descriptor.h"

// TCP FastOpen is not enabled by default on Linux.
//
// See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
//
// tcp_fastopen - INTEGER
//   0x01 - client (enabled by default)
//   0x02 - server (disabled by default)
//
// # current value
// $ cat /proc/sys/net/ipv4/tcp_fastopen
// 1
// # enable client and server
// $ echo "3" | sudo tee /proc/sys/net/ipv4/tcp_fastopen

std::error_code last_error_code() { return {errno, std::generic_category()}; }

volatile int want_shutdown{0};

static void signal_handler(int sig) { want_shutdown = 1; }

int main() {
  // don't signal SIGPIPE on write() to a closed connection
  signal(SIGPIPE, SIG_IGN);

  // allow the interrupt the blocking accept() call with SIGINT, SIGTERM
  struct sigaction action {};
  action.sa_handler = signal_handler;
  sigaction(SIGINT, &action, nullptr);
  sigaction(SIGTERM, &action, nullptr);

  SSL_library_init();
  SSL_load_error_strings();

  auto ssl_ctx = std::unique_ptr<SSL_CTX, void (*)(SSL_CTX *)>(
      SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);

  auto dh_2048 =
      std::unique_ptr<DH, void (*)(DH *)>(DH_get_2048_256(), &DH_free);

  SSL_CTX_set_tmp_dh(ssl_ctx.get(), dh_2048.get());

  SSL_CTX_set1_groups_list(ssl_ctx.get(), "P-521:P-384:P-256:X25519");

  const char key_pem[] = "key.pem";
  const char cert_pem[] = "cert.pem";

  {
    auto ssl_err =
        SSL_CTX_use_PrivateKey_file(ssl_ctx.get(), key_pem, SSL_FILETYPE_PEM);
    if (ssl_err != 1) {
      std::array<char, 120> errbuf;
      std::cerr << "use-privatekey-file(" << key_pem << ") failed: "
                << ERR_error_string(ERR_get_error(), errbuf.data())
                << std::endl;
      return EXIT_FAILURE;
    }
  }

  {
    auto ssl_err =
        SSL_CTX_use_certificate_file(ssl_ctx.get(), cert_pem, SSL_FILETYPE_PEM);
    if (ssl_err != 1) {
      std::array<char, 120> errbuf;
      std::cerr << "use-certificate-file(" << cert_pem << ") failed: "
                << ERR_error_string(ERR_get_error(), errbuf.data())
                << std::endl;
      std::cerr << "ssl: " << ERR_error_string(ERR_get_error(), errbuf.data())
                << std::endl;
      return EXIT_FAILURE;
    }
  }

  // announce we accept some early data
  SSL_CTX_set_max_early_data(ssl_ctx.get(), 32);

  // prepare the socket.
  //
  // - resolve the IP and port
  // - bind the resolve address
  addrinfo *ai_raw{};
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AI_NUMERICHOST | AI_NUMERICSERV;
  auto ai_res = getaddrinfo("127.0.0.1", "3308", nullptr, &ai_raw);
  if (ai_res != 0) {
    std::cerr << last_error_code().message() << std::endl;
    return EXIT_FAILURE;
  }
  auto ai =
      std::unique_ptr<addrinfo, void (*)(addrinfo *)>(ai_raw, &freeaddrinfo);

  FileDescriptor sock;

  sock.assign(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
  if (!sock.is_open()) {
    std::cerr << last_error_code().message() << std::endl;
    return EXIT_FAILURE;
  }

  {
    int on{1};
    setsockopt(sock.native_handle(), SOL_TCP, TCP_FASTOPEN, &on, sizeof on);
  }

  {
    int on = 1;
    setsockopt(sock.native_handle(), SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
  }

  if (0 != bind(sock.native_handle(), ai->ai_addr, ai->ai_addrlen)) {
    std::cerr << last_error_code().message() << std::endl;
    return EXIT_FAILURE;
  }
  if (0 != listen(sock.native_handle(), 128)) {
    std::cerr << last_error_code().message() << std::endl;
    return EXIT_FAILURE;
  }

  // socket is setup, ready to accept connections.
  do {
    FileDescriptor client_sock;

    client_sock.assign(accept(sock.native_handle(), nullptr, nullptr));

    if (!client_sock.is_open()) {
      std::cerr << last_error_code().message() << std::endl;
      return EXIT_FAILURE;
    }

    std::cout << "s <- c: // new connection" << std::endl;

    {
      int on = 1;
      setsockopt(client_sock.native_handle(), SOL_TCP, TCP_NODELAY, &on,
                 sizeof on);
    }

    // create a SSL handle and assign it the socket-fd
    auto ssl = std::unique_ptr<SSL, void (*)(SSL *)>(SSL_new(ssl_ctx.get()),
                                                     &SSL_free);
    SSL_set_fd(ssl.get(), client_sock.native_handle());

    std::string transfer_buf;
    transfer_buf.resize(128);
    size_t transfered{};
    do {
      {
        auto ssl_res = SSL_read_early_data(ssl.get(), &transfer_buf.front(),
                                           transfer_buf.size(), &transfered);
        if (ssl_res == SSL_READ_EARLY_DATA_ERROR) {
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
            default:
              std::cerr << __LINE__ << ": ???" << std::endl;
              break;
          }
          break;
        } else if (ssl_res == SSL_READ_EARLY_DATA_FINISH) {
          transfer_buf.resize(transfered);
          if (transfered > 0) {
            std::cout << "s <- c: " << transfer_buf << std::endl;
          }
          break;
        } else if (ssl_res == SSL_READ_EARLY_DATA_SUCCESS) {
          transfer_buf.resize(transfered);
          std::cout << "s <- c: " << transfer_buf << std::endl;
        }
      }
    } while (true);

    {
      // accept the TLS connection
      auto ssl_res = SSL_accept(ssl.get());
      if (ssl_res != 1) {
        switch (SSL_get_error(ssl.get(), ssl_res)) {
          case SSL_ERROR_NONE:
            std::cerr << "none" << std::endl;
            break;
          case SSL_ERROR_SYSCALL:
            std::cerr << last_error_code().message() << std::endl;
            break;
          case SSL_ERROR_SSL: {
            std::array<char, 120> errbuf;
            std::cerr << "ssl: "
                      << ERR_error_string(ERR_get_error(), errbuf.data())
                      << std::endl;
            break;
          }
        }

        // drop this connection and accept the next one
        continue;
      }

      std::cout << "s -> c: // established" << std::endl;
    }

    // only read data, if no early data was accepted.
    if (SSL_get_early_data_status(ssl.get()) != SSL_EARLY_DATA_ACCEPTED) {
      transfer_buf.resize(128);
      auto ssl_res = SSL_read_ex(ssl.get(), &transfer_buf.front(),
                                 transfer_buf.size(), &transfered);
      if (ssl_res == 0) {
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
      } else if (ssl_res == 1) {
        transfer_buf.resize(transfered);
        std::cout << "s <- c: " << transfer_buf << std::endl;
      }
    }

    transfer_buf.assign("PONG");
    SSL_write(ssl.get(), transfer_buf.data(), transfer_buf.size());

    std::cout << "s -> c: " << transfer_buf << std::endl;
    {
      auto ssl_res = SSL_shutdown(ssl.get());
      if (ssl_res == 0) {
        // not finished yet
        //
        // but we'll close the connection anyway.
        std::cout << "s -> c: shutdown in-progress" << std::endl;
      } else if (ssl_res == 1) {
        // finished
        std::cout << "s -> c: shutdown finished" << std::endl;
      } else if (ssl_res == -1) {
        std::array<char, 120> errbuf;
        std::cerr << __LINE__ << ": ssl: "
                  << ERR_error_string(ERR_get_error(), errbuf.data())
                  << std::endl;
      }
    }

    shutdown(sock.native_handle(), SHUT_WR);

    {
      auto ssl_res = SSL_shutdown(ssl.get());
      if (ssl_res == 0) {
        // not finished yet
        //
        // but we'll close the connection anyway.
        std::cout << "s -> c: shutdown in-progress" << std::endl;
      } else if (ssl_res == 1) {
        // finished
        std::cout << "s -> c: shutdown finished" << std::endl;
      } else if (ssl_res == -1) {
        std::array<char, 120> errbuf;
        std::cerr << __LINE__ << ": ssl: "
                  << ERR_error_string(ERR_get_error(), errbuf.data())
                  << std::endl;
      }
    }
    std::cout << "s -x c: // closed" << std::endl;
  } while (!want_shutdown);

  return 0;
}
