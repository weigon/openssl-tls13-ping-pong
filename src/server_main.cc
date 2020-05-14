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
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#ifndef WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <signal.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "file_descriptor.h"
#include "resolver.h"
#include "sock_err.h"
#include "sock_opt.h"
#include "ssl_err.h"

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
//
// On FreeBSD:
//
// $ sysctl net.inet.tcp.fastopen.server_enable=1

volatile int want_shutdown{0};

static void signal_handler(int sig) { want_shutdown = 1; }

int main(int argc, char **argv) {
#ifndef WIN32
  // don't signal SIGPIPE on write() to a closed connection
  signal(SIGPIPE, SIG_IGN);
#else
  #define SHUT_WR SD_SEND
  WSADATA wsaData;
  // Initialize Winsock
  auto iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    printf("WSAStartup failed with error: %d\n", iResult);
    return EXIT_FAILURE;
  }
  SOCKET ConnectSocket = INVALID_SOCKET;
#endif
  std::map<std::string, std::string> args{
      {"hostname", "127.0.0.1"}, {"port", "3308"},     {"data", "PONG"},
      {"verbosity", "0"},        {"cmd", "run"},       {"curves", ""},
      {"key", "key.pem"},        {"cert", "cert.pem"},
  };
  for (int ndx = 1; ndx < argc; ++ndx) {
    std::string arg(argv[ndx]);

    if (arg.substr(0, 2) == "--") {
      arg.erase(0, 2);

      auto eq_pos = arg.find('=');
      if (eq_pos == std::string::npos) {
        return EXIT_FAILURE;
      }
      auto key = arg.substr(0, eq_pos);
      auto value = arg.substr(eq_pos + 1);

      auto it = args.find(key);
      if (it == args.end()) {
        std::cerr << "unsupported option: " << key << std::endl;
        return EXIT_FAILURE;
      }

      it->second = value;
    } else if (arg.substr(0, 1) == "-") {
      if (arg.substr(1) == "?") {
        args.at("cmd") = "help";
      } else {
        std::cerr << "unsupport arg: " << arg << std::endl;
        return EXIT_FAILURE;
      }
    } else {
      std::cerr << "unsupport arg: " << arg << std::endl;
      return EXIT_FAILURE;
    }
  }

  if (args.at("cmd") == "help") {
    return cleanup(EXIT_SUCCESS);
  }

  const char *hostname = args.at("hostname").c_str();
  const char *service = args.at("port").c_str();
  const auto verbosity = std::stol(args.at("verbosity"));

#ifndef WIN32
  // allow the interrupt the blocking accept() call with SIGINT, SIGTERM
  struct sigaction action {};
  action.sa_handler = signal_handler;
  sigaction(SIGINT, &action, nullptr);
  sigaction(SIGTERM, &action, nullptr);
#else
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
#endif  // !WIN32

  SSL_library_init();
  SSL_load_error_strings();

  auto ssl_ctx_mem = std::unique_ptr<SSL_CTX, void (*)(SSL_CTX *)>(
      SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);
  SSL_CTX *ssl_ctx = ssl_ctx_mem.get();

  // set DH group to enable forward secrecy
  auto dh_2048_mem =
      std::unique_ptr<DH, void (*)(DH *)>(DH_get_2048_256(), &DH_free);
  DH *dh_2048 = dh_2048_mem.get();

  {
    auto ssl_err = SSL_CTX_set_tmp_dh(ssl_ctx, dh_2048);
    if (ssl_err != 1) {
      auto ec = last_sslerr_error_code();
      std::cerr << "ssl-ctx-set-tmp-dh() failed: " << ec.message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  {
    auto arg = args.at("curves");
    if (!arg.empty()) {
      SSL_CTX_set1_groups_list(ssl_ctx, arg.c_str());
    }
  }

  const char *key_pem = args.at("key").c_str();
  const char *cert_pem = args.at("cert").c_str();

  {
    auto ssl_err =
        SSL_CTX_use_PrivateKey_file(ssl_ctx, key_pem, SSL_FILETYPE_PEM);
    if (ssl_err != 1) {
      auto ec = last_sslerr_error_code();
      std::cerr << "use-privatekey-file(" << key_pem
                << ") failed: " << ec.message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  {
    auto ssl_err =
        SSL_CTX_use_certificate_file(ssl_ctx, cert_pem, SSL_FILETYPE_PEM);
    if (ssl_err != 1) {
      auto ec = last_sslerr_error_code();
      std::cerr << "use-certificate-file(" << cert_pem
                << ") failed: " << ec.message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
  }

  // session-id-context must be unique to the application to avoid false sharing
  // of session tickets/ids
  std::array<uint8_t, 4> session_id_context = {0x01, 0x02, 0x03, 0x04};
  {
    auto ssl_res = SSL_CTX_set_session_id_context(
        ssl_ctx, session_id_context.data(), session_id_context.size());
    if (ssl_res != 1) {
      auto ec = last_sslerr_error_code();

      std::cerr << "set-session-id-context() failed: " << ec.message()
                << std::endl;

      return cleanup(EXIT_FAILURE);
    }
  }

  // announce that early data will be accepted accepted
  {
    auto ssl_err = SSL_CTX_set_max_early_data(ssl_ctx, 32);
    if (ssl_err != 1) {
      // docs don't say that an error-code is added to the error-queue.
      std::cerr << "set-max-early-data() failed" << std::endl;

      return cleanup(EXIT_FAILURE);
    }
  }

  std::error_code ec;
  // prepare the socket.
  //
  // - resolve the IP and port
  // - bind the resolve address
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  auto ai = address_info(hostname, service, &hints, ec);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return cleanup(EXIT_FAILURE);
  }
  auto ri = address_info(hostname, service, &hints, ec);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return cleanup(EXIT_FAILURE);
  }
  FileDescriptor sock;

  sock.assign(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
  if (!sock.is_open()) {
    std::cerr << last_error_code().message() << std::endl;
    return cleanup(EXIT_FAILURE);
  }

  if (0 != bind(sock.native_handle(), ai->ai_addr, ai->ai_addrlen)) {
    std::cerr << __LINE__ << ": " << last_error_code().message() << std::endl;
    return cleanup(EXIT_FAILURE);
  }
  if (0 != listen(sock.native_handle(), 32)) {
    std::cerr << __LINE__ << ": " << last_error_code().message() << std::endl;
    return cleanup(EXIT_FAILURE);
  }

  set_tcp_fast_open_server(sock.native_handle(), 1, ec);
  if (ec) {
    std::cerr << __LINE__ << ": enable TCP FastOpen(): " << ec.message()
              << std::endl;
    // may fail if not enabled by the system.
    if (ec != make_error_code(std::errc::operation_not_permitted)) {
      return cleanup(EXIT_FAILURE);
    }
  }

  set_reuse_address(sock.native_handle(), 1, ec);
  if (ec) {
    std::cerr << ec.message() << std::endl;
    return cleanup(EXIT_FAILURE);
  }

  // socket is setup, ready to accept connections.
  do {
    FileDescriptor client_sock;
    client_sock.assign(
        accept(sock.native_handle(), (struct sockaddr *)nullptr, nullptr));

    if (!client_sock.is_open()) {
      std::cerr << last_error_code().message() << std::endl;
      return cleanup(EXIT_FAILURE);
    }
    if (verbosity > 1) {
      std::cout << "s <- c: // new connection" << std::endl;
    }

    set_tcp_nodelay(client_sock.native_handle(), 1, ec);
    if (ec) {
      std::cerr << __LINE__ << ": " << ec.message() << std::endl;
    }

    // create a SSL handle and assign it the socket-fd
    auto ssl_mem =
        std::unique_ptr<SSL, void (*)(SSL *)>(SSL_new(ssl_ctx), &SSL_free);
    SSL *ssl = ssl_mem.get();

    SSL_set_fd(ssl, client_sock.native_handle());

    std::string transfer_buf;
    transfer_buf.resize(128);
    size_t transfered{};
    do {
      {
        auto ssl_res = SSL_read_early_data(ssl, &transfer_buf.front(),
                                           transfer_buf.size(), &transfered);
        if (ssl_res == SSL_READ_EARLY_DATA_ERROR) {
          ec = last_ssl_error_code(ssl, ssl_res);
          break;
        } else if (ssl_res == SSL_READ_EARLY_DATA_FINISH) {
          transfer_buf.resize(transfered);
          if (transfered > 0) {
            if (verbosity > 1) {
              std::cout << "s <- c: " << transfer_buf << std::endl;
            }
          }
          break;
        } else if (ssl_res == SSL_READ_EARLY_DATA_SUCCESS) {
          transfer_buf.resize(transfered);
          if (verbosity > 1) {
            std::cout << "s <- c: " << transfer_buf << std::endl;
          }
        }
      }
    } while (true);

    // some error happened
    if (ec) break;

    {
      // accept the TLS connection
      auto ssl_res = SSL_accept(ssl);
      if (ssl_res != 1) {
        ec = last_ssl_error_code(ssl, ssl_res);

        std::cerr << "SSL_accept() failed: " << ec.message() << std::endl;

        // drop this connection and accept the next one
        continue;
      }

      if (verbosity > 1) {
        std::cout << "s -> c: // established" << std::endl;
      }
    }

    // only read data, if no early data was accepted.
    if (SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED) {
      transfer_buf.resize(128);
      auto ssl_res = SSL_read_ex(ssl, &transfer_buf.front(),
                                 transfer_buf.size(), &transfered);
      if (ssl_res == 0) {
        ec = last_ssl_error_code(ssl, ssl_res);

        std::cerr << "SSL_read_ex() failed: " << ec.message() << std::endl;
      } else if (ssl_res == 1) {
        transfer_buf.resize(transfered);
        if (verbosity > 1) {
          std::cout << "s <- c: " << transfer_buf << std::endl;
        }
      }
    }

    transfer_buf.assign(args.at("data"));
    SSL_write(ssl, transfer_buf.data(), transfer_buf.size());

    if (verbosity > 1) {
      std::cout << "s -> c: " << transfer_buf << std::endl;
    }
    {
      auto ssl_res = SSL_shutdown(ssl);
      if (ssl_res == 0) {
        // not finished yet
        //
        // but we'll close the connection anyway.
        if (verbosity > 1) {
          std::cout << "s -> c: shutdown in-progress" << std::endl;
        }
      } else if (ssl_res == 1) {
        // finished
        if (verbosity > 1) {
          std::cout << "s -> c: shutdown finished" << std::endl;
        }
      } else if (ssl_res == -1) {
        ec = last_sslerr_error_code();

        std::cerr << __LINE__ << ": ssl: " << ec.message() << std::endl;
      }
    }

    shutdown(sock.native_handle(), SHUT_WR);

    {
      auto ssl_res = SSL_shutdown(ssl);
      if (ssl_res == 0) {
        // not finished yet
        //
        // but we'll close the connection anyway.
        if (verbosity > 1) {
          std::cout << "s -> c: shutdown in-progress" << std::endl;
        }
      } else if (ssl_res == 1) {
        // finished
        if (verbosity > 1) {
          std::cout << "s -> c: shutdown finished" << std::endl;
        }
      } else if (ssl_res == -1) {
        ec = last_sslerr_error_code();

        std::cerr << __LINE__ << ": ssl: " << ec.message() << std::endl;
      }
    }
    if (verbosity > 1) {
      std::cout << "s -x c: // closed" << std::endl;
    }
  } while (!want_shutdown);

  return cleanup(EXIT_SUCCESS);
}
