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

#include <openssl/err.h>  // ERR_get_error
#include <openssl/ssl.h>

#include "sock_err.h"
#include "ssl_err.h"

const std::error_category &SslCategory() noexcept {
  class category_impl : public std::error_category {
   public:
    const char *name() const noexcept override { return "openssl"; }
    std::string message(int condition) const override {
      std::array<char, 120> errbuf;
      return ERR_error_string(condition, errbuf.data());
    }
  };

  static category_impl impl;
  return impl;
};

std::error_code last_sslerr_error_code() {
  return {static_cast<int>(ERR_get_error()), SslCategory()};
}

std::error_code last_ssl_error_code(SSL *ssl, int res) {
  switch (SSL_get_error(ssl, res)) {
    case SSL_ERROR_NONE:
      return {};
    case SSL_ERROR_SSL:
      return last_sslerr_error_code();
    case SSL_ERROR_SYSCALL:
      return last_error_code();
  }
  return {};
}
