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

#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#else
#include <netdb.h>  // addrinfo
#endif
#include <memory>
#include <system_error>

#include "deleter.h"
#include "resolver.h"
#include "sock_err.h"

const std::error_category &ResolverCategory() noexcept {
  class category_impl : public std::error_category {
   public:
    const char *name() const noexcept override { return "resolver"; }
    std::string message(int condition) const override {
      return gai_strerror(condition);
    }
  };

  static category_impl impl;
  return impl;
};

std::unique_ptr<addrinfo, Deleter<addrinfo>> address_info(const char *hostname,
                                                          const char *service,
                                                          const addrinfo *hints,
                                                          std::error_code &ec) {
  addrinfo *ai_raw{};
  auto ai_res = ::getaddrinfo(hostname, service, hints, &ai_raw);
  if (ai_res != 0) {
#if defined(EAI_SYSTEM)
    if (ai_res == EAI_SYSTEM) {
      ec = last_error_code();
    } else {
      ec = std::error_code(ai_res, ResolverCategory());
    }
#else
    ec = std::error_code(ai_res, ResolverCategory());
#endif

    // ai_raw should be a nullptr now.
  }

  return std::unique_ptr<addrinfo, Deleter<addrinfo>>(ai_raw);
}
