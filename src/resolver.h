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

#ifndef RESOLVER_INCLUDED
#define RESOLVER_INCLUDED

#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>  // EAI_NONAME
#else
#include <netdb.h>  // addrinfo
#endif
#include <memory>        // unique_ptr
#include <system_error>  // error_code

#include "deleter.h"

enum class resolver_errc {
  noname = EAI_NONAME,
};

std::error_code make_error_code(resolver_errc ec);

template <>
class Deleter<addrinfo> {
 public:
  void operator()(addrinfo *a) { freeaddrinfo(a); }
};

std::unique_ptr<addrinfo, Deleter<addrinfo>> address_info(const char *hostname,
                                                          const char *service,
                                                          const addrinfo *hints,
                                                          std::error_code &ec);

#endif
