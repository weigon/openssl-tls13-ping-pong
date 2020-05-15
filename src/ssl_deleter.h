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

#ifndef SSL_DELETER_INCLUDED
#define SSL_DELETER_INCLUDED

#include <openssl/ssl.h>

#include "deleter.h"

template <>
class Deleter<SSL_CTX> {
 public:
  void operator()(SSL_CTX *s) { SSL_CTX_free(s); }
};

template <>
class Deleter<SSL> {
 public:
  void operator()(SSL *s) { SSL_free(s); }
};

template <>
class Deleter<SSL_SESSION> {
 public:
  void operator()(SSL_SESSION *p) { SSL_SESSION_free(p); }
};

template <>
class Deleter<DH> {
 public:
  void operator()(DH *p) { DH_free(p); }
};

template <>
class Deleter<BIO> {
 public:
  void operator()(BIO *p) { BIO_free(p); }
};

template <>
class Deleter<BIO_METHOD> {
 public:
  void operator()(BIO_METHOD *p) { BIO_meth_free(p); }
};

#endif
