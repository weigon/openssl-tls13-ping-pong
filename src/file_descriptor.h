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

#ifndef FILE_DESCRIPTOR_INCLUDED
#define FILE_DESCRIPTOR_INCLUDED

#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#else
#include <unistd.h>  // close
#endif
#include <utility>  // exchange

class FileDescriptor {
 public:
#if defined(_WIN32)
  using native_handle_type = SOCKET;
  const native_handle_type kInvalidHandle{INVALID_SOCKET};
#else
  using native_handle_type = int;
  const native_handle_type kInvalidHandle{-1};
#endif

  FileDescriptor() = default;

  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;
  FileDescriptor(FileDescriptor &&rhs)
      : fd_{std::exchange(rhs.fd_, kInvalidHandle)} {}
  FileDescriptor &operator=(FileDescriptor &&rhs) {
    close();

    fd_ = std::exchange(rhs.fd_, -1);
    return *this;
  }

  void assign(native_handle_type fd) {
    close();

    fd_ = fd;
  }

  bool is_open() const { return fd_ != kInvalidHandle; }

  native_handle_type release() { return std::exchange(fd_, kInvalidHandle); }

  void close() {
    if (is_open()) {
#if defined(_WIN32)
      ::closesocket(fd_);
#else
      ::close(fd_);
#endif
      fd_ = kInvalidHandle;
    }
  }

  native_handle_type native_handle() const { return fd_; }

  ~FileDescriptor() { close(); }

 private:
  native_handle_type fd_{kInvalidHandle};
};

#endif
