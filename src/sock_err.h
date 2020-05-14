#ifndef SOCK_ERR_INCLUDED
#define SOCK_ERR_INCLUDED

#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#else
#include <cerrno>
#endif

#include <system_error>

inline std::error_code last_error_code() {
#if defined(_WIN32)
  return {WSAGetLastError(), std::system_category()};
#else
  return {errno, std::generic_category()};
#endif
}

#endif
