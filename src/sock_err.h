#ifndef SOCK_ERR_INCLUDED
#define SOCK_ERR_INCLUDED

#include <system_error>
#ifdef WIN32
#include<WinSock2.h>
#endif

inline std::error_code last_error_code() {
  return {errno, std::generic_category()};
}

inline int cleanup(int exit_error_code) {
#ifdef WIN32
  int err = WSACleanup();
  return exit_error_code ? exit_error_code : err;
#else
  return exit_error_code;
#endif
}
#endif
