#ifndef SOCK_ERR_INCLUDED
#define SOCK_ERR_INCLUDED

#include <system_error>

inline std::error_code last_error_code() {
  return {errno, std::generic_category()};
}

#endif
