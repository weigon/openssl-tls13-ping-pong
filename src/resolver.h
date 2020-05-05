#ifndef RESOLVER_INCLUDED
#define RESOLVER_INCLUDED

#include <netdb.h>       // addrinfo
#include <memory>        // unique_ptr
#include <system_error>  // error_code

enum class resolver_errc {
  noname = EAI_NONAME,
};

std::error_code make_error_code(resolver_errc ec);

std::unique_ptr<addrinfo, void (*)(addrinfo *)> address_info(
    const char *hostname, const char *service, const addrinfo *hints,
    std::error_code &ec);

#endif
