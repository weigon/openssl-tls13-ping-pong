#ifdef WIN32
#include <ws2tcpip.h>
#endif

#include "resolver.h"
#include "sock_err.h"

#ifdef WIN32
#define EAI_SYSTEM -11
#endif

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

std::unique_ptr<addrinfo, void (*)(addrinfo *)> address_info(
    const char *hostname, const char *service, const addrinfo *hints,
    std::error_code &ec) {
  addrinfo *ai_raw{};
  auto ai_res = ::getaddrinfo(hostname, service, hints, &ai_raw);
  if (ai_res != 0) {
    if (ai_res == EAI_SYSTEM) {
      ec = last_error_code();
    } else {
      ec = std::error_code(ai_res, ResolverCategory());
    }

    // ai_raw should be a nullptr now.
  }

  return std::unique_ptr<addrinfo, void (*)(addrinfo *)>(ai_raw, &freeaddrinfo);
}
