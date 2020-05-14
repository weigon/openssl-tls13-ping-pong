#ifndef SOCK_OPT_INCLUDED
#define SOCK_OPT_INCLUDED

#include <system_error>

#ifndef WIN32
using native_handle_type = int;
#else
#include <WinSock2.h>
using native_handle_type = SOCKET;
#endif

void set_tcp_fast_open_server(native_handle_type sock, int qlen,
                              std::error_code &ec);
void set_tcp_fast_open_client(native_handle_type sock, int on,
                              std::error_code &ec);
void set_reuse_address(native_handle_type sock, int on, std::error_code &ec);
void set_tcp_nodelay(native_handle_type sock, int on, std::error_code &ec);

#endif
