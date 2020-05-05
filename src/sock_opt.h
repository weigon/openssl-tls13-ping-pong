#ifndef SOCK_OPT_INCLUDED
#define SOCK_OPT_INCLUDED

#include <system_error>

void set_tcp_fast_open_server(int sock, int qlen, std::error_code &ec);
void set_tcp_fast_open_client(int sock, int on, std::error_code &ec);
void set_reuse_address(int sock, int on, std::error_code &ec);
void set_tcp_nodelay(int sock, int on, std::error_code &ec);

#endif
