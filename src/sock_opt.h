#ifndef SOCK_OPT_INCLUDED
#define SOCK_OPT_INCLUDED

#include <system_error>

#include "file_descriptor.h"

void set_tcp_fast_open_server(FileDescriptor::native_handle_type sock, int qlen,
                              std::error_code &ec);
void set_tcp_fast_open_client(FileDescriptor::native_handle_type sock, int on,
                              std::error_code &ec);
void set_reuse_address(FileDescriptor::native_handle_type sock, int on,
                       std::error_code &ec);
void set_tcp_nodelay(FileDescriptor::native_handle_type sock, int on,
                     std::error_code &ec);

#endif
