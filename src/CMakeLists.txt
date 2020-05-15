#
# Copyright 2020 Jan Kneschke <jan@kneschke.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT


SET(LIBS OpenSSL::SSL OpenSSL::Crypto)
IF(WIN32)
  # ensure that only the bare minimum headers are
  # included when <windows.h> is included.
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_LEAN_AND_MEAN /EHsc")

  GET_TARGET_PROPERTY(OPENSSL_IMPORTED_LOCATION OpenSSL::SSL IMPORTED_LOCATION)
  GET_FILENAME_COMPONENT(OPENSSL_LIB_DIR ${OPENSSL_IMPORTED_LOCATION} DIRECTORY)

  SET(OPENSSL_BIN_DIR ${OPENSSL_LIB_DIR}/../bin/)
  FIND_PROGRAM(OPENSSL_COMMAND
    NAMES
    openssl
    PATHS
    ${OPENSSL_BIN_DIR}
    )

  FIND_FILE(OPENSSL_SSL_DLL
    NAMES
    libssl-1_1-x64.dll
    PATHS
    ${OPENSSL_BIN_DIR}
    )
  FIND_FILE(OPENSSL_CRYPTO_DLL
    NAMES
    libcrypto-1_1-x64.dll
    PATHS
    ${OPENSSL_BIN_DIR}
    )

  IF(OPENSSL_SSL_DLL)
    LIST(APPEND COPY_TO_TARGET_FILES ${OPENSSL_SSL_DLL})
  ENDIF()
  IF(OPENSSL_CRYPTO_DLL)
    LIST(APPEND COPY_TO_TARGET_FILES ${OPENSSL_CRYPTO_DLL})
  ENDIF()

  LIST(APPEND LIBS ws2_32)   # winsock2
  LIST(APPEND LIBS crypt32)  # openssl needs crypt32

  SET(OPENSSL_CONFIG -config ${OPENSSL_BIN_DIR}/../SSL/openssl.cnf)
ELSE()
  FIND_PROGRAM(OPENSSL_COMMAND
    NAMES
    openssl
    )
ENDIF()

ADD_EXECUTABLE(tls13_ping_pong_client
  client_main.cc
  sock_opt.cc
  resolver.cc
  ssl_err.cc
  )
TARGET_LINK_LIBRARIES(tls13_ping_pong_client ${LIBS})

ADD_EXECUTABLE(tls13_ping_pong_server
  server_main.cc
  sock_opt.cc
  resolver.cc
  ssl_err.cc
  )
TARGET_LINK_LIBRARIES(tls13_ping_pong_server ${LIBS})

IF(OPENSSL_COMMAND)
  ADD_CUSTOM_COMMAND(
    OUTPUT key.pem cert.pem
    COMMAND ${OPENSSL_COMMAND}
    ARGS req
      -x509
      -newkey rsa:4096
      -keyout key.pem
      -out cert.pem
      -days 365
      -nodes
      -subj "/C=DE/ST=Berlin/L=Berlin/O=Company Name/OU=Org/CN=www.example.com"
      ${OPENSSL_CONFIG}
    )

  LIST(APPEND COPY_TO_TARGET_FILES key.pem)
  LIST(APPEND COPY_TO_TARGET_FILES cert.pem)

  ADD_CUSTOM_TARGET(build_certs
    DEPENDS key.pem cert.pem)

  ADD_DEPENDENCIES(tls13_ping_pong_server build_certs)
ENDIF()

# copy openssl DLLs, certs, ... to the folder of the binary.
FOREACH(F ${COPY_TO_TARGET_FILES})
  ADD_CUSTOM_COMMAND(
    TARGET tls13_ping_pong_server
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${F}
    $<TARGET_FILE_DIR:tls13_ping_pong_server>)
ENDFOREACH()
