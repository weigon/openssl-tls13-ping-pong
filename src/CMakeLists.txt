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

IF(WIN32)
  FIND_LIBRARY(OPENSSL_LIBRARY
               NAMES ssl libssl ssleay32 ssleay32MD
               HINTS ${OPENSSL_ROOT_DIR}/lib)
  FIND_LIBRARY(CRYPTO_LIBRARY
               NAMES crypto libcrypto libeay32
               HINTS ${OPENSSL_ROOT_DIR}/lib)
  SET(LIBS ${LIBS} ws2_32.lib ${OPENSSL_LIBRARY} ${CRYPTO_LIBRARY})
  SET (OPENSSL_INCLUDE_DIR  ${OPENSSL_ROOT_DIR}/include)

  MESSAGE(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
  MESSAGE(STATUS "OPENSSL_LIBRARY = ${OPENSSL_LIBRARY}")
  MESSAGE(STATUS "CRYPTO_LIBRARY = ${CRYPTO_LIBRARY}")

  INCLUDE_DIRECTORIES(SYSTEM ${OPENSSL_INCLUDE_DIR})

  GET_FILENAME_COMPONENT(CRYPTO_NAME "${CRYPTO_LIBRARY}" NAME_WE)
  GET_FILENAME_COMPONENT(OPENSSL_NAME "${OPENSSL_LIBRARY}" NAME_WE)

  # Different naming scheme for the matching .dll as of SSL 1.1
  SET(SSL_MSVC_VERSION_SUFFIX "-1_1")
  SET(SSL_MSVC_ARCH_SUFFIX "-x64")

  # OpenSSL 1.1 Look for libcrypto-1_1-x64.dll or libcrypto-1_1.dll
  # OpenSSL 1.0 Look for libeay32.dll
  FIND_FILE(HAVE_CRYPTO_DLL
    NAMES
    "${CRYPTO_NAME}${SSL_MSVC_VERSION_SUFFIX}${SSL_MSVC_ARCH_SUFFIX}.dll"
    "${CRYPTO_NAME}${SSL_MSVC_VERSION_SUFFIX}.dll"
    PATHS "${OPENSSL_ROOT_DIR}/bin"
    NO_DEFAULT_PATH
    )
  FIND_FILE(HAVE_OPENSSL_DLL
    NAMES
    "${OPENSSL_NAME}${SSL_MSVC_VERSION_SUFFIX}${SSL_MSVC_ARCH_SUFFIX}.dll"
    "${OPENSSL_NAME}${SSL_MSVC_VERSION_SUFFIX}.dll"
    PATHS "${OPENSSL_ROOT_DIR}/bin"
    NO_DEFAULT_PATH
    )

  MESSAGE(STATUS "HAVE_CRYPTO_DLL ${HAVE_CRYPTO_DLL}")
  MESSAGE(STATUS "HAVE_OPENSSL_DLL ${HAVE_OPENSSL_DLL}")
  IF(HAVE_CRYPTO_DLL AND HAVE_OPENSSL_DLL)
    GET_FILENAME_COMPONENT(CRYPTO_DLL_NAME "${HAVE_CRYPTO_DLL}" NAME)
    GET_FILENAME_COMPONENT(OPENSSL_DLL_NAME "${HAVE_OPENSSL_DLL}" NAME)
    ADD_CUSTOM_TARGET(copy_openssl_dlls ALL
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${HAVE_CRYPTO_DLL}"
      "${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${CRYPTO_DLL_NAME}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${HAVE_OPENSSL_DLL}"
      "${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${OPENSSL_DLL_NAME}"
      )
    MESSAGE(STATUS "INSTALL ${HAVE_CRYPTO_DLL} to ${CMAKE_BINARY_DIR}")
    MESSAGE(STATUS "INSTALL ${HAVE_OPENSSL_DLL} to ${CMAKE_BINARY_DIR}")
    INSTALL(FILES
      "${HAVE_CRYPTO_DLL}"
      "${HAVE_OPENSSL_DLL}"
      DESTINATION "${CMAKE_BINARY_DIR}" COMPONENT SharedLibraries)
  ELSE()
    MESSAGE(STATUS "Cannot find SSL dynamic libraries")
    IF(OPENSSL_MINOR_VERSION VERSION_EQUAL 1)
      SET(SSL_LIBRARIES ${SSL_LIBRARIES} crypt32.lib)
      MESSAGE(STATUS "SSL_LIBRARIES ${SSL_LIBRARIES}")
    ENDIF()
  ENDIF()

ELSE()
  SET(LIBS OpenSSL::SSL OpenSSL::Crypto)
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

ADD_CUSTOM_COMMAND(
	OUTPUT key.pem cert.pem
	COMMAND openssl
	ARGS req
		-x509
		-newkey rsa:4096
		-keyout key.pem
		-out cert.pem
		-days 365
		-nodes
		-subj "/C=DE/ST=Berlin/L=Berlin/O=Company Name/OU=Org/CN=www.example.com"
	)

ADD_CUSTOM_TARGET(build_certs
	DEPENDS key.pem cert.pem)

ADD_DEPENDENCIES(tls13_ping_pong_server build_certs)
