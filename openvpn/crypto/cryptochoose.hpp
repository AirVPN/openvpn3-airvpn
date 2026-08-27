//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#ifndef OPENVPN_CRYPTO_CRYPTO_CHOOSE_H
#define OPENVPN_CRYPTO_CRYPTO_CHOOSE_H

#include <openvpn/crypto/definitions.hpp>

#ifdef USE_OPENSSL
#include <openvpn/openssl/crypto/api.hpp>
#include <openvpn/openssl/util/rand.hpp>
#endif

#ifdef USE_MBEDTLS
#include <mbedtls/platform.h>
#include <mbedtls/debug.h> // for debug_set_threshold
#include <openvpn/mbedtls/crypto/api.hpp>
#include <openvpn/mbedtls/util/rand.hpp>
#ifdef OPENVPN_PLATFORM_UWP
#include <openvpn/mbedtls/util/uwprand.hpp>
#endif
#endif

namespace openvpn::SSLLib {
#ifdef USE_MBEDTLS
#define SSL_LIB_NAME "MbedTLS"
using CryptoAPI = MbedTLSCryptoAPI;
#if defined OPENVPN_PLATFORM_UWP
using RandomAPI = MbedTLSRandomWithUWPEntropy;
#else
using RandomAPI = MbedTLSRandom;
#endif
#elif defined(USE_OPENSSL)
#define SSL_LIB_NAME "OpenSSL"
using CryptoAPI = OpenSSLCryptoAPI;
using RandomAPI = OpenSSLRandom;
#else
#error no SSL library defined
#endif
} // namespace openvpn::SSLLib

#endif
