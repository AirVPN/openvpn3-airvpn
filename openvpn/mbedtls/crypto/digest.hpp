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

// Wrap the mbed TLS digest API defined in <mbedtls/md.h>
// so that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_MBEDTLS_CRYPTO_DIGEST_H
#define OPENVPN_MBEDTLS_CRYPTO_DIGEST_H

#include <string>

#include <mbedtls/md.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/mbedtls/mbedtls_compat.hpp>

namespace openvpn::MbedTLSCrypto {
class HMACContext;

class DigestContext
{
    DigestContext(const DigestContext &) = delete;
    DigestContext &operator=(const DigestContext &) = delete;

  public:
    friend class HMACContext;

    OPENVPN_SIMPLE_EXCEPTION(mbedtls_digest_uninitialized);
    OPENVPN_SIMPLE_EXCEPTION(mbedtls_digest_final_overflow);
    OPENVPN_EXCEPTION(mbedtls_digest_error);

    enum
    {
        MAX_DIGEST_SIZE = MBEDTLS_MD_MAX_SIZE
    };

    DigestContext()
        : initialized(false)
    {
    }

    DigestContext(const CryptoAlgs::Type alg)
        : initialized(false)
    {
        init(alg);
    }

    // SSLLib::Ctx is unused in mbedtls
    DigestContext(const CryptoAlgs::Type alg, SSLLib::Ctx)
        : initialized(false)
    {
        init(alg);
    }

    ~DigestContext()
    {
        erase();
    }

    void init(const CryptoAlgs::Type alg)
    {
        erase();

        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, digest_type(alg), 1) < 0)
            throw mbedtls_digest_error("mbedtls_md_setup");
        if (mbedtls_md_starts(&ctx) < 0)
            throw mbedtls_digest_error("mbedtls_md_starts");
        initialized = true;
    }

    void update(const unsigned char *in, const size_t size)
    {
        check_initialized();
        if (mbedtls_md_update(&ctx, in, size) < 0)
            throw mbedtls_digest_error("mbedtls_md_update");
    }

    size_t final(unsigned char *out)
    {
        check_initialized();
        if (mbedtls_md_finish(&ctx, out) < 0)
            throw mbedtls_digest_error("mbedtls_md_finish");
        return size_();
    }

    size_t size() const
    {
        check_initialized();
        return size_();
    }

    bool is_initialized() const
    {
        return initialized;
    }

  private:
    static const mbedtls_md_info_t *digest_type(const CryptoAlgs::Type alg)
    {
        switch (alg)
        {
#if MBEDTLS_VERSION_NUMBER < 0x03000000
        case CryptoAlgs::MD4:
            return mbedtls_md_info_from_type(MBEDTLS_MD_MD4);
#endif
        case CryptoAlgs::MD5:
            return mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        case CryptoAlgs::SHA1:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        case CryptoAlgs::SHA224:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA224);
        case CryptoAlgs::SHA256:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        case CryptoAlgs::SHA384:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
        case CryptoAlgs::SHA512:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
        default:
            OPENVPN_THROW(mbedtls_digest_error, CryptoAlgs::name(alg) << ": not usable");
        }
    }

    void erase()
    {
        if (initialized)
        {
            mbedtls_md_free(&ctx);
            initialized = false;
        }
    }

    size_t size_() const
    {
        return mbedtls_md_get_size(mbedtls_md_info_from_ctx(&ctx));
    }

    void check_initialized() const
    {
#ifdef OPENVPN_ENABLE_ASSERT
        if (!initialized)
            throw mbedtls_digest_uninitialized();
#endif
    }

    bool initialized;
    mbedtls_md_context_t ctx;
};
} // namespace openvpn::MbedTLSCrypto

#endif
