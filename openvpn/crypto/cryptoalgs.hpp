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

// Crypto algorithms

#ifndef OPENVPN_CRYPTO_CRYPTOALGS_H
#define OPENVPN_CRYPTO_CRYPTOALGS_H

#include <functional>
#include <string>
#include <list>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/likely.hpp>
#include <openvpn/common/arraysize.hpp>
#include <openvpn/crypto/definitions.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/error/excode.hpp>

namespace openvpn::CryptoAlgs {

    OPENVPN_EXCEPTION(crypto_alg);
    OPENVPN_SIMPLE_EXCEPTION(crypto_alg_index);

enum class KeyDerivation
{
      UNDEFINED,
      OPENVPN_PRF,
      TLS_EKM
    };

    inline const char* name(const KeyDerivation kd)
    {
      switch (kd)
	{
	  case KeyDerivation::UNDEFINED:
	    return "[PRF undefined]";
	  case KeyDerivation::OPENVPN_PRF:
	    return "OpenVPN PRF";
	  case KeyDerivation::TLS_EKM:
	    return "TLS Keying Material Exporter [RFC5705]";
	  default:
	    return "Unknown";
	}
    }

enum Type
{
      NONE=0,

      // CBC ciphers
      AES_128_CBC,
      AES_192_CBC,
      AES_256_CBC,
      DES_CBC,
      DES_EDE3_CBC,
      BF_CBC,

      // CTR ciphers
      AES_256_CTR,

      // AEAD ciphers
      AES_128_GCM,
      AES_192_GCM,
      AES_256_GCM,
      CHACHA20_POLY1305,

      // digests
      MD4,
      MD5,
      SHA1,
      SHA224,
      SHA256,
      SHA384,
      SHA512,

      SIZE,
    };

enum Mode
{
    MODE_UNDEF = 0,
    CBC_HMAC,
    AEAD,
};

enum AlgFlags
{
    F_CIPHER = (1 << 0),  // alg is a cipher
    F_DIGEST = (1 << 1),  // alg is a digest
    F_ALLOW_DC = (1 << 2) // alg may be used in OpenVPN data channel
};

    // size in bytes of AEAD "nonce tail" normally taken from
    // HMAC key material
enum
{
      AEAD_NONCE_TAIL_SIZE = 8
    };

class Alg
{
  public:
    constexpr Alg(const char *name,
                  const unsigned int flags,
                  const Mode mode,
                  const unsigned int size,
                  const unsigned int iv_length,
                  const unsigned int block_size,
                  uint64_t aead_usage_limit)

        : name_(name),
          flags_(flags),
          mode_(mode),
          size_(size),
          iv_length_(iv_length),
          block_size_(block_size),
          aead_usage_limit_(aead_usage_limit)
    {
    }

    const char *name() const
    {
        return name_;
    }
    unsigned int flags() const
    {
        return flags_;
    }
    Mode mode() const
    {
        return mode_;
    }
    size_t size() const
    {
        return size_;
    } // digest size
    size_t key_length() const
    {
        return size_;
    } // cipher key length
    size_t iv_length() const
    {
        return iv_length_;
    } // cipher only
    size_t block_size() const
    {
        return block_size_;
    } // cipher only
    bool dc_cipher() const
    {
        return (flags_ & F_CIPHER) && (flags_ & F_ALLOW_DC);
    }
    bool dc_digest() const
    {
        return (flags_ & F_DIGEST) && (flags_ & F_ALLOW_DC);
    }

    void allow_dc(bool allow)
    {
        if (allow)
            flags_ |= F_ALLOW_DC;
        else
            flags_ &= ~F_ALLOW_DC;
      }

    /** Returns the number q + s of total invocations + plain text blocks that should not be
     *  exceeded */
    uint64_t aead_usage_limit() const
    {
        return aead_usage_limit_;
    }

  private:
    const char *name_;
    unsigned int flags_;
    Mode mode_;
    unsigned int size_;
    unsigned int iv_length_;
    unsigned int block_size_;
    uint64_t aead_usage_limit_;
};

/** The limit for AES-GCM ciphers according to https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/ */
static constexpr uint64_t gcm_limit = (1ull << 36) - 1;

inline std::array<Alg, Type::SIZE> algs = {
    // clang-format off
    Alg{"none",               F_CIPHER|F_DIGEST, CBC_HMAC,   0,  0,  0, 0 },
    Alg{"AES-128-CBC",        F_CIPHER,          CBC_HMAC,  16, 16, 16, 0 },
    Alg{"AES-192-CBC",        F_CIPHER,          CBC_HMAC,  24, 16, 16, 0 },
    Alg{"AES-256-CBC",        F_CIPHER,          CBC_HMAC,  32, 16, 16, 0 },
    Alg{"DES-CBC",            F_CIPHER,          CBC_HMAC,    8,  8,  8, 0 },
    Alg{"DES-EDE3-CBC",       F_CIPHER,          CBC_HMAC,   24,  8,  8, 0 },
    Alg{"BF-CBC",             F_CIPHER,          CBC_HMAC,   16,  8,  8, 0 },
    Alg{"AES-256-CTR",        F_CIPHER,          MODE_UNDEF, 32, 16, 16, 0 },
    Alg{"AES-128-GCM",        F_CIPHER,          AEAD,       16, 12, 16, gcm_limit },
    Alg{"AES-192-GCM",        F_CIPHER,          AEAD,       24, 12, 16, gcm_limit },
    Alg{"AES-256-GCM",        F_CIPHER,          AEAD,       32, 12, 16, gcm_limit },
    Alg{"CHACHA20-POLY1305",  F_CIPHER,          AEAD,       32, 12, 16, 0 },
    Alg{"MD4",                F_DIGEST,          MODE_UNDEF, 16,  0,  0, 0 },
    Alg{"MD5",                F_DIGEST,          MODE_UNDEF, 16,  0,  0, 0 },
    Alg{"SHA1",               F_DIGEST,          MODE_UNDEF, 20,  0,  0, 0 },
    Alg{"SHA224",             F_DIGEST,          MODE_UNDEF, 28,  0,  0, 0 },
    Alg{"SHA256",             F_DIGEST,          MODE_UNDEF, 32,  0,  0, 0 },
    Alg{"SHA384",             F_DIGEST,          MODE_UNDEF, 48,  0,  0, 0 },
    Alg{"SHA512",             F_DIGEST,          MODE_UNDEF, 64,  0,  0, 0 }
    // clang-format on
    };

    inline bool defined(const Type type)
    {
      return type != NONE;
    }

    inline const Alg& get_index(const size_t i)
    {
      if (unlikely(i >= algs.size()))
	throw crypto_alg_index();
      return algs[i];
    }

    inline const Alg* get_ptr(const Type type)
    {
      const Alg& alg_ref = get_index(static_cast<size_t>(type));
      return &alg_ref;
    }

    inline const Alg& get(const Type type)
    {
      return get_index(static_cast<size_t>(type));
    }

    inline std::size_t for_each(std::function<bool (Type, const Alg&)> fn)
    {
      std::size_t count = 0;
      for (std::size_t i = 0; i < algs.size(); ++i)
	if (fn(static_cast<Type>(i), algs[i]))
	  count++;
      return count;
    }

    inline Type lookup(const std::string& name)
    {
      for (size_t i = 0; i < algs.size(); ++i)
	{
	  if (string::strcasecmp(name, algs[i].name()) == 0)
	    return static_cast<Type>(i);
	}
      OPENVPN_THROW(crypto_alg, name << ": not found");
    }

    inline const char *name(const Type type, const char *default_name = nullptr)
    {
      if (type == NONE && default_name)
	return default_name;
      else
	return get(type).name();
    }

    inline size_t size(const Type type)
    {
      const Alg& alg = get(type);
      return alg.size();
    }

    inline size_t key_length(const Type type)
    {
      const Alg& alg = get(type);
      return alg.key_length();
    }

    inline size_t iv_length(const Type type)
    {
      const Alg& alg = get(type);
      return alg.iv_length();
    }

    inline size_t block_size(const Type type)
    {
      const Alg& alg = get(type);
      return alg.block_size();
    }

    inline Mode mode(const Type type)
    {
      const Alg& alg = get(type);
      return alg.mode();
    }

    inline uint64_t aead_usage_limit(const Type type)
    {
        const Alg &alg = get(type);
        return alg.aead_usage_limit();
    }

    inline Type legal_dc_cipher(const Type type)
    {
      const Alg& alg = get(type);
      if(!alg.dc_cipher())
      {
          std::string msg;
          
          msg = alg.name();
          msg += ": bad cipher for data channel use";

          throw ErrorCode(Error::BAD_DC_CIPHER_ERROR, true, msg);
      }

      return type;
    }

    inline Type legal_dc_digest(const Type type)
    {
      const Alg& alg = get(type);
      if(!alg.dc_digest())
      {
          std::string msg;
          
          msg = alg.name();
          msg += ": bad digest for data channel use";

          throw ErrorCode(Error::BAD_DC_DIGEST_ERROR, true, msg);
      }

      return type;
    }

    inline Type dc_cbc_cipher(const Type type)
    {
      const Alg& alg = get(type);
      if(!(alg.flags() & CBC_HMAC))
      {
          std::string msg;
          
          msg = alg.name();
          msg += ": bad cipher for data channel use";

          throw ErrorCode(Error::BAD_DC_CIPHER_ERROR, true, msg);
      }

      return type;
    }

    inline Type dc_cbc_hash(const Type type)
    {
      const Alg& alg = get(type);
      if(!(alg.flags() & F_DIGEST))
      {
          std::string msg;
          
          msg = alg.name();
          msg += ": bad digest for data channel use";

          throw ErrorCode(Error::BAD_DC_DIGEST_ERROR, true, msg);
      }

      return type;
    }

    inline void allow_dc_algs(const std::list<Type> types)
    {
        for (auto &alg : algs)
            alg.allow_dc(false);
        for (auto &type : types)
            algs.at(type).allow_dc(true);
    }

	/**
	 * Allows the default algorithms but only those which are available with
	 * the library context.
	 * @param libctx 		Library context to use
	 * @param preferred 	Allow only the preferred algorithms, also disabling
	 * 						legacy (only AEAD)
	 * @param legacy	Allow also legacy algorithm that are vulnerable to SWEET32
	 * 			no effect if preferred is true
	 */
  	template  <typename CRYPTO_API>
    inline void allow_default_dc_algs(SSLLib::Ctx libctx, bool preferred=false, bool legacy=false)
    {
	  /* Disable all and reenable the ones actually allowed later */
	  for (auto& alg : algs)
		alg.allow_dc(false);

    CryptoAlgs::for_each([preferred, libctx, legacy](CryptoAlgs::Type type, const CryptoAlgs::Alg &alg) -> bool
                         {
		/* Defined in the algorithm but not actually related to data channel */
		if (type == MD4 || type == AES_256_CTR)
		  return false;

		if (preferred && alg.mode() != AEAD)
		  return false;

		if (alg.mode() == AEAD && !CRYPTO_API::CipherContextAEAD::is_supported(libctx, type))
		  return false;

		/* 64 bit block ciphers vulnerable to SWEET32 */
		if (alg.flags() & F_CIPHER && !legacy && alg.block_size() <= 8)
		  return false;

		/* This excludes MD4 */
		if (alg.flags() & F_DIGEST && !legacy && alg.size() < 20)
		  return false;

		if ((alg.flags() & F_CIPHER && alg.mode() != AEAD && type != NONE)
			&& !CRYPTO_API::CipherContext::is_supported(libctx, type))
		  return false;

		/* This algorithm has passed all checks, enable it for DC */
		algs.at(type).allow_dc(true);
		return true; });
    }

    /**
     *  Check if a specific algorithm depends on an additional digest or not
     *
     * @param type CryptoAlgs::Type to check
     *
     * @return Returns true if the queried algorithm depends on a digest,
     *         otherwise false.
     */
    inline bool use_cipher_digest(const Type type)
    {
        const Alg &alg = get(type);
        return alg.mode() != AEAD;
    }
} // namespace openvpn::CryptoAlgs

#endif
