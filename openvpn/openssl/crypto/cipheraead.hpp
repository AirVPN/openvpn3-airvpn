//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2020 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Wrap the OpenSSL AEAD API.

#ifndef OPENVPN_OPENSSL_CRYPTO_CIPHERAEAD_H
#define OPENVPN_OPENSSL_CRYPTO_CIPHERAEAD_H

#include <string>

#include <openssl/objects.h>
#include <openssl/evp.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/likely.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn
{
    namespace OpenSSLCrypto
    {
        class CipherContextAEAD
        {
            CipherContextAEAD(const CipherContextAEAD&) = delete;
            CipherContextAEAD& operator=(const CipherContextAEAD&) = delete;

            private:

            bool initialized;
            int set_tag, get_tag;
            EVP_CIPHER_CTX *ctx = nullptr;
            CryptoAlgs::Type crypto_alg;

            public:
      
            OPENVPN_EXCEPTION(openssl_aead_error);

            // mode parameter for constructor
            
            enum
            {
                MODE_UNDEF = -1,
                ENCRYPT = 1,
                DECRYPT = 0
            };

            // OpenSSL cipher constants
            
            enum
            {
                IV_LEN = 12,
                AUTH_TAG_LEN = 16,
                SUPPORTS_IN_PLACE_ENCRYPT = 0,
            };

            CipherContextAEAD()	: initialized(false)
            {
            }

            ~CipherContextAEAD()
            {
                free_cipher_context();
            }

            void init(const CryptoAlgs::Type alg, const unsigned char *key, const unsigned int keysize, const int mode)
            {
                free_cipher_context();
	
                unsigned int ckeysz = 0;
	
                const EVP_CIPHER *ciph = cipher_type(alg, ckeysz);

                if(ciph == nullptr)
                    OPENVPN_THROW(openssl_aead_error, CryptoAlgs::name(alg) << ": not usable");

                crypto_alg = alg;

                if (ckeysz > keysize)
                    throw openssl_aead_error("insufficient key material");
	
                ctx = EVP_CIPHER_CTX_new();
	
                EVP_CIPHER_CTX_reset(ctx);
	
                switch(mode)
                {
                    case ENCRYPT:
                    {
                        if(!EVP_EncryptInit_ex(ctx, ciph, nullptr, key, nullptr))
                        {
                            openssl_clear_error_stack();

                            free_cipher_context();

                            throw openssl_aead_error("EVP_EncryptInit_ex (init)");
                        }
                    }
                    break;
	  
                    case DECRYPT:
                    {
                        if(!EVP_DecryptInit_ex(ctx, ciph, nullptr, key, nullptr))
                        {
                            openssl_clear_error_stack();
                            
                            free_cipher_context();
                            
                            throw openssl_aead_error("EVP_DecryptInit_ex (init)");
                        }
                    }
                    break;
                    
                    default:
                    {
                        throw openssl_aead_error("bad mode");
                    }
                    break;
                }
	
                switch(crypto_alg)
                {
                    case CryptoAlgs::AES_128_GCM:
                    case CryptoAlgs::AES_192_GCM:
                    case CryptoAlgs::AES_256_GCM:
                    {
                        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1)
                        {
                            openssl_clear_error_stack();
                            
                            free_cipher_context();
                            
                            throw openssl_aead_error("EVP_CIPHER_CTX_ctrl set GCM IV len");
                        }
                        
                        set_tag = EVP_CTRL_GCM_SET_TAG;
                        get_tag = EVP_CTRL_GCM_GET_TAG;
                    }
                    break;

                    case CryptoAlgs::CHACHA20_POLY1305:
                    {
                        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, nullptr) != 1)
                        {
                            openssl_clear_error_stack();

                            throw openssl_aead_error("EVP_CIPHER_CTX_ctrl set CHACHA20 IV len");
                        }
                        
                        set_tag = EVP_CTRL_AEAD_SET_TAG;
                        get_tag = EVP_CTRL_AEAD_GET_TAG;
                    }
                    break;
                    
                    default:
                    {
                    }
                    break;
                }

                initialized = true;
            }

            void encrypt(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *iv, unsigned char *tag, const unsigned char *ad, size_t ad_len)
            {
                int len;
                int ciphertext_len;

                check_initialized();
	
                if(!EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, iv))
                {
                    openssl_clear_error_stack();
	    
                    throw openssl_aead_error("EVP_EncryptInit_ex (reset)");
                }
	
                if(!EVP_EncryptUpdate(ctx, nullptr, &len, ad, int(ad_len)))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_EncryptUpdate AD");
                }
	
                if(!EVP_EncryptUpdate(ctx, output, &len, input, int(length)))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_EncryptUpdate data");
                }
	
                ciphertext_len = len;
	
                if(!EVP_EncryptFinal_ex(ctx, output+len, &len))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_EncryptFinal_ex");
                }
	
                ciphertext_len += len;
	
                if((size_t)ciphertext_len != length)
                {
                    throw openssl_aead_error("encrypt size inconsistency");
                }

                if(!EVP_CIPHER_CTX_ctrl(ctx, get_tag, AUTH_TAG_LEN, tag))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_CIPHER_CTX_ctrl get tag");
                }
            }

            bool decrypt(const unsigned char *input, unsigned char *output, size_t length, const unsigned char *iv, unsigned char *tag, const unsigned char *ad, size_t ad_len)
            {
                int len;
                int plaintext_len;

                check_initialized();
	
                if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, iv))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_DecryptInit_ex (reset)");
                }
	
                if(!EVP_DecryptUpdate(ctx, nullptr, &len, ad, int(ad_len)))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_DecryptUpdate AD");
                }

                if(!EVP_DecryptUpdate(ctx, output, &len, input, int(length)))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_DecryptUpdate data");
                }
	
                plaintext_len = len;
	
                if(!EVP_CIPHER_CTX_ctrl(ctx, set_tag, AUTH_TAG_LEN, tag))
                {
                    openssl_clear_error_stack();

                    throw openssl_aead_error("EVP_CIPHER_CTX_ctrl set tag");
                }

                if(!EVP_DecryptFinal_ex(ctx, output+len, &len))
                {
                    openssl_clear_error_stack();

                    return false;
                }
	
                plaintext_len += len;
	
                if(static_cast<size_t>(plaintext_len) != length)
                {
                    throw openssl_aead_error("decrypt size inconsistency");
                }
	
                return true;
            }

            bool is_initialized() const
            {
                return ctx != nullptr;
            }
 
            static bool is_supported(const CryptoAlgs::Type alg)
            {
                unsigned int keysize;
	
                return(cipher_type(alg, keysize) != nullptr);
            }

            private:
      
            static const EVP_CIPHER *cipher_type(const CryptoAlgs::Type alg, unsigned int& keysize)
            {
                switch(alg)
                {
                    case CryptoAlgs::AES_128_GCM:
                    {
                        keysize = 16;
                        
                        return EVP_aes_128_gcm();
                    }
                    break;

                    case CryptoAlgs::AES_192_GCM:
                    {
                        keysize = 24;
	    
                        return EVP_aes_192_gcm();
                    }
                    break;

                    case CryptoAlgs::AES_256_GCM:
                    {
                        keysize = 32;
	    
                        return EVP_aes_256_gcm();
                    }
                    break;

                    case CryptoAlgs::CHACHA20_POLY1305:
                    {
                        keysize = 32;
	    
                        return EVP_chacha20_poly1305();
                    }
                    break;

                    default:
                    {
                        OPENVPN_THROW(openssl_aead_error, CryptoAlgs::name(alg) << ": not usable");
                    }
                    break;
                }
            }

            void free_cipher_context()
            {
                EVP_CIPHER_CTX_free(ctx);

                initialized = false;
            }

            void check_initialized() const
            {
#ifdef OPENVPN_ENABLE_ASSERT
                if(!ctx)
                    throw openssl_aead_error("uninitialized");
#endif
            }
        };
    }
}

#endif
