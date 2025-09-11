LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS := -lz 

ifeq ($(SSL_LIBRARY), mbedTLS)
    LOCAL_STATIC_LIBRARIES := liblzo_static liblz4_static libmbedtls_static
    LOCAL_CFLAGS := -funwind-tables -DHAVE_CONFIG_H -DTARGET_ABI=\"${TARGET_ABI}\" -DUSE_MBEDTLS=1 -DHAVE_LZO -DHAVE_LZ4 -DUSE_ASIO
    LOCAL_C_INCLUDES := lzo/include lz4/lib mbedtls mbedtls/include openvpn3-airvpn/client openvpn3-airvpn asio/asio/include
else ifeq ($(SSL_LIBRARY), openSSL)
    LOCAL_STATIC_LIBRARIES := liblzo_static liblz4_static libssl_static libcrypto_static
    LOCAL_CFLAGS := -Wno-deprecated-declarations -funwind-tables -DHAVE_CONFIG_H -DTARGET_ABI=\"${TARGET_ABI}\" -DUSE_OPENSSL=1 -DHAVE_LZO -DHAVE_LZ4 -DUSE_ASIO
    LOCAL_C_INCLUDES := lzo/include lz4/lib openssl openssl/include openssl/crypto openssl/crypto/include openvpn3-airvpn/client openvpn3-airvpn asio/asio/include
endif

LOCAL_CXXFLAGS += -std=c++20 -include openvpn/log/logbasesimple.hpp

LOCAL_CPP_FEATURES += exceptions rtti

LOCAL_LDFLAGS += "-Wl,-z,max-page-size=16384"
LOCAL_LDFLAGS += "-Wl,-z,common-page-size=16384"

LOCAL_MODULE := openvpn3

LOCAL_SRC_FILES := client/ovpncli.cpp openvpn/crypto/data_epoch.cpp

include $(BUILD_SHARED_LIBRARY)
