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

#ifndef OPENVPN_TRANSPORT_ALTPROXY_H
#define OPENVPN_TRANSPORT_ALTPROXY_H

#include <string>

#include <openvpn/common/rc.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/client/remotelist.hpp>
#include <openvpn/crypto/digestapi.hpp>

namespace openvpn {
struct AltProxy : public RC<thread_unsafe_refcount>
{
    struct Config
    {
        Config()
            : free_list_max_size(8),
              socket_protect(nullptr)
        {
        }

        RemoteList::Ptr remote_list;
        size_t free_list_max_size;
        Frame::Ptr frame;
        SessionStats::Ptr stats;

        StrongRandomAPI::Ptr rng;
        DigestFactory::Ptr digest_factory;

        SocketProtect *socket_protect;
    };

    typedef RCPtr<AltProxy> Ptr;

    // return proxy name
    virtual std::string name() const = 0;

    // called to indicate whether or not remote_list should be cached
    virtual void set_enable_cache(const bool enable_cache) = 0;

    // return a RemoteList::Ptr (optional) to precache it
    virtual void precache(RemoteList::Ptr &r) = 0;

    // iterate to next host in proxy-specific remote_list, return true
    // to prevent next() from being called on global remote_list
    virtual bool next() = 0;

    // return true if this proxy method only supports TCP transport
    virtual bool requires_tcp() const = 0;

    // return a new TransportClientFactory for this proxy
    virtual TransportClientFactory::Ptr new_transport_client_factory(const Config &) = 0;
};
} // namespace openvpn

#endif
