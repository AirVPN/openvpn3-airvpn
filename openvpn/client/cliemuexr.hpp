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

// Emulate Excluded Routes implementation (needed by Android)

#ifndef OPENVPN_CLIENT_CLIEMUEXR_H
#define OPENVPN_CLIENT_CLIEMUEXR_H

#include <openvpn/common/exception.hpp>
#include <openvpn/tun/client/emuexr.hpp>
#include <openvpn/addr/addrspacesplit.hpp>

namespace openvpn {
class EmulateExcludeRouteImpl : public EmulateExcludeRoute
{
  public:
    OPENVPN_EXCEPTION(emulate_exclude_route_error);

    typedef RCPtr<EmulateExcludeRouteImpl> Ptr;

    explicit EmulateExcludeRouteImpl(const bool exclude_server_address)
        : exclude_server_address_(exclude_server_address)
    {
    }

  private:
    void add_route(const bool add, const IP::Addr &addr, const int prefix_len) override
    {
        (add ? include : exclude).emplace_back(addr, prefix_len);
    }

    void add_default_routes(bool ipv4, bool ipv6) override
    {
        if (ipv4)
            add_route(true, IP::Addr::from_zero(IP::Addr::V4), 0);
        if (ipv6)
            add_route(true, IP::Addr::from_zero(IP::Addr::V6), 0);
    }

    bool enabled(const IPVerFlags &ipv) const override
    {
        return exclude.size() && (ipv.rgv4() || ipv.rgv6());
    }

    void emulate(TunBuilderBase *tb, IPVerFlags &ipv, const IP::Addr &server_addr) const override
    {
        const unsigned int ip_ver_flags = ipv.ip_ver_flags();
        IP::RouteList rl, tempExcludeList;
        rl.reserve(include.size() + exclude.size());
        rl.insert(rl.end(), include.begin(), include.end());
        rl.insert(rl.end(), exclude.begin(), exclude.end());

        // Check if we have to exclude the server, if yes we temporarily add it to the list
        // of excluded networks as small individual /32 or /128 network
        const IP::RouteList *excludedRoutes = &exclude;

        if (exclude_server_address_
            && (server_addr.version_mask() & ip_ver_flags)
            && !exclude.contains(IP::Route(server_addr, server_addr.size())))
        {
            rl.emplace_back(server_addr, server_addr.size());
            // Create a temporary list that includes all the routes + the server
            tempExcludeList = exclude;
            tempExcludeList.emplace_back(server_addr, server_addr.size());
            excludedRoutes = &tempExcludeList;
        }


        if (excludedRoutes->empty())
        {
            // Samsung's Android VPN API does different things if you have
            // 0.0.0.0/0 in the list of installed routes
            // (even if 0.0.0.0/1 and 128.0.0.0/1 and are present it behaves different)

            // We normally always split the address space, breaking a 0.0.0.0/0 into
            // smaller routes. If no routes are excluded, we install the original
            // routes without modifying them

            for (const auto &rt : include)
            {
                if (rt.version() & ip_ver_flags)
                {
                    if (!tb->tun_builder_add_route(rt.addr.to_string(), rt.prefix_len, -1, rt.addr.version() == IP::Addr::V6))
                        throw emulate_exclude_route_error("tun_builder_add_route failed");
                }
            }
            return;
        }

        // Complete address space (0.0.0.0/0 or ::/0) split into smaller networks
        // Figure out which parts of this non overlapping address we want to install
        for (const auto &r : IP::AddressSpaceSplitter(rl, ip_ver_flags))
        {
            if (check_route_should_be_installed(r, *excludedRoutes))
                if (!tb->tun_builder_add_route(r.addr.to_string(), r.prefix_len, -1, r.addr.version() == IP::Addr::V6))
                    throw emulate_exclude_route_error("tun_builder_add_route failed");
        }

        ipv.set_emulate_exclude_routes();
    }

    bool check_route_should_be_installed(const IP::Route &r, const IP::RouteList &excludedRoutes) const
    {
        // The whole address space was partioned into NON-overlapping routes that
        // we get one by one with the parameter r.
        // Therefore we already know that the whole route r either is included or
        // excluded IPs.
        // Figure out if this particular route should be installed or not

        IP::Route const *bestroute = nullptr;
        // Get the best (longest-prefix/smallest) route from included routes that completely
        // matches this route
        for (const auto &incRoute : include)
        {
            if (incRoute.contains(r))
            {
                if (!bestroute || bestroute->prefix_len < incRoute.prefix_len)
                    bestroute = &incRoute;
            }
        }

        // No positive route matches the route at all, do not install it
        if (!bestroute)
            return false;

        // Check if there is a more specific exclude route
        for (const auto &exclRoute : excludedRoutes)
        {
            if (exclRoute.contains(r) && exclRoute.prefix_len > bestroute->prefix_len)
                return false;
        }
        return true;
    }

    const bool exclude_server_address_;
    IP::RouteList include;
    IP::RouteList exclude;
};

class EmulateExcludeRouteFactoryImpl : public EmulateExcludeRouteFactory
{
  public:
    typedef RCPtr<EmulateExcludeRouteFactoryImpl> Ptr;

    EmulateExcludeRouteFactoryImpl(const bool exclude_server_address)
        : exclude_server_address_(exclude_server_address)
    {
    }

  private:
    EmulateExcludeRoute::Ptr new_obj() const override
    {
        return EmulateExcludeRoute::Ptr(new EmulateExcludeRouteImpl(exclude_server_address_));
    }

    const bool exclude_server_address_;
};
} // namespace openvpn

#endif
