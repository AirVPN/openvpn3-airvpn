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

#ifndef OPENVPN_CLIENT_OPTFILT_H
#define OPENVPN_CLIENT_OPTFILT_H

#include <vector>

#include <openvpn/common/options.hpp>
#include <openvpn/common/numeric_util.hpp>
#include <openvpn/client/dns.hpp>

// Options filters, consumes the route-nopull and pull-filter client options

namespace openvpn {

class PushedOptionsFilter : public OptionList::FilterBase
{
  public:
    PushedOptionsFilter(const OptionList &opt)
        : route_nopull_(opt.exists("route-nopull"))
    {
        if (!opt.exists("pull-filter"))
            return;

        for (auto i : opt.get_index("pull-filter"))
        {
            FilterAction action = None;
            auto &o = opt[i];
            o.exact_args(3);
            opt[i].touch();

            const auto &action_str = o.get(1, -1);
            if (action_str == "accept")
                action = Accept;
            else if (action_str == "ignore")
                action = Ignore;
            else if (action_str == "reject")
                action = Reject;
            else
                throw option_error(ERR_INVALID_OPTION_VAL, "invalid pull-filter action: " + action_str);

            Option match = OptionList::parse_option_from_line(o.get(2, -1), nullptr);
            pull_filter_list_.push_back({action, match});
        }
    }

    bool filter(const Option &opt) override
    {
        return filter_(opt) == Accept ? true : false;
    }

  private:
    enum FilterAction
    {
        None,
        Accept,
        Ignore,
        Reject
    };

    struct PullFilter
    {
        FilterAction action;
        Option match;
    };

    FilterAction filter_(const Option &opt)
    {
        static_filter_(opt);

        FilterAction action = pull_filter_(opt);
        if (action == None)
        {
            if (route_nopull_)
                action = route_nopull_filter_(opt);
            else
                action = Accept;
        }
        return action;
    }

    void static_filter_(const Option &o)
    {
        // Reject pushed DNS servers with priority < 0
        if (o.size() >= 3
            && o.ref(0) == "dns"
            && o.ref(1) == "server"
            && DnsOptionsParser::parse_priority(o.ref(2)) < 0)
        {
            throw option_error(ERR_INVALID_CONFIG, o.escape(false));
        }
    }

    // Return an action if a pull-filter directive matches the pushed option
    FilterAction pull_filter_(const Option &pushed)
    {
        for (const auto &pull_filter : pull_filter_list_)
        {
            if (!pull_filter_matches_(pushed, pull_filter.match))
                continue;

            if (pull_filter.action != Accept)
            {
                OPENVPN_LOG((pull_filter.action == Ignore ? "Ignored" : "Rejected")
                            << " due to pull-filter: "
                            << pushed.render(Option::RENDER_TRUNC_64 | Option::RENDER_BRACKET));
                if (pull_filter.action == Reject)
                    throw Option::RejectedException(pushed.escape(false));
            }
            return pull_filter.action;
        }
        return None;
    }

    bool pull_filter_matches_(const Option &pushed, const Option &match)
    {
        if (pushed.size() < match.size())
            return false;
        if (!is_safe_conversion<int>(match.size() - 1))
            return false;
        int i = static_cast<int>(match.size() - 1);
        if (!pushed.get(i, -1).starts_with(match.get(i, -1)))
            return false;

        while (--i >= 0)
        {
            if (pushed.get(i, -1) != match.get(i, -1))
                return false;
        }

        return true;
    }

    // return action if pushed option should be ignored due to route-nopull directive.
    FilterAction route_nopull_filter_(const Option &opt)
    {
        FilterAction action = Accept;
        if (opt.size() >= 1)
        {
            const std::string &directive = opt.ref(0);
            if (directive.length() >= 1)
            {
                switch (directive[0])
                {
                case 'b':
                    if (directive == "block-ipv6")
                    {
                        action = Ignore;
                    }
                    break;
                case 'c':
                    if (directive == "client-nat")
                    {
                        action = Ignore;
                    }
                    break;
                case 'd':
                    if (directive == "dhcp-option"
                        || directive == "dhcp-renew"
                        || directive == "dhcp-pre-release" || directive == "dhcp-release")
                    {
                        action = Ignore;
                    }
                    break;
                case 'i':
                    if (directive == "ip-win32")
                    {
                        action = Ignore;
                    }
                    break;
                case 'r':
                    if (directive == "route"
                        || directive == "route-ipv6"
                        || directive == "route-metric"
                        || directive == "redirect-gateway"
                        || directive == "redirect-private"
                        || directive == "register-dns"
                        || directive == "route-delay"
                        || directive == "route-method")
                    {
                        action = Ignore;
                    }
                    break;
                case 't':
                    if (directive == "tap-sleep")
                    {
                        action = Ignore;
                    }
                    break;
                }
                if (action == Ignore)
                {
                    OPENVPN_LOG("Ignored due to route-nopull: "
                                << opt.render(Option::RENDER_TRUNC_64 | Option::RENDER_BRACKET));
                }
            }
        }
        return action;
    }

    bool route_nopull_;
    std::vector<PullFilter> pull_filter_list_;
};

} // namespace openvpn

#endif
