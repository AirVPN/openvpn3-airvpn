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

// Environmental variables

#ifndef OPENVPN_COMMON_ENVIRON_H
#define OPENVPN_COMMON_ENVIRON_H

#include <string>
#include <cstring>
#include <vector>
#include <utility>

#include <openvpn/common/size.hpp>

extern char **environ;

namespace openvpn {

class Environ : public std::vector<std::string>
{
  public:
    static std::string find_static(const std::string &name)
    {
        for (char **e = ::environ; *e != NULL; ++e)
        {
            const char *eq = ::strchr(*e, '=');
            if (eq && eq > *e)
            {
                const size_t namelen = eq - *e;
                if (name.length() == namelen && ::strncmp(name.c_str(), *e, namelen) == 0)
                    return std::string(eq + 1);
            }
        }
        return "";
    }

    void load_from_environ()
    {
        reserve(64);
        for (char **e = ::environ; *e != NULL; ++e)
            emplace_back(*e);
    }

    std::string to_string() const
    {
        std::string ret;
        ret.reserve(512);
        for (const auto &s : *this)
        {
            ret += s;
            ret += '\n';
        }
        return ret;
    }

    int find_index(const std::string &name) const
    {
        for (size_type i = 0; i < size(); ++i)
        {
            const std::string &s = (*this)[i];
            const size_t pos = s.find_first_of('=');
            if (pos != std::string::npos)
            {
                if (name == s.substr(0, pos))
                    return static_cast<int>(i); // TODO: [OVPN3-928] Evaluate the safety of casting this down
            }
            else
            {
                if (name == s)
                    return static_cast<int>(i); // Same as above
            }
        }
        return -1;
    }

    std::string find(const std::string &name) const
    {
        const int i = find_index(name);
        if (i >= 0)
            return value(i);
        else
            return "";
    }

    std::string value(const size_t idx) const
    {
        const std::string &s = (*this)[idx];
        const size_t pos = s.find_first_of('=');
        if (pos != std::string::npos)
            return s.substr(pos + 1);
        else
            return "";
    }

    void assign(const std::string &name, const std::string &value)
    {
        std::string nv = name + '=' + value;
        const int i = find_index(name);
        if (i >= 0)
            (*this)[i] = std::move(nv);
        else
            push_back(std::move(nv));
    }
};

} // namespace openvpn
#endif
