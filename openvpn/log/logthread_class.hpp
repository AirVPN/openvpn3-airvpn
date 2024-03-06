//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2024 OpenVPN Inc.
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

#pragma once

// Define this parameter before including this header:
// OPENVPN_LOG_CLASS -- client class that exposes a log() method
#ifndef OPENVPN_LOG_CLASS
#error OPENVPN_LOG_CLASS must be defined
#endif

namespace openvpn {
namespace Log {

#ifdef OPENVPN_LOG_GLOBAL
// OPENVPN_LOG uses global object pointer
inline OPENVPN_LOG_CLASS *global_log = nullptr; // GLOBAL
#else
// OPENVPN_LOG uses thread-local object pointer
inline thread_local OPENVPN_LOG_CLASS *global_log = nullptr; // GLOBAL
#endif

/**
 * @brief Scoped RAII for the \c global_log \a pointer
 *
 * While in scope, \c global_log points to the instance of the class defined by
 * the \c OPENVPN_LOG_CLASS macro above.  When it goes out of scope, the
 * \c global_log pointer is reset to \c nullptr
 */
struct Context
{
    /**
     * @brief Argument to construct a \c Context in a different thread
     *
     * The new \c Context will have the same \c global_log pointer as the current
     * \c Context.  Intended for the thread_local version of \c global_log
     */
    class Wrapper
    {
#ifndef OPENVPN_LOG_GLOBAL
      public:
        Wrapper()
            : log(obj())
        {
        }

      private:
        friend struct Context;
        OPENVPN_LOG_CLASS *log;
#endif
    };

    /**
     * @brief construct a \c Context in a different thread
     *
     * @param wrap holds the value of \c global_log from the sourcing thread
     */
    Context(const Wrapper &wrap)
    {
#ifndef OPENVPN_LOG_GLOBAL
        global_log = wrap.log;
#endif
    }

    /**
     * @brief construct a \c Context setting the \c global_log pointer
     *
     * @param cli pointer to \c OPENVPN_LOG_CLASS instance
     */
    Context(OPENVPN_LOG_CLASS *cli)
    {
        global_log = cli;
    }

    ~Context()
    {
        global_log = nullptr;
    }

    static bool defined()
    {
        return global_log != nullptr;
    }

    static OPENVPN_LOG_CLASS *obj()
    {
        return global_log;
    }
};
} // namespace Log
} // namespace openvpn
