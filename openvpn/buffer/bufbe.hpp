//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2026- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// Bounds-checked big-endian (network byte order) integer read/write on a Buffer,
// built on the platform-independent htonl/htons from socktypes.hpp. 64-bit values
// are handled as two 32-bit halves, mirroring htonll().

#pragma once

#include <cstdint>

#include <openvpn/common/socktypes.hpp> // for ntohl/htonl/ntohs/htons
#include <openvpn/buffer/buffer.hpp>

namespace openvpn::BufferBE {

//! Append a big-endian uint16 to @p buf; false if there is no room.
inline bool write_u16(Buffer &buf, std::uint16_t v)
{
    if (buf.remaining() < sizeof(v))
        return false;
    const std::uint16_t net = htons(v);
    buf.write(&net, sizeof(net));
    return true;
}

//! Append a big-endian uint32 to @p buf; false if there is no room.
inline bool write_u32(Buffer &buf, std::uint32_t v)
{
    if (buf.remaining() < sizeof(v))
        return false;
    const std::uint32_t net = htonl(v);
    buf.write(&net, sizeof(net));
    return true;
}

//! Append a big-endian uint64 to @p buf; false if there is no room.
inline bool write_u64(Buffer &buf, std::uint64_t v)
{
    return write_u32(buf, static_cast<std::uint32_t>(v >> 32))
           && write_u32(buf, static_cast<std::uint32_t>(v & 0xffffffff));
}

//! Read a big-endian uint16 from @p buf into @p out; false if fewer than 2 bytes.
inline bool read_u16(Buffer &buf, std::uint16_t &out)
{
    if (buf.size() < sizeof(out))
        return false;
    std::uint16_t net;
    buf.read(&net, sizeof(net));
    out = ntohs(net);
    return true;
}

//! Read a big-endian uint32 from @p buf into @p out; false if fewer than 4 bytes.
inline bool read_u32(Buffer &buf, std::uint32_t &out)
{
    if (buf.size() < sizeof(out))
        return false;
    std::uint32_t net;
    buf.read(&net, sizeof(net));
    out = ntohl(net);
    return true;
}

//! Read a big-endian uint64 from @p buf into @p out; false if fewer than 8 bytes.
inline bool read_u64(Buffer &buf, std::uint64_t &out)
{
    std::uint32_t hi, lo;
    if (!read_u32(buf, hi) || !read_u32(buf, lo))
        return false;
    out = (static_cast<std::uint64_t>(hi) << 32) | lo;
    return true;
}

} // namespace openvpn::BufferBE
