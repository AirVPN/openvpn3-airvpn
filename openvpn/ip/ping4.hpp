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

#pragma once

#include <string>
#include <cstring>
#include <utility>

#include <openvpn/common/clamp_typerange.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ipv4.hpp>
#include <openvpn/ip/ipcommon.hpp>
#include <openvpn/ip/icmp4.hpp>
#include <openvpn/ip/csum.hpp>

using openvpn::numeric_util::clamp_to_typerange;

namespace openvpn::Ping4 {

inline void generate_echo_request(Buffer &buf,
                                  const IPv4::Addr &src,
                                  const IPv4::Addr &dest,
                                  const void *extra_data,
                                  const size_t extra_data_size,
                                  const uint16_t id,
                                  const uint16_t seq_num,
                                  const size_t total_size,
                                  std::string *log_info)
{
    const unsigned int data_size = std::max(int(extra_data_size), int(total_size) - int(sizeof(ICMPv4)));

    if (log_info)
        *log_info = "PING4 " + src.to_string() + " -> " + dest.to_string() + " id=" + std::to_string(id) + " seq_num=" + std::to_string(seq_num) + " data_size=" + std::to_string(data_size);

    const auto total_length = clamp_to_typerange<uint16_t>(sizeof(ICMPv4) + data_size);
    std::uint8_t *b = buf.write_alloc(total_length);
    ICMPv4 *icmp = (ICMPv4 *)b;

    // IP Header
    icmp->head.version_len = IPv4Header::ver_len(4, static_cast<int>(sizeof(IPv4Header)));
    icmp->head.tos = 0;
    icmp->head.tot_len = htons(total_length);
    icmp->head.id = 0;
    icmp->head.frag_off = 0;
    icmp->head.ttl = 64;
    icmp->head.protocol = IPCommon::ICMPv4;
    icmp->head.check = 0;
    icmp->head.saddr = src.to_uint32_net();
    icmp->head.daddr = dest.to_uint32_net();
    icmp->head.check = IPChecksum::checksum(b, sizeof(IPv4Header));

    // ICMP header
    icmp->type = ICMPv4::ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = ntohs(id);
    icmp->seq_num = ntohs(seq_num);

    // Data
    std::uint8_t *data = b + sizeof(ICMPv4);
    for (size_t i = 0; i < data_size; ++i)
        data[i] = (std::uint8_t)i;

    // Extra data
    std::memcpy(data, extra_data, extra_data_size);

    // ICMP checksum
    icmp->checksum = IPChecksum::checksum(b + sizeof(IPv4Header),
                                          sizeof(ICMPv4) - sizeof(IPv4Header) + data_size);

    // std::cout << dump_hex(buf);
}

// assumes that buf is a validated ECHO_REQUEST
inline void generate_echo_reply(Buffer &buf,
                                std::string *log_info)
{
    if (buf.size() < sizeof(ICMPv4))
    {
        if (log_info)
            *log_info = "Invalid ECHO4_REQUEST";
        return;
    }

    ICMPv4 *icmp = (ICMPv4 *)buf.c_data();
    std::swap(icmp->head.saddr, icmp->head.daddr);
    const std::uint16_t old_type_code = icmp->type_code;
    icmp->type = ICMPv4::ECHO_REPLY;
    icmp->checksum = IPChecksum::cfold(IPChecksum::diff2(old_type_code, icmp->type_code, IPChecksum::cunfold(icmp->checksum)));

    if (log_info)
        *log_info = "ECHO4_REPLY size=" + std::to_string(buf.size()) + ' ' + IPv4::Addr::from_uint32_net(icmp->head.saddr).to_string() + " -> " + IPv4::Addr::from_uint32_net(icmp->head.daddr).to_string();
}
} // namespace openvpn::Ping4