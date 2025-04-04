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

#ifndef OPENVPN_COMMON_STAT_H
#define OPENVPN_COMMON_STAT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdint> // for std::uint64_t

namespace openvpn {

// Return true if dirname is a directory
inline bool is_directory(const std::string &pathname, const bool follow_symlinks = false)
{
    if (pathname.empty())
        return false;
    struct stat sb;
    if (follow_symlinks)
        return ::stat(pathname.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode);
    else
        return ::lstat(pathname.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode);
}

// Return file modification time (in seconds since unix epoch) or 0 on error
inline time_t file_mod_time(const std::string &filename)
{
    struct stat buffer;
    if (::stat(filename.c_str(), &buffer) != 0)
        return 0;
    else
        return buffer.st_mtime;
}

// Return file modification time from a struct stat
inline std::uint64_t stat_mod_time_nanoseconds(const struct stat &s)
{
    typedef std::uint64_t T;
#if defined(__APPLE__)
    return T(s.st_mtimespec.tv_sec) * T(1000000000) + T(s.st_mtimespec.tv_nsec);
#else
    return T(s.st_mtim.tv_sec) * T(1000000000) + T(s.st_mtim.tv_nsec);
#endif
}

// Return file modification time from a file path (in nanoseconds since unix epoch) or 0 on error
inline std::uint64_t file_mod_time_nanoseconds(const char *filename)
{
    struct stat s;
    if (::stat(filename, &s) == 0)
        return stat_mod_time_nanoseconds(s);
    else
        return 0;
}

// Return file modification time from a file path (in nanoseconds since unix epoch) or 0 on error
inline std::uint64_t file_mod_time_nanoseconds(const std::string &filename)
{
    return file_mod_time_nanoseconds(filename.c_str());
}

// Return file modification time from a file descriptor (in nanoseconds since unix epoch) or 0 on error
inline std::uint64_t fd_mod_time_nanoseconds(const int fd)
{
    struct stat s;
    if (::fstat(fd, &s) == 0)
        return stat_mod_time_nanoseconds(s);
    else
        return 0;
}

// Return file modification time (in milliseconds since unix epoch) or 0 on error
inline std::uint64_t file_mod_time_milliseconds(const std::string &filename)
{
    return file_mod_time_nanoseconds(filename) / std::uint64_t(1000000);
}

} // namespace openvpn

#endif
