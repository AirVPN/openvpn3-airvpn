#include "test_common.hpp"

#include <openvpn/common/string.hpp>
#include <openvpn/common/process.hpp>

using namespace openvpn;

TEST(Misc, Pipe)
{
    RedirectPipe::InOut io;

    {
        Argv argv;
        io.in = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n";
        argv.emplace_back("sort");
        argv.emplace_back("-u");
        // OPENVPN_LOG(argv.to_string());
        const int status = system_cmd("/usr/bin/sort", argv, nullptr, io, 0, nullptr);

        EXPECT_EQ(0, status);
        EXPECT_EQ("", io.err);

        const std::string expected = "eight\nfive\nfour\nnine\none\nseven\nsix\nten\nthree\ntwo\n";
        EXPECT_EQ(io.out, expected);
    }
}
