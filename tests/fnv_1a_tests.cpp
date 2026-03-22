//
// Created by Rene Windegger on 22/03/2026.
//

#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(fnv_1a, single_block_test) {
        auto const actual = hash23::fnv_1a::calculate("Hello, World!");
        constexpr std::size_t expected = 0x6ef05bd7cc857c54uz;
        EXPECT_EQ(expected, actual);
    }
}