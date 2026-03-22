//
// Created by Rene Windegger on 22/03/2026.
//

#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(fnv_1, single_block_test) {
        auto const actual = hash23::fnv_1::calculate("Hello, World!");
        constexpr std::size_t expected = 0x7b5ea4c513c14886uz;
        EXPECT_EQ(expected, actual);
    }
}