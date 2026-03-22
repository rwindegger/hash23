//
// Created by Rene Windegger on 22/03/2026.
//

#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(crc32, single_block_test) {
        constexpr auto actual = hash23::crc32::calculate("Hello, World!");
        constexpr std::size_t expected = 0xEC4AC3D0;
        EXPECT_EQ(expected, actual);
    }

    TEST(crc32, string_test) {
        auto const actual = hash23::crc32::calculate(std::string{"Hello, World!"});
        constexpr std::size_t expected = 0xEC4AC3D0;
        EXPECT_EQ(expected, actual);
    }

    TEST(crc32, empty_input_test) {
        constexpr auto actual = hash23::crc32::calculate("");
        constexpr std::size_t expected = 0x00000000;
        EXPECT_EQ(expected, actual);
    }
}
