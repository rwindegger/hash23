//
// Created by Rene Windegger on 22/03/2026.
//

#include <gtest/gtest.h>
#include <hash23/hash23.h>
#include <string>

namespace {
    TEST(fnv_1a, single_block_test) {
        constexpr auto actual = hash23::fnv_1a::calculate("Hello, World!");
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x5aecf734uz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0x6ef05bd7cc857c54uz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1a, string_test) {
        constexpr auto actual = hash23::fnv_1a::calculate(std::string{"Hello, World!"});
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x5aecf734uz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0x6ef05bd7cc857c54uz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1a, empty_input_test) {
        constexpr auto actual = hash23::fnv_1a::calculate("");
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x811c9dc5uz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0xcbf29ce484222325uz;
            EXPECT_EQ(expected, actual);
        }
    }
}