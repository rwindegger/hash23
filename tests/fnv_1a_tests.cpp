//
// Created by Rene Windegger on 22/03/2026.
//

#include <cstddef>
#include <string>
#include <vector>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

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
        auto const actual = hash23::fnv_1a::calculate(std::string{"Hello, World!"});
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

    TEST(fnv_1a, high_byte_values_test) {
        std::vector<signed char> const data = {
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        auto const actual = hash23::fnv_1a::calculate(data);
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x9036aaacuz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0x6b576bf0e27fc9acuz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1a, std_byte_test) {
        std::vector<std::byte> const data = {
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        auto const actual = hash23::fnv_1a::calculate(data);
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x9036aaacuz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0x6b576bf0e27fc9acuz;
            EXPECT_EQ(expected, actual);
        }
    }
}