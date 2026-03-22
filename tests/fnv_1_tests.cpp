//
// Created by Rene Windegger on 22/03/2026.
//

#include <gtest/gtest.h>
#include <hash23/hash23.h>
#include <cstddef>
#include <string>
#include <vector>

namespace {
    TEST(fnv_1, single_block_test) {
        constexpr auto actual = hash23::fnv_1::calculate("Hello, World!");
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x4291a886uz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0x7b5ea4c513c14886uz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1, string_test) {
        constexpr auto actual = hash23::fnv_1::calculate(std::string{"Hello, World!"});
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x4291a886uz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0x7b5ea4c513c14886uz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1, empty_input_test) {
        constexpr auto actual = hash23::fnv_1::calculate("");
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x811c9dc5uz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0xcbf29ce484222325uz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1, high_byte_values_test) {
        std::vector<signed char> const data = {
            static_cast<signed char>(0x80), static_cast<signed char>(0xAB),
            static_cast<signed char>(0xFF), 0x00, 0x7F
        };
        auto const actual = hash23::fnv_1::calculate(data);
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x4430384auz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0xeaadd0afbf431feauz;
            EXPECT_EQ(expected, actual);
        }
    }

    TEST(fnv_1, std_byte_test) {
        std::vector<std::byte> const data = {
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        auto const actual = hash23::fnv_1::calculate(data);
        if constexpr (sizeof(std::size_t) == 4) {
            constexpr std::size_t expected = 0x4430384auz;
            EXPECT_EQ(expected, actual);
        } else {
            constexpr std::size_t expected = 0xeaadd0afbf431feauz;
            EXPECT_EQ(expected, actual);
        }
    }
}