//
// Created by Rene Windegger on 22/03/2026.
//

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(crc32, single_block_test) {
        constexpr auto actual = hash23::crc32::calculate("Hello, World!");
        constexpr std::uint32_t expected = 0xEC4AC3D0;
        EXPECT_EQ(expected, actual);
    }

    TEST(crc32, string_test) {
        auto const actual = hash23::crc32::calculate(std::string{"Hello, World!"});
        constexpr std::uint32_t expected = 0xEC4AC3D0;
        EXPECT_EQ(expected, actual);
    }

    TEST(crc32, empty_input_test) {
        constexpr auto actual = hash23::crc32::calculate("");
        constexpr std::uint32_t expected = 0x00000000;
        EXPECT_EQ(expected, actual);
    }

    TEST(crc32, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::crc32::calculate(data);
        constexpr std::uint32_t expected = 0x938C81CB;
        EXPECT_EQ(expected, actual);
    }

    TEST(crc32, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::crc32::calculate(data);
        constexpr std::uint32_t expected = 0x938C81CB;
        EXPECT_EQ(expected, actual);
    }
}
