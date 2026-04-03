//
// Created by Rene Windegger on 02/04/2026.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha3_256, empty_input_test) {
        auto const actual = hash23::sha3_256::calculate("");
        constexpr std::array expected = {
            static_cast<std::byte>(0xa7), static_cast<std::byte>(0xff), static_cast<std::byte>(0xc6),
            static_cast<std::byte>(0xf8), static_cast<std::byte>(0xbf), static_cast<std::byte>(0x1e),
            static_cast<std::byte>(0xd7), static_cast<std::byte>(0x66), static_cast<std::byte>(0x51),
            static_cast<std::byte>(0xc1), static_cast<std::byte>(0x47), static_cast<std::byte>(0x56),
            static_cast<std::byte>(0xa0), static_cast<std::byte>(0x61), static_cast<std::byte>(0xd6),
            static_cast<std::byte>(0x62), static_cast<std::byte>(0xf5), static_cast<std::byte>(0x80),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0x4d), static_cast<std::byte>(0xe4),
            static_cast<std::byte>(0x3b), static_cast<std::byte>(0x49), static_cast<std::byte>(0xfa),
            static_cast<std::byte>(0x82), static_cast<std::byte>(0xd8), static_cast<std::byte>(0x0a),
            static_cast<std::byte>(0x4b), static_cast<std::byte>(0x80), static_cast<std::byte>(0xf8),
            static_cast<std::byte>(0x43), static_cast<std::byte>(0x4a),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, single_block_test) {
        auto const actual = hash23::sha3_256::calculate("Hello, World!");
        constexpr std::array expected = {
            static_cast<std::byte>(0x1a), static_cast<std::byte>(0xf1), static_cast<std::byte>(0x7a),
            static_cast<std::byte>(0x66), static_cast<std::byte>(0x4e), static_cast<std::byte>(0x3f),
            static_cast<std::byte>(0xa8), static_cast<std::byte>(0xe4), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0xba), static_cast<std::byte>(0x05),
            static_cast<std::byte>(0xc2), static_cast<std::byte>(0xa1), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0x16), static_cast<std::byte>(0x9d), static_cast<std::byte>(0xf7),
            static_cast<std::byte>(0x61), static_cast<std::byte>(0x62), static_cast<std::byte>(0xa5),
            static_cast<std::byte>(0xa2), static_cast<std::byte>(0x86), static_cast<std::byte>(0xe0),
            static_cast<std::byte>(0xc4), static_cast<std::byte>(0x05), static_cast<std::byte>(0xb4),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0xd4), static_cast<std::byte>(0x78),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0xef),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, single_block_string_test) {
        auto const actual = hash23::sha3_256::calculate(std::string{"Hello, World!"});
        constexpr std::array expected = {
            static_cast<std::byte>(0x1a), static_cast<std::byte>(0xf1), static_cast<std::byte>(0x7a),
            static_cast<std::byte>(0x66), static_cast<std::byte>(0x4e), static_cast<std::byte>(0x3f),
            static_cast<std::byte>(0xa8), static_cast<std::byte>(0xe4), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0xba), static_cast<std::byte>(0x05),
            static_cast<std::byte>(0xc2), static_cast<std::byte>(0xa1), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0x16), static_cast<std::byte>(0x9d), static_cast<std::byte>(0xf7),
            static_cast<std::byte>(0x61), static_cast<std::byte>(0x62), static_cast<std::byte>(0xa5),
            static_cast<std::byte>(0xa2), static_cast<std::byte>(0x86), static_cast<std::byte>(0xe0),
            static_cast<std::byte>(0xc4), static_cast<std::byte>(0x05), static_cast<std::byte>(0xb4),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0xd4), static_cast<std::byte>(0x78),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0xef),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, multiple_blocks_test) {
        auto const actual = hash23::sha3_256::calculate(
            R"(Hello, World!
It's a beautiful day to calculate some hashes!
It should be a very long string just to make sure the block size does not interfere with large datasets.
Just to make sure we are longer than one block just add more text.
After some time typing text gets boring.
This should now be enough text to not fit into one single block of data.
Actually we need to fill at least 2 blocks of data to see if it's really working as expected.
Filling two blocks of 256 bytes with data should result in a valid hash.
If not I know where to look.)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xb5), static_cast<std::byte>(0x7a), static_cast<std::byte>(0x70),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0xcc), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0x87), static_cast<std::byte>(0x78), static_cast<std::byte>(0x41),
            static_cast<std::byte>(0x92), static_cast<std::byte>(0x8a), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0x55), static_cast<std::byte>(0x44), static_cast<std::byte>(0xd7),
            static_cast<std::byte>(0xea), static_cast<std::byte>(0x19), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0xdc), static_cast<std::byte>(0xa9),
            static_cast<std::byte>(0xa8), static_cast<std::byte>(0x67), static_cast<std::byte>(0x3e),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0xa9), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0x87), static_cast<std::byte>(0xae),
            static_cast<std::byte>(0x94), static_cast<std::byte>(0x1a),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, payload_size_exactly_1080_bit_test) {
        auto const actual = hash23::sha3_256::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 135 bytes so we need to add some additional data.
Some more data to fill t)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xcf), static_cast<std::byte>(0x07), static_cast<std::byte>(0x62),
            static_cast<std::byte>(0x61), static_cast<std::byte>(0xf3), static_cast<std::byte>(0x9b),
            static_cast<std::byte>(0xe9), static_cast<std::byte>(0x2b), static_cast<std::byte>(0x03),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x7b), static_cast<std::byte>(0x3b),
            static_cast<std::byte>(0x32), static_cast<std::byte>(0x77), static_cast<std::byte>(0x91),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0x64), static_cast<std::byte>(0x26),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x4b), static_cast<std::byte>(0xfb),
            static_cast<std::byte>(0x87), static_cast<std::byte>(0xe9), static_cast<std::byte>(0xb9),
            static_cast<std::byte>(0x62), static_cast<std::byte>(0xc6), static_cast<std::byte>(0x1b),
            static_cast<std::byte>(0x73), static_cast<std::byte>(0x83), static_cast<std::byte>(0x10),
            static_cast<std::byte>(0x21), static_cast<std::byte>(0x05),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, payload_size_exactly_1088_bit_test) {
        auto const actual = hash23::sha3_256::calculate(R"(Hello, World!
This is a text that will hit the sweet spot of 136 bytes so we need to add some additional data.
Some more data to fill th)");
        constexpr std::array expected = {
            static_cast<std::byte>(0xb9), static_cast<std::byte>(0x09), static_cast<std::byte>(0x80),
            static_cast<std::byte>(0xb6), static_cast<std::byte>(0x0b), static_cast<std::byte>(0x28),
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x62), static_cast<std::byte>(0xc7),
            static_cast<std::byte>(0x1d), static_cast<std::byte>(0x08), static_cast<std::byte>(0x9b),
            static_cast<std::byte>(0xba), static_cast<std::byte>(0x63), static_cast<std::byte>(0x4c),
            static_cast<std::byte>(0x24), static_cast<std::byte>(0x3d), static_cast<std::byte>(0x93),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0xa0), static_cast<std::byte>(0x42),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x60), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0x8d), static_cast<std::byte>(0x2f), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0x4e), static_cast<std::byte>(0x8e), static_cast<std::byte>(0x1d),
            static_cast<std::byte>(0xcb), static_cast<std::byte>(0x17),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, multiple_blocks_constexpr_test) {
        constexpr auto actual = hash23::sha3_256::calculate(
            R"(Hello, World!
It's a beautiful day to calculate some hashes!
It should be a very long string just to make sure the block size does not interfere with large datasets.
Just to make sure we are longer than one block just add more text.
After some time typing text gets boring.
This should now be enough text to not fit into one single block of data.
Actually we need to fill at least 2 blocks of data to see if it's really working as expected.
Filling two blocks of 256 bytes with data should result in a valid hash.
If not I know where to look.)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xb5), static_cast<std::byte>(0x7a), static_cast<std::byte>(0x70),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0xcc), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0x87), static_cast<std::byte>(0x78), static_cast<std::byte>(0x41),
            static_cast<std::byte>(0x92), static_cast<std::byte>(0x8a), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0x55), static_cast<std::byte>(0x44), static_cast<std::byte>(0xd7),
            static_cast<std::byte>(0xea), static_cast<std::byte>(0x19), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0xdc), static_cast<std::byte>(0xa9),
            static_cast<std::byte>(0xa8), static_cast<std::byte>(0x67), static_cast<std::byte>(0x3e),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0xa9), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0x87), static_cast<std::byte>(0xae),
            static_cast<std::byte>(0x94), static_cast<std::byte>(0x1a),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, multiple_blocks_string_test) {
        auto const actual = hash23::sha3_256::calculate(std::string{
            R"(Hello, World!
It's a beautiful day to calculate some hashes!
It should be a very long string just to make sure the block size does not interfere with large datasets.
Just to make sure we are longer than one block just add more text.
After some time typing text gets boring.
This should now be enough text to not fit into one single block of data.
Actually we need to fill at least 2 blocks of data to see if it's really working as expected.
Filling two blocks of 256 bytes with data should result in a valid hash.
If not I know where to look.)"
        });
        constexpr std::array expected = {
            static_cast<std::byte>(0xb5), static_cast<std::byte>(0x7a), static_cast<std::byte>(0x70),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0xcc), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0x87), static_cast<std::byte>(0x78), static_cast<std::byte>(0x41),
            static_cast<std::byte>(0x92), static_cast<std::byte>(0x8a), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0x55), static_cast<std::byte>(0x44), static_cast<std::byte>(0xd7),
            static_cast<std::byte>(0xea), static_cast<std::byte>(0x19), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0xdc), static_cast<std::byte>(0xa9),
            static_cast<std::byte>(0xa8), static_cast<std::byte>(0x67), static_cast<std::byte>(0x3e),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0xa9), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0x87), static_cast<std::byte>(0xae),
            static_cast<std::byte>(0x94), static_cast<std::byte>(0x1a),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::sha3_256::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xaf), static_cast<std::byte>(0xe7), static_cast<std::byte>(0xee),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0x22), static_cast<std::byte>(0xf6),
            static_cast<std::byte>(0x3a), static_cast<std::byte>(0x6d), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0x10), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0x5a), static_cast<std::byte>(0x8d),
            static_cast<std::byte>(0x15), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x6a),
            static_cast<std::byte>(0x1a), static_cast<std::byte>(0xf0), static_cast<std::byte>(0xee),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x96), static_cast<std::byte>(0x87),
            static_cast<std::byte>(0xbd), static_cast<std::byte>(0xb9), static_cast<std::byte>(0xd2),
            static_cast<std::byte>(0x7a), static_cast<std::byte>(0xa5), static_cast<std::byte>(0x3a),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x72),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_256, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::sha3_256::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xaf), static_cast<std::byte>(0xe7), static_cast<std::byte>(0xee),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0x22), static_cast<std::byte>(0xf6),
            static_cast<std::byte>(0x3a), static_cast<std::byte>(0x6d), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0x10), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0x5a), static_cast<std::byte>(0x8d),
            static_cast<std::byte>(0x15), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x6a),
            static_cast<std::byte>(0x1a), static_cast<std::byte>(0xf0), static_cast<std::byte>(0xee),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x96), static_cast<std::byte>(0x87),
            static_cast<std::byte>(0xbd), static_cast<std::byte>(0xb9), static_cast<std::byte>(0xd2),
            static_cast<std::byte>(0x7a), static_cast<std::byte>(0xa5), static_cast<std::byte>(0x3a),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x72),
        };
        EXPECT_EQ(expected, actual);
    }
}
