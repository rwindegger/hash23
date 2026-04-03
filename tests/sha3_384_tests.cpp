//
// Created by Rene Windegger on 03/04/2026.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha3_384, empty_input_test) {
        auto const actual = hash23::sha3_384::calculate("");
        constexpr std::array expected = {
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0x63), static_cast<std::byte>(0xa7),
            static_cast<std::byte>(0x5b), static_cast<std::byte>(0x84), static_cast<std::byte>(0x5e),
            static_cast<std::byte>(0x4f), static_cast<std::byte>(0x7d), static_cast<std::byte>(0x01),
            static_cast<std::byte>(0x10), static_cast<std::byte>(0x7d), static_cast<std::byte>(0x85),
            static_cast<std::byte>(0x2e), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0x85), static_cast<std::byte>(0xc5), static_cast<std::byte>(0x1a),
            static_cast<std::byte>(0x50), static_cast<std::byte>(0xaa), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x94), static_cast<std::byte>(0xfc), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0x5e), static_cast<std::byte>(0x71),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0xee), static_cast<std::byte>(0x98),
            static_cast<std::byte>(0x3a), static_cast<std::byte>(0x2a), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0x71), static_cast<std::byte>(0x38), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0x26), static_cast<std::byte>(0x4a), static_cast<std::byte>(0xdb),
            static_cast<std::byte>(0x47), static_cast<std::byte>(0xfb), static_cast<std::byte>(0x6b),
            static_cast<std::byte>(0xd1), static_cast<std::byte>(0xe0), static_cast<std::byte>(0x58),
            static_cast<std::byte>(0xd5), static_cast<std::byte>(0xf0), static_cast<std::byte>(0x04),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, single_block_test) {
        auto const actual = hash23::sha3_384::calculate("Hello, World!");
        constexpr std::array expected = {
            static_cast<std::byte>(0xaa), static_cast<std::byte>(0x9a), static_cast<std::byte>(0xd8),
            static_cast<std::byte>(0xa4), static_cast<std::byte>(0x9f), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0xd2), static_cast<std::byte>(0xdd), static_cast<std::byte>(0xca),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0xb7), static_cast<std::byte>(0x01),
            static_cast<std::byte>(0x0a), static_cast<std::byte>(0x15), static_cast<std::byte>(0x66),
            static_cast<std::byte>(0x41), static_cast<std::byte>(0x7c), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0x80), static_cast<std::byte>(0x3f), static_cast<std::byte>(0xef),
            static_cast<std::byte>(0x50), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x55), static_cast<std::byte>(0x88),
            static_cast<std::byte>(0x26), static_cast<std::byte>(0xf8), static_cast<std::byte>(0x72),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x68), static_cast<std::byte>(0xc5),
            static_cast<std::byte>(0x74), static_cast<std::byte>(0x3e), static_cast<std::byte>(0x7f),
            static_cast<std::byte>(0x02), static_cast<std::byte>(0x6b), static_cast<std::byte>(0x0a),
            static_cast<std::byte>(0x8e), static_cast<std::byte>(0x5b), static_cast<std::byte>(0x2d),
            static_cast<std::byte>(0x7a), static_cast<std::byte>(0x1c), static_cast<std::byte>(0xc4),
            static_cast<std::byte>(0x65), static_cast<std::byte>(0xcd), static_cast<std::byte>(0xbe),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, single_block_string_test) {
        auto const actual = hash23::sha3_384::calculate(std::string{"Hello, World!"});
        constexpr std::array expected = {
            static_cast<std::byte>(0xaa), static_cast<std::byte>(0x9a), static_cast<std::byte>(0xd8),
            static_cast<std::byte>(0xa4), static_cast<std::byte>(0x9f), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0xd2), static_cast<std::byte>(0xdd), static_cast<std::byte>(0xca),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0xb7), static_cast<std::byte>(0x01),
            static_cast<std::byte>(0x0a), static_cast<std::byte>(0x15), static_cast<std::byte>(0x66),
            static_cast<std::byte>(0x41), static_cast<std::byte>(0x7c), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0x80), static_cast<std::byte>(0x3f), static_cast<std::byte>(0xef),
            static_cast<std::byte>(0x50), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x55), static_cast<std::byte>(0x88),
            static_cast<std::byte>(0x26), static_cast<std::byte>(0xf8), static_cast<std::byte>(0x72),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x68), static_cast<std::byte>(0xc5),
            static_cast<std::byte>(0x74), static_cast<std::byte>(0x3e), static_cast<std::byte>(0x7f),
            static_cast<std::byte>(0x02), static_cast<std::byte>(0x6b), static_cast<std::byte>(0x0a),
            static_cast<std::byte>(0x8e), static_cast<std::byte>(0x5b), static_cast<std::byte>(0x2d),
            static_cast<std::byte>(0x7a), static_cast<std::byte>(0x1c), static_cast<std::byte>(0xc4),
            static_cast<std::byte>(0x65), static_cast<std::byte>(0xcd), static_cast<std::byte>(0xbe),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, multiple_blocks_test) {
        auto const actual = hash23::sha3_384::calculate(
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
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xa4), static_cast<std::byte>(0x80),
            static_cast<std::byte>(0x75), static_cast<std::byte>(0x88), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xc0), static_cast<std::byte>(0x76), static_cast<std::byte>(0xbf),
            static_cast<std::byte>(0xc7), static_cast<std::byte>(0x3e), static_cast<std::byte>(0xca),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x6e), static_cast<std::byte>(0x39),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x74), static_cast<std::byte>(0xac),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0xca), static_cast<std::byte>(0x89),
            static_cast<std::byte>(0x8c), static_cast<std::byte>(0xff), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x37), static_cast<std::byte>(0x5a),
            static_cast<std::byte>(0xfc), static_cast<std::byte>(0xf7), static_cast<std::byte>(0xb4),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0xd1), static_cast<std::byte>(0x37),
            static_cast<std::byte>(0x29), static_cast<std::byte>(0x78), static_cast<std::byte>(0xa1),
            static_cast<std::byte>(0x6a), static_cast<std::byte>(0xee), static_cast<std::byte>(0x1c),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x1a), static_cast<std::byte>(0xa6),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xdd), static_cast<std::byte>(0x94),

        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, payload_size_exactly_824_bit_test) {
        auto const actual = hash23::sha3_384::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 103 bytes so we need to add some additiona)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0x67), static_cast<std::byte>(0x02), static_cast<std::byte>(0x3b),
            static_cast<std::byte>(0x48), static_cast<std::byte>(0x58), static_cast<std::byte>(0xe5),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0x73), static_cast<std::byte>(0xe2),
            static_cast<std::byte>(0xea), static_cast<std::byte>(0xdb), static_cast<std::byte>(0xec),
            static_cast<std::byte>(0xfd), static_cast<std::byte>(0x1d), static_cast<std::byte>(0xa1),
            static_cast<std::byte>(0x97), static_cast<std::byte>(0x95), static_cast<std::byte>(0xa3),
            static_cast<std::byte>(0x69), static_cast<std::byte>(0x9f), static_cast<std::byte>(0x63),
            static_cast<std::byte>(0x81), static_cast<std::byte>(0xd7), static_cast<std::byte>(0x8b),
            static_cast<std::byte>(0x52), static_cast<std::byte>(0xb6), static_cast<std::byte>(0x15),
            static_cast<std::byte>(0x22), static_cast<std::byte>(0x1d), static_cast<std::byte>(0xa8),
            static_cast<std::byte>(0x12), static_cast<std::byte>(0x2d), static_cast<std::byte>(0x05),
            static_cast<std::byte>(0x6f), static_cast<std::byte>(0xac), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0x8b), static_cast<std::byte>(0x6b), static_cast<std::byte>(0xc4),
            static_cast<std::byte>(0x6e), static_cast<std::byte>(0xf0), static_cast<std::byte>(0xf2),
            static_cast<std::byte>(0x86), static_cast<std::byte>(0x00), static_cast<std::byte>(0x4f),
            static_cast<std::byte>(0xa4), static_cast<std::byte>(0x88), static_cast<std::byte>(0x0c),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, payload_size_exactly_832_bit_test) {
        auto const actual = hash23::sha3_384::calculate(R"(Hello, World!
This is a text that will hit the sweet spot of 104 bytes so we need to add some additional)");
        constexpr std::array expected = {
            static_cast<std::byte>(0x87), static_cast<std::byte>(0x90), static_cast<std::byte>(0x95),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0x11), static_cast<std::byte>(0x50),
            static_cast<std::byte>(0x46), static_cast<std::byte>(0xd3), static_cast<std::byte>(0x69),
            static_cast<std::byte>(0xb5), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x77),
            static_cast<std::byte>(0xb9), static_cast<std::byte>(0x32), static_cast<std::byte>(0x5d),
            static_cast<std::byte>(0x8a), static_cast<std::byte>(0x40), static_cast<std::byte>(0xed),
            static_cast<std::byte>(0x0e), static_cast<std::byte>(0xda), static_cast<std::byte>(0xd9),
            static_cast<std::byte>(0xec), static_cast<std::byte>(0x86), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x7a), static_cast<std::byte>(0x23),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0x3f), static_cast<std::byte>(0xd4),
            static_cast<std::byte>(0x4e), static_cast<std::byte>(0xf3), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0xd4), static_cast<std::byte>(0xf4), static_cast<std::byte>(0x47),
            static_cast<std::byte>(0x64), static_cast<std::byte>(0x32), static_cast<std::byte>(0x3f),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xda), static_cast<std::byte>(0xda),
            static_cast<std::byte>(0x10), static_cast<std::byte>(0x45), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0x07), static_cast<std::byte>(0xa1), static_cast<std::byte>(0x98),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, multiple_blocks_constexpr_test) {
        constexpr auto actual = hash23::sha3_384::calculate(
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
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xa4), static_cast<std::byte>(0x80),
            static_cast<std::byte>(0x75), static_cast<std::byte>(0x88), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xc0), static_cast<std::byte>(0x76), static_cast<std::byte>(0xbf),
            static_cast<std::byte>(0xc7), static_cast<std::byte>(0x3e), static_cast<std::byte>(0xca),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x6e), static_cast<std::byte>(0x39),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x74), static_cast<std::byte>(0xac),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0xca), static_cast<std::byte>(0x89),
            static_cast<std::byte>(0x8c), static_cast<std::byte>(0xff), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x37), static_cast<std::byte>(0x5a),
            static_cast<std::byte>(0xfc), static_cast<std::byte>(0xf7), static_cast<std::byte>(0xb4),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0xd1), static_cast<std::byte>(0x37),
            static_cast<std::byte>(0x29), static_cast<std::byte>(0x78), static_cast<std::byte>(0xa1),
            static_cast<std::byte>(0x6a), static_cast<std::byte>(0xee), static_cast<std::byte>(0x1c),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x1a), static_cast<std::byte>(0xa6),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xdd), static_cast<std::byte>(0x94),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, multiple_blocks_string_test) {
        auto const actual = hash23::sha3_384::calculate(std::string{
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
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xa4), static_cast<std::byte>(0x80),
            static_cast<std::byte>(0x75), static_cast<std::byte>(0x88), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xc0), static_cast<std::byte>(0x76), static_cast<std::byte>(0xbf),
            static_cast<std::byte>(0xc7), static_cast<std::byte>(0x3e), static_cast<std::byte>(0xca),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x6e), static_cast<std::byte>(0x39),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x74), static_cast<std::byte>(0xac),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0xca), static_cast<std::byte>(0x89),
            static_cast<std::byte>(0x8c), static_cast<std::byte>(0xff), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x37), static_cast<std::byte>(0x5a),
            static_cast<std::byte>(0xfc), static_cast<std::byte>(0xf7), static_cast<std::byte>(0xb4),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0xd1), static_cast<std::byte>(0x37),
            static_cast<std::byte>(0x29), static_cast<std::byte>(0x78), static_cast<std::byte>(0xa1),
            static_cast<std::byte>(0x6a), static_cast<std::byte>(0xee), static_cast<std::byte>(0x1c),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x1a), static_cast<std::byte>(0xa6),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xdd), static_cast<std::byte>(0x94),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::sha3_384::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x4a), static_cast<std::byte>(0x08), static_cast<std::byte>(0xc2),
            static_cast<std::byte>(0x93), static_cast<std::byte>(0x18), static_cast<std::byte>(0x3e),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0x61), static_cast<std::byte>(0xf8),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0x64), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0xeb), static_cast<std::byte>(0x99), static_cast<std::byte>(0x54),
            static_cast<std::byte>(0x8a), static_cast<std::byte>(0x66), static_cast<std::byte>(0x88),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xcb), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0x76), static_cast<std::byte>(0x66),
            static_cast<std::byte>(0x2e), static_cast<std::byte>(0x5d), static_cast<std::byte>(0xe8),
            static_cast<std::byte>(0xba), static_cast<std::byte>(0x6c), static_cast<std::byte>(0xf9),
            static_cast<std::byte>(0x31), static_cast<std::byte>(0x72), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x2f), static_cast<std::byte>(0xa9), static_cast<std::byte>(0xf5),
            static_cast<std::byte>(0x71), static_cast<std::byte>(0xe5), static_cast<std::byte>(0xef),
            static_cast<std::byte>(0x8b), static_cast<std::byte>(0x28), static_cast<std::byte>(0xe6),
            static_cast<std::byte>(0xcd), static_cast<std::byte>(0xb9), static_cast<std::byte>(0xf6),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0xf7), static_cast<std::byte>(0x75),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_384, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::sha3_384::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x4a), static_cast<std::byte>(0x08), static_cast<std::byte>(0xc2),
            static_cast<std::byte>(0x93), static_cast<std::byte>(0x18), static_cast<std::byte>(0x3e),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0x61), static_cast<std::byte>(0xf8),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0x64), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0xeb), static_cast<std::byte>(0x99), static_cast<std::byte>(0x54),
            static_cast<std::byte>(0x8a), static_cast<std::byte>(0x66), static_cast<std::byte>(0x88),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xcb), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0x76), static_cast<std::byte>(0x66),
            static_cast<std::byte>(0x2e), static_cast<std::byte>(0x5d), static_cast<std::byte>(0xe8),
            static_cast<std::byte>(0xba), static_cast<std::byte>(0x6c), static_cast<std::byte>(0xf9),
            static_cast<std::byte>(0x31), static_cast<std::byte>(0x72), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x2f), static_cast<std::byte>(0xa9), static_cast<std::byte>(0xf5),
            static_cast<std::byte>(0x71), static_cast<std::byte>(0xe5), static_cast<std::byte>(0xef),
            static_cast<std::byte>(0x8b), static_cast<std::byte>(0x28), static_cast<std::byte>(0xe6),
            static_cast<std::byte>(0xcd), static_cast<std::byte>(0xb9), static_cast<std::byte>(0xf6),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0xf7), static_cast<std::byte>(0x75),
        };
        EXPECT_EQ(expected, actual);
    }
}
