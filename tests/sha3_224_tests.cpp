//
// Created by Rene Windegger on 02/04/2026.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha3_224, single_block_test) {
        auto const actual = hash23::sha3_224::calculate("Hello, World!");
        constexpr std::array expected = {
            static_cast<std::byte>(0x85), static_cast<std::byte>(0x30), static_cast<std::byte>(0x48),
            static_cast<std::byte>(0xfb), static_cast<std::byte>(0x8b), static_cast<std::byte>(0x11),
            static_cast<std::byte>(0x46), static_cast<std::byte>(0x2b), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0x00), static_cast<std::byte>(0x38), static_cast<std::byte>(0x56),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xc0), static_cast<std::byte>(0xcc),
            static_cast<std::byte>(0x8d), static_cast<std::byte>(0xcd), static_cast<std::byte>(0xc6),
            static_cast<std::byte>(0xe2), static_cast<std::byte>(0xb8), static_cast<std::byte>(0xe3),
            static_cast<std::byte>(0x76), static_cast<std::byte>(0xc2), static_cast<std::byte>(0x81),
            static_cast<std::byte>(0x02), static_cast<std::byte>(0xbc), static_cast<std::byte>(0x84),
            static_cast<std::byte>(0xf2),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, single_block_string_test) {
        auto const actual = hash23::sha3_224::calculate(std::string{"Hello, World!"});
        constexpr std::array expected = {
            static_cast<std::byte>(0x85), static_cast<std::byte>(0x30), static_cast<std::byte>(0x48),
            static_cast<std::byte>(0xfb), static_cast<std::byte>(0x8b), static_cast<std::byte>(0x11),
            static_cast<std::byte>(0x46), static_cast<std::byte>(0x2b), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0x00), static_cast<std::byte>(0x38), static_cast<std::byte>(0x56),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xc0), static_cast<std::byte>(0xcc),
            static_cast<std::byte>(0x8d), static_cast<std::byte>(0xcd), static_cast<std::byte>(0xc6),
            static_cast<std::byte>(0xe2), static_cast<std::byte>(0xb8), static_cast<std::byte>(0xe3),
            static_cast<std::byte>(0x76), static_cast<std::byte>(0xc2), static_cast<std::byte>(0x81),
            static_cast<std::byte>(0x02), static_cast<std::byte>(0xbc), static_cast<std::byte>(0x84),
            static_cast<std::byte>(0xf2),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, multiple_blocks_test) {
        auto const actual = hash23::sha3_224::calculate(
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
            static_cast<std::byte>(0xaf), static_cast<std::byte>(0xbc), static_cast<std::byte>(0xd8),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x5f), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0x3b), static_cast<std::byte>(0xcf), static_cast<std::byte>(0x62),
            static_cast<std::byte>(0xf2), static_cast<std::byte>(0xca), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0x45), static_cast<std::byte>(0xd9), static_cast<std::byte>(0xf3),
            static_cast<std::byte>(0xfe), static_cast<std::byte>(0x99), static_cast<std::byte>(0xdb),
            static_cast<std::byte>(0xcf), static_cast<std::byte>(0x9a), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0x6e), static_cast<std::byte>(0x8b), static_cast<std::byte>(0x7b),
            static_cast<std::byte>(0x6f), static_cast<std::byte>(0x8c), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0x47),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, payload_size_exactly_1144_bit_test) {
        auto const actual = hash23::sha3_224::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 1144 bit for the block size.
Just some more text to fill the buffer for the test. )"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xa9), static_cast<std::byte>(0xc7), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0x62), static_cast<std::byte>(0x2d), static_cast<std::byte>(0xc2),
            static_cast<std::byte>(0x6d), static_cast<std::byte>(0xf3), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x2f), static_cast<std::byte>(0xa0),
            static_cast<std::byte>(0xd9), static_cast<std::byte>(0xdf), static_cast<std::byte>(0xb1),
            static_cast<std::byte>(0x16), static_cast<std::byte>(0x41), static_cast<std::byte>(0xfd),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x58), static_cast<std::byte>(0x22),
            static_cast<std::byte>(0x5c), static_cast<std::byte>(0x34), static_cast<std::byte>(0x42),
            static_cast<std::byte>(0x3e), static_cast<std::byte>(0x29), static_cast<std::byte>(0xf8),
            static_cast<std::byte>(0xae),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, payload_size_exactly_1152_bit_test) {
        auto const actual = hash23::sha3_224::calculate(R"(Hello, World!
This is a text that will hit the sweet spot of 1144 bit for the block size.
Just some more text to fill the buffer for the test. A)");
        constexpr std::array expected = {
            static_cast<std::byte>(0x36), static_cast<std::byte>(0x38), static_cast<std::byte>(0x3a),
            static_cast<std::byte>(0x82), static_cast<std::byte>(0x1b), static_cast<std::byte>(0xba),
            static_cast<std::byte>(0x66), static_cast<std::byte>(0x22), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0xf3), static_cast<std::byte>(0x98), static_cast<std::byte>(0x65),
            static_cast<std::byte>(0x8a), static_cast<std::byte>(0x9a), static_cast<std::byte>(0xc4),
            static_cast<std::byte>(0x2b), static_cast<std::byte>(0x72), static_cast<std::byte>(0x57),
            static_cast<std::byte>(0xb4), static_cast<std::byte>(0x8f), static_cast<std::byte>(0xbf),
            static_cast<std::byte>(0xbc), static_cast<std::byte>(0x7e), static_cast<std::byte>(0xce),
            static_cast<std::byte>(0xcd), static_cast<std::byte>(0xb2), static_cast<std::byte>(0x91),
            static_cast<std::byte>(0xf6)
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, multiple_blocks_constexpr_test) {
        constexpr auto actual = hash23::sha3_224::calculate(
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
            static_cast<std::byte>(0xaf), static_cast<std::byte>(0xbc), static_cast<std::byte>(0xd8),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x5f), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0x3b), static_cast<std::byte>(0xcf), static_cast<std::byte>(0x62),
            static_cast<std::byte>(0xf2), static_cast<std::byte>(0xca), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0x45), static_cast<std::byte>(0xd9), static_cast<std::byte>(0xf3),
            static_cast<std::byte>(0xfe), static_cast<std::byte>(0x99), static_cast<std::byte>(0xdb),
            static_cast<std::byte>(0xcf), static_cast<std::byte>(0x9a), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0x6e), static_cast<std::byte>(0x8b), static_cast<std::byte>(0x7b),
            static_cast<std::byte>(0x6f), static_cast<std::byte>(0x8c), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0x47),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, multiple_blocks_string_test) {
        auto const actual = hash23::sha3_224::calculate(std::string{
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
            static_cast<std::byte>(0xaf), static_cast<std::byte>(0xbc), static_cast<std::byte>(0xd8),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x5f), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0x3b), static_cast<std::byte>(0xcf), static_cast<std::byte>(0x62),
            static_cast<std::byte>(0xf2), static_cast<std::byte>(0xca), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0x45), static_cast<std::byte>(0xd9), static_cast<std::byte>(0xf3),
            static_cast<std::byte>(0xfe), static_cast<std::byte>(0x99), static_cast<std::byte>(0xdb),
            static_cast<std::byte>(0xcf), static_cast<std::byte>(0x9a), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0x6e), static_cast<std::byte>(0x8b), static_cast<std::byte>(0x7b),
            static_cast<std::byte>(0x6f), static_cast<std::byte>(0x8c), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0x47),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::sha3_224::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x55), static_cast<std::byte>(0xeb), static_cast<std::byte>(0x83),
            static_cast<std::byte>(0x98), static_cast<std::byte>(0x85), static_cast<std::byte>(0xcc),
            static_cast<std::byte>(0x36), static_cast<std::byte>(0xfc), static_cast<std::byte>(0xb0),
            static_cast<std::byte>(0xd3), static_cast<std::byte>(0x38), static_cast<std::byte>(0x2e),
            static_cast<std::byte>(0xe3), static_cast<std::byte>(0x8d), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0xbf), static_cast<std::byte>(0x2e), static_cast<std::byte>(0x8b),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x00), static_cast<std::byte>(0xe9),
            static_cast<std::byte>(0x11), static_cast<std::byte>(0x1a), static_cast<std::byte>(0x88),
            static_cast<std::byte>(0x55), static_cast<std::byte>(0x15), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0x28),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_224, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::sha3_224::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x55), static_cast<std::byte>(0xeb), static_cast<std::byte>(0x83),
            static_cast<std::byte>(0x98), static_cast<std::byte>(0x85), static_cast<std::byte>(0xcc),
            static_cast<std::byte>(0x36), static_cast<std::byte>(0xfc), static_cast<std::byte>(0xb0),
            static_cast<std::byte>(0xd3), static_cast<std::byte>(0x38), static_cast<std::byte>(0x2e),
            static_cast<std::byte>(0xe3), static_cast<std::byte>(0x8d), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0xbf), static_cast<std::byte>(0x2e), static_cast<std::byte>(0x8b),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x00), static_cast<std::byte>(0xe9),
            static_cast<std::byte>(0x11), static_cast<std::byte>(0x1a), static_cast<std::byte>(0x88),
            static_cast<std::byte>(0x55), static_cast<std::byte>(0x15), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0x28),
        };
        EXPECT_EQ(expected, actual);
    }
}
