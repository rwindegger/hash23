//
// Created by Rene Windegger on 03/04/2026.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha3_512, empty_input_test) {
        auto const actual = hash23::sha3_512::calculate("");
        constexpr std::array expected = {
            static_cast<std::byte>(0xa6), static_cast<std::byte>(0x9f), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0xcc), static_cast<std::byte>(0xa2), static_cast<std::byte>(0x3a),
            static_cast<std::byte>(0x9a), static_cast<std::byte>(0xc5), static_cast<std::byte>(0xc8),
            static_cast<std::byte>(0xb5), static_cast<std::byte>(0x67), static_cast<std::byte>(0xdc),
            static_cast<std::byte>(0x18), static_cast<std::byte>(0x5a), static_cast<std::byte>(0x75),
            static_cast<std::byte>(0x6e), static_cast<std::byte>(0x97), static_cast<std::byte>(0xc9),
            static_cast<std::byte>(0x82), static_cast<std::byte>(0x16), static_cast<std::byte>(0x4f),
            static_cast<std::byte>(0xe2), static_cast<std::byte>(0x58), static_cast<std::byte>(0x59),
            static_cast<std::byte>(0xe0), static_cast<std::byte>(0xd1), static_cast<std::byte>(0xdc),
            static_cast<std::byte>(0xc1), static_cast<std::byte>(0x47), static_cast<std::byte>(0x5c),
            static_cast<std::byte>(0x80), static_cast<std::byte>(0xa6), static_cast<std::byte>(0x15),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x12), static_cast<std::byte>(0x3a),
            static_cast<std::byte>(0xf1), static_cast<std::byte>(0xf5), static_cast<std::byte>(0xf9),
            static_cast<std::byte>(0x4c), static_cast<std::byte>(0x11), static_cast<std::byte>(0xe3),
            static_cast<std::byte>(0xe9), static_cast<std::byte>(0x40), static_cast<std::byte>(0x2c),
            static_cast<std::byte>(0x3a), static_cast<std::byte>(0xc5), static_cast<std::byte>(0x58),
            static_cast<std::byte>(0xf5), static_cast<std::byte>(0x00), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0x9d), static_cast<std::byte>(0x95), static_cast<std::byte>(0xb6),
            static_cast<std::byte>(0xd3), static_cast<std::byte>(0xe3), static_cast<std::byte>(0x01),
            static_cast<std::byte>(0x75), static_cast<std::byte>(0x85), static_cast<std::byte>(0x86),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0x1d), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0x26),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, single_block_test) {
        auto const actual = hash23::sha3_512::calculate("Hello, World!");
        constexpr std::array expected = {
            static_cast<std::byte>(0x38), static_cast<std::byte>(0xe0), static_cast<std::byte>(0x5c),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xd7), static_cast<std::byte>(0xb0),
            static_cast<std::byte>(0x67), static_cast<std::byte>(0x12), static_cast<std::byte>(0x7f),
            static_cast<std::byte>(0x21), static_cast<std::byte>(0x7d), static_cast<std::byte>(0x8c),
            static_cast<std::byte>(0x85), static_cast<std::byte>(0x6e), static_cast<std::byte>(0x55),
            static_cast<std::byte>(0x4f), static_cast<std::byte>(0xcf), static_cast<std::byte>(0xf0),
            static_cast<std::byte>(0x9c), static_cast<std::byte>(0x93), static_cast<std::byte>(0x20),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0xa5), static_cast<std::byte>(0x97),
            static_cast<std::byte>(0x9c), static_cast<std::byte>(0xe2), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0x5d), static_cast<std::byte>(0x95), static_cast<std::byte>(0xdd),
            static_cast<std::byte>(0x27), static_cast<std::byte>(0xba), static_cast<std::byte>(0x35),
            static_cast<std::byte>(0xd1), static_cast<std::byte>(0xfb), static_cast<std::byte>(0xa5),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0x56), static_cast<std::byte>(0x2d),
            static_cast<std::byte>(0xfd), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x6c),
            static_cast<std::byte>(0xc4), static_cast<std::byte>(0x8b), static_cast<std::byte>(0xc9),
            static_cast<std::byte>(0xc5), static_cast<std::byte>(0xba), static_cast<std::byte>(0xa4),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x08), static_cast<std::byte>(0x94),
            static_cast<std::byte>(0x41), static_cast<std::byte>(0x8c), static_cast<std::byte>(0xc9),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xd9), static_cast<std::byte>(0x68),
            static_cast<std::byte>(0xf9), static_cast<std::byte>(0x7b), static_cast<std::byte>(0xcb),
            static_cast<std::byte>(0x65), static_cast<std::byte>(0x94), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xed),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, single_block_string_test) {
        auto const actual = hash23::sha3_512::calculate(std::string{"Hello, World!"});
        constexpr std::array expected = {
            static_cast<std::byte>(0x38), static_cast<std::byte>(0xe0), static_cast<std::byte>(0x5c),
            static_cast<std::byte>(0x33), static_cast<std::byte>(0xd7), static_cast<std::byte>(0xb0),
            static_cast<std::byte>(0x67), static_cast<std::byte>(0x12), static_cast<std::byte>(0x7f),
            static_cast<std::byte>(0x21), static_cast<std::byte>(0x7d), static_cast<std::byte>(0x8c),
            static_cast<std::byte>(0x85), static_cast<std::byte>(0x6e), static_cast<std::byte>(0x55),
            static_cast<std::byte>(0x4f), static_cast<std::byte>(0xcf), static_cast<std::byte>(0xf0),
            static_cast<std::byte>(0x9c), static_cast<std::byte>(0x93), static_cast<std::byte>(0x20),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0xa5), static_cast<std::byte>(0x97),
            static_cast<std::byte>(0x9c), static_cast<std::byte>(0xe2), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0x5d), static_cast<std::byte>(0x95), static_cast<std::byte>(0xdd),
            static_cast<std::byte>(0x27), static_cast<std::byte>(0xba), static_cast<std::byte>(0x35),
            static_cast<std::byte>(0xd1), static_cast<std::byte>(0xfb), static_cast<std::byte>(0xa5),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0x56), static_cast<std::byte>(0x2d),
            static_cast<std::byte>(0xfd), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x6c),
            static_cast<std::byte>(0xc4), static_cast<std::byte>(0x8b), static_cast<std::byte>(0xc9),
            static_cast<std::byte>(0xc5), static_cast<std::byte>(0xba), static_cast<std::byte>(0xa4),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x08), static_cast<std::byte>(0x94),
            static_cast<std::byte>(0x41), static_cast<std::byte>(0x8c), static_cast<std::byte>(0xc9),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xd9), static_cast<std::byte>(0x68),
            static_cast<std::byte>(0xf9), static_cast<std::byte>(0x7b), static_cast<std::byte>(0xcb),
            static_cast<std::byte>(0x65), static_cast<std::byte>(0x94), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xed),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, multiple_blocks_test) {
        auto const actual = hash23::sha3_512::calculate(
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
            static_cast<std::byte>(0x37), static_cast<std::byte>(0x54), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0x0e), static_cast<std::byte>(0xfc), static_cast<std::byte>(0x4c),
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xd7), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xc0), static_cast<std::byte>(0x20), static_cast<std::byte>(0xec),
            static_cast<std::byte>(0xe8), static_cast<std::byte>(0x97), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0xae), static_cast<std::byte>(0x5a), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x40), static_cast<std::byte>(0xf3),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x31), static_cast<std::byte>(0xb6),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0xf6), static_cast<std::byte>(0xa9),
            static_cast<std::byte>(0x6b), static_cast<std::byte>(0x38), static_cast<std::byte>(0x51),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x51), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x15), static_cast<std::byte>(0x1b), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0x10), static_cast<std::byte>(0xda),
            static_cast<std::byte>(0xd4), static_cast<std::byte>(0xb6), static_cast<std::byte>(0x36),
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0xf7), static_cast<std::byte>(0x72),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x3e), static_cast<std::byte>(0xf0),
            static_cast<std::byte>(0xb1), static_cast<std::byte>(0x4d), static_cast<std::byte>(0x5f),
            static_cast<std::byte>(0xbc), static_cast<std::byte>(0xe8), static_cast<std::byte>(0xe3),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0x19), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0x8c), static_cast<std::byte>(0x47), static_cast<std::byte>(0xcf),
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x64), static_cast<std::byte>(0x69),
            static_cast<std::byte>(0xf7),

        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, payload_size_exactly_568_bit_test) {
        auto const actual = hash23::sha3_512::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 71 bytes s)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xed), static_cast<std::byte>(0xb1), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0x71), static_cast<std::byte>(0x06), static_cast<std::byte>(0x67),
            static_cast<std::byte>(0x97), static_cast<std::byte>(0xe6), static_cast<std::byte>(0x66),
            static_cast<std::byte>(0x7c), static_cast<std::byte>(0xd5), static_cast<std::byte>(0x4f),
            static_cast<std::byte>(0xd2), static_cast<std::byte>(0x2d), static_cast<std::byte>(0xd1),
            static_cast<std::byte>(0x1f), static_cast<std::byte>(0x7e), static_cast<std::byte>(0xc6),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x70), static_cast<std::byte>(0xda),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0x7e), static_cast<std::byte>(0x50),
            static_cast<std::byte>(0xf0), static_cast<std::byte>(0x2f), static_cast<std::byte>(0xb3),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x17), static_cast<std::byte>(0xef),
            static_cast<std::byte>(0x1f), static_cast<std::byte>(0xc5), static_cast<std::byte>(0xfe),
            static_cast<std::byte>(0xc7), static_cast<std::byte>(0xbd), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0x6a), static_cast<std::byte>(0xab), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0xe1), static_cast<std::byte>(0xf3), static_cast<std::byte>(0x8a),
            static_cast<std::byte>(0x19), static_cast<std::byte>(0x03), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0xc8), static_cast<std::byte>(0x6c),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0xce), static_cast<std::byte>(0xac),
            static_cast<std::byte>(0xb6), static_cast<std::byte>(0xcc), static_cast<std::byte>(0x14),
            static_cast<std::byte>(0x6a), static_cast<std::byte>(0x91), static_cast<std::byte>(0xb6),
            static_cast<std::byte>(0xea), static_cast<std::byte>(0x98), static_cast<std::byte>(0x29),
            static_cast<std::byte>(0x3a),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, payload_size_exactly_576_bit_test) {
        auto const actual = hash23::sha3_512::calculate(R"(Hello, World!
This is a text that will hit the sweet spot of 72 bytes so)");
        constexpr std::array expected = {
            static_cast<std::byte>(0x97), static_cast<std::byte>(0x27), static_cast<std::byte>(0x8d),
            static_cast<std::byte>(0x64), static_cast<std::byte>(0x88), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0xa1), static_cast<std::byte>(0xad), static_cast<std::byte>(0x14),
            static_cast<std::byte>(0x8e), static_cast<std::byte>(0x34), static_cast<std::byte>(0xdf),
            static_cast<std::byte>(0xc2), static_cast<std::byte>(0xec), static_cast<std::byte>(0xfc),
            static_cast<std::byte>(0x8a), static_cast<std::byte>(0x0b), static_cast<std::byte>(0xb1),
            static_cast<std::byte>(0xbe), static_cast<std::byte>(0xfa), static_cast<std::byte>(0x6e),
            static_cast<std::byte>(0xa6), static_cast<std::byte>(0x5f), static_cast<std::byte>(0x39),
            static_cast<std::byte>(0x08), static_cast<std::byte>(0xaa), static_cast<std::byte>(0x1a),
            static_cast<std::byte>(0x54), static_cast<std::byte>(0xdf), static_cast<std::byte>(0x21),
            static_cast<std::byte>(0xcd), static_cast<std::byte>(0x9d), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0x0b), static_cast<std::byte>(0xc5), static_cast<std::byte>(0xd7),
            static_cast<std::byte>(0x46), static_cast<std::byte>(0x1e), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0x2e), static_cast<std::byte>(0x14), static_cast<std::byte>(0xf6),
            static_cast<std::byte>(0x64), static_cast<std::byte>(0xab), static_cast<std::byte>(0xda),
            static_cast<std::byte>(0x3a), static_cast<std::byte>(0xa7), static_cast<std::byte>(0xec),
            static_cast<std::byte>(0xcb), static_cast<std::byte>(0x3c), static_cast<std::byte>(0xf2),
            static_cast<std::byte>(0xd1), static_cast<std::byte>(0xd4), static_cast<std::byte>(0x43),
            static_cast<std::byte>(0x3d), static_cast<std::byte>(0xf8), static_cast<std::byte>(0xcc),
            static_cast<std::byte>(0xee), static_cast<std::byte>(0x3e), static_cast<std::byte>(0x96),
            static_cast<std::byte>(0x08), static_cast<std::byte>(0xd8), static_cast<std::byte>(0xbb),
            static_cast<std::byte>(0x29),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, multiple_blocks_constexpr_test) {
        constexpr auto actual = hash23::sha3_512::calculate(
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
            static_cast<std::byte>(0x37), static_cast<std::byte>(0x54), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0x0e), static_cast<std::byte>(0xfc), static_cast<std::byte>(0x4c),
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xd7), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xc0), static_cast<std::byte>(0x20), static_cast<std::byte>(0xec),
            static_cast<std::byte>(0xe8), static_cast<std::byte>(0x97), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0xae), static_cast<std::byte>(0x5a), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x40), static_cast<std::byte>(0xf3),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x31), static_cast<std::byte>(0xb6),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0xf6), static_cast<std::byte>(0xa9),
            static_cast<std::byte>(0x6b), static_cast<std::byte>(0x38), static_cast<std::byte>(0x51),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x51), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x15), static_cast<std::byte>(0x1b), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0x10), static_cast<std::byte>(0xda),
            static_cast<std::byte>(0xd4), static_cast<std::byte>(0xb6), static_cast<std::byte>(0x36),
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0xf7), static_cast<std::byte>(0x72),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x3e), static_cast<std::byte>(0xf0),
            static_cast<std::byte>(0xb1), static_cast<std::byte>(0x4d), static_cast<std::byte>(0x5f),
            static_cast<std::byte>(0xbc), static_cast<std::byte>(0xe8), static_cast<std::byte>(0xe3),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0x19), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0x8c), static_cast<std::byte>(0x47), static_cast<std::byte>(0xcf),
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x64), static_cast<std::byte>(0x69),
            static_cast<std::byte>(0xf7),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, multiple_blocks_string_test) {
        auto const actual = hash23::sha3_512::calculate(std::string{
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
            static_cast<std::byte>(0x37), static_cast<std::byte>(0x54), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0x0e), static_cast<std::byte>(0xfc), static_cast<std::byte>(0x4c),
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xd7), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xc0), static_cast<std::byte>(0x20), static_cast<std::byte>(0xec),
            static_cast<std::byte>(0xe8), static_cast<std::byte>(0x97), static_cast<std::byte>(0x31),
            static_cast<std::byte>(0xae), static_cast<std::byte>(0x5a), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x40), static_cast<std::byte>(0xf3),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x31), static_cast<std::byte>(0xb6),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0xf6), static_cast<std::byte>(0xa9),
            static_cast<std::byte>(0x6b), static_cast<std::byte>(0x38), static_cast<std::byte>(0x51),
            static_cast<std::byte>(0x30), static_cast<std::byte>(0x51), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x15), static_cast<std::byte>(0x1b), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0x10), static_cast<std::byte>(0xda),
            static_cast<std::byte>(0xd4), static_cast<std::byte>(0xb6), static_cast<std::byte>(0x36),
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0xf7), static_cast<std::byte>(0x72),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x3e), static_cast<std::byte>(0xf0),
            static_cast<std::byte>(0xb1), static_cast<std::byte>(0x4d), static_cast<std::byte>(0x5f),
            static_cast<std::byte>(0xbc), static_cast<std::byte>(0xe8), static_cast<std::byte>(0xe3),
            static_cast<std::byte>(0xc3), static_cast<std::byte>(0x19), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0x8c), static_cast<std::byte>(0x47), static_cast<std::byte>(0xcf),
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x64), static_cast<std::byte>(0x69),
            static_cast<std::byte>(0xf7),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::sha3_512::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xf1), static_cast<std::byte>(0x55), static_cast<std::byte>(0x45),
            static_cast<std::byte>(0x20), static_cast<std::byte>(0x66), static_cast<std::byte>(0x81),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0x54), static_cast<std::byte>(0x5b),
            static_cast<std::byte>(0x7a), static_cast<std::byte>(0x2b), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0xd8), static_cast<std::byte>(0xd2),
            static_cast<std::byte>(0xf2), static_cast<std::byte>(0x1a), static_cast<std::byte>(0xb7),
            static_cast<std::byte>(0x2f), static_cast<std::byte>(0xd8), static_cast<std::byte>(0x29),
            static_cast<std::byte>(0xd9), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x4b),
            static_cast<std::byte>(0x2f), static_cast<std::byte>(0x13), static_cast<std::byte>(0x01),
            static_cast<std::byte>(0x1b), static_cast<std::byte>(0xf8), static_cast<std::byte>(0x62),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0x09), static_cast<std::byte>(0x77),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0xe0), static_cast<std::byte>(0x0e),
            static_cast<std::byte>(0x82), static_cast<std::byte>(0xc4), static_cast<std::byte>(0x30),
            static_cast<std::byte>(0x65), static_cast<std::byte>(0xf2), static_cast<std::byte>(0x27),
            static_cast<std::byte>(0xe7), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x32),
            static_cast<std::byte>(0x07), static_cast<std::byte>(0xdc), static_cast<std::byte>(0x1a),
            static_cast<std::byte>(0x45), static_cast<std::byte>(0xe3), static_cast<std::byte>(0xa1),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0xf7), static_cast<std::byte>(0xd2),
            static_cast<std::byte>(0x5f), static_cast<std::byte>(0xf6), static_cast<std::byte>(0xe4),
            static_cast<std::byte>(0xf8), static_cast<std::byte>(0x54), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0x16), static_cast<std::byte>(0x43), static_cast<std::byte>(0x8d),
            static_cast<std::byte>(0x11),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha3_512, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::sha3_512::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xf1), static_cast<std::byte>(0x55), static_cast<std::byte>(0x45),
            static_cast<std::byte>(0x20), static_cast<std::byte>(0x66), static_cast<std::byte>(0x81),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0x54), static_cast<std::byte>(0x5b),
            static_cast<std::byte>(0x7a), static_cast<std::byte>(0x2b), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0xd8), static_cast<std::byte>(0xd2),
            static_cast<std::byte>(0xf2), static_cast<std::byte>(0x1a), static_cast<std::byte>(0xb7),
            static_cast<std::byte>(0x2f), static_cast<std::byte>(0xd8), static_cast<std::byte>(0x29),
            static_cast<std::byte>(0xd9), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x4b),
            static_cast<std::byte>(0x2f), static_cast<std::byte>(0x13), static_cast<std::byte>(0x01),
            static_cast<std::byte>(0x1b), static_cast<std::byte>(0xf8), static_cast<std::byte>(0x62),
            static_cast<std::byte>(0xb8), static_cast<std::byte>(0x09), static_cast<std::byte>(0x77),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0xe0), static_cast<std::byte>(0x0e),
            static_cast<std::byte>(0x82), static_cast<std::byte>(0xc4), static_cast<std::byte>(0x30),
            static_cast<std::byte>(0x65), static_cast<std::byte>(0xf2), static_cast<std::byte>(0x27),
            static_cast<std::byte>(0xe7), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x32),
            static_cast<std::byte>(0x07), static_cast<std::byte>(0xdc), static_cast<std::byte>(0x1a),
            static_cast<std::byte>(0x45), static_cast<std::byte>(0xe3), static_cast<std::byte>(0xa1),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0xf7), static_cast<std::byte>(0xd2),
            static_cast<std::byte>(0x5f), static_cast<std::byte>(0xf6), static_cast<std::byte>(0xe4),
            static_cast<std::byte>(0xf8), static_cast<std::byte>(0x54), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0x16), static_cast<std::byte>(0x43), static_cast<std::byte>(0x8d),
            static_cast<std::byte>(0x11),
        };
        EXPECT_EQ(expected, actual);
    }
}
