//
// Created by Rene Windegger on 14/03/2025.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha2_256, single_block_test) {
        auto const actual = hash23::sha2_256::calculate("Hello, World!");
        constexpr std::array expected = {
            static_cast<std::byte>(0xdf), static_cast<std::byte>(0xfd), static_cast<std::byte>(0x60),
            static_cast<std::byte>(0x21), static_cast<std::byte>(0xbb), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xd5), static_cast<std::byte>(0xb0), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x67), static_cast<std::byte>(0x62), static_cast<std::byte>(0x90),
            static_cast<std::byte>(0x80), static_cast<std::byte>(0x9e), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0x31), static_cast<std::byte>(0x91),
            static_cast<std::byte>(0xdd), static_cast<std::byte>(0x81), static_cast<std::byte>(0xc7),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0x0a), static_cast<std::byte>(0x4b),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0x68), static_cast<std::byte>(0x8a),
            static_cast<std::byte>(0x36), static_cast<std::byte>(0x21), static_cast<std::byte>(0x82),
            static_cast<std::byte>(0x98), static_cast<std::byte>(0x6f),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, single_block_string_test) {
        auto const actual = hash23::sha2_256::calculate(std::string{"Hello, World!"});
        constexpr std::array expected = {
            static_cast<std::byte>(0xdf), static_cast<std::byte>(0xfd), static_cast<std::byte>(0x60),
            static_cast<std::byte>(0x21), static_cast<std::byte>(0xbb), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xd5), static_cast<std::byte>(0xb0), static_cast<std::byte>(0xaf),
            static_cast<std::byte>(0x67), static_cast<std::byte>(0x62), static_cast<std::byte>(0x90),
            static_cast<std::byte>(0x80), static_cast<std::byte>(0x9e), static_cast<std::byte>(0xc3),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0x31), static_cast<std::byte>(0x91),
            static_cast<std::byte>(0xdd), static_cast<std::byte>(0x81), static_cast<std::byte>(0xc7),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0x0a), static_cast<std::byte>(0x4b),
            static_cast<std::byte>(0x28), static_cast<std::byte>(0x68), static_cast<std::byte>(0x8a),
            static_cast<std::byte>(0x36), static_cast<std::byte>(0x21), static_cast<std::byte>(0x82),
            static_cast<std::byte>(0x98), static_cast<std::byte>(0x6f),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, multiple_blocks_test) {
        auto const actual = hash23::sha2_256::calculate(
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
            static_cast<std::byte>(0x83), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xd1),
            static_cast<std::byte>(0x0f), static_cast<std::byte>(0xee), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0xab), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xb9), static_cast<std::byte>(0xe9), static_cast<std::byte>(0x77),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x15), static_cast<std::byte>(0xb7),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0xbe), static_cast<std::byte>(0xa6),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0x25), static_cast<std::byte>(0x30),
            static_cast<std::byte>(0x64), static_cast<std::byte>(0x92), static_cast<std::byte>(0x64),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x46), static_cast<std::byte>(0x16),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0x41), static_cast<std::byte>(0xfe),
            static_cast<std::byte>(0x31), static_cast<std::byte>(0x3b),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, payload_size_between_480_and_512_bit_test) {
        auto const actual = hash23::sha2_256::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 5)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xb1), static_cast<std::byte>(0xb4), static_cast<std::byte>(0x22),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x55), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xbd), static_cast<std::byte>(0x24), static_cast<std::byte>(0x44),
            static_cast<std::byte>(0x14), static_cast<std::byte>(0x76), static_cast<std::byte>(0x80),
            static_cast<std::byte>(0x20), static_cast<std::byte>(0x30), static_cast<std::byte>(0xfc),
            static_cast<std::byte>(0xe0), static_cast<std::byte>(0x89), static_cast<std::byte>(0x22),
            static_cast<std::byte>(0x73), static_cast<std::byte>(0x7c), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0x27), static_cast<std::byte>(0xc4), static_cast<std::byte>(0xfb),
            static_cast<std::byte>(0x07), static_cast<std::byte>(0x4f), static_cast<std::byte>(0xee),
            static_cast<std::byte>(0x2b), static_cast<std::byte>(0xf0), static_cast<std::byte>(0x6e),
            static_cast<std::byte>(0x3b), static_cast<std::byte>(0xe0),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, payload_size_exactly_512_bit_test) {
        auto const actual = hash23::sha2_256::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 512)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0x96), static_cast<std::byte>(0x03), static_cast<std::byte>(0xdd),
            static_cast<std::byte>(0x32), static_cast<std::byte>(0x88), static_cast<std::byte>(0x15),
            static_cast<std::byte>(0x7b), static_cast<std::byte>(0x37), static_cast<std::byte>(0xa0),
            static_cast<std::byte>(0x90), static_cast<std::byte>(0xb9), static_cast<std::byte>(0x9d),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0x83), static_cast<std::byte>(0x0c),
            static_cast<std::byte>(0xd3), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0xf4), static_cast<std::byte>(0xc5),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0x4e), static_cast<std::byte>(0x87),
            static_cast<std::byte>(0xa5), static_cast<std::byte>(0xd2), static_cast<std::byte>(0x9d),
            static_cast<std::byte>(0xd9), static_cast<std::byte>(0x23), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0x1a), static_cast<std::byte>(0x2c),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, payload_size_exactly_480_bit_test) {
        auto const actual = hash23::sha2_256::calculate(R"(Hello, World!
This is a text that will hit the sweet spot of)");
        constexpr std::array expected = {
            static_cast<std::byte>(0xd6), static_cast<std::byte>(0x7a), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0x1a), static_cast<std::byte>(0x8e), static_cast<std::byte>(0x23),
            static_cast<std::byte>(0x44), static_cast<std::byte>(0xa0), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0x07), static_cast<std::byte>(0xaa), static_cast<std::byte>(0x87),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0x0e), static_cast<std::byte>(0xe1),
            static_cast<std::byte>(0xd9), static_cast<std::byte>(0xa7), static_cast<std::byte>(0xd0),
            static_cast<std::byte>(0xd5), static_cast<std::byte>(0x19), static_cast<std::byte>(0x6d),
            static_cast<std::byte>(0x00), static_cast<std::byte>(0x2c), static_cast<std::byte>(0x58),
            static_cast<std::byte>(0xb0), static_cast<std::byte>(0x54), static_cast<std::byte>(0xea),
            static_cast<std::byte>(0x40), static_cast<std::byte>(0x2a), static_cast<std::byte>(0xc2),
            static_cast<std::byte>(0xca), static_cast<std::byte>(0x3d),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, multiple_blocks_constexpr_test) {
        constexpr auto actual = hash23::sha2_256::calculate(
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
            static_cast<std::byte>(0x83), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xd1),
            static_cast<std::byte>(0x0f), static_cast<std::byte>(0xee), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0xab), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xb9), static_cast<std::byte>(0xe9), static_cast<std::byte>(0x77),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x15), static_cast<std::byte>(0xb7),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0xbe), static_cast<std::byte>(0xa6),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0x25), static_cast<std::byte>(0x30),
            static_cast<std::byte>(0x64), static_cast<std::byte>(0x92), static_cast<std::byte>(0x64),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x46), static_cast<std::byte>(0x16),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0x41), static_cast<std::byte>(0xfe),
            static_cast<std::byte>(0x31), static_cast<std::byte>(0x3b),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, multiple_blocks_string_test) {
        auto const actual = hash23::sha2_256::calculate(std::string{
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
            static_cast<std::byte>(0x83), static_cast<std::byte>(0xeb), static_cast<std::byte>(0xd1),
            static_cast<std::byte>(0x0f), static_cast<std::byte>(0xee), static_cast<std::byte>(0xa2),
            static_cast<std::byte>(0x03), static_cast<std::byte>(0xab), static_cast<std::byte>(0x24),
            static_cast<std::byte>(0xb9), static_cast<std::byte>(0xe9), static_cast<std::byte>(0x77),
            static_cast<std::byte>(0x95), static_cast<std::byte>(0x15), static_cast<std::byte>(0xb7),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0xbe), static_cast<std::byte>(0xa6),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0x25), static_cast<std::byte>(0x30),
            static_cast<std::byte>(0x64), static_cast<std::byte>(0x92), static_cast<std::byte>(0x64),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x46), static_cast<std::byte>(0x16),
            static_cast<std::byte>(0xff), static_cast<std::byte>(0x41), static_cast<std::byte>(0xfe),
            static_cast<std::byte>(0x31), static_cast<std::byte>(0x3b),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::sha2_256::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x84), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0xc7), static_cast<std::byte>(0x2c), static_cast<std::byte>(0xfa),
            static_cast<std::byte>(0xa0), static_cast<std::byte>(0xbf), static_cast<std::byte>(0xbc),
            static_cast<std::byte>(0x8b), static_cast<std::byte>(0x60), static_cast<std::byte>(0x3c),
            static_cast<std::byte>(0x29), static_cast<std::byte>(0x6f), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0xd2), static_cast<std::byte>(0xd7),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0xad), static_cast<std::byte>(0xc6),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x78), static_cast<std::byte>(0x2c),
            static_cast<std::byte>(0x0e), static_cast<std::byte>(0x2f), static_cast<std::byte>(0x2f),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0xea), static_cast<std::byte>(0xfb),
            static_cast<std::byte>(0xcf), static_cast<std::byte>(0x03),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_256, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::sha2_256::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xc9), static_cast<std::byte>(0x84), static_cast<std::byte>(0xff),
            static_cast<std::byte>(0xc7), static_cast<std::byte>(0x2c), static_cast<std::byte>(0xfa),
            static_cast<std::byte>(0xa0), static_cast<std::byte>(0xbf), static_cast<std::byte>(0xbc),
            static_cast<std::byte>(0x8b), static_cast<std::byte>(0x60), static_cast<std::byte>(0x3c),
            static_cast<std::byte>(0x29), static_cast<std::byte>(0x6f), static_cast<std::byte>(0x53),
            static_cast<std::byte>(0xf7), static_cast<std::byte>(0xd2), static_cast<std::byte>(0xd7),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0xad), static_cast<std::byte>(0xc6),
            static_cast<std::byte>(0x39), static_cast<std::byte>(0x78), static_cast<std::byte>(0x2c),
            static_cast<std::byte>(0x0e), static_cast<std::byte>(0x2f), static_cast<std::byte>(0x2f),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0xea), static_cast<std::byte>(0xfb),
            static_cast<std::byte>(0xcf), static_cast<std::byte>(0x03),
        };
        EXPECT_EQ(expected, actual);
    }
}
