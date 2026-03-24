//
// Created by Rene Windegger on 22/03/2026.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(md5, single_block_test) {
        constexpr auto actual = hash23::md5::calculate("The quick brown fox jumps over the lazy dog");
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0x10), static_cast<std::byte>(0x7d),
            static_cast<std::byte>(0x9d), static_cast<std::byte>(0x37), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xb6), static_cast<std::byte>(0x82), static_cast<std::byte>(0x6b),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x35),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xa4), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xd6),
        };
        EXPECT_EQ(expected, actual);
        constexpr auto actual1 = hash23::md5::calculate("The quick brown fox jumps over the lazy dog.");
        constexpr auto expected1 = std::array{
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0xd9), static_cast<std::byte>(0x09),
            static_cast<std::byte>(0xc2), static_cast<std::byte>(0x90), static_cast<std::byte>(0xd0),
            static_cast<std::byte>(0xfb), static_cast<std::byte>(0x1c), static_cast<std::byte>(0xa0),
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xff), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0xdf), static_cast<std::byte>(0x22), static_cast<std::byte>(0xcb),
            static_cast<std::byte>(0xd0),
        };
        EXPECT_EQ(expected1, actual1);
    }

    TEST(md5, single_block_string_test) {
        constexpr auto actual = hash23::md5::calculate(std::string{"The quick brown fox jumps over the lazy dog"});
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x9e), static_cast<std::byte>(0x10), static_cast<std::byte>(0x7d),
            static_cast<std::byte>(0x9d), static_cast<std::byte>(0x37), static_cast<std::byte>(0x2b),
            static_cast<std::byte>(0xb6), static_cast<std::byte>(0x82), static_cast<std::byte>(0x6b),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x35),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xa4), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xd6),
        };
        EXPECT_EQ(expected, actual);
        constexpr auto actual1 = hash23::md5::calculate(std::string{"The quick brown fox jumps over the lazy dog."});
        constexpr auto expected1 = std::array{
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0xd9), static_cast<std::byte>(0x09),
            static_cast<std::byte>(0xc2), static_cast<std::byte>(0x90), static_cast<std::byte>(0xd0),
            static_cast<std::byte>(0xfb), static_cast<std::byte>(0x1c), static_cast<std::byte>(0xa0),
            static_cast<std::byte>(0x68), static_cast<std::byte>(0xff), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0xdf), static_cast<std::byte>(0x22), static_cast<std::byte>(0xcb),
            static_cast<std::byte>(0xd0),
        };
        EXPECT_EQ(expected1, actual1);
    }

    TEST(md5, multiple_blocks_test) {
        auto const actual = hash23::md5::calculate(
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
            static_cast<std::byte>(0x28), static_cast<std::byte>(0xa2), static_cast<std::byte>(0x50),
            static_cast<std::byte>(0x70), static_cast<std::byte>(0x84), static_cast<std::byte>(0x08),
            static_cast<std::byte>(0x4f), static_cast<std::byte>(0x45), static_cast<std::byte>(0xf5),
            static_cast<std::byte>(0x53), static_cast<std::byte>(0x23), static_cast<std::byte>(0xad),
            static_cast<std::byte>(0x23), static_cast<std::byte>(0xae), static_cast<std::byte>(0x03),
            static_cast<std::byte>(0x81),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(md5, payload_size_between_448_and_512_bit_test) {
        auto const actual = hash23::md5::calculate(
            R"(The quick brown fox jumps over the lazy dog. Just some more.)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xe9), static_cast<std::byte>(0x34), static_cast<std::byte>(0x2d),
            static_cast<std::byte>(0x5f), static_cast<std::byte>(0x8f), static_cast<std::byte>(0x0c),
            static_cast<std::byte>(0x8a), static_cast<std::byte>(0xef), static_cast<std::byte>(0xa5),
            static_cast<std::byte>(0xec), static_cast<std::byte>(0x71), static_cast<std::byte>(0xcc),
            static_cast<std::byte>(0x3f), static_cast<std::byte>(0x82), static_cast<std::byte>(0x9c),
            static_cast<std::byte>(0xa8),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(md5, empty_input_test) {
        constexpr auto actual = hash23::md5::calculate("");
        constexpr auto expected = std::array{
            static_cast<std::byte>(0xd4), static_cast<std::byte>(0x1d), static_cast<std::byte>(0x8c),
            static_cast<std::byte>(0xd9), static_cast<std::byte>(0x8f), static_cast<std::byte>(0x00),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x04), static_cast<std::byte>(0xe9),
            static_cast<std::byte>(0x80), static_cast<std::byte>(0x09), static_cast<std::byte>(0x98),
            static_cast<std::byte>(0xec), static_cast<std::byte>(0xf8), static_cast<std::byte>(0x42),
            static_cast<std::byte>(0x7e),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(md5, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::md5::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x69), static_cast<std::byte>(0x2b), static_cast<std::byte>(0x83),
            static_cast<std::byte>(0xef), static_cast<std::byte>(0xda), static_cast<std::byte>(0x03),
            static_cast<std::byte>(0x38), static_cast<std::byte>(0x5a), static_cast<std::byte>(0xa0),
            static_cast<std::byte>(0x2a), static_cast<std::byte>(0xdd), static_cast<std::byte>(0x81),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0xc5), static_cast<std::byte>(0x7f),
            static_cast<std::byte>(0x96),

        };
        EXPECT_EQ(expected, actual);
    }

    TEST(md5, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::md5::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x69), static_cast<std::byte>(0x2b), static_cast<std::byte>(0x83),
            static_cast<std::byte>(0xef), static_cast<std::byte>(0xda), static_cast<std::byte>(0x03),
            static_cast<std::byte>(0x38), static_cast<std::byte>(0x5a), static_cast<std::byte>(0xa0),
            static_cast<std::byte>(0x2a), static_cast<std::byte>(0xdd), static_cast<std::byte>(0x81),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0xc5), static_cast<std::byte>(0x7f),
            static_cast<std::byte>(0x96),

        };
        EXPECT_EQ(expected, actual);
    }
}
