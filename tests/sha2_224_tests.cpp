//
// Created by Rene Windegger on 14/03/2025.
//

#include <array>
#include <cstddef>
#include <string>
#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha2_224, single_block_test) {
        auto const actual = hash23::sha2_224::calculate("Hello, World!");
        constexpr std::array expected = {
            static_cast<std::byte>(0x72), static_cast<std::byte>(0xa2), static_cast<std::byte>(0x3d),
            static_cast<std::byte>(0xfa), static_cast<std::byte>(0x41), static_cast<std::byte>(0x1b),
            static_cast<std::byte>(0xa6), static_cast<std::byte>(0xfd), static_cast<std::byte>(0xe0),
            static_cast<std::byte>(0x1d), static_cast<std::byte>(0xbf), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0xf3), static_cast<std::byte>(0xb0), static_cast<std::byte>(0x0a),
            static_cast<std::byte>(0x70), static_cast<std::byte>(0x9c), static_cast<std::byte>(0x93),
            static_cast<std::byte>(0xeb), static_cast<std::byte>(0xf2), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0xdc), static_cast<std::byte>(0x29), static_cast<std::byte>(0xe2),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0xb2), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0xff),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, single_block_string_test) {
        auto const actual = hash23::sha2_224::calculate(std::string{"Hello, World!"});
        constexpr std::array expected = {
            static_cast<std::byte>(0x72), static_cast<std::byte>(0xa2), static_cast<std::byte>(0x3d),
            static_cast<std::byte>(0xfa), static_cast<std::byte>(0x41), static_cast<std::byte>(0x1b),
            static_cast<std::byte>(0xa6), static_cast<std::byte>(0xfd), static_cast<std::byte>(0xe0),
            static_cast<std::byte>(0x1d), static_cast<std::byte>(0xbf), static_cast<std::byte>(0xab),
            static_cast<std::byte>(0xf3), static_cast<std::byte>(0xb0), static_cast<std::byte>(0x0a),
            static_cast<std::byte>(0x70), static_cast<std::byte>(0x9c), static_cast<std::byte>(0x93),
            static_cast<std::byte>(0xeb), static_cast<std::byte>(0xf2), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0xdc), static_cast<std::byte>(0x29), static_cast<std::byte>(0xe2),
            static_cast<std::byte>(0xd8), static_cast<std::byte>(0xb2), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0xff),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, multiple_blocks_test) {
        auto const actual = hash23::sha2_224::calculate(
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
            static_cast<std::byte>(0x05), static_cast<std::byte>(0x14), static_cast<std::byte>(0xa4),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x63),
            static_cast<std::byte>(0xa7), static_cast<std::byte>(0x91), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x0d), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0x84), static_cast<std::byte>(0xc1), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0xe4), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xaf), static_cast<std::byte>(0x7b),
            static_cast<std::byte>(0x0d), static_cast<std::byte>(0xfd), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0x58), static_cast<std::byte>(0x03), static_cast<std::byte>(0x15),
            static_cast<std::byte>(0x57),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, payload_size_between_480_and_512_bit_test) {
        auto const actual = hash23::sha2_224::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 5)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0xd2), static_cast<std::byte>(0x1a), static_cast<std::byte>(0x5f),
            static_cast<std::byte>(0xac), static_cast<std::byte>(0x37), static_cast<std::byte>(0xa8),
            static_cast<std::byte>(0xac), static_cast<std::byte>(0x29), static_cast<std::byte>(0xf4),
            static_cast<std::byte>(0x08), static_cast<std::byte>(0x5b), static_cast<std::byte>(0xbf),
            static_cast<std::byte>(0xdb), static_cast<std::byte>(0x1a), static_cast<std::byte>(0x47),
            static_cast<std::byte>(0xba), static_cast<std::byte>(0x7e), static_cast<std::byte>(0x41),
            static_cast<std::byte>(0xb7), static_cast<std::byte>(0x2b), static_cast<std::byte>(0x3e),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x99), static_cast<std::byte>(0x1d),
            static_cast<std::byte>(0xe1), static_cast<std::byte>(0xf4), static_cast<std::byte>(0xaa),
            static_cast<std::byte>(0x54),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, payload_size_exactly_512_bit_test) {
        auto const actual = hash23::sha2_224::calculate(
            R"(Hello, World!
This is a text that will hit the sweet spot of 512)"
        );
        constexpr std::array expected = {
            static_cast<std::byte>(0x74), static_cast<std::byte>(0x82), static_cast<std::byte>(0xae),
            static_cast<std::byte>(0x17), static_cast<std::byte>(0x90), static_cast<std::byte>(0x98),
            static_cast<std::byte>(0x83), static_cast<std::byte>(0x77), static_cast<std::byte>(0x44),
            static_cast<std::byte>(0x27), static_cast<std::byte>(0xde), static_cast<std::byte>(0x22),
            static_cast<std::byte>(0xe5), static_cast<std::byte>(0x08), static_cast<std::byte>(0xce),
            static_cast<std::byte>(0x5b), static_cast<std::byte>(0x73), static_cast<std::byte>(0x5c),
            static_cast<std::byte>(0x62), static_cast<std::byte>(0x2a), static_cast<std::byte>(0xed),
            static_cast<std::byte>(0x81), static_cast<std::byte>(0x9e), static_cast<std::byte>(0xc5),
            static_cast<std::byte>(0x16), static_cast<std::byte>(0xed), static_cast<std::byte>(0x35),
            static_cast<std::byte>(0xb7),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, payload_size_exactly_480_bit_test) {
        auto const actual = hash23::sha2_224::calculate(R"(Hello, World!
This is a text that will hit the sweet spot of)");
        constexpr std::array expected = {
            static_cast<std::byte>(0x97), static_cast<std::byte>(0xf0), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0xfb), static_cast<std::byte>(0x28), static_cast<std::byte>(0x86),
            static_cast<std::byte>(0x1f), static_cast<std::byte>(0x72), static_cast<std::byte>(0x69),
            static_cast<std::byte>(0xf4), static_cast<std::byte>(0xa3), static_cast<std::byte>(0x02),
            static_cast<std::byte>(0xa2), static_cast<std::byte>(0x0c), static_cast<std::byte>(0x2a),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x13), static_cast<std::byte>(0xbe),
            static_cast<std::byte>(0x0c), static_cast<std::byte>(0xeb), static_cast<std::byte>(0x8a),
            static_cast<std::byte>(0xea), static_cast<std::byte>(0x00), static_cast<std::byte>(0xbf),
            static_cast<std::byte>(0x4a), static_cast<std::byte>(0x54), static_cast<std::byte>(0xf2),
            static_cast<std::byte>(0x1d),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, multiple_blocks_constexpr_test) {
        constexpr auto actual = hash23::sha2_224::calculate(
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
            static_cast<std::byte>(0x05), static_cast<std::byte>(0x14), static_cast<std::byte>(0xa4),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x63),
            static_cast<std::byte>(0xa7), static_cast<std::byte>(0x91), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x0d), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0x84), static_cast<std::byte>(0xc1), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0xe4), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xaf), static_cast<std::byte>(0x7b),
            static_cast<std::byte>(0x0d), static_cast<std::byte>(0xfd), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0x58), static_cast<std::byte>(0x03), static_cast<std::byte>(0x15),
            static_cast<std::byte>(0x57),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, multiple_blocks_string_test) {
        auto const actual = hash23::sha2_224::calculate(std::string{
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
            static_cast<std::byte>(0x05), static_cast<std::byte>(0x14), static_cast<std::byte>(0xa4),
            static_cast<std::byte>(0xe4), static_cast<std::byte>(0x4c), static_cast<std::byte>(0x63),
            static_cast<std::byte>(0xa7), static_cast<std::byte>(0x91), static_cast<std::byte>(0x9a),
            static_cast<std::byte>(0xd0), static_cast<std::byte>(0x0d), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0x84), static_cast<std::byte>(0xc1), static_cast<std::byte>(0xb5),
            static_cast<std::byte>(0xc8), static_cast<std::byte>(0xe4), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0x42), static_cast<std::byte>(0xaf), static_cast<std::byte>(0x7b),
            static_cast<std::byte>(0x0d), static_cast<std::byte>(0xfd), static_cast<std::byte>(0x40),
            static_cast<std::byte>(0x58), static_cast<std::byte>(0x03), static_cast<std::byte>(0x15),
            static_cast<std::byte>(0x57),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, high_byte_values_test) {
        constexpr auto data = std::array{
            static_cast<signed char>(-128), static_cast<signed char>(-85),
            static_cast<signed char>(-1), static_cast<signed char>(0), static_cast<signed char>(127)
        };
        constexpr auto actual = hash23::sha2_224::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x24), static_cast<std::byte>(0x98), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0x0d), static_cast<std::byte>(0x78), static_cast<std::byte>(0x6a),
            static_cast<std::byte>(0xa6), static_cast<std::byte>(0x14), static_cast<std::byte>(0xde),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0x0a), static_cast<std::byte>(0xd4),
            static_cast<std::byte>(0x10), static_cast<std::byte>(0x0f), static_cast<std::byte>(0x6c),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x7a), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0xe3), static_cast<std::byte>(0xeb), static_cast<std::byte>(0x6f),
            static_cast<std::byte>(0x00), static_cast<std::byte>(0x5e), static_cast<std::byte>(0x5b),
            static_cast<std::byte>(0x5c), static_cast<std::byte>(0x14), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0x2f),
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha2_224, std_byte_test) {
        constexpr auto data = std::array{
            std::byte{0x80}, std::byte{0xAB}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x7F}
        };
        constexpr auto actual = hash23::sha2_224::calculate(data);
        constexpr auto expected = std::array{
            static_cast<std::byte>(0x24), static_cast<std::byte>(0x98), static_cast<std::byte>(0xcd),
            static_cast<std::byte>(0x0d), static_cast<std::byte>(0x78), static_cast<std::byte>(0x6a),
            static_cast<std::byte>(0xa6), static_cast<std::byte>(0x14), static_cast<std::byte>(0xde),
            static_cast<std::byte>(0xbb), static_cast<std::byte>(0x0a), static_cast<std::byte>(0xd4),
            static_cast<std::byte>(0x10), static_cast<std::byte>(0x0f), static_cast<std::byte>(0x6c),
            static_cast<std::byte>(0xb2), static_cast<std::byte>(0x7a), static_cast<std::byte>(0xd3),
            static_cast<std::byte>(0xe3), static_cast<std::byte>(0xeb), static_cast<std::byte>(0x6f),
            static_cast<std::byte>(0x00), static_cast<std::byte>(0x5e), static_cast<std::byte>(0x5b),
            static_cast<std::byte>(0x5c), static_cast<std::byte>(0x14), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0x2f),
        };
        EXPECT_EQ(expected, actual);
    }
}
