//
// Created by Rene Windegger on 14/03/2025.
//

#include <gtest/gtest.h>
#include <hash23/hash23.h>

namespace {
    TEST(sha512, simple_test) {
        auto const actual = hash23::sha512::calculate("Hello, World!");
        constexpr std::array<std::byte, 64> expected = {
            static_cast<std::byte>(0x37), static_cast<std::byte>(0x4D), static_cast<std::byte>(0x79),
            static_cast<std::byte>(0x4A), static_cast<std::byte>(0x95), static_cast<std::byte>(0xCD),
            static_cast<std::byte>(0xCF), static_cast<std::byte>(0xD8), static_cast<std::byte>(0xB3),
            static_cast<std::byte>(0x59), static_cast<std::byte>(0x93), static_cast<std::byte>(0x18),
            static_cast<std::byte>(0x5F), static_cast<std::byte>(0xEF), static_cast<std::byte>(0x9B),
            static_cast<std::byte>(0xA3), static_cast<std::byte>(0x68), static_cast<std::byte>(0xF1),
            static_cast<std::byte>(0x60), static_cast<std::byte>(0xD8), static_cast<std::byte>(0xDA),
            static_cast<std::byte>(0xF4), static_cast<std::byte>(0x32), static_cast<std::byte>(0xD0),
            static_cast<std::byte>(0x8B), static_cast<std::byte>(0xA9), static_cast<std::byte>(0xF1),
            static_cast<std::byte>(0xED), static_cast<std::byte>(0x1E), static_cast<std::byte>(0x5A),
            static_cast<std::byte>(0xBE), static_cast<std::byte>(0x6C), static_cast<std::byte>(0xC6),
            static_cast<std::byte>(0x92), static_cast<std::byte>(0x91), static_cast<std::byte>(0xE0),
            static_cast<std::byte>(0xFA), static_cast<std::byte>(0x2F), static_cast<std::byte>(0xE0),
            static_cast<std::byte>(0x0), static_cast<std::byte>(0x6A), static_cast<std::byte>(0x52),
            static_cast<std::byte>(0x57), static_cast<std::byte>(0xE), static_cast<std::byte>(0xF1),
            static_cast<std::byte>(0x8C), static_cast<std::byte>(0x19), static_cast<std::byte>(0xDE),
            static_cast<std::byte>(0xF4), static_cast<std::byte>(0xE6), static_cast<std::byte>(0x17),
            static_cast<std::byte>(0xC3), static_cast<std::byte>(0x3C), static_cast<std::byte>(0xE5),
            static_cast<std::byte>(0x2E), static_cast<std::byte>(0xF0), static_cast<std::byte>(0xA6),
            static_cast<std::byte>(0xE5), static_cast<std::byte>(0xFB), static_cast<std::byte>(0xE3),
            static_cast<std::byte>(0x18), static_cast<std::byte>(0xCB), static_cast<std::byte>(0x3),
            static_cast<std::byte>(0x87)
        };
        EXPECT_EQ(expected, actual);
    }

    TEST(sha512, long_test) {
        auto const actual = hash23::sha512::calculate(
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
        constexpr std::array<std::byte, 64> expected = {
            static_cast<std::byte>(0x18), static_cast<std::byte>(0xB0), static_cast<std::byte>(0x6B),
            static_cast<std::byte>(0x49), static_cast<std::byte>(0x8), static_cast<std::byte>(0x42),
            static_cast<std::byte>(0x8D), static_cast<std::byte>(0xB8), static_cast<std::byte>(0xD0),
            static_cast<std::byte>(0x76), static_cast<std::byte>(0x7), static_cast<std::byte>(0x56),
            static_cast<std::byte>(0x7D), static_cast<std::byte>(0x84), static_cast<std::byte>(0x70),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0xA), static_cast<std::byte>(0xFE),
            static_cast<std::byte>(0x9B), static_cast<std::byte>(0x60), static_cast<std::byte>(0xBB),
            static_cast<std::byte>(0x9B), static_cast<std::byte>(0x4C), static_cast<std::byte>(0x96),
            static_cast<std::byte>(0xE4), static_cast<std::byte>(0xAB), static_cast<std::byte>(0xD5),
            static_cast<std::byte>(0x99), static_cast<std::byte>(0x2D), static_cast<std::byte>(0xEE),
            static_cast<std::byte>(0x4A), static_cast<std::byte>(0xE9), static_cast<std::byte>(0xB),
            static_cast<std::byte>(0x20), static_cast<std::byte>(0x3E), static_cast<std::byte>(0x2B),
            static_cast<std::byte>(0x76), static_cast<std::byte>(0x3F), static_cast<std::byte>(0x85),
            static_cast<std::byte>(0xEB), static_cast<std::byte>(0xC9), static_cast<std::byte>(0xBA),
            static_cast<std::byte>(0xFA), static_cast<std::byte>(0x8C), static_cast<std::byte>(0x7),
            static_cast<std::byte>(0x92), static_cast<std::byte>(0xC4), static_cast<std::byte>(0xEA),
            static_cast<std::byte>(0x76), static_cast<std::byte>(0x8C), static_cast<std::byte>(0x8A),
            static_cast<std::byte>(0x6B), static_cast<std::byte>(0x61), static_cast<std::byte>(0x6E),
            static_cast<std::byte>(0x4F), static_cast<std::byte>(0xBC), static_cast<std::byte>(0xDD),
            static_cast<std::byte>(0x56), static_cast<std::byte>(0xF3), static_cast<std::byte>(0x25),
            static_cast<std::byte>(0x9D), static_cast<std::byte>(0x8C), static_cast<std::byte>(0xB1),
            static_cast<std::byte>(0x3)
        };
        EXPECT_EQ(expected, actual);
    }
}
