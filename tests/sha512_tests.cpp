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
            static_cast<std::byte>(0x1C), static_cast<std::byte>(0xD1), static_cast<std::byte>(0x98),
            static_cast<std::byte>(0xB2), static_cast<std::byte>(0xD), static_cast<std::byte>(0x7E),
            static_cast<std::byte>(0xFB), static_cast<std::byte>(0xC1), static_cast<std::byte>(0x60),
            static_cast<std::byte>(0xDA), static_cast<std::byte>(0x7E), static_cast<std::byte>(0x71),
            static_cast<std::byte>(0x73), static_cast<std::byte>(0x4B), static_cast<std::byte>(0x1E),
            static_cast<std::byte>(0x2), static_cast<std::byte>(0x34), static_cast<std::byte>(0x7E),
            static_cast<std::byte>(0xB9), static_cast<std::byte>(0x44), static_cast<std::byte>(0x9),
            static_cast<std::byte>(0xF9), static_cast<std::byte>(0x9), static_cast<std::byte>(0x35),
            static_cast<std::byte>(0x1B), static_cast<std::byte>(0xDC), static_cast<std::byte>(0x2C),
            static_cast<std::byte>(0x1A), static_cast<std::byte>(0x2D), static_cast<std::byte>(0x4C),
            static_cast<std::byte>(0x19), static_cast<std::byte>(0xC0), static_cast<std::byte>(0xE4),
            static_cast<std::byte>(0xD5), static_cast<std::byte>(0xA8), static_cast<std::byte>(0x61),
            static_cast<std::byte>(0xC8), static_cast<std::byte>(0xBE), static_cast<std::byte>(0x49),
            static_cast<std::byte>(0x85), static_cast<std::byte>(0x61), static_cast<std::byte>(0x19),
            static_cast<std::byte>(0xA), static_cast<std::byte>(0xB7), static_cast<std::byte>(0xAB),
            static_cast<std::byte>(0x98), static_cast<std::byte>(0x16), static_cast<std::byte>(0xF),
            static_cast<std::byte>(0x9F), static_cast<std::byte>(0x48), static_cast<std::byte>(0x2C),
            static_cast<std::byte>(0xDD), static_cast<std::byte>(0xAB), static_cast<std::byte>(0xD7),
            static_cast<std::byte>(0x44), static_cast<std::byte>(0x3C), static_cast<std::byte>(0x73),
            static_cast<std::byte>(0x96), static_cast<std::byte>(0x5), static_cast<std::byte>(0x34),
            static_cast<std::byte>(0x5C), static_cast<std::byte>(0xDD), static_cast<std::byte>(0xF),
            static_cast<std::byte>(0x13)
        };
        EXPECT_EQ(expected, actual);
    }
}
