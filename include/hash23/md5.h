//
// Created by Rene Windegger on 22/03/2026.
//

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <ranges>
#include <span>

namespace hash23 {
    class md5 {
    private:
        static constexpr std::array<int, 64> s = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        static constexpr std::array<std::uint32_t, 64> K = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
        };

        std::uint32_t a0_ = 0x67452301;
        std::uint32_t b0_ = 0xefcdab89;
        std::uint32_t c0_ = 0x98badcfe;
        std::uint32_t d0_ = 0x10325476;

        std::array<std::uint8_t, 64> buffer_{};
        std::size_t buffer_size_{}; // Number of bytes currently in the buffer
        std::uint64_t iterations_{}; // Number of 512-bit blocks processed

        constexpr void transform() {
            auto const M = std::bit_cast<std::array<std::uint32_t, 16> >(buffer_);

            std::uint32_t A = a0_;
            std::uint32_t B = b0_;
            std::uint32_t C = c0_;
            std::uint32_t D = d0_;

            for (auto i = 0; i < 64; ++i) {
                std::uint32_t F{};
                int g{};
                if (i < 16) {
                    F = (B & C) | (~B & D);
                    g = i;
                } else if (i < 32) {
                    F = (D & B) | (~D & C);
                    g = (5 * i + 1) % 16;
                } else if (i < 48) {
                    F = B ^ C ^ D;
                    g = (3 * i + 5) % 16;
                } else {
                    F = C ^ (B | ~D);
                    g = (7 * i) % 16;
                }
                F = F + A + K[i] + M[g];
                A = D;
                D = C;
                C = B;
                B = B + std::rotl(F, s[i]);
            }

            a0_ += A;
            b0_ += B;
            c0_ += C;
            d0_ += D;
        }

        template<typename T>
            requires std::ranges::contiguous_range<T> and (sizeof(std::ranges::range_value_t<T>) == 1)
        constexpr void update(T const &data) {
            std::size_t const remaining = buffer_.size() - buffer_size_;
            std::size_t const copy_bytes = std::min(data.size(), remaining);
            std::copy_n(data.begin(), copy_bytes, buffer_.data() + buffer_size_);
            buffer_size_ += copy_bytes;

            if (buffer_size_ < buffer_.size())
                return;

            transform();
            ++iterations_;

            std::size_t offset = copy_bytes;
            std::size_t const block_size = buffer_.size();
            std::size_t const full_blocks = (data.size() - copy_bytes) / block_size;
            for (std::size_t i = 0; i < full_blocks; ++i) {
                std::copy_n(data.data() + offset, block_size, buffer_.data());
                transform();
                offset += block_size;
                ++iterations_;
            }
            std::size_t const leftover = data.size() - offset;
            std::copy_n(data.data() + offset, leftover, buffer_.data());
            buffer_size_ = leftover;
        }

        [[nodiscard]] constexpr std::array<std::byte, 16> finalize() {
            std::uint64_t const total_bits = (iterations_ * buffer_.size() + buffer_size_) << 3;
            std::fill_n(buffer_.data() + buffer_size_, buffer_.size() - buffer_size_, 0);
            buffer_[buffer_size_] = 0x80;
            if (buffer_size_ < buffer_.size() - 8) {
                auto temp = std::bit_cast<std::array<std::uint8_t, 8> >(total_bits);
                std::copy_n(temp.data(), temp.size(), buffer_.data() + buffer_.size() - temp.size());
                transform();
            } else {
                transform();
                std::fill_n(buffer_.data(), buffer_.size(), 0);
                auto temp = std::bit_cast<std::array<std::uint8_t, 8> >(total_bits);
                std::copy_n(temp.data(), temp.size(), buffer_.data() + buffer_.size() - temp.size());
                transform();
            }

            std::array<std::byte, 16> result{};
            auto temp_a = std::bit_cast<std::array<std::byte, 4> >(a0_);
            auto temp_b = std::bit_cast<std::array<std::byte, 4> >(b0_);
            auto temp_c = std::bit_cast<std::array<std::byte, 4> >(c0_);
            auto temp_d = std::bit_cast<std::array<std::byte, 4> >(d0_);
            std::copy_n(temp_a.data(), temp_a.size(), result.data() + 0);
            std::copy_n(temp_b.data(), temp_b.size(), result.data() + 4);
            std::copy_n(temp_c.data(), temp_c.size(), result.data() + 8);
            std::copy_n(temp_d.data(), temp_d.size(), result.data() + 12);
            return result;
        }

    public:
        template<typename T>
            requires std::ranges::contiguous_range<T> and (sizeof(std::ranges::range_value_t<T>) == 1)
        [[nodiscard]] static constexpr std::array<std::byte, 16> calculate(T const &data) {
            md5 r;
            r.update(data);
            return r.finalize();
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::array<std::byte, 16> calculate(char const (&str)[N]) {
            auto const block = std::span(str, N - 1);
            return calculate(block);
        }
    };
}
