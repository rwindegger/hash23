//
// Created by Rene Windegger on 14/03/2025.
//

#pragma once

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>

namespace hash23 {
    class sha2_512 {
    private:
        static constexpr std::array<std::uint64_t, 80> look_up_table_{
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };
        std::array<std::uint64_t, 8> hash_{
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        };
        std::size_t iterations_ = 0;
        std::size_t buffer_size_ = 0;
        std::array<std::uint8_t, 128> buffer_{};

        template<typename T, std::size_t N = sizeof(T) * CHAR_BIT>
        static constexpr T rotate_right(T const value, std::size_t const count) {
            return (value >> (count & (N - 1))) | (value << (-(count & (N - 1)) & (N - 1)));
        }

        template<typename T>
        static constexpr T shift_right(T const value, std::size_t const count) {
            return value >> count;
        }

        template<typename T>
        static constexpr T ch(T const x, T const y, T const z) {
            return (x & y) ^ (~x & z);
        }

        template<typename T>
        static constexpr T maj(T const x, T const y, T const z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        template<typename T>
        static constexpr T big_sigma_0(T const value) {
            return rotate_right(value, 28) ^ rotate_right(value, 34) ^ rotate_right(value, 39);
        }

        template<typename T>
        static constexpr T big_sigma_1(T const value) {
            return rotate_right(value, 14) ^ rotate_right(value, 18) ^ rotate_right(value, 41);
        }

        template<typename T>
        static constexpr T small_sigma_0(T const value) {
            return rotate_right(value, 1) ^ rotate_right(value, 8) ^ shift_right(value, 7);
        }

        template<typename T>
        static constexpr T small_sigma_1(T const value) {
            return rotate_right(value, 19) ^ rotate_right(value, 61) ^ shift_right(value, 6);
        }

        constexpr void transform() {
            constexpr auto to_big_endian = [](auto const *b) {
                if constexpr (std::endian::native == std::endian::big) {
                    return static_cast<uint64_t>(*((b) + 0)) | static_cast<uint64_t>(*((b) + 1)) << 8 |
                           static_cast<uint64_t>(*((b) + 2)) << 16 | static_cast<uint64_t>(*((b) + 3)) << 24 |
                           static_cast<uint64_t>(*((b) + 4)) << 32 | static_cast<uint64_t>(*((b) + 5)) << 40 |
                           static_cast<uint64_t>(*((b) + 6)) << 48 | static_cast<uint64_t>(*((b) + 7)) << 56;
                } else {
                    return static_cast<uint64_t>(*((b) + 7)) | static_cast<uint64_t>(*((b) + 6)) << 8 |
                           static_cast<uint64_t>(*((b) + 5)) << 16 | static_cast<uint64_t>(*((b) + 4)) << 24 |
                           static_cast<uint64_t>(*((b) + 3)) << 32 | static_cast<uint64_t>(*((b) + 2)) << 40 |
                           static_cast<uint64_t>(*((b) + 1)) << 48 | static_cast<uint64_t>(*((b) + 0)) << 56;
                }
            };

            std::array<uint64_t, 80> w{};
            uint8_t const *tblock = buffer_.data();
            for (std::size_t j = 0; j < 16; ++j) {
                w[j] = to_big_endian(&tblock[j << 3]);
            }
            for (std::size_t j = 16; j < 80; ++j) {
                w[j] = small_sigma_1(w[j - 2]) + w[j - 7] + small_sigma_0(w[j - 15]) + w[j - 16];
            }
            std::array<uint64_t, 8> v = hash_;
            for (std::size_t j = 0; j < 80; ++j) {
                std::uint64_t const t = v[7] + big_sigma_1(v[4]) + ch(v[4], v[5], v[6]) + look_up_table_[j] + w[j];
                std::uint64_t const u = big_sigma_0(v[0]) + maj(v[0], v[1], v[2]);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3] + t;
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t + u;
            }
            for (size_t j = 0; j < 8; ++j) {
                hash_[j] += v[j];
            }
        }

        constexpr void update(std::span<std::uint8_t const> const data) {
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

        constexpr std::array<std::byte, 64> finalize() {
            constexpr auto to_big_endian = [](auto const x, auto *b) constexpr {
                if constexpr (std::endian::native == std::endian::big) {
                    *b = static_cast<std::uint8_t>(x);
                    *(b + 1) = static_cast<std::uint8_t>(x >> 8);
                    *(b + 2) = static_cast<std::uint8_t>(x >> 16);
                    *(b + 3) = static_cast<std::uint8_t>(x >> 24);
                } else {
                    *(b + 3) = static_cast<std::uint8_t>(x);
                    *(b + 2) = static_cast<std::uint8_t>(x >> 8);
                    *(b + 1) = static_cast<std::uint8_t>(x >> 16);
                    *b = static_cast<std::uint8_t>(x >> 24);
                }
            };

            // TODO: total_bits should be a 128bit integer
            std::size_t const total_bits = (iterations_ * buffer_.size() + buffer_size_) << 3;
            std::fill_n(buffer_.data() + buffer_size_, buffer_.size() - buffer_size_, 0);
            buffer_[buffer_size_] = 0x80;
            if (buffer_size_ < buffer_.size() - 16) {
                to_big_endian(total_bits, buffer_.data() + buffer_.size() - 4);
                transform();
            } else {
                transform();
                std::fill_n(buffer_.data(), buffer_.size(), 0);
                to_big_endian(total_bits, buffer_.data() + buffer_.size() - 4);
                transform();
            }

            std::array<std::byte, 64> result{};
            for (std::size_t i = 0; i < hash_.size(); ++i) {
                std::uint64_t const value = hash_[i];
                result[i * 8 + 0] = static_cast<std::byte>((value >> 56) & 0xFF);
                result[i * 8 + 1] = static_cast<std::byte>((value >> 48) & 0xFF);
                result[i * 8 + 2] = static_cast<std::byte>((value >> 40) & 0xFF);
                result[i * 8 + 3] = static_cast<std::byte>((value >> 32) & 0xFF);
                result[i * 8 + 4] = static_cast<std::byte>((value >> 24) & 0xFF);
                result[i * 8 + 5] = static_cast<std::byte>((value >> 16) & 0xFF);
                result[i * 8 + 6] = static_cast<std::byte>((value >> 8) & 0xFF);
                result[i * 8 + 7] = static_cast<std::byte>(value & 0xFF);
            }
            return result;
        }

    public:
        static std::array<std::byte, 64> calculate(std::span<std::uint8_t const> const data) {
            sha2_512 r;
            r.update(data);
            return r.finalize();
        }

        static std::array<std::byte, 64> calculate(std::string const &str) {
            auto const block = std::span(reinterpret_cast<std::uint8_t const *>(str.data()), str.size());
            return calculate(block);
        }

        template<std::size_t N>
        static std::array<std::byte, 64> calculate(char const (&str)[N]) {
            auto const block = std::span(reinterpret_cast<std::uint8_t const *>(str), N - 1);
            return calculate(block);
        }
    };
}
