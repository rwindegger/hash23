//
// Created by Rene Windegger on 14/03/2025.
//

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <bigint23/bigint.hpp>

namespace hash23 {
    using uint128_t = bigint::bigint<bigint::BitWidth{128}, bigint::Signedness::Unsigned>;

    enum class sha2_mode {
        SHA2_224,
        SHA2_256,
        SHA2_384,
        SHA2_512,
    };

    namespace detail::sha2 {
        template<sha2_mode sha2_mode>
        class sha2_impl {
        public:
            static constexpr bool is_valid = false;
        };

        template<>
        class sha2_impl<sha2_mode::SHA2_256> {
        public:
            static constexpr bool is_valid = true;
            static constexpr std::size_t result_size = 32;
            static constexpr std::size_t block_size = 64;
            static constexpr std::size_t look_up_table_size = 64;
            static constexpr std::size_t left_shift = 2;

            using length_type = std::uint64_t;
            using hash_type = std::uint32_t;

            static constexpr std::array<hash_type, look_up_table_size> look_up_table{
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };

            static constexpr std::array<hash_type, 8> initial_hash_values{
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };

            [[nodiscard]] static constexpr std::array<std::byte, result_size> finish_result(
                std::array<hash_type, 8> const &hash) {
                std::array<std::byte, result_size> result{};
                for (std::size_t i = 0; i < hash.size(); ++i) {
                    hash_type const value = hash[i];
                    result[i * 4 + 0] = static_cast<std::byte>((value >> 24) & 0xFF);
                    result[i * 4 + 1] = static_cast<std::byte>((value >> 16) & 0xFF);
                    result[i * 4 + 2] = static_cast<std::byte>((value >> 8) & 0xFF);
                    result[i * 4 + 3] = static_cast<std::byte>(value & 0xFF);
                }
                return result;
            }

            [[nodiscard]] static constexpr hash_type to_big_endian(std::uint8_t const *b) {
                if constexpr (std::endian::native == std::endian::big) {
                    return static_cast<hash_type>(*((b) + 0)) | static_cast<hash_type>(*((b) + 1)) << 8 |
                           static_cast<hash_type>(*((b) + 2)) << 16 | static_cast<hash_type>(*((b) + 3)) << 24;
                } else {
                    return static_cast<hash_type>(*((b) + 3)) | static_cast<hash_type>(*((b) + 2)) << 8 |
                           static_cast<hash_type>(*((b) + 1)) << 16 | static_cast<hash_type>(*((b) + 0)) << 24;
                }
            }

            [[nodiscard]] static constexpr hash_type shift_right(hash_type const value, std::size_t const count) {
                return value >> count;
            }

            [[nodiscard]] static constexpr hash_type big_sigma_0(hash_type const value) {
                return std::rotr(value, 2) ^ std::rotr(value, 13) ^ std::rotr(value, 22);
            }

            [[nodiscard]] static constexpr hash_type big_sigma_1(hash_type const value) {
                return std::rotr(value, 6) ^ std::rotr(value, 11) ^ std::rotr(value, 25);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_0(hash_type const value) {
                return std::rotr(value, 7) ^ std::rotr(value, 18) ^ shift_right(value, 3);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_1(hash_type const value) {
                return std::rotr(value, 17) ^ std::rotr(value, 19) ^ shift_right(value, 10);
            }
        };

        template<>
        class sha2_impl<sha2_mode::SHA2_224> {
        public:
            static constexpr bool is_valid = true;
            static constexpr std::size_t result_size = 28;
            static constexpr std::size_t block_size = sha2_impl<sha2_mode::SHA2_256>::block_size;
            static constexpr std::size_t look_up_table_size = sha2_impl<sha2_mode::SHA2_256>::look_up_table_size;
            static constexpr std::size_t left_shift = sha2_impl<sha2_mode::SHA2_256>::left_shift;

            using length_type = sha2_impl<sha2_mode::SHA2_256>::length_type;
            using hash_type = sha2_impl<sha2_mode::SHA2_256>::hash_type;

            static constexpr std::array<hash_type, look_up_table_size> look_up_table = sha2_impl<
                sha2_mode::SHA2_256>::look_up_table;

            static constexpr std::array<hash_type, 8> initial_hash_values{
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
            };

            [[nodiscard]] static constexpr std::array<std::byte, result_size> finish_result(
                std::array<hash_type, 8> const &hash) {
                std::array<std::byte, result_size> result{};
                for (std::size_t i = 0; i < hash.size() - 1; ++i) {
                    hash_type const value = hash[i];
                    result[i * 4 + 0] = static_cast<std::byte>((value >> 24) & 0xFF);
                    result[i * 4 + 1] = static_cast<std::byte>((value >> 16) & 0xFF);
                    result[i * 4 + 2] = static_cast<std::byte>((value >> 8) & 0xFF);
                    result[i * 4 + 3] = static_cast<std::byte>(value & 0xFF);
                }
                return result;
            }

            [[nodiscard]] static constexpr hash_type to_big_endian(std::uint8_t const *b) {
                return sha2_impl<sha2_mode::SHA2_256>::to_big_endian(b);
            }

            [[nodiscard]] static constexpr hash_type big_sigma_0(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_256>::big_sigma_0(value);
            }

            [[nodiscard]] static constexpr hash_type big_sigma_1(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_256>::big_sigma_1(value);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_0(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_256>::small_sigma_0(value);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_1(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_256>::small_sigma_1(value);
            }
        };

        template<>
        class sha2_impl<sha2_mode::SHA2_512> {
        public:
            static constexpr bool is_valid = true;
            static constexpr std::size_t result_size = 64;
            static constexpr std::size_t block_size = 128;
            static constexpr std::size_t look_up_table_size = 80;
            static constexpr std::size_t left_shift = 3;

            using length_type = bigint::bigint<bigint::BitWidth{128}, bigint::Signedness::Unsigned>;
            using hash_type = std::uint64_t;

            static constexpr std::array<hash_type, look_up_table_size> look_up_table{
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

            static constexpr std::array<hash_type, 8> initial_hash_values{
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
            };

            [[nodiscard]] static constexpr std::array<std::byte, result_size> finish_result(
                std::array<hash_type, 8> const &hash) {
                std::array<std::byte, result_size> result{};
                for (std::size_t i = 0; i < hash.size(); ++i) {
                    hash_type const value = hash[i];
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

            [[nodiscard]] static constexpr hash_type to_big_endian(std::uint8_t const *b) {
                if constexpr (std::endian::native == std::endian::big) {
                    return static_cast<hash_type>(*((b) + 0)) | static_cast<uint64_t>(*((b) + 1)) << 8 |
                           static_cast<hash_type>(*((b) + 2)) << 16 | static_cast<uint64_t>(*((b) + 3)) << 24 |
                           static_cast<hash_type>(*((b) + 4)) << 32 | static_cast<uint64_t>(*((b) + 5)) << 40 |
                           static_cast<hash_type>(*((b) + 6)) << 48 | static_cast<uint64_t>(*((b) + 7)) << 56;
                } else {
                    return static_cast<hash_type>(*((b) + 7)) | static_cast<hash_type>(*((b) + 6)) << 8 |
                           static_cast<hash_type>(*((b) + 5)) << 16 | static_cast<hash_type>(*((b) + 4)) << 24 |
                           static_cast<hash_type>(*((b) + 3)) << 32 | static_cast<hash_type>(*((b) + 2)) << 40 |
                           static_cast<hash_type>(*((b) + 1)) << 48 | static_cast<hash_type>(*((b) + 0)) << 56;
                }
            }

            [[nodiscard]] static constexpr hash_type shift_right(hash_type const value, std::size_t const count) {
                return value >> count;
            }

            [[nodiscard]] static constexpr hash_type big_sigma_0(hash_type const value) {
                return std::rotr(value, 28) ^ std::rotr(value, 34) ^ std::rotr(value, 39);
            }

            [[nodiscard]] static constexpr hash_type big_sigma_1(hash_type const value) {
                return std::rotr(value, 14) ^ std::rotr(value, 18) ^ std::rotr(value, 41);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_0(hash_type const value) {
                return std::rotr(value, 1) ^ std::rotr(value, 8) ^ shift_right(value, 7);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_1(hash_type const value) {
                return std::rotr(value, 19) ^ std::rotr(value, 61) ^ shift_right(value, 6);
            }
        };

        template<>
        class sha2_impl<sha2_mode::SHA2_384> {
        public:
            static constexpr bool is_valid = true;
            static constexpr std::size_t result_size = 48;
            static constexpr std::size_t block_size = sha2_impl<sha2_mode::SHA2_512>::block_size;
            static constexpr std::size_t look_up_table_size = sha2_impl<sha2_mode::SHA2_512>::look_up_table_size;
            static constexpr std::size_t left_shift = sha2_impl<sha2_mode::SHA2_512>::left_shift;

            using length_type = sha2_impl<sha2_mode::SHA2_512>::length_type;
            using hash_type = sha2_impl<sha2_mode::SHA2_512>::hash_type;

            static constexpr std::array<hash_type, look_up_table_size> look_up_table = sha2_impl<
                sha2_mode::SHA2_512>::look_up_table;

            static constexpr std::array<hash_type, 8> initial_hash_values{
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
            };

            [[nodiscard]] static constexpr std::array<std::byte, result_size> finish_result(
                std::array<hash_type, 8> const &hash) {
                std::array<std::byte, result_size> result{};
                for (std::size_t i = 0; i < hash.size() - 2; ++i) {
                    hash_type const value = hash[i];
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

            [[nodiscard]] static constexpr hash_type to_big_endian(std::uint8_t const *b) {
                return sha2_impl<sha2_mode::SHA2_512>::to_big_endian(b);
            }

            [[nodiscard]] static constexpr hash_type big_sigma_0(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_512>::big_sigma_0(value);
            }

            [[nodiscard]] static constexpr hash_type big_sigma_1(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_512>::big_sigma_1(value);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_0(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_512>::small_sigma_0(value);
            }

            [[nodiscard]] static constexpr hash_type small_sigma_1(hash_type const value) {
                return sha2_impl<sha2_mode::SHA2_512>::small_sigma_1(value);
            }
        };
    }

    template<sha2_mode sha2_mode>
    class sha2 {
    private:
        static_assert(detail::sha2::sha2_impl<sha2_mode>::is_valid, "Invalid SHA2 mode");

        static constexpr std::size_t result_size = detail::sha2::sha2_impl<sha2_mode>::result_size;
        static constexpr std::size_t block_size = detail::sha2::sha2_impl<sha2_mode>::block_size;

        using length_type = detail::sha2::sha2_impl<sha2_mode>::length_type;
        using hash_type = detail::sha2::sha2_impl<sha2_mode>::hash_type;

        std::array<hash_type, 8> hash_ = detail::sha2::sha2_impl<sha2_mode>::initial_hash_values;
        length_type iterations_ = 0;
        std::size_t buffer_size_ = 0;
        std::array<std::uint8_t, block_size> buffer_{};

        [[nodiscard]] static constexpr hash_type ch(hash_type const x, hash_type const y, hash_type const z) {
            return (x & y) ^ (~x & z);
        }

        [[nodiscard]] static constexpr hash_type maj(hash_type const x, hash_type const y, hash_type const z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        constexpr void transform() {
            std::array<hash_type, detail::sha2::sha2_impl<sha2_mode>::look_up_table_size> w{};
            uint8_t const *tblock = buffer_.data();
            for (std::size_t j = 0; j < 16; ++j) {
                w[j] = detail::sha2::sha2_impl<sha2_mode>::to_big_endian(
                    &tblock[j << detail::sha2::sha2_impl<sha2_mode>::left_shift]);
            }
            for (std::size_t j = 16; j < detail::sha2::sha2_impl<sha2_mode>::look_up_table_size; ++j) {
                w[j] = detail::sha2::sha2_impl<sha2_mode>::small_sigma_1(w[j - 2]) + w[j - 7]
                       + detail::sha2::sha2_impl<sha2_mode>::small_sigma_0(w[j - 15]) + w[j - 16];
            }
            std::array<hash_type, 8> v = hash_;
            for (std::size_t j = 0; j < detail::sha2::sha2_impl<sha2_mode>::look_up_table_size; ++j) {
                hash_type const t = v[7] + detail::sha2::sha2_impl<sha2_mode>::big_sigma_1(v[4])
                                    + ch(v[4], v[5], v[6])
                                    + detail::sha2::sha2_impl<sha2_mode>::look_up_table[j] + w[j];
                hash_type const u = detail::sha2::sha2_impl<sha2_mode>::big_sigma_0(v[0]) + maj(v[0], v[1], v[2]);
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

        template<typename T>
            requires std::ranges::contiguous_range<T>
                     and std::ranges::sized_range<T>
                     and (sizeof(std::ranges::range_value_t<T>) == 1)
        constexpr void update(T const &data) {
            auto const *const data_ptr = std::ranges::data(data);
            std::size_t const data_size = std::ranges::size(data);
            std::size_t const remaining = buffer_.size() - buffer_size_;
            std::size_t const copy_bytes = std::min(data_size, remaining);
            // Manual byte copy for constexpr
            for (std::size_t i = 0; i < copy_bytes; ++i) {
                buffer_[buffer_size_ + i] = static_cast<std::uint8_t>(data_ptr[i]);
            }
            buffer_size_ += copy_bytes;

            if (buffer_size_ < buffer_.size()) {
                return;
            }

            transform();
            ++iterations_;

            std::size_t offset = copy_bytes;
            std::size_t const full_blocks = (data_size - copy_bytes) / block_size;
            for (std::size_t i = 0; i < full_blocks; ++i) {
                for (std::size_t j = 0; j < block_size; ++j) {
                    buffer_[j] = static_cast<std::uint8_t>(data_ptr[offset + j]);
                }
                transform();
                offset += block_size;
                ++iterations_;
            }
            std::size_t const leftover = data_size - offset;
            for (std::size_t i = 0; i < leftover; ++i) {
                buffer_[i] = static_cast<std::uint8_t>(data_ptr[offset + i]);
            }
            buffer_size_ = leftover;
        }

        [[nodiscard]] constexpr std::array<std::byte, result_size> finalize() {
            uint128_t const total_bits = (iterations_ * buffer_.size() + buffer_size_) << 3;
            uint128_t total_be = total_bits;
            if constexpr (std::endian::native == std::endian::little) {
                total_be = bigint::byteswap(total_be);
            }
            std::fill_n(buffer_.data() + buffer_size_, buffer_.size() - buffer_size_, 0);
            buffer_[buffer_size_] = 0x80;
            if (buffer_size_ < buffer_.size() - 16) {
                auto temp = std::bit_cast<std::array<std::uint8_t, 16> >(total_be);
                std::copy_n(temp.data(), temp.size(), buffer_.data() + buffer_.size() - temp.size());
                transform();
            } else {
                transform();
                std::fill_n(buffer_.data(), buffer_.size(), 0);
                auto temp = std::bit_cast<std::array<std::uint8_t, 16> >(total_be);
                std::copy_n(temp.data(), temp.size(), buffer_.data() + buffer_.size() - temp.size());
                transform();
            }

            return detail::sha2::sha2_impl<sha2_mode>::finish_result(hash_);
        }

    public:
        template<typename T>
            requires std::ranges::contiguous_range<T>
                     and std::ranges::sized_range<T>
                     and (sizeof(std::ranges::range_value_t<T>) == 1)
        [[nodiscard]] static constexpr std::array<std::byte, result_size> calculate(T const &data) {
            sha2 r;
            r.update(data);
            return r.finalize();
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::array<std::byte, result_size> calculate(char const (&str)[N]) {
            auto const block = std::span(str, N - 1);
            return calculate(block);
        }
    };

    using sha2_224 = sha2<sha2_mode::SHA2_224>;
    using sha2_256 = sha2<sha2_mode::SHA2_256>;
    using sha2_384 = sha2<sha2_mode::SHA2_384>;
    using sha2_512 = sha2<sha2_mode::SHA2_512>;
}
