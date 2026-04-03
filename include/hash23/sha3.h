//
// Created by Rene Windegger on 01/04/2026.
//

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>

namespace hash23 {
    enum class sha3_mode {
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
    };

    namespace detail::sha3 {
        template<std::size_t result_size>
        [[nodiscard]] static constexpr std::array<std::byte, result_size> finish_result(
            std::array<std::uint64_t, 25> const &sponge) {
            std::array<std::byte, result_size> result{};
            for (auto i = 0uz; i < result.size(); ++i) {
                auto const lane = i / sizeof(std::uint64_t);
                auto const shift = (i % sizeof(std::uint64_t)) * 8uz;
                result[i] = static_cast<std::byte>((sponge[lane] >> shift) & 0xFFu);
            }
            return result;
        }

        template<sha3_mode mode>
        class sha3_impl {
        public:
            static constexpr auto is_valid = false;
        };

        template<>
        class sha3_impl<sha3_mode::SHA3_224> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto result_size = 28uz;
            static constexpr auto rate_bytes = 144uz;
        };

        template<>
        class sha3_impl<sha3_mode::SHA3_256> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto result_size = 32uz;
            static constexpr auto rate_bytes = 136uz;
        };

        template<>
        class sha3_impl<sha3_mode::SHA3_384> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto result_size = 48uz;
            static constexpr auto rate_bytes = 104uz;
        };

        template<>
        class sha3_impl<sha3_mode::SHA3_512> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto result_size = 64uz;
            static constexpr auto rate_bytes = 72uz;
        };
    }

    template<sha3_mode mode>
    class sha3 {
    private:
        static_assert(detail::sha3::sha3_impl<mode>::is_valid, "Invalid SHA3 mode");

        static constexpr auto result_size = detail::sha3::sha3_impl<mode>::result_size;
        static constexpr auto block_size = detail::sha3::sha3_impl<mode>::rate_bytes;

        static constexpr auto round_constants = std::array<std::uint64_t, 24>{
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
        };

        static constexpr auto rotation_offsets = std::array<int, 25>{
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        };

        std::size_t buffer_size_ = 0;
        std::array<std::uint8_t, block_size> buffer_{};
        std::array<std::uint64_t, 25> sponge_{};

        [[nodiscard]] static constexpr std::size_t lane_index(std::size_t const x, std::size_t const y) {
            return x + 5uz * y;
        }

        constexpr void transform() {
            for (auto i = 0uz; i < block_size; ++i) {
                auto const lane = i / sizeof(std::uint64_t);
                auto const shift = (i % sizeof(std::uint64_t)) * 8uz;
                sponge_[lane] ^= static_cast<std::uint64_t>(buffer_[i]) << shift;
            }

            for (auto const round_constant: round_constants) {
                std::array<std::uint64_t, 5> c{};
                for (auto x = 0uz; x < 5uz; ++x) {
                    c[x] = sponge_[lane_index(x, 0)] ^ sponge_[lane_index(x, 1)] ^ sponge_[lane_index(x, 2)]
                           ^ sponge_[lane_index(x, 3)] ^ sponge_[lane_index(x, 4)];
                }

                std::array<std::uint64_t, 5> d{};
                for (auto x = 0uz; x < 5uz; ++x) {
                    d[x] = c[(x + 4uz) % 5uz] ^ std::rotl(c[(x + 1uz) % 5uz], 1);
                }

                for (auto x = 0uz; x < 5uz; ++x) {
                    for (auto y = 0uz; y < 5uz; ++y) {
                        sponge_[lane_index(x, y)] ^= d[x];
                    }
                }

                std::array<std::uint64_t, 25> b{};
                for (auto x = 0uz; x < 5uz; ++x) {
                    for (auto y = 0uz; y < 5uz; ++y) {
                        b[lane_index(y, (2uz * x + 3uz * y) % 5uz)] = std::rotl(
                            sponge_[lane_index(x, y)],
                            rotation_offsets[lane_index(x, y)]
                        );
                    }
                }

                for (auto x = 0uz; x < 5uz; ++x) {
                    for (auto y = 0uz; y < 5uz; ++y) {
                        sponge_[lane_index(x, y)] = b[lane_index(x, y)]
                                                    ^ ((~b[lane_index((x + 1uz) % 5uz, y)])
                                                       & b[lane_index((x + 2uz) % 5uz, y)]);
                    }
                }

                sponge_[0] ^= round_constant;
            }
        }

        template<typename T>
            requires std::ranges::contiguous_range<T>
                     and std::ranges::sized_range<T>
                     and (sizeof(std::ranges::range_value_t<T>) == 1)
        constexpr void update(T const &data) {
            auto const *const data_ptr = std::ranges::data(data);
            auto const data_size = std::ranges::size(data);
            auto const remaining = buffer_.size() - buffer_size_;
            auto const copy_bytes = std::min(data_size, remaining);
            // Manual byte copy for constexpr
            for (auto i = 0uz; i < copy_bytes; ++i) {
                buffer_[buffer_size_ + i] = static_cast<std::uint8_t>(data_ptr[i]);
            }
            buffer_size_ += copy_bytes;

            if (buffer_size_ < buffer_.size()) {
                return;
            }

            transform();

            auto offset = copy_bytes;
            auto const full_blocks = (data_size - copy_bytes) / buffer_.size();
            for (auto i = 0uz; i < full_blocks; ++i) {
                for (auto j = 0uz; j < buffer_.size(); ++j) {
                    buffer_[j] = static_cast<std::uint8_t>(data_ptr[offset + j]);
                }
                transform();
                offset += buffer_.size();
            }
            auto const leftover = data_size - offset;
            for (auto i = 0uz; i < leftover; ++i) {
                buffer_[i] = static_cast<std::uint8_t>(data_ptr[offset + i]);
            }
            buffer_size_ = leftover;
        }

        [[nodiscard]] constexpr std::array<std::byte, result_size> finalize() {
            std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.end(), 0);
            buffer_[buffer_size_] ^= 0x06;
            buffer_[buffer_.size() - 1] ^= 0x80;
            transform();

            return detail::sha3::finish_result<result_size>(sponge_);
        }

    public:
        template<typename T>
            requires std::ranges::contiguous_range<T>
                     and std::ranges::sized_range<T>
                     and (sizeof(std::ranges::range_value_t<T>) == 1)
        [[nodiscard]] static constexpr std::array<std::byte, result_size> calculate(T const &data) {
            sha3 r;
            r.update(data);
            return r.finalize();
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::array<std::byte, result_size> calculate(char const (&str)[N]) {
            auto const block = std::span(str, N - 1);
            return calculate(block);
        }
    };

    using sha3_224 = sha3<sha3_mode::SHA3_224>;
    using sha3_256 = sha3<sha3_mode::SHA3_256>;
    using sha3_384 = sha3<sha3_mode::SHA3_384>;
    using sha3_512 = sha3<sha3_mode::SHA3_512>;
}
