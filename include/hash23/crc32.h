//
// Created by Rene Windegger on 22/03/2026.
//

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <type_traits>

namespace hash23 {
    namespace detail::crc32 {
        [[nodiscard]] static constexpr std::array<std::uint32_t, 256> calculate_table() {
            std::array<std::uint32_t, 256> table{};
            std::uint32_t crc32 = 1;
            for (std::uint32_t i = 128; i; i >>= 1) {
                crc32 = (crc32 >> 1) ^ (crc32 & 1 ? 0xedb88320 : 0);
                for (std::uint32_t j = 0; j < 256; j += 2 * i) {
                    table.at(i + j) = crc32 ^ table.at(j);
                }
            }
            return table;
        }
    }

    class crc32 {
    private:
        static constexpr auto crc_table = detail::crc32::calculate_table();
        std::uint32_t hash_ = 0xFFFFFFFF;

        template<typename T>
            requires std::ranges::contiguous_range<T> and (sizeof(std::ranges::range_value_t<T>) == 1)
        constexpr void update(T const &data) {
            for (auto const &byte : data) {
                using value_type = std::remove_cvref_t<decltype(byte)>;
                std::uint8_t b;
                if constexpr (std::is_same_v<value_type, std::byte>) {
                    b = std::to_integer<std::uint8_t>(byte);
                } else {
                    b = static_cast<std::uint8_t>(byte);
                }
                hash_ ^= b;
                hash_ = (hash_ >> 8) ^ crc_table[hash_ & 0xFF];
            }
        }

        [[nodiscard]] constexpr std::uint32_t finalize() const {
            return hash_ ^ 0xFFFFFFFF;
        }

    public:
        template<typename T>
            requires std::ranges::contiguous_range<T> and (sizeof(std::ranges::range_value_t<T>) == 1)
        [[nodiscard]] static constexpr std::uint32_t calculate(T const &data) {
            crc32 r;
            r.update(data);
            return r.finalize();
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::uint32_t calculate(char const (&str)[N]) {
            auto const block = std::span(str, N - 1);
            return calculate(block);
        }
    };
}
