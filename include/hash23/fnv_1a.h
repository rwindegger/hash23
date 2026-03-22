//
// Created by Rene Windegger on 22/03/2026.
//

#pragma once

#include <ranges>
#include <span>

namespace hash23 {
    class fnv_1a {
    private:
        std::size_t hash_ = offset_basis();

        [[nodiscard]] static constexpr std::size_t prime() {
            static_assert(sizeof(std::size_t) == 4 || sizeof(std::size_t) == 8,
                          "hash23::fnv_1::prime requires 32-bit or 64-bit std::size_t");
            if constexpr (sizeof(std::size_t) == 4) {
                return 0x01000193uz;
            } else {
                return 0x00000100000001b3uz;
            }
        }

        [[nodiscard]] static constexpr std::size_t offset_basis() {
            static_assert(sizeof(std::size_t) == 4 || sizeof(std::size_t) == 8,
                          "hash23::fnv_1::offset_basis requires 32-bit or 64-bit std::size_t");
            if constexpr (sizeof(std::size_t) == 4) {
                return 0x811c9dc5uz;
            } else {
                return 0xcbf29ce484222325uz;
            }
        }

        template<typename T>
            requires std::ranges::contiguous_range<T>
        constexpr void update(T const &data) {
            for (auto const &byte: data) {
                hash_ ^= static_cast<std::size_t>(byte);
                hash_ *= prime();
            }
        }

        [[nodiscard]] constexpr std::size_t finalize() const {
            return hash_;
        }

    public:
        template<typename T>
            requires std::ranges::contiguous_range<T>
        [[nodiscard]] static constexpr std::size_t calculate(T const &data) {
            fnv_1a r;
            r.update(data);
            return r.finalize();
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::size_t calculate(char const (&str)[N]) {
            auto const block = std::span(str, N - 1);
            return calculate(block);
        }
    };
}
