//
// Created by Rene Windegger on 22/03/2026.
//

#pragma once

#include <span>
#include <vector>

namespace hash23 {
    class fnv_1 {
    private:
        std::vector<std::uint8_t> buffer_;

        [[nodiscard]] static consteval std::size_t prime() {
            if constexpr (sizeof(std::size_t) == 4) {
                return 0x01000193uz;
            } else {
                return 0x00000100000001b3uz;
            }
            return 0uz;
        }

        [[nodiscard]] static consteval std::size_t offset_basis() {
            if constexpr (sizeof(std::size_t) == 4) {
                return 0x811c9dc5uz;
            } else {
                return 0xcbf29ce484222325uz;
            }
            return 0uz;
        }

        template<typename T>
            requires std::ranges::contiguous_range<T>
        constexpr void update(T const &data) {
            auto const start_offset = buffer_.size();
            buffer_.resize(start_offset + data.size());
            std::copy_n(data.data(), data.size(), buffer_.data() + start_offset);
        }

        [[nodiscard]] constexpr std::size_t finalize() const {
            std::size_t hash = offset_basis();

            for (auto const &byte : buffer_) {
                hash *= prime();
                hash ^= byte;
            }

            return hash;
        }
    public:
        template<typename T>
            requires std::ranges::contiguous_range<T>
        [[nodiscard]] static constexpr std::size_t calculate(T const &data) {
            fnv_1 r;
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
