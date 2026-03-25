# hash23
[![codecov](https://codecov.io/gh/rwindegger/hash23/graph/badge.svg?token=Q8EMA6ONYM)](https://codecov.io/gh/rwindegger/hash23)
[![covdbg](https://covdbg.com/badge.svg/)](https://covdbg.com/)

A compact C++ hashing library with a simple `calculate(...)` API for checksums, non-cryptographic hashes, and cryptographic digests.

## Supported Algorithms

| Algorithm | Category | Return type | Output size | Typical use | Important note |
| --- | --- | --- | --- | --- | --- |
| CRC32 | Checksum | `std::uint32_t` | 32 bits | Detecting accidental corruption | Fast and compact, but not secure against adversarial input |
| FNV-1 | Non-cryptographic hash | `std::size_t` | 32 or 64 bits | Lightweight hashing for tables and identifiers | Output width depends on the target platform |
| FNV-1a | Non-cryptographic hash | `std::size_t` | 32 or 64 bits | General-purpose fast hashing | Usually preferred over FNV-1 for better distribution |
| MD5 | Cryptographic hash (legacy) | `std::array<std::byte, 16>` | 128 bits | Legacy compatibility and test vectors | Broken for security-sensitive use |
| SHA2-224 | Cryptographic hash | `std::array<std::byte, 28>` | 224 bits | Compact modern cryptographic hashing | Smaller SHA2 digest with lower security margin than SHA2-256 and above |
| SHA2-256 | Cryptographic hash | `std::array<std::byte, 32>` | 256 bits | General-purpose cryptographic hashing | Common modern default with a balanced digest size |
| SHA2-384 | Cryptographic hash | `std::array<std::byte, 48>` | 384 bits | Strong cryptographic hashing with a mid-sized digest | Larger digest than SHA2-256 with less overhead than SHA2-512 |
| SHA2-512 | Cryptographic hash | `std::array<std::byte, 64>` | 512 bits | Strong integrity and security-oriented hashing | Larger digest and more computation than the non-cryptographic options |

## Usage

Include the main header:

```cpp
#include <hash23/hash23.h>
```

All algorithms expose a static `calculate(...)` function.

### Accepted input types

The public API accepts contiguous ranges whose element size is 1 byte, including:

- string literals
- `std::string`
- `std::array<char, N>`
- `std::vector<std::byte>`
- `std::span<const std::uint8_t>`

For string literals, the terminating null byte is excluded automatically.

### Formatting digest output

`MD5` and the `SHA2-*` algorithms return `std::array<std::byte, N>`. If you want a hexadecimal string for printing or comparisons, a helper like this is useful:

```cpp
#include <array>
#include <cstddef>
#include <iomanip>
#include <sstream>
#include <string>

template <std::size_t N>
std::string to_hex(std::array<std::byte, N> const& digest) {
	std::ostringstream os;
	os << std::hex << std::setfill('0');
	for (auto b : digest) {
		os << std::setw(2) << std::to_integer<int>(b);
	}
	return os.str();
}
```

## Algorithm Details

### CRC32

CRC32 is a classic checksum designed to catch accidental data corruption. It is a good fit for verifying file transfers, archive entries, or buffers where you want a quick consistency check.

- Returns `std::uint32_t`
- Very fast and easy to store
- Good for error detection
- Not appropriate for passwords, signatures, or security checks

```cpp
#include <hash23/hash23.h>

constexpr auto crc = hash23::crc32::calculate("Hello, World!");
static_assert(crc == 0xEC4AC3D0u);
```

### FNV-1

FNV-1 is a small, fast non-cryptographic hash. In this implementation it returns `std::size_t`, so its width follows the platform: 32-bit on 32-bit targets and 64-bit on 64-bit targets.

- Returns `std::size_t`
- Multiplies by a fixed prime before XOR'ing each byte
- Useful for lightweight hashing in in-memory data structures
- Not stable across platforms with different `std::size_t` widths

```cpp
#include <hash23/hash23.h>

constexpr auto fnv1 = hash23::fnv_1::calculate("Hello, World!");

if constexpr (sizeof(std::size_t) == 8) {
	static_assert(fnv1 == 0x7b5ea4c513c14886uz);
} else {
	static_assert(fnv1 == 0x4291a886uz);
}
```

### FNV-1a

FNV-1a is the sibling variant of FNV-1. It XORs each byte first and multiplies second, which usually gives better distribution for many real-world short inputs.

- Returns `std::size_t`
- Same platform-dependent width as `FNV-1`
- Often the better default choice between the two FNV variants
- Still non-cryptographic, so it should not be used for secure hashing

```cpp
#include <hash23/hash23.h>

constexpr auto fnv1a = hash23::fnv_1a::calculate("Hello, World!");

if constexpr (sizeof(std::size_t) == 8) {
	static_assert(fnv1a == 0x6ef05bd7cc857c54uz);
} else {
	static_assert(fnv1a == 0x5aecf734uz);
}
```

### MD5

MD5 produces a 128-bit digest and remains useful for interoperability with older tooling, protocols, and published test vectors. It should not be used for new security-sensitive designs because practical collision attacks are well known.

- Returns `std::array<std::byte, 16>`
- Compact 128-bit digest
- Useful for legacy compatibility
- Not collision resistant enough for modern security use

```cpp
#include <hash23/hash23.h>

auto const md5 = hash23::md5::calculate("The quick brown fox jumps over the lazy dog");
auto const md5_hex = to_hex(md5);
// md5_hex == "9e107d9d372bb6826bd81d3542a419d6"
```

### SHA2-224

SHA2-224 is the shortest SHA2 variant provided by `hash23`. It produces a 224-bit digest and is useful when you want a modern cryptographic hash with less output than SHA2-256 while still staying within the SHA2 family.

- Returns `std::array<std::byte, 28>`
- Compact 224-bit SHA2 digest
- Useful when you want a smaller modern digest
- Lower security margin than the longer SHA2 variants

```cpp
#include <hash23/hash23.h>

auto const sha2 = hash23::sha2_224::calculate("Hello, World!");
auto const sha2_hex = to_hex(sha2);
// sha2_hex == "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff"
```

### SHA2-256

SHA2-256 is a widely used modern cryptographic hash and often the default SHA2 choice when you want a strong digest without the larger output size of SHA2-384 or SHA2-512.

- Returns `std::array<std::byte, 32>`
- Well-balanced 256-bit digest
- Suitable for general-purpose integrity verification and cryptographic hashing
- Commonly preferred when SHA2 compatibility matters and 256 bits are sufficient

```cpp
#include <hash23/hash23.h>

auto const sha2 = hash23::sha2_256::calculate("Hello, World!");
auto const sha2_hex = to_hex(sha2);
// sha2_hex == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
```

### SHA2-384

SHA2-384 offers a larger digest than SHA2-256 while remaining shorter than SHA2-512. It is a good fit when you want a stronger margin than SHA2-256 but do not need the full 512-bit output.

- Returns `std::array<std::byte, 48>`
- Strong 384-bit digest
- Useful for higher-assurance integrity checks and cryptographic hashing
- Middle ground between SHA2-256 and SHA2-512 in digest size and cost

```cpp
#include <hash23/hash23.h>

auto const sha2 = hash23::sha2_384::calculate("Hello, World!");
auto const sha2_hex = to_hex(sha2);
// sha2_hex == "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515"
```

### SHA2-512

SHA2-512 is the strongest algorithm currently provided by `hash23`. It produces a 512-bit digest and is the best option in this library when you need a modern cryptographic hash for integrity or security-focused workflows.

- Returns `std::array<std::byte, 64>`
- Strong 512-bit digest
- Suitable for integrity verification and security-oriented hashing
- Larger output and more work than CRC32 or FNV

```cpp
#include <hash23/hash23.h>

auto const sha2 = hash23::sha2_512::calculate("Hello, World!");
auto const sha2_hex = to_hex(sha2);
// sha2_hex == "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
```

## Choosing an Algorithm

- Use `CRC32` for fast corruption checks.
- Use `FNV-1a` for lightweight, non-cryptographic hashing.
- Use `FNV-1` only when you specifically need that variant.
- Use `MD5` for compatibility with existing MD5-based systems or fixtures.
- Use `SHA2-224` when you want the smallest SHA2-family digest.
- Use `SHA2-256` as a good general-purpose modern cryptographic hash.
- Use `SHA2-384` when you want a larger digest without going all the way to SHA2-512.
- Use `SHA2-512` when you need a modern cryptographic hash from this library.

## Contributing

Contributions, bug reports, and feature requests are welcome! Feel free to open an [issue](https://github.com/rwindegger/hash23/issues) or submit a pull request.

1. Fork it!
2. Create your feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## License

This project is licensed under the [MIT License](LICENSE).

---

Happy hashing! If you have any questions or feedback, please open an issue or start a discussion.