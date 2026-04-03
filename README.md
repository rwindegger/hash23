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
| SHA3-224 | Cryptographic hash | `std::array<std::byte, 28>` | 224 bits | Compact modern cryptographic hashing | Based on Keccak sponge; different design from SHA2 |
| SHA3-256 | Cryptographic hash | `std::array<std::byte, 32>` | 256 bits | General-purpose cryptographic hashing | Drop-in complement to SHA2-256 with a different internal structure |
| SHA3-384 | Cryptographic hash | `std::array<std::byte, 48>` | 384 bits | Strong cryptographic hashing with a mid-sized digest | Larger digest than SHA3-256 with the Keccak sponge construction |
| SHA3-512 | Cryptographic hash | `std::array<std::byte, 64>` | 512 bits | Strong integrity and security-oriented hashing | Strongest SHA3 variant; largest digest in this library |

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

`MD5`, the `SHA2-*`, and the `SHA3-*` algorithms return `std::array<std::byte, N>`. If you want a hexadecimal string for printing or comparisons, a helper like this is useful:

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

### SHA3-224

SHA3-224 is the shortest SHA3 variant provided by `hash23`. It uses the Keccak sponge construction standardised in FIPS 202 and is architecturally independent from the SHA2 family, providing an alternative when you need a compact modern digest.

- Returns `std::array<std::byte, 28>`
- Compact 224-bit SHA3 digest
- Useful when you want a smaller digest from the SHA3 family
- Lower security margin than the longer SHA3 variants

```cpp
#include <hash23/hash23.h>

auto const sha3 = hash23::sha3_224::calculate("Hello, World!");
auto const sha3_hex = to_hex(sha3);
// sha3_hex == "853048fb8b11462b6100385633c0cc8dcddc6e2b8e376c28102bc84f"
```

### SHA3-256

SHA3-256 produces a 256-bit digest using the Keccak sponge construction. It is a natural alternative to SHA2-256 when you want the same output size but prefer a structurally different algorithm.

- Returns `std::array<std::byte, 32>`
- Well-balanced 256-bit digest
- Good general-purpose choice within the SHA3 family
- Different internal design from SHA2-256, making it useful for algorithm diversity

```cpp
#include <hash23/hash23.h>

auto const sha3 = hash23::sha3_256::calculate("Hello, World!");
auto const sha3_hex = to_hex(sha3);
// sha3_hex == "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef"
```

### SHA3-384

SHA3-384 offers a larger digest than SHA3-256 while remaining shorter than SHA3-512. It is a good fit when you want a stronger margin than SHA3-256 but do not need the full 512-bit output.

- Returns `std::array<std::byte, 48>`
- Strong 384-bit SHA3 digest
- Useful for higher-assurance integrity checks
- Middle ground between SHA3-256 and SHA3-512 in digest size

```cpp
#include <hash23/hash23.h>

auto const sha3 = hash23::sha3_384::calculate("Hello, World!");
auto const sha3_hex = to_hex(sha3);
// sha3_hex == "aa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe"
```

### SHA3-512

SHA3-512 is the strongest SHA3 algorithm provided by `hash23`. It produces a 512-bit digest using the Keccak sponge construction and is the best option when you need a modern cryptographic hash with maximum digest size.

- Returns `std::array<std::byte, 64>`
- Strong 512-bit SHA3 digest
- Suitable for integrity verification and security-oriented hashing
- Largest digest in the library; pairs well with SHA2-512 for algorithm agility

```cpp
#include <hash23/hash23.h>

auto const sha3 = hash23::sha3_512::calculate("Hello, World!");
auto const sha3_hex = to_hex(sha3);
// sha3_hex == "38e05c33d7b067127f217d8c856e554fcff09c9320b8a5979ce2ff5d95dd27ba35d1fba50c562dfd1d6cc48bc9c5baa4390894418cc942d968f97bcb659419ed"
```

## Choosing an Algorithm

- Use `CRC32` for fast corruption checks.
- Use `FNV-1a` for lightweight, non-cryptographic hashing.
- Use `FNV-1` only when you specifically need that variant.
- Use `MD5` for compatibility with existing MD5-based systems or fixtures.
- Use `SHA2-224` when you want the smallest SHA2-family digest.
- Use `SHA2-256` as a good general-purpose modern cryptographic hash.
- Use `SHA2-384` when you want a larger digest without going all the way to SHA2-512.
- Use `SHA2-512` when you need a strong SHA2 hash with a 512-bit digest.
- Use `SHA3-224` when you want the smallest SHA3-family digest.
- Use `SHA3-256` as an alternative to SHA2-256 based on a structurally different algorithm.
- Use `SHA3-384` when you want a larger SHA3 digest without the full 512-bit overhead.
- Use `SHA3-512` when you need the strongest hash in this library, or want algorithm diversity alongside SHA2-512.

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