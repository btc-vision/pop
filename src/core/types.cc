#include "types.hh"
#include <algorithm>
#include <atomic>
#include <cstring>

namespace pop {

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

[[nodiscard]] std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (auto byte : bytes) {
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> hex_to_bytes(std::string_view hex) {
    // Skip optional 0x prefix
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex = hex.substr(2);
    }

    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> result;
    result.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        auto high = hex[i];
        auto low = hex[i + 1];

        std::uint8_t byte = 0;

        if (high >= '0' && high <= '9') {
            byte = static_cast<std::uint8_t>((high - '0') << 4);
        } else if (high >= 'a' && high <= 'f') {
            byte = static_cast<std::uint8_t>((high - 'a' + 10) << 4);
        } else if (high >= 'A' && high <= 'F') {
            byte = static_cast<std::uint8_t>((high - 'A' + 10) << 4);
        } else {
            return std::nullopt;
        }

        if (low >= '0' && low <= '9') {
            byte |= static_cast<std::uint8_t>(low - '0');
        } else if (low >= 'a' && low <= 'f') {
            byte |= static_cast<std::uint8_t>(low - 'a' + 10);
        } else if (low >= 'A' && low <= 'F') {
            byte |= static_cast<std::uint8_t>(low - 'A' + 10);
        } else {
            return std::nullopt;
        }

        result.push_back(byte);
    }

    return result;
}

// ============================================================================
// Secure Zero
// ============================================================================

void secure_zero(void* ptr, std::size_t len) {
    volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

// ============================================================================
// Address Implementation
// ============================================================================

std::string Address::to_hex() const {
    return "0x" + bytes_to_hex(bytes);
}

std::optional<Address> Address::from_hex(std::string_view hex) {
    auto bytes_opt = hex_to_bytes(hex);
    if (!bytes_opt || bytes_opt->size() != HASH_SIZE) {
        return std::nullopt;
    }
    Address addr;
    std::copy(bytes_opt->begin(), bytes_opt->end(), addr.bytes.begin());
    return addr;
}

// ============================================================================
// NodeId Implementation
// ============================================================================

std::string NodeId::to_hex() const {
    return bytes_to_hex(public_key);
}

}  // namespace pop
