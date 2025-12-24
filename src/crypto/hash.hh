#pragma once

#include "core/types.hh"
#include <span>
#include <vector>

namespace pop {

// ============================================================================
// SHA3-256 Hashing
// ============================================================================

class SHA3Hasher {
public:
    SHA3Hasher();
    ~SHA3Hasher();

    SHA3Hasher(const SHA3Hasher&) = delete;
    SHA3Hasher& operator=(const SHA3Hasher&) = delete;
    SHA3Hasher(SHA3Hasher&&) noexcept;
    SHA3Hasher& operator=(SHA3Hasher&&) noexcept;

    void update(std::span<const std::uint8_t> data);
    void update(const void* data, std::size_t len);
    [[nodiscard]] hash_t finalize();

    void reset();

private:
    void* ctx_;
};

// Convenience functions
[[nodiscard]] hash_t sha3_256(std::span<const std::uint8_t> data);
[[nodiscard]] hash_t sha3_256(const void* data, std::size_t len);

// Hash multiple inputs (concatenated)
template<typename... Args>
[[nodiscard]] hash_t sha3_256_multi(Args&&... args) {
    SHA3Hasher hasher;
    (hasher.update(std::forward<Args>(args)), ...);
    return hasher.finalize();
}

// ============================================================================
// Merkle Tree Utilities
// ============================================================================

class MerkleTree {
public:
    explicit MerkleTree(std::vector<hash_t> leaves);

    [[nodiscard]] const hash_t& root() const { return root_; }
    [[nodiscard]] std::vector<hash_t> proof(std::size_t index) const;
    [[nodiscard]] static bool verify(const hash_t& leaf, const std::vector<hash_t>& proof,
                                      std::size_t index, const hash_t& root);

    // Public for use by compute_merkle_root
    [[nodiscard]] static hash_t hash_pair(const hash_t& left, const hash_t& right);

private:
    std::vector<hash_t> leaves_;
    std::vector<std::vector<hash_t>> layers_;
    hash_t root_;

    void build();
};

// Compute Merkle root directly without building full tree
[[nodiscard]] hash_t compute_merkle_root(std::span<const hash_t> leaves);

// ============================================================================
// Hash-based Random Functions
// ============================================================================

// Derive a position from a hash
[[nodiscard]] inline position_t hash_to_position(const hash_t& h) {
    std::uint32_t val = decode_u32(h.data());
    return val % POSITION_MODULUS;
}

// Check if hash meets difficulty (leading zeros)
[[nodiscard]] bool hash_meets_difficulty(const hash_t& h, std::size_t leading_zeros);

// Derive multiple values from a seed
class HashDRBG {
public:
    explicit HashDRBG(const hash_t& seed);

    [[nodiscard]] hash_t next();
    [[nodiscard]] std::uint64_t next_u64();
    [[nodiscard]] std::uint32_t next_u32();
    [[nodiscard]] std::uint32_t next_range(std::uint32_t max);

private:
    hash_t state_;
    std::uint64_t counter_;
};

}  // namespace pop
