#include "hash.hh"
#include "core/logging.hh"
#include <openssl/evp.h>
#include <algorithm>
#include <stdexcept>

namespace pop {

// ============================================================================
// SHA3Hasher Implementation
// ============================================================================

SHA3Hasher::SHA3Hasher() {
    ctx_ = EVP_MD_CTX_new();
    if (!ctx_) {
        log::crypto.error("Failed to create EVP_MD_CTX");
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(static_cast<EVP_MD_CTX*>(ctx_), EVP_sha3_256(), nullptr) != 1) {
        log::crypto.error("Failed to initialize SHA3-256");
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
        throw std::runtime_error("Failed to initialize SHA3-256");
    }
}

SHA3Hasher::~SHA3Hasher() {
    if (ctx_) {
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
    }
}

SHA3Hasher::SHA3Hasher(SHA3Hasher&& other) noexcept : ctx_(other.ctx_) {
    other.ctx_ = nullptr;
}

SHA3Hasher& SHA3Hasher::operator=(SHA3Hasher&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
        }
        ctx_ = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

void SHA3Hasher::update(std::span<const std::uint8_t> data) {
    update(data.data(), data.size());
}

void SHA3Hasher::update(const void* data, std::size_t len) {
    if (EVP_DigestUpdate(static_cast<EVP_MD_CTX*>(ctx_), data, len) != 1) {
        log::crypto.error("SHA3-256 update failed");
        throw std::runtime_error("SHA3-256 update failed");
    }
}

hash_t SHA3Hasher::finalize() {
    hash_t result;
    unsigned int len = HASH_SIZE;
    if (EVP_DigestFinal_ex(static_cast<EVP_MD_CTX*>(ctx_), result.data(), &len) != 1) {
        log::crypto.error("SHA3-256 finalize failed");
        throw std::runtime_error("SHA3-256 finalize failed");
    }
    return result;
}

void SHA3Hasher::reset() {
    if (EVP_DigestInit_ex(static_cast<EVP_MD_CTX*>(ctx_), EVP_sha3_256(), nullptr) != 1) {
        log::crypto.error("SHA3-256 reset failed");
        throw std::runtime_error("SHA3-256 reset failed");
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

hash_t sha3_256(std::span<const std::uint8_t> data) {
    return sha3_256(data.data(), data.size());
}

hash_t sha3_256(const void* data, std::size_t len) {
    hash_t result;
    unsigned int out_len = HASH_SIZE;
    if (EVP_Digest(data, len, result.data(), &out_len, EVP_sha3_256(), nullptr) != 1) {
        log::crypto.error("SHA3-256 failed");
        throw std::runtime_error("SHA3-256 failed");
    }
    return result;
}

// ============================================================================
// Merkle Tree Implementation
// ============================================================================

MerkleTree::MerkleTree(std::vector<hash_t> leaves) : leaves_(std::move(leaves)) {
    if (leaves_.empty()) {
        root_ = {};
    } else {
        build();
    }
}

void MerkleTree::build() {
    layers_.clear();
    layers_.push_back(leaves_);

    while (layers_.back().size() > 1) {
        const auto& prev = layers_.back();
        std::vector<hash_t> next;
        next.reserve((prev.size() + 1) / 2);

        for (std::size_t i = 0; i < prev.size(); i += 2) {
            if (i + 1 < prev.size()) {
                next.push_back(hash_pair(prev[i], prev[i + 1]));
            } else {
                // Odd number: duplicate the last element
                next.push_back(hash_pair(prev[i], prev[i]));
            }
        }
        layers_.push_back(std::move(next));
    }

    root_ = layers_.back()[0];
}

hash_t MerkleTree::hash_pair(const hash_t& left, const hash_t& right) {
    SHA3Hasher hasher;
    hasher.update(left);
    hasher.update(right);
    return hasher.finalize();
}

std::vector<hash_t> MerkleTree::proof(std::size_t index) const {
    if (index >= leaves_.size()) {
        return {};
    }

    std::vector<hash_t> proof;
    std::size_t idx = index;

    for (std::size_t layer = 0; layer < layers_.size() - 1; ++layer) {
        const auto& current = layers_[layer];
        std::size_t sibling_idx = (idx % 2 == 0) ? idx + 1 : idx - 1;

        if (sibling_idx < current.size()) {
            proof.push_back(current[sibling_idx]);
        } else {
            // Odd layer, sibling is self
            proof.push_back(current[idx]);
        }

        idx /= 2;
    }

    return proof;
}

bool MerkleTree::verify(const hash_t& leaf, const std::vector<hash_t>& proof,
                        std::size_t index, const hash_t& root) {
    hash_t current = leaf;
    std::size_t idx = index;

    for (const auto& sibling : proof) {
        if (idx % 2 == 0) {
            current = hash_pair(current, sibling);
        } else {
            current = hash_pair(sibling, current);
        }
        idx /= 2;
    }

    return current == root;
}

hash_t compute_merkle_root(std::span<const hash_t> leaves) {
    if (leaves.empty()) {
        return {};
    }
    if (leaves.size() == 1) {
        return leaves[0];
    }

    std::vector<hash_t> layer(leaves.begin(), leaves.end());

    while (layer.size() > 1) {
        std::vector<hash_t> next;
        next.reserve((layer.size() + 1) / 2);

        for (std::size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 < layer.size()) {
                next.push_back(MerkleTree::hash_pair(layer[i], layer[i + 1]));
            } else {
                next.push_back(MerkleTree::hash_pair(layer[i], layer[i]));
            }
        }
        layer = std::move(next);
    }

    return layer[0];
}

// ============================================================================
// Hash Difficulty Check
// ============================================================================

bool hash_meets_difficulty(const hash_t& h, std::size_t leading_zeros) {
    std::size_t bits_checked = 0;

    for (std::size_t i = 0; i < HASH_SIZE && bits_checked < leading_zeros; ++i) {
        std::uint8_t byte = h[i];
        for (int bit = 7; bit >= 0 && bits_checked < leading_zeros; --bit) {
            if ((byte >> bit) & 1) {
                return false;  // Found a 1 bit before reaching required zeros
            }
            ++bits_checked;
        }
    }

    return true;
}

// ============================================================================
// HashDRBG Implementation
// ============================================================================

HashDRBG::HashDRBG(const hash_t& seed) : state_(seed), counter_(0) {}

hash_t HashDRBG::next() {
    SHA3Hasher hasher;
    hasher.update(state_);

    std::array<std::uint8_t, 8> counter_bytes;
    encode_u64(counter_bytes.data(), counter_++);
    hasher.update(counter_bytes);

    state_ = hasher.finalize();
    return state_;
}

std::uint64_t HashDRBG::next_u64() {
    auto h = next();
    return decode_u64(h.data());
}

std::uint32_t HashDRBG::next_u32() {
    auto h = next();
    return decode_u32(h.data());
}

std::uint32_t HashDRBG::next_range(std::uint32_t max) {
    if (max == 0) return 0;
    return next_u32() % max;
}

// ============================================================================
// NodeId hash implementation (defined in types.hh, implemented here)
// ============================================================================

hash_t NodeId::hash() const {
    return sha3_256(public_key);
}

// ============================================================================
// Address from public key (defined in types.hh, implemented here)
// ============================================================================

Address Address::from_public_key(const mldsa_public_key_t& pk) {
    Address addr;
    addr.bytes = sha3_256(pk);
    return addr;
}

}  // namespace pop
