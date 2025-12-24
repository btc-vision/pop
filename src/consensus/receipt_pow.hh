#pragma once

#include "core/types.hh"
#include "consensus/vdf_proof.hh"
#include <array>
#include <span>
#include <vector>

namespace pop {

// ============================================================================
// Sequential Proof of Work Constants
// ============================================================================

// 80,000 SHA3-256 iterations - calibrated to ~10ms on 2021 desktop CPU
// (Intel Core i5-11400 / AMD Ryzen 5 5600X)
inline constexpr std::uint64_t RECEIPT_POW_ITERATIONS = 80'000;

// Checkpoints at iterations 0, 20000, 40000, 60000, 80000 for efficient verification
inline constexpr std::uint64_t RECEIPT_POW_CHECKPOINT_INTERVAL = 20'000;
inline constexpr std::size_t RECEIPT_POW_CHECKPOINT_COUNT = 5;

// ============================================================================
// Sequential PoW Result
// ============================================================================

struct SequentialPoWResult {
    // Input seed: SHA3(reveal_root || peer_id || nonce)
    hash_t seed;

    // Final output after RECEIPT_POW_ITERATIONS
    hash_t final_hash;

    // Checkpoints at 0, 20000, 40000, 60000, 80000
    std::array<hash_t, RECEIPT_POW_CHECKPOINT_COUNT> checkpoints;

    // The nonce used (for grinding if needed)
    std::uint64_t nonce;

    // Serialize/deserialize
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<SequentialPoWResult> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        HASH_SIZE +                                           // seed
        HASH_SIZE +                                           // final_hash
        (RECEIPT_POW_CHECKPOINT_COUNT * HASH_SIZE) +          // checkpoints
        sizeof(std::uint64_t);                                // nonce
};

// ============================================================================
// Sequential PoW Generator
// ============================================================================

class SequentialPoWGenerator {
public:
    // Generate sequential PoW for a receipt
    // Input: reveal_root (from Merkle tree of reveals), peer_id (our identity)
    [[nodiscard]] static SequentialPoWResult generate(
        const hash_t& reveal_root,
        const hash_t& peer_id,
        std::uint64_t nonce = 0);

    // Verify a sequential PoW result
    // Can verify all checkpoints (full) or just spot-check (fast)
    enum class VerifyMode {
        FULL,           // Verify all iterations (slow, ~10ms)
        CHECKPOINTS,    // Verify only checkpoint transitions (faster, ~2ms)
        SPOT_CHECK,     // Verify random checkpoint (fastest, ~0.5ms)
    };
    [[nodiscard]] static bool verify(
        const SequentialPoWResult& result,
        const hash_t& reveal_root,
        const hash_t& peer_id,
        VerifyMode mode = VerifyMode::CHECKPOINTS);

    // Compute a single checkpoint transition (20,000 iterations)
    [[nodiscard]] static hash_t compute_checkpoint_transition(const hash_t& input);

private:
    // Compute seed from inputs
    [[nodiscard]] static hash_t compute_seed(
        const hash_t& reveal_root,
        const hash_t& peer_id,
        std::uint64_t nonce);
};

// ============================================================================
// Chunk Assignment
// ============================================================================

// Reed-Solomon erasure coding parameters
inline constexpr std::size_t ERASURE_TOTAL_CHUNKS = 32;
inline constexpr std::size_t ERASURE_THRESHOLD = 16;  // Need 16 of 32 to reconstruct

// Compute which chunk a peer is assigned for a reveal
// chunk_index = SHA3(reveal_root || peer_id || epoch_randomness) mod 32
[[nodiscard]] std::uint8_t compute_chunk_assignment(
    const hash_t& reveal_root,
    const hash_t& peer_id,
    const hash_t& epoch_randomness);

// Compute epoch randomness based on global finality state
// Normal: SHA3("chunks" || global_state_root_of_epoch_minus_1)
// Timeout: SHA3("chunks_timeout" || last_global_root || soft_state_root || epoch)
[[nodiscard]] hash_t compute_epoch_randomness(
    const hash_t& state_root,
    tx_epoch_t epoch,
    bool is_timeout_mode = false,
    const hash_t* soft_state_root = nullptr);

// ============================================================================
// Enhanced Receipt with Sequential PoW
// ============================================================================

struct EnhancedReceipt {
    // Basic receipt fields
    tx_epoch_t epoch_id;
    std::uint8_t bucket_id;
    hash_t merkle_root;           // Root of reveal hashes
    hash_t peer_id;

    // Sequential PoW proof
    SequentialPoWResult pow_proof;

    // Assigned chunk data
    std::uint8_t assigned_chunk_index;
    std::vector<std::uint8_t> chunk_data;
    std::vector<hash_t> chunk_merkle_proof;  // Proof that chunk belongs to reveal

    // VDF bucket binding
    tx_epoch_t vdf_checkpoint_epoch;  // Reference epoch for VDF checkpoint
    std::uint16_t vdf_bucket_offset;  // Steps from checkpoint to bucket
    VDFBucketProof vdf_proof;         // Cryptographic proof of bucket timing
    hash_t bucket_vdf_value;          // VDF output at bucket step

    // ML-DSA signature over everything
    mldsa_signature_t signature;

    // Verify the receipt (basic verification)
    [[nodiscard]] bool verify(
        const mldsa_public_key_t& peer_pk,
        const hash_t& epoch_randomness) const;

    // Verify VDF bucket binding
    [[nodiscard]] bool verify_vdf_binding(
        const VDFEpochCheckpoint& checkpoint) const;

    // Full verification (PoW + VDF + signature)
    [[nodiscard]] bool verify_full(
        const mldsa_public_key_t& peer_pk,
        const hash_t& epoch_randomness,
        const VDFEpochCheckpoint& checkpoint) const;

    // Get message bytes for signing
    [[nodiscard]] std::vector<std::uint8_t> message_bytes() const;

    // Serialize/deserialize
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<EnhancedReceipt> deserialize(
        std::span<const std::uint8_t> data);
};

}  // namespace pop
