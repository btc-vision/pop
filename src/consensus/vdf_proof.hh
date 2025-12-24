#pragma once

#include "core/types.hh"
#include <array>
#include <map>
#include <mutex>
#include <span>
#include <unordered_map>
#include <vector>
#include <optional>

namespace pop {

// ============================================================================
// VDF Bucket Proof Constants
// ============================================================================

// VDF steps per slot (calibrated to ~100ms on reference hardware)
inline constexpr std::uint64_t VDF_STEPS_PER_SLOT = 1'000'000;

// Mini-checkpoint interval (every 10,000 steps = ~1ms)
inline constexpr std::uint64_t VDF_MINI_CHECKPOINT_INTERVAL = 10'000;

// Maximum proof size (steps from checkpoint to bucket)
inline constexpr std::uint64_t VDF_MAX_PROOF_STEPS = 10'000;

// Threshold for requiring mini-checkpoint reference
inline constexpr std::uint64_t VDF_MINI_CHECKPOINT_THRESHOLD = 10'000;

// ============================================================================
// VDF Checkpoint (Epoch Boundary)
// ============================================================================

struct VDFEpochCheckpoint {
    tx_epoch_t epoch;
    std::uint64_t step_number;     // VDF step at epoch boundary
    hash_t vdf_value;              // VDF output at this step
    mldsa_signature_t signature;   // Signed by checkpoint publisher

    [[nodiscard]] bool verify(const mldsa_public_key_t& pk) const;
    [[nodiscard]] std::vector<std::uint8_t> message_bytes() const;
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFEpochCheckpoint> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        sizeof(tx_epoch_t) +
        sizeof(std::uint64_t) +
        HASH_SIZE +
        MLDSA65_SIGNATURE_SIZE;
};

// ============================================================================
// VDF Mini-Checkpoint (Every 10,000 steps)
// ============================================================================

struct VDFMiniCheckpoint {
    std::uint64_t step_number;          // VDF step number
    hash_t vdf_value;                   // VDF output at this step
    std::uint64_t prev_checkpoint_step; // Reference to previous checkpoint
    hash_t prev_checkpoint_value;       // For verification chain
    mldsa_signature_t signature;

    [[nodiscard]] bool verify(const mldsa_public_key_t& pk) const;
    [[nodiscard]] std::vector<std::uint8_t> message_bytes() const;
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFMiniCheckpoint> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        sizeof(std::uint64_t) +     // step_number
        HASH_SIZE +                  // vdf_value
        sizeof(std::uint64_t) +      // prev_checkpoint_step
        HASH_SIZE +                  // prev_checkpoint_value
        MLDSA65_SIGNATURE_SIZE;
};

// ============================================================================
// VDF Bucket Proof
// ============================================================================

// Proves that a receipt was generated at a specific VDF bucket
// by providing a chain of hashes from a known checkpoint to the bucket

struct VDFBucketProof {
    // Reference checkpoint
    tx_epoch_t checkpoint_epoch;
    std::uint64_t checkpoint_step;
    hash_t checkpoint_value;

    // Optional mini-checkpoint for distant buckets
    std::optional<VDFMiniCheckpoint> mini_checkpoint;

    // Bucket position relative to reference
    std::uint64_t bucket_step;          // Step at bucket
    std::uint16_t steps_from_reference; // Steps to compute from reference

    // Intermediate hashes for verification (sampled, not all)
    // For efficiency, we don't store all hashes - verifier recomputes
    // This field is for partial verification / spot-checking
    std::vector<hash_t> sample_points;  // Every 1000 steps

    [[nodiscard]] bool verify(
        const hash_t& expected_bucket_value,
        const VDFEpochCheckpoint& epoch_checkpoint) const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFBucketProof> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// VDF Bucket Calculator
// ============================================================================

class VDFBucketCalculator {
public:
    // Get bucket ID for a given VDF step within an epoch
    [[nodiscard]] static std::uint8_t step_to_bucket(
        std::uint64_t vdf_step,
        std::uint64_t epoch_start_step);

    // Get VDF step range for a bucket
    [[nodiscard]] static std::pair<std::uint64_t, std::uint64_t> bucket_to_step_range(
        tx_epoch_t epoch,
        std::uint8_t bucket_id);

    // Check if a VDF step is within a bucket
    [[nodiscard]] static bool is_in_bucket(
        std::uint64_t vdf_step,
        tx_epoch_t epoch,
        std::uint8_t bucket_id);

    // Compute VDF value at a step (sequential hash chain)
    [[nodiscard]] static hash_t compute_vdf_at_step(
        const hash_t& start_value,
        std::uint64_t start_step,
        std::uint64_t target_step);

    // Generate bucket proof from checkpoint
    [[nodiscard]] static VDFBucketProof generate_proof(
        const VDFEpochCheckpoint& checkpoint,
        std::uint64_t bucket_step,
        const std::optional<VDFMiniCheckpoint>& mini_checkpoint = std::nullopt);
};

// ============================================================================
// VDF Checkpoint Store
// ============================================================================

class VDFCheckpointStore {
public:
    // Add epoch checkpoint
    void add_epoch_checkpoint(const VDFEpochCheckpoint& checkpoint);

    // Add mini-checkpoint
    void add_mini_checkpoint(const VDFMiniCheckpoint& checkpoint);

    // Get nearest checkpoint for a step
    [[nodiscard]] std::optional<VDFEpochCheckpoint> get_epoch_checkpoint(
        tx_epoch_t epoch) const;

    // Get nearest mini-checkpoint before a step
    [[nodiscard]] std::optional<VDFMiniCheckpoint> get_nearest_mini_checkpoint(
        std::uint64_t step) const;

    // Generate proof for a bucket step
    [[nodiscard]] std::optional<VDFBucketProof> generate_proof_for_step(
        std::uint64_t bucket_step,
        tx_epoch_t epoch) const;

    // Verify a proof against stored checkpoints
    [[nodiscard]] bool verify_proof(
        const VDFBucketProof& proof,
        const hash_t& expected_bucket_value) const;

    // Prune old checkpoints
    void prune(tx_epoch_t before_epoch);

private:
    std::unordered_map<tx_epoch_t, VDFEpochCheckpoint> epoch_checkpoints_;
    std::map<std::uint64_t, VDFMiniCheckpoint> mini_checkpoints_;  // Ordered by step
    mutable std::mutex mutex_;
};

// ============================================================================
// Receipt with VDF Bucket Binding
// ============================================================================

struct VDFBoundReceipt {
    // Standard receipt fields
    tx_epoch_t epoch_id;
    std::uint8_t bucket_id;
    hash_t merkle_root;
    hash_t peer_id;

    // VDF bucket binding
    VDFBucketProof vdf_proof;
    hash_t bucket_vdf_value;  // VDF value at bucket step

    // Sequential PoW (from receipt_pow.hh)
    // SequentialPoWResult pow_proof;

    // Signature
    mldsa_signature_t signature;

    [[nodiscard]] bool verify(
        const mldsa_public_key_t& peer_pk,
        const VDFEpochCheckpoint& epoch_checkpoint) const;

    [[nodiscard]] std::vector<std::uint8_t> message_bytes() const;
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFBoundReceipt> deserialize(
        std::span<const std::uint8_t> data);
};

}  // namespace pop
