#pragma once

#include "core/types.hh"
#include "identity.hh"
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

// Forward declaration to avoid circular dependency
namespace pop { class EligibilityTracker; }

namespace pop {

// ============================================================================
// Batch Receipt
// ============================================================================

struct BatchReceipt {
    tx_epoch_t epoch_id;         // Transaction epoch
    std::uint8_t bucket_id;       // 0-19, cutoff at 17
    hash_t merkle_root;           // Root of reveal hashes in bucket
    hash_t peer_id;               // SHA3(peer public key)
    mldsa_signature_t signature;

    // Verify signature against public key
    [[nodiscard]] bool verify(const mldsa_public_key_t& pk) const;

    // Get message bytes for signing/verification
    [[nodiscard]] std::vector<std::uint8_t> message_bytes() const;

    // Serialize/deserialize
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<BatchReceipt> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        sizeof(tx_epoch_t) +              // epoch_id
        sizeof(std::uint8_t) +            // bucket_id
        HASH_SIZE +                       // merkle_root
        HASH_SIZE +                       // peer_id
        MLDSA65_SIGNATURE_SIZE;           // signature  (~5.3KB total)
};

// ============================================================================
// Receipt Inclusion Proof
// ============================================================================

struct ReceiptInclusionProof {
    BatchReceipt receipt;
    std::vector<hash_t> merkle_proof;  // Path from reveal_hash to merkle_root
    std::size_t leaf_index;

    [[nodiscard]] bool verify(const hash_t& reveal_hash) const;
};

// ============================================================================
// Reveal Eligibility (30+ receipts from distinct peers)
// ============================================================================

struct RevealEligibility {
    hash_t reveal_hash;
    std::vector<ReceiptInclusionProof> proofs;

    // Verify that we have 30+ distinct eligible peers attesting
    [[nodiscard]] bool verify(
        const IdentityRegistry& reg,
        identity_epoch_t epoch) const;

    // Get the set of distinct peer IDs
    [[nodiscard]] std::unordered_set<hash_t> peer_set() const;

    // Serialize/deserialize
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<RevealEligibility> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Batch Receipt Pool
// ============================================================================

class BatchReceiptPool {
public:
    BatchReceiptPool() = default;

    // Public key type for bucket indexing (used by ReceiptGenerator too)
    struct BucketKey {
        tx_epoch_t epoch;
        std::uint8_t bucket;

        bool operator==(const BucketKey& other) const {
            return epoch == other.epoch && bucket == other.bucket;
        }
    };

    struct BucketKeyHash {
        std::size_t operator()(const BucketKey& k) const {
            return std::hash<tx_epoch_t>{}(k.epoch) ^
                   (std::hash<std::uint8_t>{}(k.bucket) << 1);
        }
    };

    // Add a receipt to the pool
    enum class AddResult {
        ADDED,
        DUPLICATE,
        INVALID_SIGNATURE,
        INVALID_TIMING,
        PEER_NOT_ELIGIBLE,
        BUCKET_FROZEN,
    };
    AddResult add_receipt(
        const BatchReceipt& receipt,
        const mldsa_public_key_t& peer_pk,
        const IdentityRegistry& identity_reg,
        identity_epoch_t current_identity_epoch);

    // Check if a reveal has sufficient receipts (count-based, legacy)
    [[nodiscard]] bool has_sufficient_receipts(
        const hash_t& reveal_hash,
        const IdentityRegistry& reg,
        identity_epoch_t epoch) const;

    // Check if a reveal has sufficient attestation weight (age-weighted)
    // Returns true if total weight of attestations meets MIN_ATTESTATION_WEIGHT
    [[nodiscard]] bool has_sufficient_attestation_weight(
        const hash_t& reveal_hash,
        const IdentityRegistry& reg,
        const EligibilityTracker& eligibility,
        identity_epoch_t epoch) const;

    // Get the total attestation weight for a reveal
    [[nodiscard]] double get_attestation_weight(
        const hash_t& reveal_hash,
        const IdentityRegistry& reg,
        const EligibilityTracker& eligibility,
        identity_epoch_t epoch) const;

    // Build eligibility proof for a reveal
    [[nodiscard]] std::optional<RevealEligibility> build_eligibility(
        const hash_t& reveal_hash,
        const IdentityRegistry& reg,
        identity_epoch_t epoch) const;

    // Check if pool is frozen for an epoch
    [[nodiscard]] bool is_frozen(tx_epoch_t epoch, timestamp_t now, timestamp_t genesis) const;

    // Get all receipts for an epoch/bucket
    [[nodiscard]] std::vector<BatchReceipt> get_receipts(
        tx_epoch_t epoch,
        std::uint8_t bucket) const;

    // Get receipt count for a reveal
    [[nodiscard]] std::size_t receipt_count(const hash_t& reveal_hash) const;

    // Prune old epochs
    void prune(tx_epoch_t before_epoch);

    // Total receipts in pool
    [[nodiscard]] std::size_t total_receipts() const;

private:
    struct RevealRecord {
        hash_t reveal_hash;
        std::vector<BatchReceipt> receipts;
        std::unordered_set<hash_t> peer_ids;  // For dedup
    };

    // Receipts organized by bucket
    std::unordered_map<BucketKey, std::vector<BatchReceipt>, BucketKeyHash> bucket_receipts_;

    // Receipts organized by reveal hash
    std::unordered_map<hash_t, RevealRecord> reveal_receipts_;

    mutable std::mutex mutex_;
};

// ============================================================================
// Receipt Generator (for creating receipts from observed reveals)
// ============================================================================

class ReceiptGenerator {
public:
    explicit ReceiptGenerator(const mldsa_public_key_t& my_public_key);

    // Add a reveal hash to the current bucket
    void add_reveal(
        const hash_t& reveal_hash,
        tx_epoch_t epoch,
        std::uint8_t bucket);

    // Generate a receipt for a bucket (computes merkle root and signs)
    [[nodiscard]] std::optional<BatchReceipt> generate_receipt(
        tx_epoch_t epoch,
        std::uint8_t bucket,
        const std::function<std::optional<mldsa_signature_t>(std::span<const std::uint8_t>)>& sign_fn);

    // Clear reveals for a bucket (after receipt generated)
    void clear_bucket(tx_epoch_t epoch, std::uint8_t bucket);

    // Get current bucket based on time
    [[nodiscard]] static std::uint8_t current_bucket(timestamp_t now, timestamp_t epoch_start);

    // Check if bucket is past cutoff
    [[nodiscard]] static bool is_past_cutoff(std::uint8_t bucket);

private:
    struct BucketData {
        std::vector<hash_t> reveal_hashes;
        bool receipt_generated = false;
    };

    mldsa_public_key_t my_public_key_;
    hash_t my_peer_id_;

    std::unordered_map<BatchReceiptPool::BucketKey, BucketData,
                       BatchReceiptPool::BucketKeyHash> buckets_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Reward Distribution
// ============================================================================

struct RewardShare {
    hash_t peer_id;
    std::uint64_t amount;
    std::uint8_t bucket_id;
};

class RewardDistributor {
public:
    // Distribute reward pool among receipt providers
    // Order: by bucket_id ascending, then by SHA3(peer_id) within bucket
    [[nodiscard]] static std::vector<RewardShare> distribute(
        std::uint64_t pool,
        const std::vector<BatchReceipt>& receipts,
        std::size_t max_recipients = 100);

    // Calculate individual share (proportional)
    [[nodiscard]] static std::uint64_t calculate_share(
        std::uint64_t pool,
        std::size_t total_recipients,
        std::size_t recipient_index);
};

// ============================================================================
// Timing Helpers
// ============================================================================

// Note: slot_to_tx_epoch is defined in core/types.hh

// Get epoch start time
[[nodiscard]] inline timestamp_t tx_epoch_start_time(tx_epoch_t epoch, timestamp_t genesis) {
    slot_t start_slot = epoch * SLOTS_PER_TX_EPOCH;
    return slot_to_time(start_slot, genesis);
}

// Get pool freeze time for an epoch
[[nodiscard]] inline timestamp_t pool_freeze_time(tx_epoch_t epoch, timestamp_t genesis) {
    auto epoch_start = tx_epoch_start_time(epoch, genesis);
    return epoch_start + timestamp_t(POOL_FREEZE_DELAY_MS * 1000);  // Convert ms to us
}

}  // namespace pop
