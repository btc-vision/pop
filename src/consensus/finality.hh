#pragma once

#include "core/types.hh"
#include "identity.hh"
#include "vdf.hh"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

namespace pop {

// ============================================================================
// Finality Constants
// ============================================================================

// Soft finality: VDF-bounded, binding (~12 seconds of VDF steps)
inline constexpr std::uint64_t SOFT_FINALITY_VDF_STEPS = 120 * VDF_STEPS_PER_SLOT;

// Hard finality: convergence-based, confirms soft path (~40 seconds typical)
inline constexpr std::uint64_t HARD_FINALITY_TYPICAL_STEPS = 400 * VDF_STEPS_PER_SLOT;

// Attestation weight threshold for tiebreaker (percentage of total age-weight)
inline constexpr std::uint32_t ATTESTATION_WEIGHT_THRESHOLD_PCT = 67;

// ============================================================================
// Attestation - Age-weighted state commitment
// ============================================================================

struct Attestation {
    hash_t state_root;           // State root being attested
    tx_epoch_t epoch;            // Transaction epoch
    hash_t peer_id;              // SHA3(peer public key)
    std::size_t identity_age;    // Consecutive epochs of validity (weight)
    mldsa_signature_t signature;

    [[nodiscard]] bool verify(const mldsa_public_key_t& pk) const;
    [[nodiscard]] std::vector<std::uint8_t> message_bytes() const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<Attestation> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        HASH_SIZE +                   // state_root
        sizeof(tx_epoch_t) +          // epoch
        HASH_SIZE +                   // peer_id
        sizeof(std::size_t) +         // identity_age
        MLDSA65_SIGNATURE_SIZE;       // signature
};

// ============================================================================
// Soft Finality Record
// ============================================================================

struct SoftFinalityRecord {
    tx_epoch_t epoch;
    hash_t state_root;
    hash_t reveal_set_commitment;  // Merkle root of included reveals
    std::uint64_t freeze_vdf_step;
    bool is_binding = false;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<SoftFinalityRecord> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Hard Finality Record
// ============================================================================

struct HardFinalityRecord {
    tx_epoch_t epoch;
    hash_t state_root;
    hash_t reveal_set_commitment;
    std::uint64_t convergence_vdf_step;
    std::size_t total_attestation_weight;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<HardFinalityRecord> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Finality Tracker
// ============================================================================

class FinalityTracker {
public:
    FinalityTracker() = default;

    // Record soft finality for an epoch
    void record_soft_finality(
        tx_epoch_t epoch,
        const hash_t& state_root,
        const hash_t& reveal_set_commitment,
        std::uint64_t freeze_vdf_step);

    // Check if epoch has soft finality
    [[nodiscard]] bool has_soft_finality(tx_epoch_t epoch) const;

    // Get soft finality record
    [[nodiscard]] std::optional<SoftFinalityRecord> get_soft_finality(
        tx_epoch_t epoch) const;

    // Add attestation for convergence
    enum class AttestationResult {
        ACCEPTED,
        DUPLICATE,
        INVALID_SIGNATURE,
        EPOCH_NOT_SOFT_FINAL,
        PEER_NOT_ELIGIBLE,
        WRONG_STATE_ROOT,
    };
    AttestationResult add_attestation(
        const Attestation& att,
        const mldsa_public_key_t& peer_pk,
        const IdentityRegistry& identity_reg,
        identity_epoch_t current_identity_epoch);

    // Get attestation weight for a state root
    [[nodiscard]] std::size_t get_attestation_weight(
        tx_epoch_t epoch,
        const hash_t& state_root) const;

    // Check if epoch has hard finality (convergence achieved)
    [[nodiscard]] bool has_hard_finality(tx_epoch_t epoch) const;

    // Get hard finality record
    [[nodiscard]] std::optional<HardFinalityRecord> get_hard_finality(
        tx_epoch_t epoch) const;

    // Check for convergence and promote to hard finality if achieved
    bool check_convergence(
        tx_epoch_t epoch,
        std::uint64_t current_vdf_step,
        const IdentityRegistry& identity_reg);

    // Resolve partition using age-weighted attestation tiebreaker
    [[nodiscard]] hash_t resolve_partition(
        tx_epoch_t epoch,
        const std::vector<hash_t>& competing_roots) const;

    // Get the last hard-finalized state root (for identity salt)
    [[nodiscard]] std::optional<hash_t> get_last_hard_finalized_root() const;

    // Get finality type for an epoch
    [[nodiscard]] FinalityType get_finality_type(tx_epoch_t epoch) const;

    // Prune old records
    void prune(tx_epoch_t before_epoch);

private:
    struct EpochState {
        SoftFinalityRecord soft;
        std::optional<HardFinalityRecord> hard;

        // Attestations by state root
        std::unordered_map<hash_t, std::vector<Attestation>> attestations;
        std::unordered_map<hash_t, std::size_t> attestation_weights;
        std::unordered_set<hash_t> seen_peer_ids;  // For dedup
    };

    std::unordered_map<tx_epoch_t, EpochState> epochs_;
    tx_epoch_t last_hard_finalized_epoch_ = 0;
    mutable std::mutex mutex_;
};

// ============================================================================
// IBLT Cell - Invertible Bloom Lookup Table component
// ============================================================================

struct IBLTCell {
    hash_t key_sum;
    hash_t value_sum;
    std::int32_t count;

    IBLTCell() : count(0) {
        key_sum.fill(0);
        value_sum.fill(0);
    }

    void insert(const hash_t& key, const hash_t& value);
    void remove(const hash_t& key, const hash_t& value);
    [[nodiscard]] bool is_pure() const;
    [[nodiscard]] bool is_empty() const;
};

// ============================================================================
// IBLT - Invertible Bloom Lookup Table for set reconciliation
// ============================================================================

class IBLT {
public:
    static constexpr std::size_t CELL_COUNT = IBLT_CELL_COUNT;
    static constexpr std::size_t HASH_COUNT = IBLT_HASH_COUNT;

    IBLT();

    // Insert key-value pair
    void insert(const hash_t& key, const hash_t& value);

    // Remove key-value pair
    void remove(const hash_t& key, const hash_t& value);

    // Subtract another IBLT (for set difference)
    [[nodiscard]] IBLT subtract(const IBLT& other) const;

    // Decode the IBLT to recover set difference
    struct DecodeResult {
        bool success;
        std::vector<std::pair<hash_t, hash_t>> items_we_have;   // In ours, not theirs
        std::vector<std::pair<hash_t, hash_t>> items_they_have; // In theirs, not ours
    };
    [[nodiscard]] DecodeResult decode() const;

    // Get all items (for small IBLTs)
    [[nodiscard]] std::vector<std::pair<hash_t, hash_t>> list_entries() const;

    // Serialize/deserialize
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<IBLT> deserialize(
        std::span<const std::uint8_t> data);

private:
    std::array<IBLTCell, CELL_COUNT> cells_;

    // Get hash indices for a key
    [[nodiscard]] std::array<std::size_t, HASH_COUNT> get_indices(
        const hash_t& key) const;
};

// ============================================================================
// Reconciliation Manager
// ============================================================================

class ReconciliationManager {
public:
    ReconciliationManager() = default;

    // Build IBLT from local reveal set
    [[nodiscard]] IBLT build_local_iblt(tx_epoch_t epoch) const;

    // Add a reveal to tracking
    void add_reveal(tx_epoch_t epoch, const hash_t& reveal_hash);

    // Check if reconciliation is needed based on peer's state root
    [[nodiscard]] bool needs_reconciliation(
        tx_epoch_t epoch,
        const hash_t& peer_state_root) const;

    // Set local state root for epoch (for comparison in needs_reconciliation)
    void set_local_state_root(tx_epoch_t epoch, const hash_t& state_root);

    // Get local state root for epoch
    [[nodiscard]] std::optional<hash_t> get_local_state_root(tx_epoch_t epoch) const;

    // Get number of reveals we have for an epoch
    [[nodiscard]] std::size_t reveal_count(tx_epoch_t epoch) const;

    // Perform reconciliation with peer's IBLT
    struct ReconciliationResult {
        std::vector<hash_t> reveals_we_need;   // Request these from peer
        std::vector<hash_t> reveals_to_send;   // Send these to peer
    };
    [[nodiscard]] ReconciliationResult reconcile(
        tx_epoch_t epoch,
        const IBLT& peer_iblt);

    // Check rate limit for reconciliation requests
    [[nodiscard]] bool check_rate_limit(const hash_t& peer_id);

    // Mark reveals as received from reconciliation
    void mark_received(tx_epoch_t epoch, const std::vector<hash_t>& reveals);

    // Clear epoch data after hard finality
    void clear_epoch(tx_epoch_t epoch);

private:
    struct EpochData {
        std::unordered_set<hash_t> reveal_hashes;
        IBLT iblt;
        std::optional<hash_t> local_state_root;  // Our computed state root
    };

    std::unordered_map<tx_epoch_t, EpochData> epochs_;
    std::unordered_map<hash_t, std::uint64_t> peer_request_counts_;
    std::uint64_t current_rate_window_ = 0;
    mutable std::mutex mutex_;

    static constexpr std::uint32_t MAX_REQUESTS_PER_PEER_PER_WINDOW = 10;
};

}  // namespace pop
