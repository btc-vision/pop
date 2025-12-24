#pragma once

#include "core/types.hh"
#include "consensus/identity.hh"
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace pop {

// ============================================================================
// Eligibility Constants
// ============================================================================

// Peers must be seen within the last 100 epochs to be eligible
inline constexpr std::size_t ELIGIBILITY_LOOKBACK_EPOCHS = 100;

// Need at least 10 distinct relayers before becoming fully eligible
inline constexpr std::size_t MIN_RELAYS_FOR_ELIGIBILITY = 10;

// Each sponsor can vouch for at most 10 new peers per epoch
inline constexpr std::size_t MAX_NEW_PEERS_PER_SPONSOR_PER_EPOCH = 10;

// Minimum attestation weight for batch receipt eligibility
inline constexpr std::size_t MIN_ATTESTATION_WEIGHT = 100;

// ============================================================================
// Eligibility Criteria
// ============================================================================

struct EligibilityCriteria {
    bool seen_in_lookback;         // Seen activity within last 100 epochs
    bool identity_epoch_valid;     // Has valid identity for current epoch
    bool has_sufficient_relays;    // At least 10 distinct relayers
    bool is_not_banned;            // Not on the ban list

    [[nodiscard]] bool is_eligible() const {
        return seen_in_lookback &&
               identity_epoch_valid &&
               has_sufficient_relays &&
               is_not_banned;
    }
};

// ============================================================================
// Sponsorship Result
// ============================================================================

enum class SponsorshipResult : std::uint8_t {
    SUCCESS,
    SPONSOR_NOT_ELIGIBLE,        // Sponsor is not eligible themselves
    SPONSOR_AT_LIMIT,            // Sponsor already sponsored 10 peers this epoch
    NEW_PEER_ALREADY_SPONSORED,  // New peer already has a sponsor
    NEW_PEER_ALREADY_ELIGIBLE,   // New peer is already eligible (no sponsorship needed)
};

[[nodiscard]] inline std::string_view sponsorship_result_string(SponsorshipResult result) {
    switch (result) {
        case SponsorshipResult::SUCCESS: return "success";
        case SponsorshipResult::SPONSOR_NOT_ELIGIBLE: return "sponsor_not_eligible";
        case SponsorshipResult::SPONSOR_AT_LIMIT: return "sponsor_at_limit";
        case SponsorshipResult::NEW_PEER_ALREADY_SPONSORED: return "new_peer_already_sponsored";
        case SponsorshipResult::NEW_PEER_ALREADY_ELIGIBLE: return "new_peer_already_eligible";
    }
    return "unknown";
}

// ============================================================================
// Eligibility Violation
// ============================================================================

enum class EligibilityViolation : std::uint8_t {
    INVALID_RECEIPT,             // Submitted malformed receipt
    MISSING_CHUNK,               // Failed to provide assigned chunk
    SIGNATURE_MISMATCH,          // Receipt signature doesn't match identity
    VDF_BINDING_INVALID,         // VDF bucket binding verification failed
};

[[nodiscard]] inline std::string_view eligibility_violation_string(EligibilityViolation violation) {
    switch (violation) {
        case EligibilityViolation::INVALID_RECEIPT: return "invalid_receipt";
        case EligibilityViolation::MISSING_CHUNK: return "missing_chunk";
        case EligibilityViolation::SIGNATURE_MISMATCH: return "signature_mismatch";
        case EligibilityViolation::VDF_BINDING_INVALID: return "vdf_binding_invalid";
    }
    return "unknown";
}

// ============================================================================
// Peer Activity Record
// ============================================================================

struct PeerActivityRecord {
    hash_t peer_id;
    tx_epoch_t first_seen_epoch;
    tx_epoch_t last_seen_epoch;
    std::unordered_set<hash_t> relayers;        // Who relayed for this peer
    std::vector<tx_epoch_t> active_epochs;      // Epochs where we saw activity
    std::size_t receipt_count;                  // Total receipts submitted
    std::size_t violation_count;                // Number of violations

    [[nodiscard]] bool has_sufficient_relays() const {
        return relayers.size() >= MIN_RELAYS_FOR_ELIGIBILITY;
    }

    [[nodiscard]] std::size_t relay_count() const {
        return relayers.size();
    }
};

// ============================================================================
// Sponsorship Record
// ============================================================================

struct SponsorshipRecord {
    hash_t sponsor_id;
    hash_t new_peer_id;
    tx_epoch_t epoch;
};

// ============================================================================
// Eligibility Tracker
// ============================================================================

class EligibilityTracker {
public:
    EligibilityTracker() = default;

    // Move constructor/assignment
    EligibilityTracker(EligibilityTracker&& other) noexcept
        : activity_records_(std::move(other.activity_records_)),
          sponsorship_counts_(std::move(other.sponsorship_counts_)),
          sponsorships_(std::move(other.sponsorships_)),
          violation_counts_(std::move(other.violation_counts_)) {}

    EligibilityTracker& operator=(EligibilityTracker&& other) noexcept {
        if (this != &other) {
            activity_records_ = std::move(other.activity_records_);
            sponsorship_counts_ = std::move(other.sponsorship_counts_);
            sponsorships_ = std::move(other.sponsorships_);
            violation_counts_ = std::move(other.violation_counts_);
        }
        return *this;
    }

    // Non-copyable
    EligibilityTracker(const EligibilityTracker&) = delete;
    EligibilityTracker& operator=(const EligibilityTracker&) = delete;

    // ========================================================================
    // Core Eligibility Checks
    // ========================================================================

    // Check if a peer is eligible at a given epoch
    [[nodiscard]] bool is_eligible(
        const hash_t& peer_id,
        tx_epoch_t epoch,
        const IdentityRegistry& identity_reg) const;

    // Get detailed eligibility criteria for a peer
    [[nodiscard]] EligibilityCriteria get_criteria(
        const hash_t& peer_id,
        tx_epoch_t epoch,
        const IdentityRegistry& identity_reg) const;

    // ========================================================================
    // Activity Recording
    // ========================================================================

    // Record that we saw a peer (e.g., received a message from them)
    void record_seen(const hash_t& peer_id, tx_epoch_t epoch);

    // Record that a peer relayed for another peer
    void record_relay(
        const hash_t& peer_id,
        const hash_t& relayer_id,
        tx_epoch_t epoch);

    // Record a receipt submission
    void record_receipt(const hash_t& peer_id, tx_epoch_t epoch);

    // ========================================================================
    // Sponsorship
    // ========================================================================

    // Check if sponsorship is allowed
    [[nodiscard]] SponsorshipResult check_sponsorship(
        const hash_t& sponsor_id,
        const hash_t& new_peer_id,
        tx_epoch_t epoch,
        const IdentityRegistry& identity_reg) const;

    // Record a sponsorship (should call check_sponsorship first)
    void record_sponsorship(
        const hash_t& sponsor_id,
        const hash_t& new_peer_id,
        tx_epoch_t epoch);

    // Get count of sponsorships by a sponsor in an epoch
    [[nodiscard]] std::size_t get_sponsor_count(
        const hash_t& sponsor_id,
        tx_epoch_t epoch) const;

    // ========================================================================
    // Violations
    // ========================================================================

    // Record a violation (may lead to temporary ineligibility)
    void record_violation(
        const hash_t& peer_id,
        tx_epoch_t epoch,
        EligibilityViolation violation);

    // Get violation count for a peer
    [[nodiscard]] std::size_t get_violation_count(const hash_t& peer_id) const;

    // ========================================================================
    // Attestation Weight
    // ========================================================================

    // Get attestation weight (based on identity age)
    // Weight = identity_age (consecutive valid epochs)
    // New peers start at weight 1
    [[nodiscard]] double attestation_weight(
        const hash_t& peer_id,
        const IdentityRegistry& identity_reg,
        identity_epoch_t current_epoch) const;

    // Check if a set of receipts meets the minimum attestation weight threshold
    [[nodiscard]] bool meets_attestation_threshold(
        const std::vector<hash_t>& peer_ids,
        const IdentityRegistry& identity_reg,
        identity_epoch_t current_epoch) const;

    // ========================================================================
    // Maintenance
    // ========================================================================

    // Prune records for peers not seen in the last ELIGIBILITY_LOOKBACK_EPOCHS
    // Returns number of peers pruned
    std::size_t prune_inactive(tx_epoch_t current_epoch);

    // Get the activity record for a peer (if exists)
    [[nodiscard]] std::optional<PeerActivityRecord> get_activity_record(
        const hash_t& peer_id) const;

    // Get total number of tracked peers
    [[nodiscard]] std::size_t peer_count() const;

    // Get count of eligible peers at an epoch
    [[nodiscard]] std::size_t eligible_count(
        tx_epoch_t epoch,
        const IdentityRegistry& identity_reg) const;

    // ========================================================================
    // Serialization
    // ========================================================================

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<EligibilityTracker> deserialize(
        std::span<const std::uint8_t> data);

private:
    // Peer activity records (keyed by peer_id hash)
    std::unordered_map<hash_t, PeerActivityRecord> activity_records_;

    // Sponsorship tracking: epoch -> sponsor -> count
    std::unordered_map<tx_epoch_t,
        std::unordered_map<hash_t, std::size_t>> sponsorship_counts_;

    // Sponsorship records for verification
    std::vector<SponsorshipRecord> sponsorships_;

    // Violation records
    std::unordered_map<hash_t, std::size_t> violation_counts_;

    mutable std::mutex mutex_;

    // Helper to check if peer was seen within lookback window
    [[nodiscard]] bool seen_in_lookback(
        const hash_t& peer_id,
        tx_epoch_t current_epoch) const;

    // Helper to ensure a peer record exists
    PeerActivityRecord& ensure_record(const hash_t& peer_id, tx_epoch_t epoch);
};

}  // namespace pop
