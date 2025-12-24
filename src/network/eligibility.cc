#include "network/eligibility.hh"
#include "crypto/hash.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// Core Eligibility Checks
// ============================================================================

bool EligibilityTracker::is_eligible(
    const hash_t& peer_id,
    tx_epoch_t epoch,
    const IdentityRegistry& identity_reg) const {

    auto criteria = get_criteria(peer_id, epoch, identity_reg);
    return criteria.is_eligible();
}

EligibilityCriteria EligibilityTracker::get_criteria(
    const hash_t& peer_id,
    tx_epoch_t epoch,
    const IdentityRegistry& identity_reg) const {

    std::lock_guard<std::mutex> lock(mutex_);

    EligibilityCriteria criteria{};

    // Check if peer was seen within lookback window
    criteria.seen_in_lookback = seen_in_lookback(peer_id, epoch);

    // Check if peer has a valid identity for the epoch
    // Note: peer_id is SHA3(public_key), so we need to look up identity by peer_id
    auto it = activity_records_.find(peer_id);
    if (it != activity_records_.end()) {
        // We have a record for this peer
        criteria.identity_epoch_valid = true;  // Simplified - in real impl, would check IdentityRegistry

        // Check relay count
        criteria.has_sufficient_relays = it->second.has_sufficient_relays();
    } else {
        criteria.identity_epoch_valid = false;
        criteria.has_sufficient_relays = false;
    }

    // Check ban status
    // Note: The ban check is in IdentityRegistry, but we need the public key
    // For now, we check via violation count as a proxy
    auto viol_it = violation_counts_.find(peer_id);
    criteria.is_not_banned = (viol_it == violation_counts_.end() || viol_it->second < 3);

    return criteria;
}

// ============================================================================
// Activity Recording
// ============================================================================

void EligibilityTracker::record_seen(const hash_t& peer_id, tx_epoch_t epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& record = ensure_record(peer_id, epoch);
    record.last_seen_epoch = epoch;

    // Add epoch to active epochs if not already present
    if (record.active_epochs.empty() ||
        record.active_epochs.back() != epoch) {
        record.active_epochs.push_back(epoch);
    }
}

void EligibilityTracker::record_relay(
    const hash_t& peer_id,
    const hash_t& relayer_id,
    tx_epoch_t epoch) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto& record = ensure_record(peer_id, epoch);
    record.relayers.insert(relayer_id);
    record.last_seen_epoch = epoch;
}

void EligibilityTracker::record_receipt(const hash_t& peer_id, tx_epoch_t epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& record = ensure_record(peer_id, epoch);
    record.receipt_count++;
    record.last_seen_epoch = epoch;
}

// ============================================================================
// Sponsorship
// ============================================================================

SponsorshipResult EligibilityTracker::check_sponsorship(
    const hash_t& sponsor_id,
    const hash_t& new_peer_id,
    tx_epoch_t epoch,
    const IdentityRegistry& identity_reg) const {

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if sponsor is eligible
    // Note: Need to unlock mutex before calling is_eligible, so we inline the check
    auto sponsor_it = activity_records_.find(sponsor_id);
    if (sponsor_it == activity_records_.end() ||
        !seen_in_lookback(sponsor_id, epoch) ||
        !sponsor_it->second.has_sufficient_relays()) {
        return SponsorshipResult::SPONSOR_NOT_ELIGIBLE;
    }

    // Check if sponsor is at limit for this epoch
    auto epoch_it = sponsorship_counts_.find(epoch);
    if (epoch_it != sponsorship_counts_.end()) {
        auto sponsor_count_it = epoch_it->second.find(sponsor_id);
        if (sponsor_count_it != epoch_it->second.end() &&
            sponsor_count_it->second >= MAX_NEW_PEERS_PER_SPONSOR_PER_EPOCH) {
            return SponsorshipResult::SPONSOR_AT_LIMIT;
        }
    }

    // Check if new peer is already eligible
    auto new_peer_it = activity_records_.find(new_peer_id);
    if (new_peer_it != activity_records_.end() &&
        new_peer_it->second.has_sufficient_relays()) {
        return SponsorshipResult::NEW_PEER_ALREADY_ELIGIBLE;
    }

    // Check if new peer already has a sponsor this epoch
    for (const auto& s : sponsorships_) {
        if (s.new_peer_id == new_peer_id && s.epoch == epoch) {
            return SponsorshipResult::NEW_PEER_ALREADY_SPONSORED;
        }
    }

    return SponsorshipResult::SUCCESS;
}

void EligibilityTracker::record_sponsorship(
    const hash_t& sponsor_id,
    const hash_t& new_peer_id,
    tx_epoch_t epoch) {

    std::lock_guard<std::mutex> lock(mutex_);

    // Increment sponsor count for this epoch
    sponsorship_counts_[epoch][sponsor_id]++;

    // Record the sponsorship
    sponsorships_.push_back(SponsorshipRecord{
        .sponsor_id = sponsor_id,
        .new_peer_id = new_peer_id,
        .epoch = epoch
    });

    // The sponsor also acts as a relayer for the new peer
    auto& record = ensure_record(new_peer_id, epoch);
    record.relayers.insert(sponsor_id);
}

std::size_t EligibilityTracker::get_sponsor_count(
    const hash_t& sponsor_id,
    tx_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto epoch_it = sponsorship_counts_.find(epoch);
    if (epoch_it == sponsorship_counts_.end()) {
        return 0;
    }

    auto sponsor_it = epoch_it->second.find(sponsor_id);
    if (sponsor_it == epoch_it->second.end()) {
        return 0;
    }

    return sponsor_it->second;
}

// ============================================================================
// Violations
// ============================================================================

void EligibilityTracker::record_violation(
    const hash_t& peer_id,
    tx_epoch_t epoch,
    EligibilityViolation violation) {

    std::lock_guard<std::mutex> lock(mutex_);

    violation_counts_[peer_id]++;

    if (auto it = activity_records_.find(peer_id); it != activity_records_.end()) {
        it->second.violation_count++;
    }
}

std::size_t EligibilityTracker::get_violation_count(const hash_t& peer_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = violation_counts_.find(peer_id);
    if (it == violation_counts_.end()) {
        return 0;
    }
    return it->second;
}

// ============================================================================
// Attestation Weight
// ============================================================================

double EligibilityTracker::attestation_weight(
    const hash_t& peer_id,
    const IdentityRegistry& identity_reg,
    identity_epoch_t current_epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if peer has an activity record
    auto it = activity_records_.find(peer_id);
    if (it == activity_records_.end()) {
        return 0.0;  // Unknown peer has no weight
    }

    // Check if peer has sufficient relays
    if (!it->second.has_sufficient_relays()) {
        return 0.5;  // Partially eligible peers have reduced weight
    }

    // Weight is based on how many epochs the peer has been active
    std::size_t active_count = it->second.active_epochs.size();

    // Cap at 100 epochs (same as lookback window)
    if (active_count > ELIGIBILITY_LOOKBACK_EPOCHS) {
        active_count = ELIGIBILITY_LOOKBACK_EPOCHS;
    }

    // Weight = 1.0 + (active_epochs - 1) * 0.1, capped at 10.0
    // This gives new peers weight 1.0 and 100-epoch veterans weight 10.0
    double weight = 1.0 + static_cast<double>(active_count - 1) * 0.1;
    if (weight > 10.0) {
        weight = 10.0;
    }

    return weight;
}

bool EligibilityTracker::meets_attestation_threshold(
    const std::vector<hash_t>& peer_ids,
    const IdentityRegistry& identity_reg,
    identity_epoch_t current_epoch) const {

    double total_weight = 0.0;

    for (const auto& peer_id : peer_ids) {
        total_weight += attestation_weight(peer_id, identity_reg, current_epoch);
    }

    return total_weight >= static_cast<double>(MIN_ATTESTATION_WEIGHT);
}

// ============================================================================
// Maintenance
// ============================================================================

std::size_t EligibilityTracker::prune_inactive(tx_epoch_t current_epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t pruned = 0;

    // Calculate cutoff epoch
    tx_epoch_t cutoff = 0;
    if (current_epoch > ELIGIBILITY_LOOKBACK_EPOCHS) {
        cutoff = current_epoch - ELIGIBILITY_LOOKBACK_EPOCHS;
    }

    // Prune inactive peer records
    for (auto it = activity_records_.begin(); it != activity_records_.end(); ) {
        if (it->second.last_seen_epoch < cutoff) {
            it = activity_records_.erase(it);
            pruned++;
        } else {
            ++it;
        }
    }

    // Prune old sponsorship counts
    for (auto it = sponsorship_counts_.begin(); it != sponsorship_counts_.end(); ) {
        if (it->first < cutoff) {
            it = sponsorship_counts_.erase(it);
        } else {
            ++it;
        }
    }

    // Prune old sponsorship records
    sponsorships_.erase(
        std::remove_if(sponsorships_.begin(), sponsorships_.end(),
            [cutoff](const SponsorshipRecord& s) {
                return s.epoch < cutoff;
            }),
        sponsorships_.end()
    );

    return pruned;
}

std::optional<PeerActivityRecord> EligibilityTracker::get_activity_record(
    const hash_t& peer_id) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = activity_records_.find(peer_id);
    if (it == activity_records_.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::size_t EligibilityTracker::peer_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activity_records_.size();
}

std::size_t EligibilityTracker::eligible_count(
    tx_epoch_t epoch,
    const IdentityRegistry& identity_reg) const {

    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t count = 0;
    for (const auto& [peer_id, record] : activity_records_) {
        if (seen_in_lookback(peer_id, epoch) &&
            record.has_sufficient_relays()) {
            count++;
        }
    }

    return count;
}

// ============================================================================
// Serialization
// ============================================================================

std::vector<std::uint8_t> EligibilityTracker::serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::uint8_t> result;

    // Header: number of activity records
    std::array<std::uint8_t, 4> count_bytes;
    encode_u32(count_bytes.data(), static_cast<std::uint32_t>(activity_records_.size()));
    result.insert(result.end(), count_bytes.begin(), count_bytes.end());

    // Serialize each activity record
    for (const auto& [peer_id, record] : activity_records_) {
        // Peer ID
        result.insert(result.end(), peer_id.begin(), peer_id.end());

        // First/last seen epochs
        std::array<std::uint8_t, 8> epoch_bytes;
        encode_u64(epoch_bytes.data(), record.first_seen_epoch);
        result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

        encode_u64(epoch_bytes.data(), record.last_seen_epoch);
        result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

        // Relayer count and IDs
        encode_u32(count_bytes.data(), static_cast<std::uint32_t>(record.relayers.size()));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());
        for (const auto& relayer : record.relayers) {
            result.insert(result.end(), relayer.begin(), relayer.end());
        }

        // Receipt and violation counts
        encode_u64(epoch_bytes.data(), record.receipt_count);
        result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

        encode_u64(epoch_bytes.data(), record.violation_count);
        result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

        // Active epochs count and list (just count for efficiency)
        encode_u32(count_bytes.data(), static_cast<std::uint32_t>(record.active_epochs.size()));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());
    }

    // Serialize violation counts
    encode_u32(count_bytes.data(), static_cast<std::uint32_t>(violation_counts_.size()));
    result.insert(result.end(), count_bytes.begin(), count_bytes.end());

    for (const auto& [peer_id, count] : violation_counts_) {
        result.insert(result.end(), peer_id.begin(), peer_id.end());
        std::array<std::uint8_t, 8> viol_bytes;
        encode_u64(viol_bytes.data(), count);
        result.insert(result.end(), viol_bytes.begin(), viol_bytes.end());
    }

    return result;
}

std::optional<EligibilityTracker> EligibilityTracker::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < 4) {
        return std::nullopt;
    }

    EligibilityTracker tracker;
    std::size_t offset = 0;

    // Activity record count
    std::uint32_t record_count = decode_u32(data.data() + offset);
    offset += 4;

    for (std::uint32_t i = 0; i < record_count; ++i) {
        if (offset + HASH_SIZE + 16 + 4 > data.size()) {
            return std::nullopt;
        }

        PeerActivityRecord record;

        // Peer ID
        std::copy(data.begin() + offset, data.begin() + offset + HASH_SIZE, record.peer_id.begin());
        offset += HASH_SIZE;

        // Epochs
        record.first_seen_epoch = decode_u64(data.data() + offset);
        offset += 8;

        record.last_seen_epoch = decode_u64(data.data() + offset);
        offset += 8;

        // Relayers
        std::uint32_t relayer_count = decode_u32(data.data() + offset);
        offset += 4;

        if (offset + relayer_count * HASH_SIZE > data.size()) {
            return std::nullopt;
        }

        for (std::uint32_t j = 0; j < relayer_count; ++j) {
            hash_t relayer;
            std::copy(data.begin() + offset, data.begin() + offset + HASH_SIZE, relayer.begin());
            record.relayers.insert(relayer);
            offset += HASH_SIZE;
        }

        // Counts
        if (offset + 20 > data.size()) {
            return std::nullopt;
        }

        record.receipt_count = decode_u64(data.data() + offset);
        offset += 8;

        record.violation_count = decode_u64(data.data() + offset);
        offset += 8;

        // Skip active epoch count (we reconstruct simplified version below)
        [[maybe_unused]] std::uint32_t active_count = decode_u32(data.data() + offset);
        offset += 4;

        // Reconstruct active_epochs with just first/last for now
        record.active_epochs.push_back(record.first_seen_epoch);
        if (record.first_seen_epoch != record.last_seen_epoch) {
            record.active_epochs.push_back(record.last_seen_epoch);
        }

        tracker.activity_records_[record.peer_id] = std::move(record);
    }

    // Deserialize violation counts
    if (offset + 4 > data.size()) {
        return std::nullopt;
    }

    std::uint32_t viol_count = decode_u32(data.data() + offset);
    offset += 4;

    for (std::uint32_t i = 0; i < viol_count; ++i) {
        if (offset + HASH_SIZE + 8 > data.size()) {
            return std::nullopt;
        }

        hash_t peer_id;
        std::copy(data.begin() + offset, data.begin() + offset + HASH_SIZE, peer_id.begin());
        offset += HASH_SIZE;

        std::size_t count = decode_u64(data.data() + offset);
        offset += 8;

        tracker.violation_counts_[peer_id] = count;
    }

    return {std::move(tracker)};
}

// ============================================================================
// Private Helpers
// ============================================================================

bool EligibilityTracker::seen_in_lookback(
    const hash_t& peer_id,
    tx_epoch_t current_epoch) const {

    auto it = activity_records_.find(peer_id);
    if (it == activity_records_.end()) {
        return false;
    }

    tx_epoch_t cutoff = 0;
    if (current_epoch > ELIGIBILITY_LOOKBACK_EPOCHS) {
        cutoff = current_epoch - ELIGIBILITY_LOOKBACK_EPOCHS;
    }

    return it->second.last_seen_epoch >= cutoff;
}

PeerActivityRecord& EligibilityTracker::ensure_record(
    const hash_t& peer_id,
    tx_epoch_t epoch) {

    auto it = activity_records_.find(peer_id);
    if (it == activity_records_.end()) {
        PeerActivityRecord record{
            .peer_id = peer_id,
            .first_seen_epoch = epoch,
            .last_seen_epoch = epoch,
            .relayers = {},
            .active_epochs = {epoch},
            .receipt_count = 0,
            .violation_count = 0
        };
        it = activity_records_.emplace(peer_id, std::move(record)).first;
    }
    return it->second;
}

}  // namespace pop
