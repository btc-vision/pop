#include "finality.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "core/logging.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// Attestation Implementation
// ============================================================================

bool Attestation::verify(const mldsa_public_key_t& pk) const {
    // Verify peer_id matches
    hash_t expected_peer_id = sha3_256(pk);
    if (expected_peer_id != peer_id) {
        return false;
    }

    auto msg = message_bytes();
    return mldsa_verify(pk, msg, signature);
}

std::vector<std::uint8_t> Attestation::message_bytes() const {
    std::vector<std::uint8_t> result;
    result.reserve(HASH_SIZE + sizeof(tx_epoch_t) + HASH_SIZE + sizeof(std::size_t));

    // State root
    result.insert(result.end(), state_root.begin(), state_root.end());

    // Epoch
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    // Peer ID
    result.insert(result.end(), peer_id.begin(), peer_id.end());

    // Identity age
    encode_u64(epoch_bytes.data(), identity_age);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    return result;
}

std::vector<std::uint8_t> Attestation::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    std::copy(state_root.begin(), state_root.end(), ptr);
    ptr += HASH_SIZE;

    encode_u64(ptr, epoch);
    ptr += sizeof(tx_epoch_t);

    std::copy(peer_id.begin(), peer_id.end(), ptr);
    ptr += HASH_SIZE;

    encode_u64(ptr, identity_age);
    ptr += sizeof(std::size_t);

    std::copy(signature.begin(), signature.end(), ptr);

    return result;
}

std::optional<Attestation> Attestation::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    Attestation att;
    const std::uint8_t* ptr = data.data();

    std::copy(ptr, ptr + HASH_SIZE, att.state_root.begin());
    ptr += HASH_SIZE;

    att.epoch = decode_u64(ptr);
    ptr += sizeof(tx_epoch_t);

    std::copy(ptr, ptr + HASH_SIZE, att.peer_id.begin());
    ptr += HASH_SIZE;

    att.identity_age = decode_u64(ptr);
    ptr += sizeof(std::size_t);

    std::copy(ptr, ptr + MLDSA65_SIGNATURE_SIZE, att.signature.begin());

    return att;
}

// ============================================================================
// SoftFinalityRecord Implementation
// ============================================================================

std::vector<std::uint8_t> SoftFinalityRecord::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(sizeof(tx_epoch_t) + HASH_SIZE * 2 + sizeof(std::uint64_t) + 1);

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), epoch);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    result.insert(result.end(), state_root.begin(), state_root.end());
    result.insert(result.end(), reveal_set_commitment.begin(), reveal_set_commitment.end());

    encode_u64(u64_bytes.data(), freeze_vdf_step);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    result.push_back(is_binding ? 1 : 0);

    return result;
}

std::optional<SoftFinalityRecord> SoftFinalityRecord::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < sizeof(tx_epoch_t) + HASH_SIZE * 2 + sizeof(std::uint64_t) + 1) {
        return std::nullopt;
    }

    SoftFinalityRecord record;
    const std::uint8_t* ptr = data.data();

    record.epoch = decode_u64(ptr);
    ptr += sizeof(tx_epoch_t);

    std::copy(ptr, ptr + HASH_SIZE, record.state_root.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, record.reveal_set_commitment.begin());
    ptr += HASH_SIZE;

    record.freeze_vdf_step = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    record.is_binding = (*ptr != 0);

    return record;
}

// ============================================================================
// HardFinalityRecord Implementation
// ============================================================================

std::vector<std::uint8_t> HardFinalityRecord::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(sizeof(tx_epoch_t) + HASH_SIZE * 2 + sizeof(std::uint64_t) * 2);

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), epoch);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    result.insert(result.end(), state_root.begin(), state_root.end());
    result.insert(result.end(), reveal_set_commitment.begin(), reveal_set_commitment.end());

    encode_u64(u64_bytes.data(), convergence_vdf_step);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    encode_u64(u64_bytes.data(), total_attestation_weight);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    return result;
}

std::optional<HardFinalityRecord> HardFinalityRecord::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < sizeof(tx_epoch_t) + HASH_SIZE * 2 + sizeof(std::uint64_t) * 2) {
        return std::nullopt;
    }

    HardFinalityRecord record;
    const std::uint8_t* ptr = data.data();

    record.epoch = decode_u64(ptr);
    ptr += sizeof(tx_epoch_t);

    std::copy(ptr, ptr + HASH_SIZE, record.state_root.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, record.reveal_set_commitment.begin());
    ptr += HASH_SIZE;

    record.convergence_vdf_step = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    record.total_attestation_weight = decode_u64(ptr);

    return record;
}

// ============================================================================
// FinalityTracker Implementation
// ============================================================================

void FinalityTracker::record_soft_finality(
    tx_epoch_t epoch,
    const hash_t& state_root,
    const hash_t& reveal_set_commitment,
    std::uint64_t freeze_vdf_step) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto& state = epochs_[epoch];
    state.soft.epoch = epoch;
    state.soft.state_root = state_root;
    state.soft.reveal_set_commitment = reveal_set_commitment;
    state.soft.freeze_vdf_step = freeze_vdf_step;
    state.soft.is_binding = true;

    POP_LOG_INFO(log::consensus) << "Soft finality recorded for epoch " << epoch << " at VDF step " << freeze_vdf_step;
}

bool FinalityTracker::has_soft_finality(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = epochs_.find(epoch);
    return it != epochs_.end() && it->second.soft.is_binding;
}

std::optional<SoftFinalityRecord> FinalityTracker::get_soft_finality(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = epochs_.find(epoch);
    if (it == epochs_.end() || !it->second.soft.is_binding) {
        return std::nullopt;
    }
    return it->second.soft;
}

FinalityTracker::AttestationResult FinalityTracker::add_attestation(
    const Attestation& att,
    const mldsa_public_key_t& peer_pk,
    const IdentityRegistry& identity_reg,
    identity_epoch_t current_identity_epoch) {

    std::lock_guard<std::mutex> lock(mutex_);

    // Check epoch has soft finality
    auto it = epochs_.find(att.epoch);
    if (it == epochs_.end() || !it->second.soft.is_binding) {
        POP_LOG_DEBUG(log::consensus) << "Attestation rejected: epoch " << att.epoch << " not soft-final";
        return AttestationResult::EPOCH_NOT_SOFT_FINAL;
    }

    // Verify signature
    if (!att.verify(peer_pk)) {
        POP_LOG_DEBUG(log::consensus) << "Attestation rejected: invalid signature";
        return AttestationResult::INVALID_SIGNATURE;
    }

    // Check peer eligibility
    if (!identity_reg.is_valid(peer_pk, current_identity_epoch)) {
        POP_LOG_DEBUG(log::consensus) << "Attestation rejected: peer not eligible";
        return AttestationResult::PEER_NOT_ELIGIBLE;
    }

    // Check for duplicate
    if (it->second.seen_peer_ids.count(att.peer_id) > 0) {
        POP_LOG_TRACE(log::consensus) << "Attestation skipped: duplicate";
        return AttestationResult::DUPLICATE;
    }

    // Check state root matches soft finality
    if (att.state_root != it->second.soft.state_root) {
        // This could be a competing root in partition scenario
        // Still accept for tiebreaker resolution
        POP_LOG_DEBUG(log::consensus) << "Attestation for competing root in epoch " << att.epoch;
    }

    // Record attestation
    it->second.attestations[att.state_root].push_back(att);
    it->second.attestation_weights[att.state_root] += att.identity_age;
    it->second.seen_peer_ids.insert(att.peer_id);

    POP_LOG_TRACE(log::consensus) << "Attestation accepted for epoch " << att.epoch
                                   << " with weight " << att.identity_age
                                   << ", total weight now "
                                   << it->second.attestation_weights[att.state_root];

    return AttestationResult::ACCEPTED;
}

std::size_t FinalityTracker::get_attestation_weight(
    tx_epoch_t epoch,
    const hash_t& state_root) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return 0;
    }

    auto weight_it = it->second.attestation_weights.find(state_root);
    if (weight_it == it->second.attestation_weights.end()) {
        return 0;
    }

    return weight_it->second;
}

bool FinalityTracker::has_hard_finality(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = epochs_.find(epoch);
    return it != epochs_.end() && it->second.hard.has_value();
}

std::optional<HardFinalityRecord> FinalityTracker::get_hard_finality(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = epochs_.find(epoch);
    if (it == epochs_.end() || !it->second.hard.has_value()) {
        return std::nullopt;
    }
    return it->second.hard;
}

bool FinalityTracker::check_convergence(
    tx_epoch_t epoch,
    std::uint64_t current_vdf_step,
    const IdentityRegistry& identity_reg) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end() || !it->second.soft.is_binding) {
        return false;
    }

    if (it->second.hard.has_value()) {
        return true;  // Already hard-finalized
    }

    // Calculate total identity age weight in registry
    std::size_t total_weight = 0;
    for (const auto& [root, weight] : it->second.attestation_weights) {
        total_weight = std::max(total_weight, weight);
    }

    // For now, use soft finality state root
    auto soft_root_weight = get_attestation_weight(epoch, it->second.soft.state_root);

    // Check if we have sufficient attestation weight
    // In a real implementation, we'd compare against total eligible weight
    if (soft_root_weight > 0) {
        HardFinalityRecord hard;
        hard.epoch = epoch;
        hard.state_root = it->second.soft.state_root;
        hard.reveal_set_commitment = it->second.soft.reveal_set_commitment;
        hard.convergence_vdf_step = current_vdf_step;
        hard.total_attestation_weight = soft_root_weight;

        it->second.hard = hard;
        last_hard_finalized_epoch_ = std::max(last_hard_finalized_epoch_, epoch);

        POP_LOG_INFO(log::consensus) << "HARD FINALITY achieved for epoch " << epoch
                                      << " at VDF step " << current_vdf_step
                                      << " with weight " << soft_root_weight;
        return true;
    }

    return false;
}

hash_t FinalityTracker::resolve_partition(
    tx_epoch_t epoch,
    const std::vector<hash_t>& competing_roots) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return competing_roots.empty() ? hash_t{} : competing_roots[0];
    }

    // Find root with highest age-weighted attestation
    hash_t winner;
    std::size_t max_weight = 0;

    for (const auto& root : competing_roots) {
        auto weight_it = it->second.attestation_weights.find(root);
        if (weight_it != it->second.attestation_weights.end()) {
            if (weight_it->second > max_weight) {
                max_weight = weight_it->second;
                winner = root;
            } else if (weight_it->second == max_weight && root < winner) {
                // Tie: use lexicographic ordering
                winner = root;
            }
        }
    }

    return winner;
}

std::optional<hash_t> FinalityTracker::get_last_hard_finalized_root() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (last_hard_finalized_epoch_ == 0) {
        return std::nullopt;
    }

    auto it = epochs_.find(last_hard_finalized_epoch_);
    if (it == epochs_.end() || !it->second.hard.has_value()) {
        return std::nullopt;
    }

    return it->second.hard->state_root;
}

FinalityType FinalityTracker::get_finality_type(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return FinalityType::NONE;
    }

    if (it->second.hard.has_value()) {
        return FinalityType::HARD;
    }

    if (it->second.soft.is_binding) {
        return FinalityType::SOFT;
    }

    return FinalityType::NONE;
}

void FinalityTracker::prune(tx_epoch_t before_epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<tx_epoch_t> to_remove;
    for (const auto& [epoch, state] : epochs_) {
        if (epoch < before_epoch) {
            to_remove.push_back(epoch);
        }
    }

    for (auto epoch : to_remove) {
        epochs_.erase(epoch);
    }
}

// ============================================================================
// IBLTCell Implementation
// ============================================================================

void IBLTCell::insert(const hash_t& key, const hash_t& value) {
    for (std::size_t i = 0; i < HASH_SIZE; ++i) {
        key_sum[i] ^= key[i];
        value_sum[i] ^= value[i];
    }
    count++;
}

void IBLTCell::remove(const hash_t& key, const hash_t& value) {
    for (std::size_t i = 0; i < HASH_SIZE; ++i) {
        key_sum[i] ^= key[i];
        value_sum[i] ^= value[i];
    }
    count--;
}

bool IBLTCell::is_pure() const {
    return count == 1 || count == -1;
}

bool IBLTCell::is_empty() const {
    if (count != 0) return false;
    for (auto b : key_sum) {
        if (b != 0) return false;
    }
    for (auto b : value_sum) {
        if (b != 0) return false;
    }
    return true;
}

// ============================================================================
// IBLT Implementation
// ============================================================================

IBLT::IBLT() = default;

std::array<std::size_t, IBLT::HASH_COUNT> IBLT::get_indices(const hash_t& key) const {
    std::array<std::size_t, HASH_COUNT> indices;

    // Use different portions of SHA3(key) for each index
    SHA3Hasher hasher;
    hasher.update(key);
    hash_t h = hasher.finalize();

    for (std::size_t i = 0; i < HASH_COUNT; ++i) {
        std::uint64_t val = decode_u64(h.data() + (i * 8) % (HASH_SIZE - 7));
        indices[i] = val % CELL_COUNT;
    }

    return indices;
}

void IBLT::insert(const hash_t& key, const hash_t& value) {
    auto indices = get_indices(key);
    for (auto idx : indices) {
        cells_[idx].insert(key, value);
    }
}

void IBLT::remove(const hash_t& key, const hash_t& value) {
    auto indices = get_indices(key);
    for (auto idx : indices) {
        cells_[idx].remove(key, value);
    }
}

IBLT IBLT::subtract(const IBLT& other) const {
    IBLT result;
    for (std::size_t i = 0; i < CELL_COUNT; ++i) {
        for (std::size_t j = 0; j < HASH_SIZE; ++j) {
            result.cells_[i].key_sum[j] = cells_[i].key_sum[j] ^ other.cells_[i].key_sum[j];
            result.cells_[i].value_sum[j] = cells_[i].value_sum[j] ^ other.cells_[i].value_sum[j];
        }
        result.cells_[i].count = cells_[i].count - other.cells_[i].count;
    }
    return result;
}

IBLT::DecodeResult IBLT::decode() const {
    DecodeResult result;
    result.success = false;

    // Make a copy to modify during peeling
    std::array<IBLTCell, CELL_COUNT> cells = cells_;

    bool progress = true;
    while (progress) {
        progress = false;

        for (std::size_t i = 0; i < CELL_COUNT; ++i) {
            if (cells[i].is_pure()) {
                hash_t key = cells[i].key_sum;
                hash_t value = cells[i].value_sum;

                if (cells[i].count == 1) {
                    result.items_we_have.emplace_back(key, value);
                } else {
                    result.items_they_have.emplace_back(key, value);
                }

                // Remove from all cells
                auto indices = get_indices(key);
                for (auto idx : indices) {
                    if (cells[i].count == 1) {
                        cells[idx].remove(key, value);
                    } else {
                        cells[idx].insert(key, value);
                    }
                }

                progress = true;
            }
        }
    }

    // Check if all cells are now empty
    result.success = true;
    for (const auto& cell : cells) {
        if (!cell.is_empty()) {
            result.success = false;
            break;
        }
    }

    return result;
}

std::vector<std::pair<hash_t, hash_t>> IBLT::list_entries() const {
    auto result = decode();
    return result.items_we_have;
}

std::vector<std::uint8_t> IBLT::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(CELL_COUNT * (HASH_SIZE * 2 + sizeof(std::int32_t)));

    for (const auto& cell : cells_) {
        result.insert(result.end(), cell.key_sum.begin(), cell.key_sum.end());
        result.insert(result.end(), cell.value_sum.begin(), cell.value_sum.end());

        std::array<std::uint8_t, 4> count_bytes;
        std::memcpy(count_bytes.data(), &cell.count, sizeof(std::int32_t));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());
    }

    return result;
}

std::optional<IBLT> IBLT::deserialize(std::span<const std::uint8_t> data) {
    std::size_t expected_size = CELL_COUNT * (HASH_SIZE * 2 + sizeof(std::int32_t));
    if (data.size() < expected_size) {
        return std::nullopt;
    }

    IBLT iblt;
    const std::uint8_t* ptr = data.data();

    for (std::size_t i = 0; i < CELL_COUNT; ++i) {
        std::copy(ptr, ptr + HASH_SIZE, iblt.cells_[i].key_sum.begin());
        ptr += HASH_SIZE;

        std::copy(ptr, ptr + HASH_SIZE, iblt.cells_[i].value_sum.begin());
        ptr += HASH_SIZE;

        std::memcpy(&iblt.cells_[i].count, ptr, sizeof(std::int32_t));
        ptr += sizeof(std::int32_t);
    }

    return iblt;
}

// ============================================================================
// ReconciliationManager Implementation
// ============================================================================

IBLT ReconciliationManager::build_local_iblt(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return IBLT{};
    }

    return it->second.iblt;
}

void ReconciliationManager::add_reveal(tx_epoch_t epoch, const hash_t& reveal_hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& data = epochs_[epoch];
    if (data.reveal_hashes.insert(reveal_hash).second) {
        // Use reveal_hash as both key and value for simplicity
        data.iblt.insert(reveal_hash, reveal_hash);
    }
}

bool ReconciliationManager::needs_reconciliation(
    tx_epoch_t epoch,
    const hash_t& peer_state_root) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);

    // If we have no data for this epoch, we might need reveals from the peer
    if (it == epochs_.end()) {
        // Check if peer has a non-empty state root (meaning they have data)
        hash_t empty_root{};
        return peer_state_root != empty_root;
    }

    // If we don't have a local state root yet, we can't compare
    if (!it->second.local_state_root.has_value()) {
        // If we have some reveals, we might need more from peer
        return !it->second.reveal_hashes.empty();
    }

    // Compare our state root with peer's
    // If they differ, reconciliation is needed
    if (*it->second.local_state_root != peer_state_root) {
        POP_LOG_TRACE(log::consensus) << "Reconciliation needed for epoch " << epoch
                                       << ": state roots differ";
        return true;
    }

    // State roots match, no reconciliation needed
    return false;
}

void ReconciliationManager::set_local_state_root(tx_epoch_t epoch, const hash_t& state_root) {
    std::lock_guard<std::mutex> lock(mutex_);
    epochs_[epoch].local_state_root = state_root;
}

std::optional<hash_t> ReconciliationManager::get_local_state_root(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return std::nullopt;
    }

    return it->second.local_state_root;
}

std::size_t ReconciliationManager::reveal_count(tx_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return 0;
    }

    return it->second.reveal_hashes.size();
}

ReconciliationManager::ReconciliationResult ReconciliationManager::reconcile(
    tx_epoch_t epoch,
    const IBLT& peer_iblt) {

    std::lock_guard<std::mutex> lock(mutex_);

    ReconciliationResult result;

    auto it = epochs_.find(epoch);
    if (it == epochs_.end()) {
        return result;
    }

    // Subtract peer's IBLT from ours
    IBLT diff = it->second.iblt.subtract(peer_iblt);
    auto decoded = diff.decode();

    if (decoded.success) {
        // items_we_have: reveals we have that peer doesn't
        for (const auto& [key, value] : decoded.items_we_have) {
            result.reveals_to_send.push_back(key);
        }

        // items_they_have: reveals peer has that we don't
        for (const auto& [key, value] : decoded.items_they_have) {
            result.reveals_we_need.push_back(key);
        }
    }

    return result;
}

bool ReconciliationManager::check_rate_limit(const hash_t& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& count = peer_request_counts_[peer_id];
    if (count >= MAX_REQUESTS_PER_PEER_PER_WINDOW) {
        return false;
    }

    count++;
    return true;
}

void ReconciliationManager::mark_received(tx_epoch_t epoch, const std::vector<hash_t>& reveals) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& data = epochs_[epoch];
    for (const auto& reveal_hash : reveals) {
        if (data.reveal_hashes.insert(reveal_hash).second) {
            data.iblt.insert(reveal_hash, reveal_hash);
        }
    }
}

void ReconciliationManager::clear_epoch(tx_epoch_t epoch) {
    std::lock_guard<std::mutex> lock(mutex_);
    epochs_.erase(epoch);
}

}  // namespace pop
