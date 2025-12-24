#include "batch_receipt.hh"
#include "network/eligibility.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "core/logging.hh"
#include <algorithm>

namespace pop {

// ============================================================================
// BatchReceipt Implementation
// ============================================================================

bool BatchReceipt::verify(const mldsa_public_key_t& pk) const {
    // Verify peer_id matches
    hash_t expected_peer_id = sha3_256(pk);
    if (expected_peer_id != peer_id) {
        POP_LOG_DEBUG(log::consensus) << "BatchReceipt verification failed: peer_id mismatch";
        return false;
    }

    auto msg = message_bytes();
    bool valid = mldsa_verify(pk, msg, signature);
    if (!valid) {
        POP_LOG_DEBUG(log::consensus) << "BatchReceipt verification failed: invalid signature";
    }
    return valid;
}

std::vector<std::uint8_t> BatchReceipt::message_bytes() const {
    std::vector<std::uint8_t> result;
    result.reserve(sizeof(tx_epoch_t) + 1 + HASH_SIZE + HASH_SIZE);

    // epoch_id
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch_id);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    // bucket_id
    result.push_back(bucket_id);

    // merkle_root
    result.insert(result.end(), merkle_root.begin(), merkle_root.end());

    // peer_id
    result.insert(result.end(), peer_id.begin(), peer_id.end());

    return result;
}

std::vector<std::uint8_t> BatchReceipt::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    encode_u64(ptr, epoch_id);
    ptr += sizeof(tx_epoch_t);

    *ptr++ = bucket_id;

    std::copy(merkle_root.begin(), merkle_root.end(), ptr);
    ptr += HASH_SIZE;

    std::copy(peer_id.begin(), peer_id.end(), ptr);
    ptr += HASH_SIZE;

    std::copy(signature.begin(), signature.end(), ptr);

    return result;
}

std::optional<BatchReceipt> BatchReceipt::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    BatchReceipt receipt;
    const std::uint8_t* ptr = data.data();

    receipt.epoch_id = decode_u64(ptr);
    ptr += sizeof(tx_epoch_t);

    receipt.bucket_id = *ptr++;

    std::copy(ptr, ptr + HASH_SIZE, receipt.merkle_root.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, receipt.peer_id.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + MLDSA65_SIGNATURE_SIZE, receipt.signature.begin());

    return receipt;
}

// ============================================================================
// ReceiptInclusionProof Implementation
// ============================================================================

bool ReceiptInclusionProof::verify(const hash_t& reveal_hash) const {
    return MerkleTree::verify(reveal_hash, merkle_proof, leaf_index, receipt.merkle_root);
}

// ============================================================================
// RevealEligibility Implementation
// ============================================================================

bool RevealEligibility::verify(
    const IdentityRegistry& reg,
    identity_epoch_t epoch) const {

    std::unordered_set<hash_t> verified_peers;

    for (const auto& proof : proofs) {
        // Verify merkle proof
        if (!proof.verify(reveal_hash)) {
            continue;
        }

        // Check peer eligibility (we'd need pk lookup - simplified here)
        // In practice, we'd verify the peer has a valid identity for the epoch
        verified_peers.insert(proof.receipt.peer_id);
    }

    return verified_peers.size() >= MIN_DISTINCT_PEER_RECEIPTS;
}

std::unordered_set<hash_t> RevealEligibility::peer_set() const {
    std::unordered_set<hash_t> peers;
    for (const auto& proof : proofs) {
        peers.insert(proof.receipt.peer_id);
    }
    return peers;
}

std::vector<std::uint8_t> RevealEligibility::serialize() const {
    std::vector<std::uint8_t> result;

    // reveal_hash
    result.insert(result.end(), reveal_hash.begin(), reveal_hash.end());

    // proof count
    std::array<std::uint8_t, 4> count_bytes;
    encode_u32(count_bytes.data(), static_cast<std::uint32_t>(proofs.size()));
    result.insert(result.end(), count_bytes.begin(), count_bytes.end());

    // Each proof
    for (const auto& proof : proofs) {
        // Receipt
        auto receipt_bytes = proof.receipt.serialize();
        result.insert(result.end(), receipt_bytes.begin(), receipt_bytes.end());

        // Merkle proof length
        encode_u32(count_bytes.data(), static_cast<std::uint32_t>(proof.merkle_proof.size()));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());

        // Merkle proof hashes
        for (const auto& h : proof.merkle_proof) {
            result.insert(result.end(), h.begin(), h.end());
        }

        // Leaf index
        std::array<std::uint8_t, 8> idx_bytes;
        encode_u64(idx_bytes.data(), proof.leaf_index);
        result.insert(result.end(), idx_bytes.begin(), idx_bytes.end());
    }

    return result;
}

std::optional<RevealEligibility> RevealEligibility::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < HASH_SIZE + 4) {
        return std::nullopt;
    }

    RevealEligibility elig;
    const std::uint8_t* ptr = data.data();

    std::copy(ptr, ptr + HASH_SIZE, elig.reveal_hash.begin());
    ptr += HASH_SIZE;

    std::uint32_t proof_count = decode_u32(ptr);
    ptr += 4;

    for (std::uint32_t i = 0; i < proof_count; ++i) {
        ReceiptInclusionProof proof;

        // Receipt
        auto receipt_opt = BatchReceipt::deserialize({ptr, BatchReceipt::SERIALIZED_SIZE});
        if (!receipt_opt) {
            return std::nullopt;
        }
        proof.receipt = *receipt_opt;
        ptr += BatchReceipt::SERIALIZED_SIZE;

        // Merkle proof length
        std::uint32_t merkle_len = decode_u32(ptr);
        ptr += 4;

        // Merkle proof hashes
        for (std::uint32_t j = 0; j < merkle_len; ++j) {
            hash_t h;
            std::copy(ptr, ptr + HASH_SIZE, h.begin());
            proof.merkle_proof.push_back(h);
            ptr += HASH_SIZE;
        }

        // Leaf index
        proof.leaf_index = decode_u64(ptr);
        ptr += 8;

        elig.proofs.push_back(std::move(proof));
    }

    return elig;
}

// ============================================================================
// BatchReceiptPool Implementation
// ============================================================================

BatchReceiptPool::AddResult BatchReceiptPool::add_receipt(
    const BatchReceipt& receipt,
    const mldsa_public_key_t& peer_pk,
    const IdentityRegistry& identity_reg,
    identity_epoch_t current_identity_epoch) {

    std::lock_guard<std::mutex> lock(mutex_);

    // Verify signature
    if (!receipt.verify(peer_pk)) {
        POP_LOG_DEBUG(log::consensus) << "Receipt rejected: invalid signature for epoch "
                                       << receipt.epoch_id << " bucket " << (int)receipt.bucket_id;
        return AddResult::INVALID_SIGNATURE;
    }

    // Check bucket timing
    if (receipt.bucket_id > BUCKETS_PER_TX_EPOCH - 1) {
        POP_LOG_DEBUG(log::consensus) << "Receipt rejected: invalid bucket " << (int)receipt.bucket_id;
        return AddResult::INVALID_TIMING;
    }
    if (receipt.bucket_id > RECEIPT_CUTOFF_BUCKET) {
        POP_LOG_DEBUG(log::consensus) << "Receipt rejected: bucket " << (int)receipt.bucket_id << " is frozen";
        return AddResult::BUCKET_FROZEN;
    }

    // Check peer eligibility
    if (!identity_reg.is_valid(peer_pk, current_identity_epoch)) {
        POP_LOG_DEBUG(log::consensus) << "Receipt rejected: peer not eligible";
        return AddResult::PEER_NOT_ELIGIBLE;
    }

    // Check for duplicate
    BucketKey key{receipt.epoch_id, receipt.bucket_id};
    auto& bucket = bucket_receipts_[key];
    for (const auto& existing : bucket) {
        if (existing.peer_id == receipt.peer_id) {
            POP_LOG_TRACE(log::consensus) << "Receipt skipped: duplicate from peer";
            return AddResult::DUPLICATE;
        }
    }

    // Add to bucket
    bucket.push_back(receipt);
    POP_LOG_TRACE(log::consensus) << "Receipt added: epoch " << receipt.epoch_id
                                   << " bucket " << (int)receipt.bucket_id
                                   << ", bucket now has " << bucket.size() << " receipts";

    return AddResult::ADDED;
}

bool BatchReceiptPool::has_sufficient_receipts(
    const hash_t& reveal_hash,
    const IdentityRegistry& reg,
    identity_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reveal_receipts_.find(reveal_hash);
    if (it == reveal_receipts_.end()) {
        return false;
    }

    // Count distinct eligible peers
    std::size_t eligible_count = 0;
    for (const auto& peer_id : it->second.peer_ids) {
        // Simplified check - in practice we'd verify identity
        eligible_count++;
    }

    return eligible_count >= MIN_DISTINCT_PEER_RECEIPTS;
}

bool BatchReceiptPool::has_sufficient_attestation_weight(
    const hash_t& reveal_hash,
    const IdentityRegistry& reg,
    const EligibilityTracker& eligibility,
    identity_epoch_t epoch) const {

    double total_weight = get_attestation_weight(reveal_hash, reg, eligibility, epoch);
    return total_weight >= static_cast<double>(MIN_ATTESTATION_WEIGHT);
}

double BatchReceiptPool::get_attestation_weight(
    const hash_t& reveal_hash,
    const IdentityRegistry& reg,
    const EligibilityTracker& eligibility,
    identity_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reveal_receipts_.find(reveal_hash);
    if (it == reveal_receipts_.end()) {
        return 0.0;
    }

    double total_weight = 0.0;

    // Sum attestation weight for each distinct peer
    for (const auto& peer_id : it->second.peer_ids) {
        // Get the age-weighted attestation value for this peer
        double peer_weight = eligibility.attestation_weight(peer_id, reg, epoch);
        total_weight += peer_weight;
    }

    return total_weight;
}

std::optional<RevealEligibility> BatchReceiptPool::build_eligibility(
    const hash_t& reveal_hash,
    const IdentityRegistry& reg,
    identity_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reveal_receipts_.find(reveal_hash);
    if (it == reveal_receipts_.end()) {
        return std::nullopt;
    }

    RevealEligibility elig;
    elig.reveal_hash = reveal_hash;

    // Build proofs from receipts
    // In practice, we'd build proper merkle proofs
    for (const auto& receipt : it->second.receipts) {
        ReceiptInclusionProof proof;
        proof.receipt = receipt;
        proof.leaf_index = 0;  // Simplified
        // proof.merkle_proof would be populated with actual proof
        elig.proofs.push_back(proof);

        if (elig.proofs.size() >= MIN_DISTINCT_PEER_RECEIPTS) {
            break;
        }
    }

    if (elig.proofs.size() < MIN_DISTINCT_PEER_RECEIPTS) {
        return std::nullopt;
    }

    return elig;
}

bool BatchReceiptPool::is_frozen(tx_epoch_t epoch, timestamp_t now, timestamp_t genesis) const {
    auto freeze_time = pool_freeze_time(epoch, genesis);
    return now >= freeze_time;
}

std::vector<BatchReceipt> BatchReceiptPool::get_receipts(
    tx_epoch_t epoch,
    std::uint8_t bucket) const {

    std::lock_guard<std::mutex> lock(mutex_);

    BucketKey key{epoch, bucket};
    auto it = bucket_receipts_.find(key);
    if (it == bucket_receipts_.end()) {
        return {};
    }
    return it->second;
}

std::size_t BatchReceiptPool::receipt_count(const hash_t& reveal_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reveal_receipts_.find(reveal_hash);
    if (it == reveal_receipts_.end()) {
        return 0;
    }
    return it->second.receipts.size();
}

void BatchReceiptPool::prune(tx_epoch_t before_epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Prune bucket receipts
    std::vector<BucketKey> to_remove;
    for (const auto& [key, receipts] : bucket_receipts_) {
        if (key.epoch < before_epoch) {
            to_remove.push_back(key);
        }
    }
    for (const auto& key : to_remove) {
        bucket_receipts_.erase(key);
    }

    // Prune reveal receipts
    std::vector<hash_t> reveals_to_remove;
    for (const auto& [reveal_hash, record] : reveal_receipts_) {
        // Check if all receipts are old
        bool all_old = true;
        for (const auto& receipt : record.receipts) {
            if (receipt.epoch_id >= before_epoch) {
                all_old = false;
                break;
            }
        }
        if (all_old) {
            reveals_to_remove.push_back(reveal_hash);
        }
    }
    for (const auto& h : reveals_to_remove) {
        reveal_receipts_.erase(h);
    }

    if (!to_remove.empty() || !reveals_to_remove.empty()) {
        POP_LOG_DEBUG(log::consensus) << "Pruned " << to_remove.size() << " bucket entries and "
                                       << reveals_to_remove.size() << " reveal entries before epoch "
                                       << before_epoch;
    }
}

std::size_t BatchReceiptPool::total_receipts() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t total = 0;
    for (const auto& [key, receipts] : bucket_receipts_) {
        total += receipts.size();
    }
    return total;
}

// ============================================================================
// ReceiptGenerator Implementation
// ============================================================================

ReceiptGenerator::ReceiptGenerator(const mldsa_public_key_t& my_public_key)
    : my_public_key_(my_public_key)
    , my_peer_id_(sha3_256(my_public_key)) {}

void ReceiptGenerator::add_reveal(
    const hash_t& reveal_hash,
    tx_epoch_t epoch,
    std::uint8_t bucket) {

    std::lock_guard<std::mutex> lock(mutex_);

    BatchReceiptPool::BucketKey key{epoch, bucket};
    auto& data = buckets_[key];

    if (!data.receipt_generated) {
        data.reveal_hashes.push_back(reveal_hash);
    }
}

std::optional<BatchReceipt> ReceiptGenerator::generate_receipt(
    tx_epoch_t epoch,
    std::uint8_t bucket,
    const std::function<std::optional<mldsa_signature_t>(std::span<const std::uint8_t>)>& sign_fn) {

    std::lock_guard<std::mutex> lock(mutex_);

    BatchReceiptPool::BucketKey key{epoch, bucket};
    auto it = buckets_.find(key);
    if (it == buckets_.end() || it->second.reveal_hashes.empty()) {
        return std::nullopt;
    }

    if (it->second.receipt_generated) {
        POP_LOG_TRACE(log::consensus) << "Receipt already generated for epoch " << epoch << " bucket " << (int)bucket;
        return std::nullopt;  // Already generated
    }

    // Compute merkle root of reveal hashes
    hash_t merkle_root = compute_merkle_root(it->second.reveal_hashes);

    BatchReceipt receipt;
    receipt.epoch_id = epoch;
    receipt.bucket_id = bucket;
    receipt.merkle_root = merkle_root;
    receipt.peer_id = my_peer_id_;

    // Sign
    auto msg = receipt.message_bytes();
    auto sig_opt = sign_fn(msg);
    if (!sig_opt) {
        POP_LOG_ERROR(log::consensus) << "Failed to sign batch receipt for epoch " << epoch << " bucket " << (int)bucket;
        return std::nullopt;
    }
    receipt.signature = *sig_opt;

    it->second.receipt_generated = true;

    POP_LOG_DEBUG(log::consensus) << "Generated batch receipt for epoch " << epoch << " bucket " << (int)bucket
                                   << " with " << it->second.reveal_hashes.size() << " reveals";
    return receipt;
}

void ReceiptGenerator::clear_bucket(tx_epoch_t epoch, std::uint8_t bucket) {
    std::lock_guard<std::mutex> lock(mutex_);

    BatchReceiptPool::BucketKey key{epoch, bucket};
    buckets_.erase(key);
}

std::uint8_t ReceiptGenerator::current_bucket(timestamp_t now, timestamp_t epoch_start) {
    auto elapsed = now - epoch_start;
    auto elapsed_ms = elapsed.count() / 1000;  // Convert us to ms
    return static_cast<std::uint8_t>(elapsed_ms / BUCKET_DURATION_MS);
}

bool ReceiptGenerator::is_past_cutoff(std::uint8_t bucket) {
    return bucket > RECEIPT_CUTOFF_BUCKET;
}

// ============================================================================
// RewardDistributor Implementation
// ============================================================================

std::vector<RewardShare> RewardDistributor::distribute(
    std::uint64_t pool,
    const std::vector<BatchReceipt>& receipts,
    std::size_t max_recipients) {

    if (receipts.empty() || pool == 0) {
        return {};
    }

    // Sort by bucket_id, then by peer_id hash
    std::vector<std::pair<std::size_t, const BatchReceipt*>> sorted;
    for (std::size_t i = 0; i < receipts.size(); ++i) {
        sorted.emplace_back(i, &receipts[i]);
    }

    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) {
            if (a.second->bucket_id != b.second->bucket_id) {
                return a.second->bucket_id < b.second->bucket_id;
            }
            return a.second->peer_id < b.second->peer_id;
        });

    // Limit recipients
    std::size_t num_recipients = std::min(sorted.size(), max_recipients);

    // Calculate shares (proportional, equal for now)
    std::vector<RewardShare> shares;
    shares.reserve(num_recipients);

    std::uint64_t remaining = pool;
    for (std::size_t i = 0; i < num_recipients; ++i) {
        RewardShare share;
        share.peer_id = sorted[i].second->peer_id;
        share.bucket_id = sorted[i].second->bucket_id;
        share.amount = calculate_share(pool, num_recipients, i);

        remaining -= share.amount;
        shares.push_back(share);
    }

    // Distribute any remainder to first recipient
    if (remaining > 0 && !shares.empty()) {
        shares[0].amount += remaining;
    }

    return shares;
}

std::uint64_t RewardDistributor::calculate_share(
    std::uint64_t pool,
    std::size_t total_recipients,
    std::size_t recipient_index) {

    if (total_recipients == 0) {
        return 0;
    }

    // Simple equal share for now
    // Could be weighted by bucket (earlier = more) in future
    return pool / total_recipients;
}

}  // namespace pop
