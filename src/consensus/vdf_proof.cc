#include "consensus/vdf_proof.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "core/logging.hh"

namespace pop {

// ============================================================================
// VDFEpochCheckpoint Implementation
// ============================================================================

std::vector<std::uint8_t> VDFEpochCheckpoint::message_bytes() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    std::array<std::uint8_t, 8> step_bytes;
    encode_u64(step_bytes.data(), step_number);
    result.insert(result.end(), step_bytes.begin(), step_bytes.end());

    result.insert(result.end(), vdf_value.begin(), vdf_value.end());

    return result;
}

bool VDFEpochCheckpoint::verify(const mldsa_public_key_t& pk) const {
    auto msg = message_bytes();
    return mldsa_verify(pk, msg, signature);
}

std::vector<std::uint8_t> VDFEpochCheckpoint::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(SERIALIZED_SIZE);

    auto msg = message_bytes();
    result.insert(result.end(), msg.begin(), msg.end());
    result.insert(result.end(), signature.begin(), signature.end());

    return result;
}

std::optional<VDFEpochCheckpoint> VDFEpochCheckpoint::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    VDFEpochCheckpoint result;
    std::size_t offset = 0;

    result.epoch = decode_u64(data.data() + offset);
    offset += sizeof(tx_epoch_t);

    result.step_number = decode_u64(data.data() + offset);
    offset += sizeof(std::uint64_t);

    std::copy_n(data.begin() + offset, HASH_SIZE, result.vdf_value.begin());
    offset += HASH_SIZE;

    std::copy_n(data.begin() + offset, MLDSA65_SIGNATURE_SIZE, result.signature.begin());

    return result;
}

// ============================================================================
// VDFMiniCheckpoint Implementation
// ============================================================================

std::vector<std::uint8_t> VDFMiniCheckpoint::message_bytes() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 8> step_bytes;
    encode_u64(step_bytes.data(), step_number);
    result.insert(result.end(), step_bytes.begin(), step_bytes.end());

    result.insert(result.end(), vdf_value.begin(), vdf_value.end());

    std::array<std::uint8_t, 8> prev_step_bytes;
    encode_u64(prev_step_bytes.data(), prev_checkpoint_step);
    result.insert(result.end(), prev_step_bytes.begin(), prev_step_bytes.end());

    result.insert(result.end(), prev_checkpoint_value.begin(), prev_checkpoint_value.end());

    return result;
}

bool VDFMiniCheckpoint::verify(const mldsa_public_key_t& pk) const {
    auto msg = message_bytes();
    return mldsa_verify(pk, msg, signature);
}

std::vector<std::uint8_t> VDFMiniCheckpoint::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(SERIALIZED_SIZE);

    auto msg = message_bytes();
    result.insert(result.end(), msg.begin(), msg.end());
    result.insert(result.end(), signature.begin(), signature.end());

    return result;
}

std::optional<VDFMiniCheckpoint> VDFMiniCheckpoint::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    VDFMiniCheckpoint result;
    std::size_t offset = 0;

    result.step_number = decode_u64(data.data() + offset);
    offset += sizeof(std::uint64_t);

    std::copy_n(data.begin() + offset, HASH_SIZE, result.vdf_value.begin());
    offset += HASH_SIZE;

    result.prev_checkpoint_step = decode_u64(data.data() + offset);
    offset += sizeof(std::uint64_t);

    std::copy_n(data.begin() + offset, HASH_SIZE, result.prev_checkpoint_value.begin());
    offset += HASH_SIZE;

    std::copy_n(data.begin() + offset, MLDSA65_SIGNATURE_SIZE, result.signature.begin());

    return result;
}

// ============================================================================
// VDFBucketProof Implementation
// ============================================================================

bool VDFBucketProof::verify(
    const hash_t& expected_bucket_value,
    const VDFEpochCheckpoint& epoch_checkpoint) const {

    // Verify checkpoint reference matches
    if (checkpoint_epoch != epoch_checkpoint.epoch ||
        checkpoint_step != epoch_checkpoint.step_number ||
        checkpoint_value != epoch_checkpoint.vdf_value) {
        POP_LOG_DEBUG(log::consensus) << "VDFBucketProof: checkpoint mismatch";
        return false;
    }

    // Determine start point for verification
    hash_t start_value = checkpoint_value;
    std::uint64_t start_step = checkpoint_step;

    if (mini_checkpoint) {
        // Verify mini-checkpoint chains back to epoch checkpoint
        // (In full impl, would verify signature and chain)
        start_value = mini_checkpoint->vdf_value;
        start_step = mini_checkpoint->step_number;
    }

    // Verify step count is reasonable
    if (bucket_step < start_step) {
        POP_LOG_DEBUG(log::consensus) << "VDFBucketProof: bucket_step before start";
        return false;
    }

    std::uint64_t steps_to_compute = bucket_step - start_step;
    if (steps_to_compute != steps_from_reference) {
        POP_LOG_DEBUG(log::consensus) << "VDFBucketProof: steps mismatch";
        return false;
    }

    // Compute VDF from start to bucket step
    hash_t computed = VDFBucketCalculator::compute_vdf_at_step(
        start_value, start_step, bucket_step);

    if (computed != expected_bucket_value) {
        POP_LOG_DEBUG(log::consensus) << "VDFBucketProof: computed value mismatch";
        return false;
    }

    return true;
}

std::vector<std::uint8_t> VDFBucketProof::serialize() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), checkpoint_epoch);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    std::array<std::uint8_t, 8> step_bytes;
    encode_u64(step_bytes.data(), checkpoint_step);
    result.insert(result.end(), step_bytes.begin(), step_bytes.end());

    result.insert(result.end(), checkpoint_value.begin(), checkpoint_value.end());

    // Mini-checkpoint flag and data
    result.push_back(mini_checkpoint.has_value() ? 1 : 0);
    if (mini_checkpoint) {
        auto mini_data = mini_checkpoint->serialize();
        result.insert(result.end(), mini_data.begin(), mini_data.end());
    }

    std::array<std::uint8_t, 8> bucket_step_bytes;
    encode_u64(bucket_step_bytes.data(), bucket_step);
    result.insert(result.end(), bucket_step_bytes.begin(), bucket_step_bytes.end());

    std::array<std::uint8_t, 2> steps_bytes;
    encode_u16(steps_bytes.data(), steps_from_reference);
    result.insert(result.end(), steps_bytes.begin(), steps_bytes.end());

    // Sample points
    std::array<std::uint8_t, 4> sample_count;
    encode_u32(sample_count.data(), static_cast<std::uint32_t>(sample_points.size()));
    result.insert(result.end(), sample_count.begin(), sample_count.end());

    for (const auto& point : sample_points) {
        result.insert(result.end(), point.begin(), point.end());
    }

    return result;
}

std::optional<VDFBucketProof> VDFBucketProof::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < sizeof(tx_epoch_t) + sizeof(std::uint64_t) + HASH_SIZE + 1 +
                       sizeof(std::uint64_t) + sizeof(std::uint16_t) + 4) {
        return std::nullopt;
    }

    VDFBucketProof result;
    std::size_t offset = 0;

    result.checkpoint_epoch = decode_u64(data.data() + offset);
    offset += sizeof(tx_epoch_t);

    result.checkpoint_step = decode_u64(data.data() + offset);
    offset += sizeof(std::uint64_t);

    std::copy_n(data.begin() + offset, HASH_SIZE, result.checkpoint_value.begin());
    offset += HASH_SIZE;

    bool has_mini = data[offset++] != 0;
    if (has_mini) {
        if (data.size() < offset + VDFMiniCheckpoint::SERIALIZED_SIZE) {
            return std::nullopt;
        }
        result.mini_checkpoint = VDFMiniCheckpoint::deserialize(
            data.subspan(offset, VDFMiniCheckpoint::SERIALIZED_SIZE));
        if (!result.mini_checkpoint) {
            return std::nullopt;
        }
        offset += VDFMiniCheckpoint::SERIALIZED_SIZE;
    }

    if (data.size() < offset + sizeof(std::uint64_t) + sizeof(std::uint16_t) + 4) {
        return std::nullopt;
    }

    result.bucket_step = decode_u64(data.data() + offset);
    offset += sizeof(std::uint64_t);

    result.steps_from_reference = decode_u16(data.data() + offset);
    offset += sizeof(std::uint16_t);

    std::uint32_t sample_count = decode_u32(data.data() + offset);
    offset += 4;

    if (data.size() < offset + sample_count * HASH_SIZE) {
        return std::nullopt;
    }

    result.sample_points.resize(sample_count);
    for (std::uint32_t i = 0; i < sample_count; i++) {
        std::copy_n(data.begin() + offset, HASH_SIZE, result.sample_points[i].begin());
        offset += HASH_SIZE;
    }

    return result;
}

// ============================================================================
// VDFBucketCalculator Implementation
// ============================================================================

std::uint8_t VDFBucketCalculator::step_to_bucket(
    std::uint64_t vdf_step,
    std::uint64_t epoch_start_step) {

    if (vdf_step < epoch_start_step) {
        return 0;
    }

    std::uint64_t steps_into_epoch = vdf_step - epoch_start_step;
    std::uint64_t steps_per_bucket = (SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT) / BUCKETS_PER_TX_EPOCH;

    std::uint8_t bucket = static_cast<std::uint8_t>(steps_into_epoch / steps_per_bucket);
    return std::min(bucket, static_cast<std::uint8_t>(BUCKETS_PER_TX_EPOCH - 1));
}

std::pair<std::uint64_t, std::uint64_t> VDFBucketCalculator::bucket_to_step_range(
    tx_epoch_t epoch,
    std::uint8_t bucket_id) {

    std::uint64_t epoch_start_step = epoch * SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT;
    std::uint64_t steps_per_bucket = (SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT) / BUCKETS_PER_TX_EPOCH;

    std::uint64_t bucket_start = epoch_start_step + bucket_id * steps_per_bucket;
    std::uint64_t bucket_end = bucket_start + steps_per_bucket - 1;

    return {bucket_start, bucket_end};
}

bool VDFBucketCalculator::is_in_bucket(
    std::uint64_t vdf_step,
    tx_epoch_t epoch,
    std::uint8_t bucket_id) {

    auto [start, end] = bucket_to_step_range(epoch, bucket_id);
    return vdf_step >= start && vdf_step <= end;
}

hash_t VDFBucketCalculator::compute_vdf_at_step(
    const hash_t& start_value,
    std::uint64_t start_step,
    std::uint64_t target_step) {

    if (target_step <= start_step) {
        return start_value;
    }

    hash_t current = start_value;
    std::uint64_t steps = target_step - start_step;

    for (std::uint64_t i = 0; i < steps; i++) {
        current = sha3_256(current);
    }

    return current;
}

VDFBucketProof VDFBucketCalculator::generate_proof(
    const VDFEpochCheckpoint& checkpoint,
    std::uint64_t bucket_step,
    const std::optional<VDFMiniCheckpoint>& mini_checkpoint) {

    VDFBucketProof proof;

    proof.checkpoint_epoch = checkpoint.epoch;
    proof.checkpoint_step = checkpoint.step_number;
    proof.checkpoint_value = checkpoint.vdf_value;
    proof.mini_checkpoint = mini_checkpoint;
    proof.bucket_step = bucket_step;

    // Calculate steps from reference
    std::uint64_t start_step = checkpoint.step_number;
    if (mini_checkpoint) {
        start_step = mini_checkpoint->step_number;
    }

    if (bucket_step >= start_step) {
        proof.steps_from_reference = static_cast<std::uint16_t>(
            std::min(bucket_step - start_step, static_cast<std::uint64_t>(UINT16_MAX)));
    } else {
        proof.steps_from_reference = 0;
    }

    // Generate sample points every 1000 steps for spot-checking
    if (proof.steps_from_reference > 1000) {
        hash_t start_value = mini_checkpoint ?
            mini_checkpoint->vdf_value : checkpoint.vdf_value;

        hash_t current = start_value;
        for (std::uint64_t i = 0; i < proof.steps_from_reference; i++) {
            current = sha3_256(current);
            if ((i + 1) % 1000 == 0) {
                proof.sample_points.push_back(current);
            }
        }
    }

    return proof;
}

// ============================================================================
// VDFCheckpointStore Implementation
// ============================================================================

void VDFCheckpointStore::add_epoch_checkpoint(const VDFEpochCheckpoint& checkpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    epoch_checkpoints_[checkpoint.epoch] = checkpoint;
}

void VDFCheckpointStore::add_mini_checkpoint(const VDFMiniCheckpoint& checkpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    mini_checkpoints_[checkpoint.step_number] = checkpoint;
}

std::optional<VDFEpochCheckpoint> VDFCheckpointStore::get_epoch_checkpoint(
    tx_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = epoch_checkpoints_.find(epoch);
    if (it == epoch_checkpoints_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<VDFMiniCheckpoint> VDFCheckpointStore::get_nearest_mini_checkpoint(
    std::uint64_t step) const {

    std::lock_guard<std::mutex> lock(mutex_);

    if (mini_checkpoints_.empty()) {
        return std::nullopt;
    }

    // Find first checkpoint at or after step
    auto it = mini_checkpoints_.lower_bound(step);

    // We want the checkpoint before step
    if (it == mini_checkpoints_.begin()) {
        // No checkpoint before this step
        return std::nullopt;
    }

    --it;
    return it->second;
}

std::optional<VDFBucketProof> VDFCheckpointStore::generate_proof_for_step(
    std::uint64_t bucket_step,
    tx_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto epoch_it = epoch_checkpoints_.find(epoch);
    if (epoch_it == epoch_checkpoints_.end()) {
        return std::nullopt;
    }

    const auto& checkpoint = epoch_it->second;

    // Check if we need a mini-checkpoint
    std::optional<VDFMiniCheckpoint> mini;
    if (bucket_step > checkpoint.step_number + VDF_MINI_CHECKPOINT_THRESHOLD) {
        // Find nearest mini-checkpoint
        auto mini_it = mini_checkpoints_.lower_bound(bucket_step);
        if (mini_it != mini_checkpoints_.begin()) {
            --mini_it;
            if (mini_it->first > checkpoint.step_number &&
                mini_it->first <= bucket_step) {
                mini = mini_it->second;
            }
        }
    }

    return VDFBucketCalculator::generate_proof(checkpoint, bucket_step, mini);
}

bool VDFCheckpointStore::verify_proof(
    const VDFBucketProof& proof,
    const hash_t& expected_bucket_value) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto epoch_it = epoch_checkpoints_.find(proof.checkpoint_epoch);
    if (epoch_it == epoch_checkpoints_.end()) {
        return false;
    }

    return proof.verify(expected_bucket_value, epoch_it->second);
}

void VDFCheckpointStore::prune(tx_epoch_t before_epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Prune epoch checkpoints
    for (auto it = epoch_checkpoints_.begin(); it != epoch_checkpoints_.end();) {
        if (it->first < before_epoch) {
            it = epoch_checkpoints_.erase(it);
        } else {
            ++it;
        }
    }

    // Prune mini-checkpoints before epoch start step
    std::uint64_t before_step = before_epoch * SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT;
    mini_checkpoints_.erase(mini_checkpoints_.begin(),
                             mini_checkpoints_.lower_bound(before_step));
}

// ============================================================================
// VDFBoundReceipt Implementation
// ============================================================================

std::vector<std::uint8_t> VDFBoundReceipt::message_bytes() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch_id);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    result.push_back(bucket_id);

    result.insert(result.end(), merkle_root.begin(), merkle_root.end());
    result.insert(result.end(), peer_id.begin(), peer_id.end());

    auto proof_bytes = vdf_proof.serialize();
    result.insert(result.end(), proof_bytes.begin(), proof_bytes.end());

    result.insert(result.end(), bucket_vdf_value.begin(), bucket_vdf_value.end());

    return result;
}

bool VDFBoundReceipt::verify(
    const mldsa_public_key_t& peer_pk,
    const VDFEpochCheckpoint& epoch_checkpoint) const {

    // Verify peer_id matches public key
    hash_t expected_peer_id = sha3_256(peer_pk);
    if (expected_peer_id != peer_id) {
        POP_LOG_DEBUG(log::consensus) << "VDFBoundReceipt: peer_id mismatch";
        return false;
    }

    // Verify VDF proof
    if (!vdf_proof.verify(bucket_vdf_value, epoch_checkpoint)) {
        POP_LOG_DEBUG(log::consensus) << "VDFBoundReceipt: VDF proof invalid";
        return false;
    }

    // Verify bucket matches VDF step
    if (!VDFBucketCalculator::is_in_bucket(vdf_proof.bucket_step, epoch_id, bucket_id)) {
        POP_LOG_DEBUG(log::consensus) << "VDFBoundReceipt: bucket mismatch";
        return false;
    }

    // Verify signature
    auto msg = message_bytes();
    if (!mldsa_verify(peer_pk, msg, signature)) {
        POP_LOG_DEBUG(log::consensus) << "VDFBoundReceipt: signature invalid";
        return false;
    }

    return true;
}

std::vector<std::uint8_t> VDFBoundReceipt::serialize() const {
    auto result = message_bytes();
    result.insert(result.end(), signature.begin(), signature.end());
    return result;
}

std::optional<VDFBoundReceipt> VDFBoundReceipt::deserialize(
    std::span<const std::uint8_t> data) {

    // Minimum size check
    if (data.size() < sizeof(tx_epoch_t) + 1 + HASH_SIZE * 2 +
                       HASH_SIZE + MLDSA65_SIGNATURE_SIZE) {
        return std::nullopt;
    }

    VDFBoundReceipt result;
    std::size_t offset = 0;

    result.epoch_id = decode_u64(data.data() + offset);
    offset += sizeof(tx_epoch_t);

    result.bucket_id = data[offset++];

    std::copy_n(data.begin() + offset, HASH_SIZE, result.merkle_root.begin());
    offset += HASH_SIZE;

    std::copy_n(data.begin() + offset, HASH_SIZE, result.peer_id.begin());
    offset += HASH_SIZE;

    // Deserialize VDF proof (variable size)
    auto proof_opt = VDFBucketProof::deserialize(data.subspan(offset));
    if (!proof_opt) {
        return std::nullopt;
    }
    result.vdf_proof = *proof_opt;

    // Need to figure out how much the proof consumed
    auto proof_serialized = result.vdf_proof.serialize();
    offset += proof_serialized.size();

    if (data.size() < offset + HASH_SIZE + MLDSA65_SIGNATURE_SIZE) {
        return std::nullopt;
    }

    std::copy_n(data.begin() + offset, HASH_SIZE, result.bucket_vdf_value.begin());
    offset += HASH_SIZE;

    std::copy_n(data.begin() + offset, MLDSA65_SIGNATURE_SIZE, result.signature.begin());

    return result;
}

}  // namespace pop
