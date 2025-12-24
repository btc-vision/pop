#include "consensus/receipt_pow.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "core/logging.hh"
#include <random>

namespace pop {

// ============================================================================
// SequentialPoWResult Implementation
// ============================================================================

std::vector<std::uint8_t> SequentialPoWResult::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(SERIALIZED_SIZE);

    result.insert(result.end(), seed.begin(), seed.end());
    result.insert(result.end(), final_hash.begin(), final_hash.end());

    for (const auto& checkpoint : checkpoints) {
        result.insert(result.end(), checkpoint.begin(), checkpoint.end());
    }

    std::array<std::uint8_t, 8> nonce_bytes;
    encode_u64(nonce_bytes.data(), nonce);
    result.insert(result.end(), nonce_bytes.begin(), nonce_bytes.end());

    return result;
}

std::optional<SequentialPoWResult> SequentialPoWResult::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    SequentialPoWResult result;
    std::size_t offset = 0;

    std::copy_n(data.begin() + offset, HASH_SIZE, result.seed.begin());
    offset += HASH_SIZE;

    std::copy_n(data.begin() + offset, HASH_SIZE, result.final_hash.begin());
    offset += HASH_SIZE;

    for (std::size_t i = 0; i < RECEIPT_POW_CHECKPOINT_COUNT; i++) {
        std::copy_n(data.begin() + offset, HASH_SIZE, result.checkpoints[i].begin());
        offset += HASH_SIZE;
    }

    result.nonce = decode_u64(data.data() + offset);

    return result;
}

// ============================================================================
// SequentialPoWGenerator Implementation
// ============================================================================

hash_t SequentialPoWGenerator::compute_seed(
    const hash_t& reveal_root,
    const hash_t& peer_id,
    std::uint64_t nonce) {

    SHA3Hasher hasher;
    hasher.update(reveal_root);
    hasher.update(peer_id);

    std::array<std::uint8_t, 8> nonce_bytes;
    encode_u64(nonce_bytes.data(), nonce);
    hasher.update(nonce_bytes);

    return hasher.finalize();
}

hash_t SequentialPoWGenerator::compute_checkpoint_transition(const hash_t& input) {
    hash_t current = input;

    // Perform RECEIPT_POW_CHECKPOINT_INTERVAL iterations
    for (std::uint64_t i = 0; i < RECEIPT_POW_CHECKPOINT_INTERVAL; i++) {
        current = sha3_256(current);
    }

    return current;
}

SequentialPoWResult SequentialPoWGenerator::generate(
    const hash_t& reveal_root,
    const hash_t& peer_id,
    std::uint64_t nonce) {

    SequentialPoWResult result;
    result.nonce = nonce;
    result.seed = compute_seed(reveal_root, peer_id, nonce);

    // Checkpoint 0 is the seed itself
    result.checkpoints[0] = result.seed;

    // Compute each checkpoint transition
    hash_t current = result.seed;
    for (std::size_t i = 1; i < RECEIPT_POW_CHECKPOINT_COUNT; i++) {
        current = compute_checkpoint_transition(current);
        result.checkpoints[i] = current;
    }

    result.final_hash = current;

    return result;
}

bool SequentialPoWGenerator::verify(
    const SequentialPoWResult& result,
    const hash_t& reveal_root,
    const hash_t& peer_id,
    VerifyMode mode) {

    // Verify seed computation
    hash_t expected_seed = compute_seed(reveal_root, peer_id, result.nonce);
    if (expected_seed != result.seed) {
        return false;
    }

    // Verify checkpoint[0] is the seed
    if (result.checkpoints[0] != result.seed) {
        return false;
    }

    switch (mode) {
        case VerifyMode::FULL: {
            // Verify all checkpoint transitions
            for (std::size_t i = 1; i < RECEIPT_POW_CHECKPOINT_COUNT; i++) {
                hash_t expected = compute_checkpoint_transition(result.checkpoints[i - 1]);
                if (expected != result.checkpoints[i]) {
                    return false;
                }
            }
            break;
        }

        case VerifyMode::CHECKPOINTS: {
            // Verify every other checkpoint transition (still verifies work, faster)
            for (std::size_t i = 1; i < RECEIPT_POW_CHECKPOINT_COUNT; i += 2) {
                hash_t expected = compute_checkpoint_transition(result.checkpoints[i - 1]);
                if (expected != result.checkpoints[i]) {
                    return false;
                }
            }
            break;
        }

        case VerifyMode::SPOT_CHECK: {
            // Randomly pick one checkpoint to verify
            thread_local std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<std::size_t> dist(1, RECEIPT_POW_CHECKPOINT_COUNT - 1);
            std::size_t check_idx = dist(rng);

            hash_t expected = compute_checkpoint_transition(result.checkpoints[check_idx - 1]);
            if (expected != result.checkpoints[check_idx]) {
                return false;
            }
            break;
        }
    }

    // Verify final_hash matches last checkpoint
    if (result.final_hash != result.checkpoints[RECEIPT_POW_CHECKPOINT_COUNT - 1]) {
        return false;
    }

    return true;
}

// ============================================================================
// Chunk Assignment Implementation
// ============================================================================

std::uint8_t compute_chunk_assignment(
    const hash_t& reveal_root,
    const hash_t& peer_id,
    const hash_t& epoch_randomness) {

    SHA3Hasher hasher;
    hasher.update(reveal_root);
    hasher.update(peer_id);
    hasher.update(epoch_randomness);
    hash_t result = hasher.finalize();

    // Take first byte mod 32
    return result[0] % ERASURE_TOTAL_CHUNKS;
}

hash_t compute_epoch_randomness(
    const hash_t& state_root,
    tx_epoch_t epoch,
    bool is_timeout_mode,
    const hash_t* soft_state_root) {

    SHA3Hasher hasher;

    if (is_timeout_mode) {
        // Timeout mode: include multiple entropy sources
        const std::string_view prefix = "chunks_timeout";
        hasher.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(prefix.data()), prefix.size()));

        hasher.update(state_root);  // Last available global root

        if (soft_state_root) {
            hasher.update(*soft_state_root);  // Soft state root at epoch boundary
        }

        std::array<std::uint8_t, 8> epoch_bytes;
        encode_u64(epoch_bytes.data(), epoch);
        hasher.update(epoch_bytes);
    } else {
        // Normal mode: just the global state root
        const std::string_view prefix = "chunks";
        hasher.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(prefix.data()), prefix.size()));

        hasher.update(state_root);
    }

    return hasher.finalize();
}

// ============================================================================
// EnhancedReceipt Implementation
// ============================================================================

std::vector<std::uint8_t> EnhancedReceipt::message_bytes() const {
    std::vector<std::uint8_t> result;

    // Epoch and bucket
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch_id);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());
    result.push_back(bucket_id);

    // Merkle root and peer ID
    result.insert(result.end(), merkle_root.begin(), merkle_root.end());
    result.insert(result.end(), peer_id.begin(), peer_id.end());

    // PoW proof
    auto pow_bytes = pow_proof.serialize();
    result.insert(result.end(), pow_bytes.begin(), pow_bytes.end());

    // Chunk assignment
    result.push_back(assigned_chunk_index);

    // Chunk data length and data
    std::array<std::uint8_t, 4> chunk_len;
    encode_u32(chunk_len.data(), static_cast<std::uint32_t>(chunk_data.size()));
    result.insert(result.end(), chunk_len.begin(), chunk_len.end());
    result.insert(result.end(), chunk_data.begin(), chunk_data.end());

    // Merkle proof for chunk
    std::array<std::uint8_t, 4> proof_count;
    encode_u32(proof_count.data(), static_cast<std::uint32_t>(chunk_merkle_proof.size()));
    result.insert(result.end(), proof_count.begin(), proof_count.end());
    for (const auto& node : chunk_merkle_proof) {
        result.insert(result.end(), node.begin(), node.end());
    }

    // VDF bucket binding
    encode_u64(epoch_bytes.data(), vdf_checkpoint_epoch);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    std::array<std::uint8_t, 2> offset_bytes;
    encode_u16(offset_bytes.data(), vdf_bucket_offset);
    result.insert(result.end(), offset_bytes.begin(), offset_bytes.end());

    auto vdf_proof_bytes = vdf_proof.serialize();
    result.insert(result.end(), vdf_proof_bytes.begin(), vdf_proof_bytes.end());

    result.insert(result.end(), bucket_vdf_value.begin(), bucket_vdf_value.end());

    return result;
}

bool EnhancedReceipt::verify(
    const mldsa_public_key_t& peer_pk,
    const hash_t& epoch_randomness) const {

    // Verify peer_id matches public key
    hash_t expected_peer_id = sha3_256(peer_pk);
    if (expected_peer_id != peer_id) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: peer_id mismatch";
        return false;
    }

    // Verify chunk assignment
    std::uint8_t expected_chunk = compute_chunk_assignment(
        merkle_root, peer_id, epoch_randomness);
    if (expected_chunk != assigned_chunk_index) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: chunk assignment mismatch";
        return false;
    }

    // Verify sequential PoW
    if (!SequentialPoWGenerator::verify(
            pow_proof, merkle_root, peer_id,
            SequentialPoWGenerator::VerifyMode::CHECKPOINTS)) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: PoW verification failed";
        return false;
    }

    // Verify signature
    auto msg = message_bytes();
    if (!mldsa_verify(peer_pk, msg, signature)) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: signature verification failed";
        return false;
    }

    return true;
}

bool EnhancedReceipt::verify_vdf_binding(
    const VDFEpochCheckpoint& checkpoint) const {

    // Verify the checkpoint epoch matches
    if (checkpoint.epoch != vdf_checkpoint_epoch) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: VDF checkpoint epoch mismatch";
        return false;
    }

    // Verify the VDF proof
    if (!vdf_proof.verify(bucket_vdf_value, checkpoint)) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: VDF proof verification failed";
        return false;
    }

    // Verify the bucket_id corresponds to the VDF step
    std::uint8_t expected_bucket = VDFBucketCalculator::step_to_bucket(
        vdf_proof.bucket_step, checkpoint.step_number);
    if (expected_bucket != bucket_id) {
        POP_LOG_DEBUG(log::consensus) << "EnhancedReceipt: VDF bucket_id mismatch";
        return false;
    }

    return true;
}

bool EnhancedReceipt::verify_full(
    const mldsa_public_key_t& peer_pk,
    const hash_t& epoch_randomness,
    const VDFEpochCheckpoint& checkpoint) const {

    // Verify basic receipt (PoW, chunk assignment, signature)
    if (!verify(peer_pk, epoch_randomness)) {
        return false;
    }

    // Verify VDF bucket binding
    if (!verify_vdf_binding(checkpoint)) {
        return false;
    }

    return true;
}

std::vector<std::uint8_t> EnhancedReceipt::serialize() const {
    auto result = message_bytes();

    // Append signature
    result.insert(result.end(), signature.begin(), signature.end());

    return result;
}

std::optional<EnhancedReceipt> EnhancedReceipt::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < sizeof(tx_epoch_t) + 1 + HASH_SIZE * 2 +
                       SequentialPoWResult::SERIALIZED_SIZE + 1 + 4 + 4 +
                       MLDSA65_SIGNATURE_SIZE) {
        return std::nullopt;
    }

    EnhancedReceipt result;
    std::size_t offset = 0;

    // Epoch and bucket
    result.epoch_id = decode_u64(data.data() + offset);
    offset += sizeof(tx_epoch_t);

    result.bucket_id = data[offset++];

    // Merkle root and peer ID
    std::copy_n(data.begin() + offset, HASH_SIZE, result.merkle_root.begin());
    offset += HASH_SIZE;

    std::copy_n(data.begin() + offset, HASH_SIZE, result.peer_id.begin());
    offset += HASH_SIZE;

    // PoW proof
    auto pow_opt = SequentialPoWResult::deserialize(
        data.subspan(offset, SequentialPoWResult::SERIALIZED_SIZE));
    if (!pow_opt) {
        return std::nullopt;
    }
    result.pow_proof = *pow_opt;
    offset += SequentialPoWResult::SERIALIZED_SIZE;

    // Chunk assignment
    result.assigned_chunk_index = data[offset++];

    // Chunk data
    if (data.size() < offset + 4) return std::nullopt;
    std::uint32_t chunk_len = decode_u32(data.data() + offset);
    offset += 4;

    if (data.size() < offset + chunk_len) return std::nullopt;
    result.chunk_data.assign(data.begin() + offset, data.begin() + offset + chunk_len);
    offset += chunk_len;

    // Merkle proof
    if (data.size() < offset + 4) return std::nullopt;
    std::uint32_t proof_count = decode_u32(data.data() + offset);
    offset += 4;

    if (data.size() < offset + proof_count * HASH_SIZE) return std::nullopt;
    result.chunk_merkle_proof.resize(proof_count);
    for (std::uint32_t i = 0; i < proof_count; i++) {
        std::copy_n(data.begin() + offset, HASH_SIZE, result.chunk_merkle_proof[i].begin());
        offset += HASH_SIZE;
    }

    // VDF bucket binding
    if (data.size() < offset + sizeof(tx_epoch_t) + 2) return std::nullopt;
    result.vdf_checkpoint_epoch = decode_u64(data.data() + offset);
    offset += sizeof(tx_epoch_t);

    result.vdf_bucket_offset = decode_u16(data.data() + offset);
    offset += 2;

    // VDF proof (variable size due to sample_points)
    auto vdf_proof_opt = VDFBucketProof::deserialize(data.subspan(offset));
    if (!vdf_proof_opt) {
        return std::nullopt;
    }
    result.vdf_proof = *vdf_proof_opt;
    auto vdf_proof_bytes = result.vdf_proof.serialize();
    offset += vdf_proof_bytes.size();

    // Bucket VDF value
    if (data.size() < offset + HASH_SIZE) return std::nullopt;
    std::copy_n(data.begin() + offset, HASH_SIZE, result.bucket_vdf_value.begin());
    offset += HASH_SIZE;

    // Signature
    if (data.size() < offset + MLDSA65_SIGNATURE_SIZE) return std::nullopt;
    std::copy_n(data.begin() + offset, MLDSA65_SIGNATURE_SIZE, result.signature.begin());

    return result;
}

}  // namespace pop
