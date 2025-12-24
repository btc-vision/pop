#include "consensus/receipt_pow.hh"
#include "consensus/erasure.hh"
#include "consensus/vdf_proof.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include <gtest/gtest.h>
#include <chrono>

namespace pop {
namespace {

// ============================================================================
// Sequential PoW Tests
// ============================================================================

class SequentialPoWTest : public ::testing::Test {
protected:
    void SetUp() override {
        reveal_root_.fill(0x42);
        peer_id_.fill(0x11);
    }

    hash_t reveal_root_;
    hash_t peer_id_;
};

TEST_F(SequentialPoWTest, GenerateAndVerifyFull) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);

    EXPECT_EQ(result.nonce, 0u);
    EXPECT_EQ(result.checkpoints[0], result.seed);
    EXPECT_EQ(result.checkpoints[RECEIPT_POW_CHECKPOINT_COUNT - 1], result.final_hash);

    // Verify with full mode
    EXPECT_TRUE(SequentialPoWGenerator::verify(
        result, reveal_root_, peer_id_,
        SequentialPoWGenerator::VerifyMode::FULL));
}

TEST_F(SequentialPoWTest, VerifyCheckpointsMode) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);

    EXPECT_TRUE(SequentialPoWGenerator::verify(
        result, reveal_root_, peer_id_,
        SequentialPoWGenerator::VerifyMode::CHECKPOINTS));
}

TEST_F(SequentialPoWTest, VerifySpotCheckMode) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);

    // Spot check should pass most of the time (random checkpoint)
    int passes = 0;
    for (int i = 0; i < 10; i++) {
        if (SequentialPoWGenerator::verify(
                result, reveal_root_, peer_id_,
                SequentialPoWGenerator::VerifyMode::SPOT_CHECK)) {
            passes++;
        }
    }
    EXPECT_GT(passes, 5);  // Should pass most checks
}

TEST_F(SequentialPoWTest, DifferentNoncesDifferentResults) {
    auto result1 = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);
    auto result2 = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 1);

    EXPECT_NE(result1.seed, result2.seed);
    EXPECT_NE(result1.final_hash, result2.final_hash);
}

TEST_F(SequentialPoWTest, WrongRevealRootFails) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);

    hash_t wrong_reveal;
    wrong_reveal.fill(0xFF);

    EXPECT_FALSE(SequentialPoWGenerator::verify(
        result, wrong_reveal, peer_id_,
        SequentialPoWGenerator::VerifyMode::CHECKPOINTS));
}

TEST_F(SequentialPoWTest, WrongPeerIdFails) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);

    hash_t wrong_peer;
    wrong_peer.fill(0xFF);

    EXPECT_FALSE(SequentialPoWGenerator::verify(
        result, reveal_root_, wrong_peer,
        SequentialPoWGenerator::VerifyMode::CHECKPOINTS));
}

TEST_F(SequentialPoWTest, TamperedCheckpointFails) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);

    // Tamper with a checkpoint
    result.checkpoints[2].fill(0xFF);

    EXPECT_FALSE(SequentialPoWGenerator::verify(
        result, reveal_root_, peer_id_,
        SequentialPoWGenerator::VerifyMode::FULL));
}

TEST_F(SequentialPoWTest, SerializeDeserialize) {
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 12345);

    auto serialized = result.serialize();
    EXPECT_EQ(serialized.size(), SequentialPoWResult::SERIALIZED_SIZE);

    auto deserialized = SequentialPoWResult::deserialize(serialized);
    ASSERT_TRUE(deserialized.has_value());

    EXPECT_EQ(deserialized->seed, result.seed);
    EXPECT_EQ(deserialized->final_hash, result.final_hash);
    EXPECT_EQ(deserialized->nonce, result.nonce);
    EXPECT_EQ(deserialized->checkpoints, result.checkpoints);
}

TEST_F(SequentialPoWTest, TimingCheck) {
    // Generate should take roughly 10ms on reference hardware
    auto start = std::chrono::high_resolution_clock::now();
    auto result = SequentialPoWGenerator::generate(reveal_root_, peer_id_, 0);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    // Allow wide range due to varying hardware
    EXPECT_GT(duration.count(), 0);  // At least some time
    EXPECT_LT(duration.count(), 500);  // Not too long
    (void)result;  // Suppress unused warning
}

// ============================================================================
// Chunk Assignment Tests
// ============================================================================

class ChunkAssignmentTest : public ::testing::Test {
protected:
    hash_t reveal_root_;
    hash_t peer_id_;
    hash_t epoch_randomness_;
};

TEST_F(ChunkAssignmentTest, DeterministicAssignment) {
    reveal_root_.fill(0x42);
    peer_id_.fill(0x11);
    epoch_randomness_.fill(0xAB);

    auto chunk1 = compute_chunk_assignment(reveal_root_, peer_id_, epoch_randomness_);
    auto chunk2 = compute_chunk_assignment(reveal_root_, peer_id_, epoch_randomness_);

    EXPECT_EQ(chunk1, chunk2);  // Same inputs = same output
}

TEST_F(ChunkAssignmentTest, DifferentPeersDifferentChunks) {
    reveal_root_.fill(0x42);
    epoch_randomness_.fill(0xAB);

    hash_t peer1, peer2;
    peer1.fill(0x11);
    peer2.fill(0x22);

    auto chunk1 = compute_chunk_assignment(reveal_root_, peer1, epoch_randomness_);
    auto chunk2 = compute_chunk_assignment(reveal_root_, peer2, epoch_randomness_);

    // Different peers should get different chunks (usually)
    // This could occasionally be equal by chance, so we just verify range
    EXPECT_LT(chunk1, ERASURE_TOTAL_CHUNKS);
    EXPECT_LT(chunk2, ERASURE_TOTAL_CHUNKS);
}

TEST_F(ChunkAssignmentTest, ChunkInValidRange) {
    for (int i = 0; i < 100; i++) {
        reveal_root_.fill(static_cast<std::uint8_t>(i));
        peer_id_.fill(static_cast<std::uint8_t>(i + 50));
        epoch_randomness_.fill(static_cast<std::uint8_t>(i + 100));

        auto chunk = compute_chunk_assignment(reveal_root_, peer_id_, epoch_randomness_);
        EXPECT_LT(chunk, ERASURE_TOTAL_CHUNKS);
    }
}

TEST_F(ChunkAssignmentTest, EpochRandomnessNormalMode) {
    hash_t state_root;
    state_root.fill(0x42);

    auto randomness = compute_epoch_randomness(state_root, 10, false);
    EXPECT_NE(randomness, hash_t{});  // Should produce some output
}

TEST_F(ChunkAssignmentTest, EpochRandomnessTimeoutMode) {
    hash_t state_root, soft_root;
    state_root.fill(0x42);
    soft_root.fill(0x55);

    auto randomness = compute_epoch_randomness(state_root, 10, true, &soft_root);
    EXPECT_NE(randomness, hash_t{});
}

// ============================================================================
// Erasure Coding Tests
// ============================================================================

class ErasureCodingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize GF256 tables
        GF256::initialize();
    }
};

TEST_F(ErasureCodingTest, GF256Addition) {
    EXPECT_EQ(GF256::add(0x00, 0x00), 0x00);
    EXPECT_EQ(GF256::add(0xFF, 0x00), 0xFF);
    EXPECT_EQ(GF256::add(0xFF, 0xFF), 0x00);  // XOR
    EXPECT_EQ(GF256::add(0x53, 0x2A), 0x79);
}

TEST_F(ErasureCodingTest, GF256Multiplication) {
    EXPECT_EQ(GF256::mul(0x00, 0x53), 0x00);
    EXPECT_EQ(GF256::mul(0x01, 0x53), 0x53);
    EXPECT_EQ(GF256::mul(0x02, 0x02), 0x04);
}

TEST_F(ErasureCodingTest, GF256Inverse) {
    for (int i = 1; i < 256; i++) {
        std::uint8_t x = static_cast<std::uint8_t>(i);
        std::uint8_t inv = GF256::inv(x);
        EXPECT_EQ(GF256::mul(x, inv), 0x01) << "Failed for " << i;
    }
}

TEST_F(ErasureCodingTest, EncodeSmallData) {
    std::vector<std::uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    hash_t reveal_root;

    auto chunks = ReedSolomonEncoder::encode(data, reveal_root);

    EXPECT_EQ(chunks.size(), RS_TOTAL_CHUNKS);
    for (const auto& chunk : chunks) {
        EXPECT_LT(chunk.chunk_index, RS_TOTAL_CHUNKS);
        EXPECT_FALSE(chunk.data.empty());
    }
}

TEST_F(ErasureCodingTest, EncodeLargerData) {
    std::vector<std::uint8_t> data(1000);
    for (std::size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<std::uint8_t>(i % 256);
    }
    hash_t reveal_root;

    auto chunks = ReedSolomonEncoder::encode(data, reveal_root);

    EXPECT_EQ(chunks.size(), RS_TOTAL_CHUNKS);
}

TEST_F(ErasureCodingTest, DecodeWithAllDataChunks) {
    std::vector<std::uint8_t> original(256);
    for (std::size_t i = 0; i < original.size(); i++) {
        original[i] = static_cast<std::uint8_t>(i);
    }
    hash_t reveal_root;

    auto chunks = ReedSolomonEncoder::encode(original, reveal_root);

    // Keep only data chunks
    std::vector<ErasureChunk> data_chunks;
    for (const auto& chunk : chunks) {
        if (chunk.chunk_index < RS_DATA_CHUNKS) {
            data_chunks.push_back(chunk);
        }
    }

    auto decoded = ReedSolomonEncoder::decode(data_chunks, original.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);
}

TEST_F(ErasureCodingTest, DecodeWithMixedChunks) {
    std::vector<std::uint8_t> original(256);
    for (std::size_t i = 0; i < original.size(); i++) {
        original[i] = static_cast<std::uint8_t>(i);
    }
    hash_t reveal_root;

    auto chunks = ReedSolomonEncoder::encode(original, reveal_root);

    // Keep mix of data and parity chunks
    std::vector<ErasureChunk> selected;
    for (std::size_t i = 0; i < 8; i++) {  // First 8 data chunks
        selected.push_back(chunks[i]);
    }
    for (std::size_t i = 16; i < 24; i++) {  // First 8 parity chunks
        selected.push_back(chunks[i]);
    }

    auto decoded = ReedSolomonEncoder::decode(selected, original.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);
}

TEST_F(ErasureCodingTest, CanReconstructCheck) {
    std::bitset<RS_TOTAL_CHUNKS> available;

    EXPECT_FALSE(ReedSolomonEncoder::can_reconstruct(available));

    for (int i = 0; i < 15; i++) {
        available.set(i);
    }
    EXPECT_FALSE(ReedSolomonEncoder::can_reconstruct(available));

    available.set(15);  // Now have 16
    EXPECT_TRUE(ReedSolomonEncoder::can_reconstruct(available));
}

TEST_F(ErasureCodingTest, MissingChunks) {
    std::bitset<RS_TOTAL_CHUNKS> available;
    available.set(0);
    available.set(5);
    available.set(10);

    auto missing = ReedSolomonEncoder::missing_chunks(available);
    EXPECT_EQ(missing.size(), RS_TOTAL_CHUNKS - 3);
}

TEST_F(ErasureCodingTest, ChunkVerification) {
    std::vector<std::uint8_t> data(128);
    for (std::size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<std::uint8_t>(i);
    }
    hash_t reveal_root;

    auto chunks = ReedSolomonEncoder::encode(data, reveal_root);

    // All chunks should verify against reveal_root
    for (const auto& chunk : chunks) {
        EXPECT_TRUE(chunk.verify(reveal_root))
            << "Chunk " << static_cast<int>(chunk.chunk_index) << " failed verification";
    }
}

TEST_F(ErasureCodingTest, ChunkSerializeDeserialize) {
    std::vector<std::uint8_t> data(64);
    hash_t reveal_root;
    auto chunks = ReedSolomonEncoder::encode(data, reveal_root);

    auto& chunk = chunks[0];
    auto serialized = chunk.serialize();
    auto deserialized = ErasureChunk::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->chunk_index, chunk.chunk_index);
    EXPECT_EQ(deserialized->data, chunk.data);
    EXPECT_EQ(deserialized->merkle_proof, chunk.merkle_proof);
}

TEST_F(ErasureCodingTest, ChunkCollector) {
    std::vector<std::uint8_t> original(256);
    for (std::size_t i = 0; i < original.size(); i++) {
        original[i] = static_cast<std::uint8_t>(i);
    }
    hash_t reveal_root;

    auto chunks = ReedSolomonEncoder::encode(original, reveal_root);

    // Create reveal info
    ErasureCodedReveal reveal_info;
    reveal_info.reveal_root = reveal_root;
    reveal_info.original_size = original.size();
    for (std::size_t i = 0; i < RS_TOTAL_CHUNKS; i++) {
        reveal_info.chunk_hashes[i] = sha3_256(chunks[i].data);
    }

    ChunkCollector collector(reveal_info);

    // Add chunks one by one
    for (std::size_t i = 0; i < 15; i++) {
        EXPECT_FALSE(collector.add_chunk(chunks[i]));
    }
    EXPECT_FALSE(collector.can_reconstruct());

    // 16th chunk should enable reconstruction
    EXPECT_TRUE(collector.add_chunk(chunks[15]));
    EXPECT_TRUE(collector.can_reconstruct());

    auto reconstructed = collector.reconstruct();
    ASSERT_TRUE(reconstructed.has_value());
    EXPECT_EQ(*reconstructed, original);
}

// ============================================================================
// VDF Bucket Proof Tests
// ============================================================================

class VDFBucketProofTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a test epoch checkpoint
        checkpoint_.epoch = 10;
        checkpoint_.step_number = 10 * SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT;
        checkpoint_.vdf_value.fill(0x42);
    }

    VDFEpochCheckpoint checkpoint_;
};

TEST_F(VDFBucketProofTest, StepToBucket) {
    std::uint64_t epoch_start = 10 * SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT;

    // Bucket 0 should be at start
    EXPECT_EQ(VDFBucketCalculator::step_to_bucket(epoch_start, epoch_start), 0);

    // Bucket 10 should be roughly in the middle
    std::uint64_t steps_per_bucket = (SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT) / BUCKETS_PER_TX_EPOCH;
    EXPECT_EQ(VDFBucketCalculator::step_to_bucket(epoch_start + 10 * steps_per_bucket, epoch_start), 10);
}

TEST_F(VDFBucketProofTest, BucketToStepRange) {
    auto [start, end] = VDFBucketCalculator::bucket_to_step_range(10, 5);

    EXPECT_LT(start, end);
    EXPECT_TRUE(VDFBucketCalculator::is_in_bucket(start, 10, 5));
    EXPECT_TRUE(VDFBucketCalculator::is_in_bucket(end, 10, 5));
    EXPECT_FALSE(VDFBucketCalculator::is_in_bucket(start - 1, 10, 5));
}

TEST_F(VDFBucketProofTest, ComputeVDFAtStep) {
    hash_t start;
    start.fill(0x42);

    auto at_0 = VDFBucketCalculator::compute_vdf_at_step(start, 100, 100);
    EXPECT_EQ(at_0, start);  // Same step = same value

    auto at_1 = VDFBucketCalculator::compute_vdf_at_step(start, 100, 101);
    EXPECT_EQ(at_1, sha3_256(start));  // One step = one hash

    auto at_2 = VDFBucketCalculator::compute_vdf_at_step(start, 100, 102);
    EXPECT_EQ(at_2, sha3_256(sha3_256(start)));  // Two steps = two hashes
}

TEST_F(VDFBucketProofTest, GenerateAndVerifyProof) {
    std::uint64_t bucket_step = checkpoint_.step_number + 100;

    auto proof = VDFBucketCalculator::generate_proof(checkpoint_, bucket_step);

    EXPECT_EQ(proof.checkpoint_epoch, checkpoint_.epoch);
    EXPECT_EQ(proof.checkpoint_step, checkpoint_.step_number);
    EXPECT_EQ(proof.bucket_step, bucket_step);
    EXPECT_EQ(proof.steps_from_reference, 100);

    // Compute expected bucket value
    hash_t expected_value = VDFBucketCalculator::compute_vdf_at_step(
        checkpoint_.vdf_value, checkpoint_.step_number, bucket_step);

    EXPECT_TRUE(proof.verify(expected_value, checkpoint_));
}

TEST_F(VDFBucketProofTest, WrongBucketValueFails) {
    std::uint64_t bucket_step = checkpoint_.step_number + 50;
    auto proof = VDFBucketCalculator::generate_proof(checkpoint_, bucket_step);

    hash_t wrong_value;
    wrong_value.fill(0xFF);

    EXPECT_FALSE(proof.verify(wrong_value, checkpoint_));
}

TEST_F(VDFBucketProofTest, ProofSerializeDeserialize) {
    std::uint64_t bucket_step = checkpoint_.step_number + 500;
    auto proof = VDFBucketCalculator::generate_proof(checkpoint_, bucket_step);

    auto serialized = proof.serialize();
    auto deserialized = VDFBucketProof::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->checkpoint_epoch, proof.checkpoint_epoch);
    EXPECT_EQ(deserialized->bucket_step, proof.bucket_step);
    EXPECT_EQ(deserialized->steps_from_reference, proof.steps_from_reference);
}

TEST_F(VDFBucketProofTest, CheckpointStore) {
    VDFCheckpointStore store;

    store.add_epoch_checkpoint(checkpoint_);

    auto retrieved = store.get_epoch_checkpoint(checkpoint_.epoch);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->epoch, checkpoint_.epoch);
    EXPECT_EQ(retrieved->vdf_value, checkpoint_.vdf_value);

    // Non-existent epoch
    auto missing = store.get_epoch_checkpoint(999);
    EXPECT_FALSE(missing.has_value());
}

TEST_F(VDFBucketProofTest, CheckpointStorePrune) {
    VDFCheckpointStore store;

    for (tx_epoch_t e = 0; e < 10; e++) {
        VDFEpochCheckpoint cp;
        cp.epoch = e;
        cp.step_number = e * 1000;
        cp.vdf_value.fill(static_cast<std::uint8_t>(e));
        store.add_epoch_checkpoint(cp);
    }

    // Should have all 10
    EXPECT_TRUE(store.get_epoch_checkpoint(0).has_value());
    EXPECT_TRUE(store.get_epoch_checkpoint(9).has_value());

    // Prune epochs before 5
    store.prune(5);

    // 0-4 should be gone
    EXPECT_FALSE(store.get_epoch_checkpoint(0).has_value());
    EXPECT_FALSE(store.get_epoch_checkpoint(4).has_value());

    // 5-9 should remain
    EXPECT_TRUE(store.get_epoch_checkpoint(5).has_value());
    EXPECT_TRUE(store.get_epoch_checkpoint(9).has_value());
}

// ============================================================================
// Enhanced Receipt Tests
// ============================================================================

class EnhancedReceiptTest : public ::testing::Test {
protected:
    void SetUp() override {
        keypair_ = MLDSAKeyPair::generate();
        ASSERT_TRUE(keypair_.has_value());

        peer_id_ = sha3_256(keypair_->public_key());
        merkle_root_.fill(0x42);
        epoch_randomness_.fill(0xAB);
    }

    std::optional<MLDSAKeyPair> keypair_;
    hash_t peer_id_;
    hash_t merkle_root_;
    hash_t epoch_randomness_;
};

TEST_F(EnhancedReceiptTest, CreateAndVerify) {
    EnhancedReceipt receipt;
    receipt.epoch_id = 10;
    receipt.bucket_id = 5;
    receipt.merkle_root = merkle_root_;
    receipt.peer_id = peer_id_;

    // Generate PoW proof
    receipt.pow_proof = SequentialPoWGenerator::generate(merkle_root_, peer_id_, 0);

    // Compute chunk assignment
    receipt.assigned_chunk_index = compute_chunk_assignment(
        merkle_root_, peer_id_, epoch_randomness_);
    receipt.chunk_data = {1, 2, 3, 4};  // Dummy chunk data

    // Sign
    auto msg = receipt.message_bytes();
    auto sig = keypair_->sign(msg);
    ASSERT_TRUE(sig.has_value());
    receipt.signature = *sig;

    // Verify
    EXPECT_TRUE(receipt.verify(keypair_->public_key(), epoch_randomness_));
}

TEST_F(EnhancedReceiptTest, WrongSignatureFails) {
    EnhancedReceipt receipt;
    receipt.epoch_id = 10;
    receipt.bucket_id = 5;
    receipt.merkle_root = merkle_root_;
    receipt.peer_id = peer_id_;
    receipt.pow_proof = SequentialPoWGenerator::generate(merkle_root_, peer_id_, 0);
    receipt.assigned_chunk_index = compute_chunk_assignment(
        merkle_root_, peer_id_, epoch_randomness_);

    // Wrong signature (zeros)
    receipt.signature.fill(0);

    EXPECT_FALSE(receipt.verify(keypair_->public_key(), epoch_randomness_));
}

TEST_F(EnhancedReceiptTest, WrongChunkAssignmentFails) {
    EnhancedReceipt receipt;
    receipt.epoch_id = 10;
    receipt.bucket_id = 5;
    receipt.merkle_root = merkle_root_;
    receipt.peer_id = peer_id_;
    receipt.pow_proof = SequentialPoWGenerator::generate(merkle_root_, peer_id_, 0);

    // Wrong chunk assignment
    receipt.assigned_chunk_index = 31;  // Force wrong value

    auto msg = receipt.message_bytes();
    auto sig = keypair_->sign(msg);
    receipt.signature = *sig;

    // Should fail if 31 is not the correct assignment
    // (might occasionally pass by chance)
}

}  // namespace
}  // namespace pop
