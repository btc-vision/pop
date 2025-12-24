#include <gtest/gtest.h>
#include "consensus/vdf.hh"
#include "crypto/hash.hh"

namespace pop {
namespace {

class VDFTest : public ::testing::Test {
protected:
    void SetUp() override {
        genesis_seed_.fill(0x42);
    }

    hash_t genesis_seed_;
};

TEST_F(VDFTest, VDFStepSequential) {
    VDFStep step = vdf_genesis(genesis_seed_);
    EXPECT_EQ(step.step_number, 0);

    VDFStep next = step.next();
    EXPECT_EQ(next.step_number, 1);
    EXPECT_NE(step.value, next.value);

    // Verify the chain
    EXPECT_TRUE(step.verify_next(next));
}

TEST_F(VDFTest, VDFStepDeterministic) {
    VDFStep step1 = vdf_genesis(genesis_seed_);
    VDFStep step2 = vdf_genesis(genesis_seed_);

    EXPECT_EQ(step1.value, step2.value);
    EXPECT_EQ(step1.next().value, step2.next().value);
}

TEST_F(VDFTest, VDFStepSerialization) {
    VDFStep step = vdf_genesis(genesis_seed_);
    step = step.next().next().next();  // Advance a few steps

    auto bytes = step.serialize();
    EXPECT_EQ(bytes.size(), VDFStep::SERIALIZED_SIZE);

    auto deserialized = VDFStep::deserialize(bytes);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->step_number, step.step_number);
    EXPECT_EQ(deserialized->value, step.value);
}

TEST_F(VDFTest, VDFTimeConversion) {
    // At step 0
    VDFTime t0{0};
    EXPECT_EQ(t0.to_slot(), 0);
    EXPECT_EQ(t0.to_tx_epoch(), 0);
    EXPECT_EQ(t0.to_identity_epoch(), 0);

    // At one slot
    VDFTime t1{VDF_STEPS_PER_SLOT};
    EXPECT_EQ(t1.to_slot(), 1);

    // At one tx epoch
    VDFTime t2{VDF_STEPS_PER_TX_EPOCH};
    EXPECT_EQ(t2.to_tx_epoch(), 1);

    // At one identity epoch
    VDFTime t3{VDF_STEPS_PER_IDENTITY_EPOCH};
    EXPECT_EQ(t3.to_identity_epoch(), 1);
}

TEST_F(VDFTest, VDFTimeFromSlot) {
    slot_t slot = 42;
    VDFTime t = VDFTime::from_slot(slot);
    EXPECT_EQ(t.to_slot(), slot);
}

TEST_F(VDFTest, VDFBucketCalculation) {
    tx_epoch_t epoch = 5;

    // At epoch start
    std::uint64_t epoch_start = epoch * VDF_STEPS_PER_TX_EPOCH;
    auto bucket0 = VDFBucket::from_step(epoch_start);
    EXPECT_EQ(bucket0.epoch, epoch);
    EXPECT_EQ(bucket0.bucket_id, 0);

    // One bucket (slot) later
    auto bucket1 = VDFBucket::from_step(epoch_start + VDF_STEPS_PER_SLOT);
    EXPECT_EQ(bucket1.bucket_id, 1);
}

TEST_F(VDFTest, VDFBucketCutoff) {
    tx_epoch_t epoch = 5;
    std::uint64_t epoch_start = epoch * VDF_STEPS_PER_TX_EPOCH;

    // Bucket at cutoff should still be valid
    std::uint64_t cutoff_step = epoch_start + RECEIPT_CUTOFF_BUCKET * VDF_STEPS_PER_SLOT;
    auto cutoff_bucket = VDFBucket::from_step(cutoff_step);
    EXPECT_EQ(cutoff_bucket.bucket_id, RECEIPT_CUTOFF_BUCKET);
    EXPECT_TRUE(cutoff_bucket.is_cutoff_bucket());
    EXPECT_FALSE(cutoff_bucket.is_past_cutoff());

    // Bucket after cutoff
    std::uint64_t after_cutoff = epoch_start + (RECEIPT_CUTOFF_BUCKET + 1) * VDF_STEPS_PER_SLOT;
    auto late_bucket = VDFBucket::from_step(after_cutoff);
    EXPECT_TRUE(late_bucket.is_past_cutoff());
}

TEST_F(VDFTest, PoolFreezeStep) {
    tx_epoch_t epoch = 10;
    std::uint64_t freeze = pool_freeze_step(epoch);

    // Freeze should be at next epoch start + 21 slots
    std::uint64_t expected = (epoch + 1) * VDF_STEPS_PER_TX_EPOCH + 21 * VDF_STEPS_PER_SLOT;
    EXPECT_EQ(freeze, expected);
}

TEST_F(VDFTest, IsPoolFrozen) {
    tx_epoch_t epoch = 10;
    std::uint64_t freeze_step = pool_freeze_step(epoch);

    // Before freeze
    EXPECT_FALSE(is_pool_frozen(epoch, freeze_step - 1));

    // At and after freeze
    EXPECT_TRUE(is_pool_frozen(epoch, freeze_step));
    EXPECT_TRUE(is_pool_frozen(epoch, freeze_step + 1000));
}

TEST_F(VDFTest, IdentitySaltDeterministic) {
    hash_t state_root;
    state_root.fill(0xAB);

    hash_t salt1 = compute_identity_salt(5, state_root);
    hash_t salt2 = compute_identity_salt(5, state_root);

    EXPECT_EQ(salt1, salt2);

    // Different epoch = different salt
    hash_t salt3 = compute_identity_salt(6, state_root);
    EXPECT_NE(salt1, salt3);

    // Different state root = different salt
    hash_t other_root;
    other_root.fill(0xCD);
    hash_t salt4 = compute_identity_salt(5, other_root);
    EXPECT_NE(salt1, salt4);
}

TEST_F(VDFTest, VDFProofVerificationSmallRange) {
    VDFStep start = vdf_genesis(genesis_seed_);
    VDFStep end = start;

    // Advance 100 steps
    for (int i = 0; i < 100; ++i) {
        end = end.next();
    }

    VDFProof proof;
    proof.start_step = start.step_number;
    proof.end_step = end.step_number;
    proof.start_value = start.value;
    proof.end_value = end.value;

    EXPECT_TRUE(proof.verify());
}

TEST_F(VDFTest, VDFProofInvalidEndValue) {
    VDFStep start = vdf_genesis(genesis_seed_);
    VDFStep end = start.next().next();

    VDFProof proof;
    proof.start_step = start.step_number;
    proof.end_step = end.step_number;
    proof.start_value = start.value;
    proof.end_value = start.value;  // Wrong!

    EXPECT_FALSE(proof.verify());
}

TEST_F(VDFTest, VDFProofSerialization) {
    VDFProof proof;
    proof.start_step = 100;
    proof.end_step = 200;
    proof.start_value.fill(0x11);
    proof.end_value.fill(0x22);
    proof.stark_proof = {0x01, 0x02, 0x03, 0x04};

    auto bytes = proof.serialize();
    auto deserialized = VDFProof::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->start_step, proof.start_step);
    EXPECT_EQ(deserialized->end_step, proof.end_step);
    EXPECT_EQ(deserialized->start_value, proof.start_value);
    EXPECT_EQ(deserialized->end_value, proof.end_value);
    EXPECT_EQ(deserialized->stark_proof, proof.stark_proof);
}

}  // namespace
}  // namespace pop
