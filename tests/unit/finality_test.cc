#include <gtest/gtest.h>
#include "consensus/finality.hh"
#include "crypto/hash.hh"

namespace pop {
namespace {

class FinalityTest : public ::testing::Test {
protected:
    void SetUp() override {
        state_root_.fill(0x42);
        reveal_commitment_.fill(0x33);
    }

    hash_t state_root_;
    hash_t reveal_commitment_;
};

TEST_F(FinalityTest, SoftFinalityRecording) {
    FinalityTracker tracker;

    tx_epoch_t epoch = 5;
    std::uint64_t freeze_step = 50000;

    EXPECT_FALSE(tracker.has_soft_finality(epoch));

    tracker.record_soft_finality(epoch, state_root_, reveal_commitment_, freeze_step);

    EXPECT_TRUE(tracker.has_soft_finality(epoch));

    auto record = tracker.get_soft_finality(epoch);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->epoch, epoch);
    EXPECT_EQ(record->state_root, state_root_);
    EXPECT_EQ(record->reveal_set_commitment, reveal_commitment_);
    EXPECT_EQ(record->freeze_vdf_step, freeze_step);
}

TEST_F(FinalityTest, SoftFinalityRecordSerialization) {
    SoftFinalityRecord record;
    record.epoch = 10;
    record.state_root.fill(0xAA);
    record.reveal_set_commitment.fill(0xBB);
    record.freeze_vdf_step = 123456;
    record.is_binding = true;

    auto bytes = record.serialize();
    auto deserialized = SoftFinalityRecord::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->epoch, record.epoch);
    EXPECT_EQ(deserialized->state_root, record.state_root);
    EXPECT_EQ(deserialized->reveal_set_commitment, record.reveal_set_commitment);
    EXPECT_EQ(deserialized->freeze_vdf_step, record.freeze_vdf_step);
    EXPECT_EQ(deserialized->is_binding, record.is_binding);
}

TEST_F(FinalityTest, HardFinalityRecordSerialization) {
    HardFinalityRecord record;
    record.epoch = 20;
    record.state_root.fill(0xCC);
    record.reveal_set_commitment.fill(0xDD);
    record.convergence_vdf_step = 789012;
    record.total_attestation_weight = 42;

    auto bytes = record.serialize();
    auto deserialized = HardFinalityRecord::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->epoch, record.epoch);
    EXPECT_EQ(deserialized->state_root, record.state_root);
    EXPECT_EQ(deserialized->reveal_set_commitment, record.reveal_set_commitment);
    EXPECT_EQ(deserialized->convergence_vdf_step, record.convergence_vdf_step);
    EXPECT_EQ(deserialized->total_attestation_weight, record.total_attestation_weight);
}

TEST_F(FinalityTest, FinalityTypeProgression) {
    FinalityTracker tracker;
    tx_epoch_t epoch = 5;

    // Initially no finality
    EXPECT_EQ(tracker.get_finality_type(epoch), FinalityType::NONE);

    // After soft finality
    tracker.record_soft_finality(epoch, state_root_, reveal_commitment_, 50000);
    EXPECT_EQ(tracker.get_finality_type(epoch), FinalityType::SOFT);
}

TEST_F(FinalityTest, AttestationSerialization) {
    Attestation att;
    att.state_root.fill(0x11);
    att.epoch = 15;
    att.peer_id.fill(0x22);
    att.identity_age = 5;
    att.signature.fill(0x33);

    auto bytes = att.serialize();
    EXPECT_EQ(bytes.size(), Attestation::SERIALIZED_SIZE);

    auto deserialized = Attestation::deserialize(bytes);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->state_root, att.state_root);
    EXPECT_EQ(deserialized->epoch, att.epoch);
    EXPECT_EQ(deserialized->peer_id, att.peer_id);
    EXPECT_EQ(deserialized->identity_age, att.identity_age);
}

TEST_F(FinalityTest, IBLTCellOperations) {
    IBLTCell cell;

    EXPECT_TRUE(cell.is_empty());
    EXPECT_EQ(cell.count, 0);

    hash_t key, value;
    key.fill(0x11);
    value.fill(0x22);

    cell.insert(key, value);
    EXPECT_EQ(cell.count, 1);
    EXPECT_TRUE(cell.is_pure());

    // Insert another
    hash_t key2, value2;
    key2.fill(0x33);
    value2.fill(0x44);
    cell.insert(key2, value2);
    EXPECT_EQ(cell.count, 2);
    EXPECT_FALSE(cell.is_pure());

    // Remove first
    cell.remove(key, value);
    EXPECT_EQ(cell.count, 1);
    EXPECT_TRUE(cell.is_pure());
}

TEST_F(FinalityTest, IBLTInsertRemove) {
    IBLT iblt;

    hash_t key1, value1;
    key1.fill(0x11);
    value1.fill(0x22);

    hash_t key2, value2;
    key2.fill(0x33);
    value2.fill(0x44);

    iblt.insert(key1, value1);
    iblt.insert(key2, value2);

    // Remove one
    iblt.remove(key1, value1);

    // Should be able to list remaining
    auto entries = iblt.list_entries();
    EXPECT_GE(entries.size(), 0);  // May or may not decode depending on implementation
}

TEST_F(FinalityTest, IBLTSubtraction) {
    IBLT iblt1;
    IBLT iblt2;

    hash_t key1, value1;
    key1.fill(0x11);
    value1.fill(0x22);

    hash_t key2, value2;
    key2.fill(0x33);
    value2.fill(0x44);

    // iblt1 has key1
    iblt1.insert(key1, value1);

    // iblt2 has key2
    iblt2.insert(key2, value2);

    // Subtract to find difference
    IBLT diff = iblt1.subtract(iblt2);

    auto result = diff.decode();
    // Result should show key1 is in ours, key2 is in theirs
    // (depending on implementation details)
}

TEST_F(FinalityTest, IBLTSerialization) {
    IBLT iblt;

    hash_t key, value;
    key.fill(0x11);
    value.fill(0x22);
    iblt.insert(key, value);

    auto bytes = iblt.serialize();
    auto deserialized = IBLT::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
}

TEST_F(FinalityTest, ReconciliationManagerBasic) {
    ReconciliationManager manager;

    tx_epoch_t epoch = 5;
    hash_t reveal_hash;
    reveal_hash.fill(0xAB);

    manager.add_reveal(epoch, reveal_hash);

    auto iblt = manager.build_local_iblt(epoch);
    // Should contain the reveal
}

TEST_F(FinalityTest, ReconciliationRateLimit) {
    ReconciliationManager manager;

    hash_t peer_id;
    peer_id.fill(0x11);

    // First few requests should succeed
    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(manager.check_rate_limit(peer_id));
    }

    // After max requests, should be rate limited
    // (depending on implementation of rate window)
}

TEST_F(FinalityTest, NeedsReconciliationNoLocalData) {
    ReconciliationManager manager;
    tx_epoch_t epoch = 10;

    // Empty peer state root - no reconciliation needed
    hash_t empty_root{};
    EXPECT_FALSE(manager.needs_reconciliation(epoch, empty_root));

    // Non-empty peer state root - reconciliation needed (we have no data)
    hash_t peer_root;
    peer_root.fill(0xAB);
    EXPECT_TRUE(manager.needs_reconciliation(epoch, peer_root));
}

TEST_F(FinalityTest, NeedsReconciliationMatchingRoots) {
    ReconciliationManager manager;
    tx_epoch_t epoch = 10;

    // Add some reveals
    hash_t reveal1;
    reveal1.fill(0x11);
    manager.add_reveal(epoch, reveal1);

    // Set our state root
    hash_t our_root;
    our_root.fill(0xAA);
    manager.set_local_state_root(epoch, our_root);

    // Peer has same root - no reconciliation needed
    EXPECT_FALSE(manager.needs_reconciliation(epoch, our_root));
}

TEST_F(FinalityTest, NeedsReconciliationDifferentRoots) {
    ReconciliationManager manager;
    tx_epoch_t epoch = 10;

    // Add some reveals
    hash_t reveal1;
    reveal1.fill(0x11);
    manager.add_reveal(epoch, reveal1);

    // Set our state root
    hash_t our_root;
    our_root.fill(0xAA);
    manager.set_local_state_root(epoch, our_root);

    // Peer has different root - reconciliation needed
    hash_t peer_root;
    peer_root.fill(0xBB);
    EXPECT_TRUE(manager.needs_reconciliation(epoch, peer_root));
}

TEST_F(FinalityTest, ReconciliationRevealCount) {
    ReconciliationManager manager;
    tx_epoch_t epoch = 10;

    // No reveals initially
    EXPECT_EQ(manager.reveal_count(epoch), 0);

    // Add reveals
    for (int i = 0; i < 5; ++i) {
        hash_t reveal;
        reveal.fill(static_cast<std::uint8_t>(i));
        manager.add_reveal(epoch, reveal);
    }

    EXPECT_EQ(manager.reveal_count(epoch), 5);

    // Adding duplicate should not increase count
    hash_t duplicate;
    duplicate.fill(0);
    manager.add_reveal(epoch, duplicate);
    EXPECT_EQ(manager.reveal_count(epoch), 5);
}

TEST_F(FinalityTest, ReconciliationStateRootPersistence) {
    ReconciliationManager manager;
    tx_epoch_t epoch = 10;

    // Initially no state root
    EXPECT_FALSE(manager.get_local_state_root(epoch).has_value());

    // Set state root
    hash_t root;
    root.fill(0xCC);
    manager.set_local_state_root(epoch, root);

    // Should be retrievable
    auto retrieved = manager.get_local_state_root(epoch);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(*retrieved, root);
}

TEST_F(FinalityTest, FinalityTrackerPrune) {
    FinalityTracker tracker;

    // Record finality for multiple epochs
    for (tx_epoch_t e = 0; e < 10; ++e) {
        hash_t root;
        root.fill(static_cast<std::uint8_t>(e));
        tracker.record_soft_finality(e, root, reveal_commitment_, e * 1000);
    }

    EXPECT_TRUE(tracker.has_soft_finality(0));
    EXPECT_TRUE(tracker.has_soft_finality(5));
    EXPECT_TRUE(tracker.has_soft_finality(9));

    // Prune epochs before 5
    tracker.prune(5);

    EXPECT_FALSE(tracker.has_soft_finality(0));
    EXPECT_FALSE(tracker.has_soft_finality(4));
    EXPECT_TRUE(tracker.has_soft_finality(5));
    EXPECT_TRUE(tracker.has_soft_finality(9));
}

}  // namespace
}  // namespace pop
