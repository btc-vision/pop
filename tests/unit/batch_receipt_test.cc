#include <gtest/gtest.h>
#include "consensus/batch_receipt.hh"
#include "network/eligibility.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"

using namespace pop;

// ============================================================================
// BatchReceipt Tests
// ============================================================================

TEST(BatchReceiptTest, MessageBytes) {
    BatchReceipt receipt;
    receipt.epoch_id = 42;
    receipt.bucket_id = 5;
    receipt.merkle_root[0] = 0xAB;
    receipt.peer_id[0] = 0xCD;

    auto msg = receipt.message_bytes();

    // Should contain epoch, bucket, merkle_root, peer_id
    EXPECT_GT(msg.size(), 0);
}

TEST(BatchReceiptTest, SerializeDeserialize) {
    BatchReceipt original;
    original.epoch_id = 12345;
    original.bucket_id = 15;
    original.merkle_root[0] = 0xAB;
    original.merkle_root[31] = 0xCD;
    original.peer_id[0] = 0xEF;
    original.signature[0] = 0x12;

    auto serialized = original.serialize();
    EXPECT_EQ(serialized.size(), BatchReceipt::SERIALIZED_SIZE);

    auto restored = BatchReceipt::deserialize(serialized);
    ASSERT_TRUE(restored.has_value());

    EXPECT_EQ(original.epoch_id, restored->epoch_id);
    EXPECT_EQ(original.bucket_id, restored->bucket_id);
    EXPECT_EQ(original.merkle_root, restored->merkle_root);
    EXPECT_EQ(original.peer_id, restored->peer_id);
    EXPECT_EQ(original.signature, restored->signature);
}

TEST(BatchReceiptTest, Verify) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    BatchReceipt receipt;
    receipt.epoch_id = 1;
    receipt.bucket_id = 0;
    receipt.merkle_root[0] = 0x42;
    receipt.peer_id = sha3_256(keypair->public_key());

    auto msg = receipt.message_bytes();
    auto sig = keypair->sign(msg);
    ASSERT_TRUE(sig.has_value());
    receipt.signature = *sig;

    EXPECT_TRUE(receipt.verify(keypair->public_key()));
}

TEST(BatchReceiptTest, VerifyWrongKey) {
    auto keypair1 = MLDSAKeyPair::generate();
    auto keypair2 = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());

    BatchReceipt receipt;
    receipt.epoch_id = 1;
    receipt.bucket_id = 0;
    receipt.peer_id = sha3_256(keypair1->public_key());

    auto msg = receipt.message_bytes();
    auto sig = keypair1->sign(msg);
    ASSERT_TRUE(sig.has_value());
    receipt.signature = *sig;

    // Wrong key should fail
    EXPECT_FALSE(receipt.verify(keypair2->public_key()));
}

// ============================================================================
// RevealEligibility Tests
// ============================================================================

TEST(RevealEligibilityTest, PeerSet) {
    RevealEligibility elig;
    elig.reveal_hash[0] = 0x42;

    // Add some proofs
    for (int i = 0; i < 5; ++i) {
        ReceiptInclusionProof proof;
        proof.receipt.peer_id[0] = static_cast<std::uint8_t>(i);
        elig.proofs.push_back(proof);
    }

    auto peers = elig.peer_set();
    EXPECT_EQ(peers.size(), 5);
}

TEST(RevealEligibilityTest, SerializeDeserialize) {
    RevealEligibility original;
    original.reveal_hash[0] = 0x42;

    ReceiptInclusionProof proof;
    proof.receipt.epoch_id = 1;
    proof.receipt.bucket_id = 2;
    proof.receipt.peer_id[0] = 0xAB;
    proof.leaf_index = 5;
    proof.merkle_proof.push_back(hash_t{});

    original.proofs.push_back(proof);

    auto serialized = original.serialize();
    auto restored = RevealEligibility::deserialize(serialized);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(original.reveal_hash, restored->reveal_hash);
    EXPECT_EQ(original.proofs.size(), restored->proofs.size());
}

// ============================================================================
// BatchReceiptPool Tests
// ============================================================================

TEST(BatchReceiptPoolTest, Basic) {
    BatchReceiptPool pool;
    EXPECT_EQ(pool.total_receipts(), 0);
}

TEST(BatchReceiptPoolTest, GetReceipts) {
    BatchReceiptPool pool;

    auto receipts = pool.get_receipts(1, 0);
    EXPECT_TRUE(receipts.empty());
}

TEST(BatchReceiptPoolTest, Prune) {
    BatchReceiptPool pool;

    // Just verify prune doesn't crash on empty pool
    pool.prune(100);
    EXPECT_EQ(pool.total_receipts(), 0);
}

TEST(BatchReceiptPoolTest, ReceiptCount) {
    BatchReceiptPool pool;

    hash_t reveal_hash{};
    reveal_hash[0] = 0x42;

    EXPECT_EQ(pool.receipt_count(reveal_hash), 0);
}

TEST(BatchReceiptPoolTest, IsFrozen) {
    BatchReceiptPool pool;
    timestamp_t genesis(0);

    // Epoch 0 freezes at POOL_FREEZE_DELAY_MS
    timestamp_t before_freeze(POOL_FREEZE_DELAY_MS * 1000 - 1);
    timestamp_t after_freeze(POOL_FREEZE_DELAY_MS * 1000 + 1);

    EXPECT_FALSE(pool.is_frozen(0, before_freeze, genesis));
    EXPECT_TRUE(pool.is_frozen(0, after_freeze, genesis));
}

// ============================================================================
// ReceiptGenerator Tests
// ============================================================================

TEST(ReceiptGeneratorTest, Create) {
    mldsa_public_key_t pk{};
    pk[0] = 0x01;

    ReceiptGenerator gen(pk);
    // Should not crash
}

TEST(ReceiptGeneratorTest, CurrentBucket) {
    timestamp_t epoch_start(0);

    EXPECT_EQ(ReceiptGenerator::current_bucket(timestamp_t(0), epoch_start), 0);
    EXPECT_EQ(ReceiptGenerator::current_bucket(timestamp_t(100'000), epoch_start), 1);
    EXPECT_EQ(ReceiptGenerator::current_bucket(timestamp_t(500'000), epoch_start), 5);
}

TEST(ReceiptGeneratorTest, IsPastCutoff) {
    EXPECT_FALSE(ReceiptGenerator::is_past_cutoff(0));
    EXPECT_FALSE(ReceiptGenerator::is_past_cutoff(RECEIPT_CUTOFF_BUCKET));
    EXPECT_TRUE(ReceiptGenerator::is_past_cutoff(RECEIPT_CUTOFF_BUCKET + 1));
    EXPECT_TRUE(ReceiptGenerator::is_past_cutoff(19));
}

TEST(ReceiptGeneratorTest, AddReveal) {
    mldsa_public_key_t pk{};
    ReceiptGenerator gen(pk);

    hash_t reveal_hash{};
    reveal_hash[0] = 0x42;

    gen.add_reveal(reveal_hash, 1, 0);
    // Should not crash
}

TEST(ReceiptGeneratorTest, ClearBucket) {
    mldsa_public_key_t pk{};
    ReceiptGenerator gen(pk);

    gen.clear_bucket(1, 0);
    // Should not crash
}

// ============================================================================
// RewardDistributor Tests
// ============================================================================

TEST(RewardDistributorTest, DistributeEmpty) {
    std::vector<BatchReceipt> receipts;
    auto shares = RewardDistributor::distribute(1000, receipts);
    EXPECT_TRUE(shares.empty());
}

TEST(RewardDistributorTest, DistributeZeroPool) {
    std::vector<BatchReceipt> receipts;
    BatchReceipt r;
    r.peer_id[0] = 0x01;
    receipts.push_back(r);

    auto shares = RewardDistributor::distribute(0, receipts);
    EXPECT_TRUE(shares.empty());
}

TEST(RewardDistributorTest, DistributeSingle) {
    std::vector<BatchReceipt> receipts;
    BatchReceipt r;
    r.peer_id[0] = 0x01;
    r.bucket_id = 0;
    receipts.push_back(r);

    auto shares = RewardDistributor::distribute(1000, receipts);
    ASSERT_EQ(shares.size(), 1);
    EXPECT_EQ(shares[0].amount, 1000);
}

TEST(RewardDistributorTest, DistributeMultiple) {
    std::vector<BatchReceipt> receipts;
    for (int i = 0; i < 4; ++i) {
        BatchReceipt r;
        r.peer_id[0] = static_cast<std::uint8_t>(i);
        r.bucket_id = static_cast<std::uint8_t>(i);
        receipts.push_back(r);
    }

    auto shares = RewardDistributor::distribute(1000, receipts);
    EXPECT_EQ(shares.size(), 4);

    std::uint64_t total = 0;
    for (const auto& share : shares) {
        total += share.amount;
    }
    EXPECT_EQ(total, 1000);
}

TEST(RewardDistributorTest, DistributeWithMaxRecipients) {
    std::vector<BatchReceipt> receipts;
    for (int i = 0; i < 10; ++i) {
        BatchReceipt r;
        r.peer_id[0] = static_cast<std::uint8_t>(i);
        receipts.push_back(r);
    }

    auto shares = RewardDistributor::distribute(1000, receipts, 5);
    EXPECT_EQ(shares.size(), 5);
}

TEST(RewardDistributorTest, CalculateShare) {
    // Equal shares
    EXPECT_EQ(RewardDistributor::calculate_share(1000, 4, 0), 250);
    EXPECT_EQ(RewardDistributor::calculate_share(1000, 4, 1), 250);

    // Edge cases
    EXPECT_EQ(RewardDistributor::calculate_share(0, 4, 0), 0);
    EXPECT_EQ(RewardDistributor::calculate_share(1000, 0, 0), 0);
}

// ============================================================================
// Timing Helpers Tests
// ============================================================================

TEST(BatchReceiptTimingTest, SlotToTxEpoch) {
    EXPECT_EQ(slot_to_tx_epoch(0), 0);
    EXPECT_EQ(slot_to_tx_epoch(99), 0);
    EXPECT_EQ(slot_to_tx_epoch(100), 1);
}

TEST(BatchReceiptTimingTest, TxEpochStartTime) {
    timestamp_t genesis(1'000'000);  // 1 second

    auto start0 = tx_epoch_start_time(0, genesis);
    EXPECT_EQ(start0, genesis);

    auto start1 = tx_epoch_start_time(1, genesis);
    EXPECT_GT(start1, genesis);
}

TEST(BatchReceiptTimingTest, PoolFreezeTime) {
    timestamp_t genesis(0);

    auto freeze = pool_freeze_time(0, genesis);
    EXPECT_EQ(freeze.count(), POOL_FREEZE_DELAY_MS * 1000);
}

// ============================================================================
// Age-Weighted Attestation Tests
// ============================================================================

namespace {

class AgeWeightedAttestationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create identity registry
        identity_reg_ = std::make_unique<IdentityRegistry>();

        // Create eligibility tracker
        eligibility_ = std::make_unique<EligibilityTracker>();

        // Create a pool that we can populate with reveal receipts
        pool_ = std::make_unique<BatchReceiptPool>();
    }

    // Helper to create a peer with a given identity age and sufficient relays
    hash_t create_peer_with_age(std::uint8_t id_byte, std::size_t age_epochs, identity_epoch_t current_epoch) {
        hash_t peer_id{};
        peer_id[0] = id_byte;

        // Register peer in eligibility tracker for multiple epochs to build age
        tx_epoch_t start_epoch = current_epoch > age_epochs ? current_epoch - age_epochs : 0;
        for (tx_epoch_t e = start_epoch; e <= current_epoch; ++e) {
            eligibility_->record_seen(peer_id, e);
        }

        // Add sufficient relays (MIN_RELAYS_FOR_ELIGIBILITY = 10)
        for (std::size_t i = 0; i < MIN_RELAYS_FOR_ELIGIBILITY; ++i) {
            hash_t relayer_id{};
            relayer_id[0] = id_byte;
            relayer_id[1] = static_cast<std::uint8_t>(i + 1);  // Unique relayer
            eligibility_->record_relay(peer_id, relayer_id, current_epoch);
        }

        return peer_id;
    }

    // Helper to create a peer without sufficient relays (for testing reduced weight)
    hash_t create_peer_without_relays(std::uint8_t id_byte, std::size_t age_epochs, identity_epoch_t current_epoch) {
        hash_t peer_id{};
        peer_id[0] = id_byte;

        // Register peer in eligibility tracker for multiple epochs to build age
        tx_epoch_t start_epoch = current_epoch > age_epochs ? current_epoch - age_epochs : 0;
        for (tx_epoch_t e = start_epoch; e <= current_epoch; ++e) {
            eligibility_->record_seen(peer_id, e);
        }

        return peer_id;
    }

    std::unique_ptr<IdentityRegistry> identity_reg_;
    std::unique_ptr<EligibilityTracker> eligibility_;
    std::unique_ptr<BatchReceiptPool> pool_;
};

}  // namespace

TEST_F(AgeWeightedAttestationTest, GetWeightNoReveals) {
    hash_t reveal_hash{};
    reveal_hash[0] = 0x42;

    // No receipts for this reveal
    double weight = pool_->get_attestation_weight(
        reveal_hash, *identity_reg_, *eligibility_, 100);

    EXPECT_DOUBLE_EQ(weight, 0.0);
}

TEST_F(AgeWeightedAttestationTest, HasSufficientWeightNoReveals) {
    hash_t reveal_hash{};
    reveal_hash[0] = 0x42;

    // No receipts, should not have sufficient weight
    bool sufficient = pool_->has_sufficient_attestation_weight(
        reveal_hash, *identity_reg_, *eligibility_, 100);

    EXPECT_FALSE(sufficient);
}

TEST_F(AgeWeightedAttestationTest, WeightBasedOnPeerAge) {
    // Create peers with different ages
    identity_epoch_t current_epoch = 100;

    // Peer with 1 epoch of history (weight 1.0)
    hash_t peer1 = create_peer_with_age(0x01, 1, current_epoch);

    // Peer with 50 epochs of history (weight 1.0 + 49*0.1 = 5.9, capped at 10)
    hash_t peer2 = create_peer_with_age(0x02, 50, current_epoch);

    // Peer with 100 epochs of history (weight 10.0, max)
    hash_t peer3 = create_peer_with_age(0x03, 100, current_epoch);

    // Get individual weights
    double w1 = eligibility_->attestation_weight(peer1, *identity_reg_, current_epoch);
    double w2 = eligibility_->attestation_weight(peer2, *identity_reg_, current_epoch);
    double w3 = eligibility_->attestation_weight(peer3, *identity_reg_, current_epoch);

    // Verify weights increase with age
    EXPECT_GT(w2, w1);
    EXPECT_GE(w3, w2);
    EXPECT_LE(w3, 10.0);  // Max weight is 10.0
}

TEST_F(AgeWeightedAttestationTest, MeetsThresholdWithVeteranPeers) {
    // MIN_ATTESTATION_WEIGHT is 100
    // We need to create enough veteran peers to meet the threshold

    identity_epoch_t current_epoch = 200;

    // Create 15 veteran peers with 100 epochs of activity each
    // Each should have max weight of 10.0, total = 150
    std::vector<hash_t> veteran_peers;
    for (std::size_t i = 0; i < 15; ++i) {
        hash_t peer_id = create_peer_with_age(static_cast<std::uint8_t>(i), 100, current_epoch);
        veteran_peers.push_back(peer_id);
    }

    // Verify the threshold check
    bool meets_threshold = eligibility_->meets_attestation_threshold(
        veteran_peers, *identity_reg_, current_epoch);

    EXPECT_TRUE(meets_threshold);
}

TEST_F(AgeWeightedAttestationTest, DoesNotMeetThresholdWithFewNewPeers) {
    // Create only 5 new peers with full eligibility (1 epoch each = weight 1.0)
    // Total weight = 5.0, which is below MIN_ATTESTATION_WEIGHT of 100

    identity_epoch_t current_epoch = 100;

    std::vector<hash_t> new_peers;
    for (std::size_t i = 0; i < 5; ++i) {
        hash_t peer_id = create_peer_with_age(static_cast<std::uint8_t>(i), 1, current_epoch);
        new_peers.push_back(peer_id);
    }

    bool meets_threshold = eligibility_->meets_attestation_threshold(
        new_peers, *identity_reg_, current_epoch);

    EXPECT_FALSE(meets_threshold);
}

TEST_F(AgeWeightedAttestationTest, ReducedWeightWithoutRelays) {
    // Peers without sufficient relays should have reduced weight (0.5)
    identity_epoch_t current_epoch = 100;

    hash_t peer_with_relays = create_peer_with_age(0x01, 50, current_epoch);
    hash_t peer_without_relays = create_peer_without_relays(0x02, 50, current_epoch);

    double w1 = eligibility_->attestation_weight(peer_with_relays, *identity_reg_, current_epoch);
    double w2 = eligibility_->attestation_weight(peer_without_relays, *identity_reg_, current_epoch);

    // Peer with relays should have higher weight based on age
    EXPECT_GT(w1, 1.0);
    // Peer without relays should have reduced weight of 0.5
    EXPECT_DOUBLE_EQ(w2, 0.5);
}
