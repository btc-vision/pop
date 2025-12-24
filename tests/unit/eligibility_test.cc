#include <gtest/gtest.h>
#include "network/eligibility.hh"
#include "consensus/identity.hh"
#include "crypto/hash.hh"
#include <random>

using namespace pop;

namespace {

// Helper to create a random peer ID
hash_t random_peer_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint8_t> dist(0, 255);

    hash_t id;
    for (auto& byte : id) {
        byte = dist(gen);
    }
    return id;
}

// Helper to create N random peer IDs
std::vector<hash_t> create_peer_ids(std::size_t count) {
    std::vector<hash_t> ids;
    ids.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        ids.push_back(random_peer_id());
    }
    return ids;
}

}  // namespace

// ============================================================================
// EligibilityTracker Basic Tests
// ============================================================================

class EligibilityTrackerTest : public ::testing::Test {
protected:
    void SetUp() override {
        tracker_ = std::make_unique<EligibilityTracker>();
        identity_reg_ = std::make_unique<IdentityRegistry>();
    }

    std::unique_ptr<EligibilityTracker> tracker_;
    std::unique_ptr<IdentityRegistry> identity_reg_;
};

TEST_F(EligibilityTrackerTest, NewPeerNotEligible) {
    auto peer_id = random_peer_id();
    tx_epoch_t epoch = 100;

    // A brand new peer with no activity should not be eligible
    EXPECT_FALSE(tracker_->is_eligible(peer_id, epoch, *identity_reg_));

    auto criteria = tracker_->get_criteria(peer_id, epoch, *identity_reg_);
    EXPECT_FALSE(criteria.seen_in_lookback);
    EXPECT_FALSE(criteria.has_sufficient_relays);
    EXPECT_FALSE(criteria.is_eligible());
}

TEST_F(EligibilityTrackerTest, RecordSeenCreatesActivity) {
    auto peer_id = random_peer_id();
    tx_epoch_t epoch = 100;

    EXPECT_EQ(tracker_->peer_count(), 0);

    tracker_->record_seen(peer_id, epoch);

    EXPECT_EQ(tracker_->peer_count(), 1);

    auto record = tracker_->get_activity_record(peer_id);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->first_seen_epoch, epoch);
    EXPECT_EQ(record->last_seen_epoch, epoch);
    EXPECT_EQ(record->receipt_count, 0);
}

TEST_F(EligibilityTrackerTest, RecordRelayBuildsRelayCount) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(15);
    tx_epoch_t epoch = 100;

    // Record the peer being seen
    tracker_->record_seen(peer_id, epoch);

    // Add relayers one by one
    for (std::size_t i = 0; i < MIN_RELAYS_FOR_ELIGIBILITY - 1; ++i) {
        tracker_->record_relay(peer_id, relayers[i], epoch);

        auto record = tracker_->get_activity_record(peer_id);
        ASSERT_TRUE(record.has_value());
        EXPECT_EQ(record->relay_count(), i + 1);
        EXPECT_FALSE(record->has_sufficient_relays());
    }

    // Add the 10th relayer - now should have sufficient relays
    tracker_->record_relay(peer_id, relayers[9], epoch);

    auto record = tracker_->get_activity_record(peer_id);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->relay_count(), MIN_RELAYS_FOR_ELIGIBILITY);
    EXPECT_TRUE(record->has_sufficient_relays());
}

TEST_F(EligibilityTrackerTest, DuplicateRelayersNotCounted) {
    auto peer_id = random_peer_id();
    auto relayer = random_peer_id();
    tx_epoch_t epoch = 100;

    tracker_->record_seen(peer_id, epoch);

    // Record same relayer multiple times
    for (int i = 0; i < 20; ++i) {
        tracker_->record_relay(peer_id, relayer, epoch);
    }

    auto record = tracker_->get_activity_record(peer_id);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->relay_count(), 1);  // Still just 1 unique relayer
}

TEST_F(EligibilityTrackerTest, EligibilityWithSufficientRelays) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    tracker_->record_seen(peer_id, epoch);

    for (const auto& relayer : relayers) {
        tracker_->record_relay(peer_id, relayer, epoch);
    }

    auto criteria = tracker_->get_criteria(peer_id, epoch, *identity_reg_);
    EXPECT_TRUE(criteria.seen_in_lookback);
    EXPECT_TRUE(criteria.has_sufficient_relays);
}

// ============================================================================
// Lookback Window Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, LookbackWindowExpiry) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t old_epoch = 10;
    tx_epoch_t current_epoch = old_epoch + ELIGIBILITY_LOOKBACK_EPOCHS + 1;

    // Register peer in old epoch
    tracker_->record_seen(peer_id, old_epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(peer_id, relayer, old_epoch);
    }

    // Should not be eligible at current epoch (outside lookback window)
    auto criteria = tracker_->get_criteria(peer_id, current_epoch, *identity_reg_);
    EXPECT_FALSE(criteria.seen_in_lookback);
    EXPECT_FALSE(criteria.is_eligible());
}

TEST_F(EligibilityTrackerTest, LookbackWindowStillValid) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t old_epoch = 10;
    tx_epoch_t current_epoch = old_epoch + ELIGIBILITY_LOOKBACK_EPOCHS - 1;

    // Register peer in old epoch (within lookback window)
    tracker_->record_seen(peer_id, old_epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(peer_id, relayer, old_epoch);
    }

    // Should still be eligible (within lookback window)
    auto criteria = tracker_->get_criteria(peer_id, current_epoch, *identity_reg_);
    EXPECT_TRUE(criteria.seen_in_lookback);
    EXPECT_TRUE(criteria.has_sufficient_relays);
}

TEST_F(EligibilityTrackerTest, PruneInactive) {
    auto peer_ids = create_peer_ids(5);
    tx_epoch_t old_epoch = 5;           // Will be outside lookback
    tx_epoch_t recent_epoch = 100;      // Will be inside lookback
    tx_epoch_t current_epoch = 110;     // cutoff = 110 - 100 = 10, so epoch 5 < 10

    // Register 3 peers in old epoch (epoch 5, which is < cutoff 10)
    for (std::size_t i = 0; i < 3; ++i) {
        tracker_->record_seen(peer_ids[i], old_epoch);
    }

    // Register 2 peers in recent epoch (epoch 100, which is >= cutoff 10)
    for (std::size_t i = 3; i < 5; ++i) {
        tracker_->record_seen(peer_ids[i], recent_epoch);
    }

    EXPECT_EQ(tracker_->peer_count(), 5);

    // Prune inactive (old_epoch is outside 100-epoch lookback from current_epoch)
    std::size_t pruned = tracker_->prune_inactive(current_epoch);

    EXPECT_EQ(pruned, 3);
    EXPECT_EQ(tracker_->peer_count(), 2);

    // Verify correct peers were pruned
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_FALSE(tracker_->get_activity_record(peer_ids[i]).has_value());
    }
    for (std::size_t i = 3; i < 5; ++i) {
        EXPECT_TRUE(tracker_->get_activity_record(peer_ids[i]).has_value());
    }
}

// ============================================================================
// Sponsorship Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, SponsorshipBasic) {
    auto sponsor_id = random_peer_id();
    auto new_peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    // Make sponsor eligible
    tracker_->record_seen(sponsor_id, epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(sponsor_id, relayer, epoch);
    }

    // Check sponsorship is allowed
    auto result = tracker_->check_sponsorship(sponsor_id, new_peer_id, epoch, *identity_reg_);
    EXPECT_EQ(result, SponsorshipResult::SUCCESS);

    // Record sponsorship
    tracker_->record_sponsorship(sponsor_id, new_peer_id, epoch);

    // New peer should now have sponsor as a relayer
    auto record = tracker_->get_activity_record(new_peer_id);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->relay_count(), 1);
}

TEST_F(EligibilityTrackerTest, SponsorNotEligible) {
    auto sponsor_id = random_peer_id();
    auto new_peer_id = random_peer_id();
    tx_epoch_t epoch = 100;

    // Don't make sponsor eligible (no relays)
    tracker_->record_seen(sponsor_id, epoch);

    auto result = tracker_->check_sponsorship(sponsor_id, new_peer_id, epoch, *identity_reg_);
    EXPECT_EQ(result, SponsorshipResult::SPONSOR_NOT_ELIGIBLE);
}

TEST_F(EligibilityTrackerTest, SponsorAtLimit) {
    auto sponsor_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    // Make sponsor eligible
    tracker_->record_seen(sponsor_id, epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(sponsor_id, relayer, epoch);
    }

    // Sponsor MAX_NEW_PEERS_PER_SPONSOR_PER_EPOCH peers
    for (std::size_t i = 0; i < MAX_NEW_PEERS_PER_SPONSOR_PER_EPOCH; ++i) {
        auto new_peer = random_peer_id();
        auto result = tracker_->check_sponsorship(sponsor_id, new_peer, epoch, *identity_reg_);
        EXPECT_EQ(result, SponsorshipResult::SUCCESS);
        tracker_->record_sponsorship(sponsor_id, new_peer, epoch);
    }

    EXPECT_EQ(tracker_->get_sponsor_count(sponsor_id, epoch), MAX_NEW_PEERS_PER_SPONSOR_PER_EPOCH);

    // Try to sponsor one more - should fail
    auto one_more = random_peer_id();
    auto result = tracker_->check_sponsorship(sponsor_id, one_more, epoch, *identity_reg_);
    EXPECT_EQ(result, SponsorshipResult::SPONSOR_AT_LIMIT);
}

TEST_F(EligibilityTrackerTest, PeerAlreadySponsored) {
    auto sponsor1 = random_peer_id();
    auto sponsor2 = random_peer_id();
    auto new_peer = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    // Make both sponsors eligible
    tracker_->record_seen(sponsor1, epoch);
    tracker_->record_seen(sponsor2, epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(sponsor1, relayer, epoch);
        tracker_->record_relay(sponsor2, relayer, epoch);
    }

    // First sponsor sponsors the new peer
    tracker_->record_sponsorship(sponsor1, new_peer, epoch);

    // Second sponsor tries to sponsor same peer
    auto result = tracker_->check_sponsorship(sponsor2, new_peer, epoch, *identity_reg_);
    EXPECT_EQ(result, SponsorshipResult::NEW_PEER_ALREADY_SPONSORED);
}

// ============================================================================
// Violation Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, ViolationTracking) {
    auto peer_id = random_peer_id();
    tx_epoch_t epoch = 100;

    EXPECT_EQ(tracker_->get_violation_count(peer_id), 0);

    tracker_->record_violation(peer_id, epoch, EligibilityViolation::INVALID_RECEIPT);
    EXPECT_EQ(tracker_->get_violation_count(peer_id), 1);

    tracker_->record_violation(peer_id, epoch, EligibilityViolation::MISSING_CHUNK);
    EXPECT_EQ(tracker_->get_violation_count(peer_id), 2);
}

TEST_F(EligibilityTrackerTest, ViolationsAffectEligibility) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    // Make peer eligible
    tracker_->record_seen(peer_id, epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(peer_id, relayer, epoch);
    }

    // Initially eligible
    auto criteria = tracker_->get_criteria(peer_id, epoch, *identity_reg_);
    EXPECT_TRUE(criteria.is_not_banned);

    // Record 3 violations (threshold for is_not_banned is <3)
    for (int i = 0; i < 3; ++i) {
        tracker_->record_violation(peer_id, epoch, EligibilityViolation::INVALID_RECEIPT);
    }

    // Should no longer be eligible due to violations
    criteria = tracker_->get_criteria(peer_id, epoch, *identity_reg_);
    EXPECT_FALSE(criteria.is_not_banned);
    EXPECT_FALSE(criteria.is_eligible());
}

// ============================================================================
// Attestation Weight Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, AttestationWeightNewPeer) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    tracker_->record_seen(peer_id, epoch);
    for (const auto& relayer : relayers) {
        tracker_->record_relay(peer_id, relayer, epoch);
    }

    // New peer with 1 active epoch should have weight 1.0
    double weight = tracker_->attestation_weight(peer_id, *identity_reg_, epoch);
    EXPECT_NEAR(weight, 1.0, 0.01);
}

TEST_F(EligibilityTrackerTest, AttestationWeightVeteranPeer) {
    auto peer_id = random_peer_id();
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);

    // Active for 50 epochs
    for (tx_epoch_t epoch = 50; epoch < 100; ++epoch) {
        tracker_->record_seen(peer_id, epoch);
    }

    // Add relayers
    for (const auto& relayer : relayers) {
        tracker_->record_relay(peer_id, relayer, 99);
    }

    // 50 active epochs should give higher weight
    double weight = tracker_->attestation_weight(peer_id, *identity_reg_, 100);
    EXPECT_GT(weight, 1.0);
    EXPECT_LE(weight, 10.0);
}

TEST_F(EligibilityTrackerTest, AttestationWeightInsufficientRelays) {
    auto peer_id = random_peer_id();
    tx_epoch_t epoch = 100;

    // Peer seen but no relayers
    tracker_->record_seen(peer_id, epoch);

    // Should have reduced weight (0.5)
    double weight = tracker_->attestation_weight(peer_id, *identity_reg_, epoch);
    EXPECT_NEAR(weight, 0.5, 0.01);
}

TEST_F(EligibilityTrackerTest, MeetsAttestationThreshold) {
    // MIN_ATTESTATION_WEIGHT = 100
    // Weight formula: 1.0 + (active_epochs - 1) * 0.1, capped at 10.0
    // We need 10+ peers with max weight (10.0 each) to reach 100

    auto peer_ids = create_peer_ids(15);  // 15 veteran peers
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    // Make all peers eligible with long activity history (100 epochs = max weight)
    for (const auto& peer_id : peer_ids) {
        // Give each peer 100 epochs of activity for max weight
        for (tx_epoch_t e = 1; e <= epoch; ++e) {
            tracker_->record_seen(peer_id, e);
        }
        for (const auto& relayer : relayers) {
            tracker_->record_relay(peer_id, relayer, epoch);
        }
    }

    // Just a few peers (3 * 10.0 = 30) shouldn't meet threshold (100)
    std::vector<hash_t> few_peers(peer_ids.begin(), peer_ids.begin() + 3);
    EXPECT_FALSE(tracker_->meets_attestation_threshold(few_peers, *identity_reg_, epoch));

    // 10 veteran peers (10 * 10.0 = 100) should meet threshold exactly
    std::vector<hash_t> ten_peers(peer_ids.begin(), peer_ids.begin() + 10);
    EXPECT_TRUE(tracker_->meets_attestation_threshold(ten_peers, *identity_reg_, epoch));

    // All 15 peers (15 * 10.0 = 150) should definitely meet threshold
    EXPECT_TRUE(tracker_->meets_attestation_threshold(peer_ids, *identity_reg_, epoch));
}

// ============================================================================
// Receipt Recording Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, RecordReceipt) {
    auto peer_id = random_peer_id();
    tx_epoch_t epoch = 100;

    tracker_->record_seen(peer_id, epoch);

    EXPECT_EQ(tracker_->get_activity_record(peer_id)->receipt_count, 0);

    tracker_->record_receipt(peer_id, epoch);
    EXPECT_EQ(tracker_->get_activity_record(peer_id)->receipt_count, 1);

    tracker_->record_receipt(peer_id, epoch);
    tracker_->record_receipt(peer_id, epoch);
    EXPECT_EQ(tracker_->get_activity_record(peer_id)->receipt_count, 3);
}

// ============================================================================
// Serialization Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, SerializeDeserializeEmpty) {
    auto data = tracker_->serialize();
    EXPECT_GE(data.size(), 4);  // At least count header

    auto restored = EligibilityTracker::deserialize(data);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->peer_count(), 0);
}

TEST_F(EligibilityTrackerTest, SerializeDeserializeWithData) {
    auto peer_ids = create_peer_ids(5);
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    for (const auto& peer_id : peer_ids) {
        tracker_->record_seen(peer_id, epoch);
        for (const auto& relayer : relayers) {
            tracker_->record_relay(peer_id, relayer, epoch);
        }
    }

    // Add some violations
    tracker_->record_violation(peer_ids[0], epoch, EligibilityViolation::INVALID_RECEIPT);
    tracker_->record_violation(peer_ids[0], epoch, EligibilityViolation::MISSING_CHUNK);

    auto data = tracker_->serialize();
    auto restored = EligibilityTracker::deserialize(data);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->peer_count(), 5);

    // Check that activity records are preserved
    for (const auto& peer_id : peer_ids) {
        auto record = restored->get_activity_record(peer_id);
        ASSERT_TRUE(record.has_value());
        EXPECT_EQ(record->relay_count(), MIN_RELAYS_FOR_ELIGIBILITY);
    }

    // Check violations preserved
    EXPECT_EQ(restored->get_violation_count(peer_ids[0]), 2);
    EXPECT_EQ(restored->get_violation_count(peer_ids[1]), 0);
}

// ============================================================================
// Eligible Count Tests
// ============================================================================

TEST_F(EligibilityTrackerTest, EligibleCount) {
    auto peer_ids = create_peer_ids(10);
    auto relayers = create_peer_ids(MIN_RELAYS_FOR_ELIGIBILITY);
    tx_epoch_t epoch = 100;

    // Make first 5 peers fully eligible
    for (std::size_t i = 0; i < 5; ++i) {
        tracker_->record_seen(peer_ids[i], epoch);
        for (const auto& relayer : relayers) {
            tracker_->record_relay(peer_ids[i], relayer, epoch);
        }
    }

    // Make last 5 peers only seen (not enough relays)
    for (std::size_t i = 5; i < 10; ++i) {
        tracker_->record_seen(peer_ids[i], epoch);
    }

    EXPECT_EQ(tracker_->peer_count(), 10);
    EXPECT_EQ(tracker_->eligible_count(epoch, *identity_reg_), 5);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(EligibilityTrackerTest, UnknownPeerWeight) {
    auto unknown_peer = random_peer_id();

    double weight = tracker_->attestation_weight(unknown_peer, *identity_reg_, 100);
    EXPECT_NEAR(weight, 0.0, 0.01);
}

TEST_F(EligibilityTrackerTest, EmptyPeerIdVectorMeetsThreshold) {
    std::vector<hash_t> empty;

    // Empty vector has total weight 0, should not meet threshold
    EXPECT_FALSE(tracker_->meets_attestation_threshold(empty, *identity_reg_, 100));
}
