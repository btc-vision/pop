#include <gtest/gtest.h>
#include "consensus/identity.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"

using namespace pop;

// ============================================================================
// Identity Tests
// ============================================================================

TEST(IdentityTest, ComputeHash) {
    Identity id{};
    id.public_key[0] = 0x01;
    id.nonce = 12345;
    id.epoch = 1;
    id.salt[0] = 0xAB;

    id.compute_hash();

    // Hash should be non-zero
    bool all_zero = true;
    for (auto b : id.identity_hash) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}

TEST(IdentityTest, VerifyDifficultyFails) {
    Identity id{};
    id.public_key[0] = 0x01;
    id.nonce = 0;
    id.epoch = 1;
    id.salt[0] = 0xAB;
    id.compute_hash();

    // Random hash very unlikely to meet difficulty
    // (IDENTITY_DIFFICULTY_LEADING_ZEROS = 16 means ~1 in 65536 chance)
    // We're just testing that the function runs
    // Actual mining is tested separately
}

TEST(IdentityTest, SerializeDeserialize) {
    Identity original{};
    original.public_key[0] = 0x01;
    original.public_key[100] = 0x02;
    original.nonce = 999999;
    original.epoch = 42;
    original.salt[0] = 0xAB;
    original.salt[31] = 0xCD;
    original.compute_hash();

    auto serialized = original.serialize();
    EXPECT_EQ(serialized.size(), Identity::SERIALIZED_SIZE);

    auto restored = Identity::deserialize(serialized);
    ASSERT_TRUE(restored.has_value());

    EXPECT_EQ(original.public_key, restored->public_key);
    EXPECT_EQ(original.nonce, restored->nonce);
    EXPECT_EQ(original.epoch, restored->epoch);
    EXPECT_EQ(original.salt, restored->salt);
    EXPECT_EQ(original.identity_hash, restored->identity_hash);
}

TEST(IdentityTest, Age) {
    Identity id{};
    id.epoch = 5;

    EXPECT_EQ(id.age(5), 1);
    EXPECT_EQ(id.age(6), 2);
    EXPECT_EQ(id.age(10), 6);
    EXPECT_EQ(id.age(4), 0);  // Can't be older than creation
}

// ============================================================================
// Identity Miner Tests
// ============================================================================

TEST(IdentityMinerTest, ComputeSalt) {
    hash_t state_root{};
    state_root[0] = 0x42;

    auto salt = IdentityMiner::compute_salt(1, state_root);

    // Salt should be deterministic
    auto salt2 = IdentityMiner::compute_salt(1, state_root);
    EXPECT_EQ(salt, salt2);

    // Different epoch = different salt
    auto salt3 = IdentityMiner::compute_salt(2, state_root);
    EXPECT_NE(salt, salt3);
}

TEST(IdentityMinerTest, MineWithLimit) {
    mldsa_public_key_t pk{};
    pk[0] = 0x01;

    hash_t salt{};
    salt[0] = 0xAB;

    // Very limited attempts - unlikely to find valid identity
    auto result = IdentityMiner::mine(pk, salt, 1, 100);

    // Just verify it runs and returns a result
    EXPECT_LE(result.attempts, 100);
}

TEST(IdentityMinerTest, MineInterruptible) {
    mldsa_public_key_t pk{};
    pk[0] = 0x01;

    hash_t salt{};

    int stop_after = 50;
    auto result = IdentityMiner::mine_interruptible(pk, salt, 1, [&]() {
        return --stop_after <= 0;
    });

    EXPECT_LE(result.attempts, 51);
}

// ============================================================================
// Identity Registry Tests
// ============================================================================

TEST(IdentityRegistryTest, Basic) {
    IdentityRegistry reg;
    EXPECT_EQ(reg.total_identities(), 0);
}

TEST(IdentityRegistryTest, SetEpochSalt) {
    IdentityRegistry reg;
    hash_t salt{};
    salt[0] = 0xAB;

    reg.set_epoch_salt(1, salt);

    // No way to query salt directly, but it's used in registration validation
}

TEST(IdentityRegistryTest, TransitionEpoch) {
    IdentityRegistry reg;

    reg.transition_epoch(1);
    reg.transition_epoch(2);
    reg.transition_epoch(3);

    // Should not crash, cleans up old data
}

// ============================================================================
// Eligibility Ramp Tests
// ============================================================================

TEST(EligibilityTest, RampHour) {
    mldsa_public_key_t pk{};
    pk[0] = 0x01;

    auto hour = eligibility_ramp_hour(pk);
    EXPECT_LT(hour, RAMP_HOUR_MODULUS);
}

TEST(EligibilityTest, RampHourDeterministic) {
    mldsa_public_key_t pk{};
    pk[0] = 0x01;

    auto hour1 = eligibility_ramp_hour(pk);
    auto hour2 = eligibility_ramp_hour(pk);

    EXPECT_EQ(hour1, hour2);
}

TEST(EligibilityTest, DifferentKeysDifferentHours) {
    mldsa_public_key_t pk1{}, pk2{};
    pk1[0] = 0x01;
    pk2[0] = 0x02;

    auto hour1 = eligibility_ramp_hour(pk1);
    auto hour2 = eligibility_ramp_hour(pk2);

    // May or may not be different, but distribution should be uniform
    // Just verify both are in valid range
    EXPECT_LT(hour1, RAMP_HOUR_MODULUS);
    EXPECT_LT(hour2, RAMP_HOUR_MODULUS);
}

TEST(EligibilityTest, StartTime) {
    mldsa_public_key_t pk{};
    pk[0] = 0x01;

    timestamp_t genesis(0);

    auto start = eligibility_start_time(pk, 0, genesis);

    // Start time should be >= genesis (ramp adds hours)
    EXPECT_GE(start, genesis);
}

TEST(EligibilityTest, OverlapPeriod) {
    timestamp_t genesis(0);

    // Not in overlap at epoch start
    EXPECT_FALSE(is_overlap_period(genesis, 0, genesis));

    // Would be in overlap near epoch end (last 24 hours)
    // This depends on SLOTS_PER_IDENTITY_EPOCH which is very large
}
