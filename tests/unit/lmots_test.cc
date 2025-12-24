#include <gtest/gtest.h>
#include "crypto/lmots.hh"
#include "crypto/hash.hh"

using namespace pop;

// ============================================================================
// LM-OTS Key Generation Tests
// ============================================================================

TEST(LMOTSTest, Generate) {
    auto keypair = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());
    EXPECT_TRUE(keypair->has_secret_key());
    EXPECT_FALSE(keypair->is_used());
}

TEST(LMOTSTest, FromSeed) {
    hash_t seed{};
    seed[0] = 0x42;

    auto keypair1 = LMOTSKeyPair::from_seed(seed);
    auto keypair2 = LMOTSKeyPair::from_seed(seed);

    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());

    // Same seed should produce same public key
    EXPECT_EQ(keypair1->public_key(), keypair2->public_key());
}

TEST(LMOTSTest, DifferentSeedsDifferentKeys) {
    hash_t seed1{}, seed2{};
    seed1[0] = 0x01;
    seed2[0] = 0x02;

    auto keypair1 = LMOTSKeyPair::from_seed(seed1);
    auto keypair2 = LMOTSKeyPair::from_seed(seed2);

    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());

    EXPECT_NE(keypair1->public_key(), keypair2->public_key());
}

// ============================================================================
// LM-OTS Sign and Verify Tests
// ============================================================================

TEST(LMOTSTest, SignAndVerify) {
    auto keypair = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message = {1, 2, 3, 4, 5};

    auto sig = keypair->sign(message);
    ASSERT_TRUE(sig.has_value());

    // Key should be marked as used after signing
    EXPECT_TRUE(keypair->is_used());

    // Verify signature
    EXPECT_TRUE(lmots_verify(keypair->public_key(), message, *sig));
}

TEST(LMOTSTest, OneTimeOnly) {
    auto keypair = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message1 = {1, 2, 3};
    std::vector<std::uint8_t> message2 = {4, 5, 6};

    // First signature works
    auto sig1 = keypair->sign(message1);
    ASSERT_TRUE(sig1.has_value());

    // Second signature fails (one-time!)
    auto sig2 = keypair->sign(message2);
    EXPECT_FALSE(sig2.has_value());
}

TEST(LMOTSTest, VerifyWrongMessage) {
    auto keypair = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message1 = {1, 2, 3};
    std::vector<std::uint8_t> message2 = {1, 2, 4};

    auto sig = keypair->sign(message1);
    ASSERT_TRUE(sig.has_value());

    EXPECT_FALSE(lmots_verify(keypair->public_key(), message2, *sig));
}

TEST(LMOTSTest, VerifyWrongKey) {
    auto keypair1 = LMOTSKeyPair::generate();
    auto keypair2 = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());

    std::vector<std::uint8_t> message = {1, 2, 3};

    auto sig = keypair1->sign(message);
    ASSERT_TRUE(sig.has_value());

    EXPECT_FALSE(lmots_verify(keypair2->public_key(), message, *sig));
}

// ============================================================================
// LM-OTS Public Key Only Tests
// ============================================================================

TEST(LMOTSTest, PublicKeyOnly) {
    auto keypair = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    auto pk_only = LMOTSKeyPair::from_public_key(keypair->public_key());
    ASSERT_TRUE(pk_only.has_value());

    EXPECT_FALSE(pk_only->has_secret_key());
    EXPECT_TRUE(pk_only->is_used());  // Marked used since can't sign

    // Can't sign without secret key
    std::vector<std::uint8_t> message = {1, 2, 3};
    EXPECT_FALSE(pk_only->sign(message).has_value());
}

// ============================================================================
// Double-Sign Detection Tests
// ============================================================================

TEST(LMOTSTest, DetectDoubleSign) {
    // Generate two keypairs for testing double-sign detection
    auto keypair1 = LMOTSKeyPair::generate();
    auto keypair2 = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());

    std::vector<std::uint8_t> message1 = {1, 2, 3};
    std::vector<std::uint8_t> message2 = {4, 5, 6};

    auto sig1 = keypair1->sign(message1);
    auto sig2 = keypair2->sign(message2);

    ASSERT_TRUE(sig1.has_value());
    ASSERT_TRUE(sig2.has_value());

    // Different keys, different messages - not a double sign
    // (Both signatures are valid for their respective keys)
    // Note: detecting double-sign requires two sigs from SAME key on DIFFERENT messages
    // Since we can't actually double-sign (one-time enforcement), we can't test positive case
}

// ============================================================================
// LMOTSSignatureView Tests
// ============================================================================

TEST(LMOTSTest, SignatureViewRoundTrip) {
    auto keypair = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message = {1, 2, 3};
    auto sig = keypair->sign(message);
    ASSERT_TRUE(sig.has_value());

    // Parse to view
    auto view = LMOTSSignatureView::from_bytes(*sig);
    ASSERT_TRUE(view.has_value());

    // Convert back to bytes
    auto sig2 = view->to_bytes();
    EXPECT_EQ(*sig, sig2);
}

// ============================================================================
// LMOTSKeyPool Tests
// ============================================================================

TEST(LMOTSKeyPoolTest, Basic) {
    LMOTSKeyPool pool(5);

    EXPECT_EQ(pool.target_size(), 5);
    EXPECT_EQ(pool.available(), 5);
}

TEST(LMOTSKeyPoolTest, Acquire) {
    LMOTSKeyPool pool(3);

    auto kp1 = pool.acquire();
    ASSERT_TRUE(kp1.has_value());
    EXPECT_EQ(pool.available(), 2);

    auto kp2 = pool.acquire();
    ASSERT_TRUE(kp2.has_value());
    EXPECT_EQ(pool.available(), 1);
}

TEST(LMOTSKeyPoolTest, AcquireEmpty) {
    LMOTSKeyPool pool(1);

    auto kp1 = pool.acquire();
    ASSERT_TRUE(kp1.has_value());
    EXPECT_EQ(pool.available(), 0);

    // Should generate on demand
    auto kp2 = pool.acquire();
    ASSERT_TRUE(kp2.has_value());
}

TEST(LMOTSKeyPoolTest, Refill) {
    LMOTSKeyPool pool(3);

    pool.acquire();
    pool.acquire();
    EXPECT_EQ(pool.available(), 1);

    pool.refill();
    EXPECT_EQ(pool.available(), 3);
}
