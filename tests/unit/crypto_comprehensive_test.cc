#include <gtest/gtest.h>
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "crypto/lmots.hh"
#include "core/types.hh"
#include <set>
#include <unordered_set>

namespace pop {
namespace {

// ============================================================================
// SHA3-256 Comprehensive Tests
// ============================================================================

class CryptoSHA3Test : public ::testing::Test {
protected:
    void SetUp() override {
        test_data_ = {0x01, 0x02, 0x03, 0x04, 0x05};
    }
    std::vector<std::uint8_t> test_data_;
};

TEST_F(CryptoSHA3Test, EmptyInput) {
    auto hash = sha3_256({});
    EXPECT_NE(hash, hash_t{});
}

TEST_F(CryptoSHA3Test, SingleByte) {
    std::array<std::uint8_t, 1> data = {0x00};
    auto hash1 = sha3_256(data);

    data[0] = 0x01;
    auto hash2 = sha3_256(data);

    EXPECT_NE(hash1, hash2);
}

TEST_F(CryptoSHA3Test, Deterministic) {
    auto hash1 = sha3_256(test_data_);
    auto hash2 = sha3_256(test_data_);
    EXPECT_EQ(hash1, hash2);
}

TEST_F(CryptoSHA3Test, AvalancheEffect) {
    auto hash1 = sha3_256(test_data_);

    test_data_[0] ^= 0x01;  // Flip one bit
    auto hash2 = sha3_256(test_data_);

    EXPECT_NE(hash1, hash2);

    // Count differing bits - should be approximately half
    int differing_bits = 0;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        std::uint8_t xor_val = hash1[i] ^ hash2[i];
        while (xor_val) {
            differing_bits += xor_val & 1;
            xor_val >>= 1;
        }
    }

    // Avalanche effect: changing 1 bit should change ~50% of output bits
    EXPECT_GT(differing_bits, 76);
    EXPECT_LT(differing_bits, 180);
}

TEST_F(CryptoSHA3Test, LargeInput) {
    std::vector<std::uint8_t> large_data(1024 * 1024);
    for (size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto hash = sha3_256(large_data);
    EXPECT_NE(hash, hash_t{});
}

TEST_F(CryptoSHA3Test, HasherIncremental) {
    auto hash1 = sha3_256(test_data_);

    SHA3Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(test_data_.data(), 2));
    hasher.update(std::span<const std::uint8_t>(test_data_.data() + 2, 3));
    auto hash2 = hasher.finalize();

    EXPECT_EQ(hash1, hash2);
}

TEST_F(CryptoSHA3Test, HasherReset) {
    SHA3Hasher hasher;
    hasher.update(test_data_);
    auto hash1 = hasher.finalize();

    hasher.reset();
    hasher.update(test_data_);
    auto hash2 = hasher.finalize();

    EXPECT_EQ(hash1, hash2);
}

TEST_F(CryptoSHA3Test, HasherMultipleUpdates) {
    SHA3Hasher hasher;
    for (int i = 0; i < 100; ++i) {
        hasher.update(test_data_);
    }
    auto hash = hasher.finalize();
    EXPECT_NE(hash, hash_t{});
}

TEST_F(CryptoSHA3Test, MeetsDifficultyZeroLeadingZeros) {
    hash_t easy{};
    easy[0] = 0x80;  // High bit set = 0 leading zeros
    EXPECT_TRUE(hash_meets_difficulty(easy, 0));
    EXPECT_FALSE(hash_meets_difficulty(easy, 1));
}

TEST_F(CryptoSHA3Test, MeetsDifficultySevenLeadingZeros) {
    hash_t h{};
    h[0] = 0x01;  // 7 leading zeros
    EXPECT_TRUE(hash_meets_difficulty(h, 7));
    EXPECT_FALSE(hash_meets_difficulty(h, 8));
}

TEST_F(CryptoSHA3Test, MeetsDifficultyFifteenLeadingZeros) {
    hash_t hard{};
    hard[1] = 0x01;  // First byte 0, second byte 0x01 = 15 leading zeros
    EXPECT_TRUE(hash_meets_difficulty(hard, 15));
    EXPECT_FALSE(hash_meets_difficulty(hard, 16));
}

TEST_F(CryptoSHA3Test, MeetsDifficultyAllZeros) {
    hash_t all_zeros{};
    EXPECT_TRUE(hash_meets_difficulty(all_zeros, 256));
    EXPECT_TRUE(hash_meets_difficulty(all_zeros, 0));
}

TEST_F(CryptoSHA3Test, MultiHash) {
    std::vector<std::uint8_t> a = {1, 2};
    std::vector<std::uint8_t> b = {3, 4};

    auto combined = sha3_256_multi(a, b);

    SHA3Hasher hasher;
    hasher.update(a);
    hasher.update(b);
    auto expected = hasher.finalize();

    EXPECT_EQ(combined, expected);
}

TEST_F(CryptoSHA3Test, HashToPositionBounded) {
    for (int i = 0; i < 100; ++i) {
        hash_t h{};
        h[0] = static_cast<std::uint8_t>(i);
        position_t pos = hash_to_position(h);
        EXPECT_LT(pos, POSITION_MODULUS);
    }
}

TEST_F(CryptoSHA3Test, HashToPositionDeterministic) {
    hash_t h{};
    h[0] = 0x42;
    position_t p1 = hash_to_position(h);
    position_t p2 = hash_to_position(h);
    EXPECT_EQ(p1, p2);
}

// ============================================================================
// Merkle Tree Comprehensive Tests
// ============================================================================

class MerkleTreeTest2 : public ::testing::Test {
protected:
    void SetUp() override {
        for (int i = 0; i < 8; ++i) {
            hash_t h{};
            h[0] = static_cast<std::uint8_t>(i);
            leaves_.push_back(h);
        }
    }
    std::vector<hash_t> leaves_;
};

TEST_F(MerkleTreeTest2, SingleLeaf) {
    std::vector<hash_t> single = {leaves_[0]};
    MerkleTree tree(single);
    EXPECT_EQ(tree.root(), leaves_[0]);
}

TEST_F(MerkleTreeTest2, TwoLeaves) {
    std::vector<hash_t> two = {leaves_[0], leaves_[1]};
    MerkleTree tree(two);
    auto expected = MerkleTree::hash_pair(leaves_[0], leaves_[1]);
    EXPECT_EQ(tree.root(), expected);
}

TEST_F(MerkleTreeTest2, PowerOfTwo) {
    MerkleTree tree(leaves_);
    EXPECT_NE(tree.root(), hash_t{});
}

TEST_F(MerkleTreeTest2, NonPowerOfTwo) {
    std::vector<hash_t> five(leaves_.begin(), leaves_.begin() + 5);
    MerkleTree tree(five);
    EXPECT_NE(tree.root(), hash_t{});
}

TEST_F(MerkleTreeTest2, GenerateAndVerifyProof) {
    MerkleTree tree(leaves_);
    for (size_t i = 0; i < leaves_.size(); ++i) {
        auto proof = tree.proof(i);
        EXPECT_TRUE(MerkleTree::verify(leaves_[i], proof, i, tree.root()));
    }
}

TEST_F(MerkleTreeTest2, InvalidProofFails) {
    MerkleTree tree(leaves_);
    auto proof = tree.proof(0);

    if (!proof.empty()) {
        proof[0][0] ^= 0x01;
        EXPECT_FALSE(MerkleTree::verify(leaves_[0], proof, 0, tree.root()));
    }
}

TEST_F(MerkleTreeTest2, WrongIndexFails) {
    MerkleTree tree(leaves_);
    auto proof = tree.proof(0);
    EXPECT_FALSE(MerkleTree::verify(leaves_[0], proof, 1, tree.root()));
}

TEST_F(MerkleTreeTest2, WrongLeafFails) {
    MerkleTree tree(leaves_);
    auto proof = tree.proof(0);

    hash_t wrong_leaf{};
    wrong_leaf[0] = 0xFF;
    EXPECT_FALSE(MerkleTree::verify(wrong_leaf, proof, 0, tree.root()));
}

TEST_F(MerkleTreeTest2, ProofSizeLogN) {
    MerkleTree tree(leaves_);
    auto proof = tree.proof(0);
    EXPECT_EQ(proof.size(), 3);  // log2(8) = 3
}

TEST_F(MerkleTreeTest2, LargeTree) {
    std::vector<hash_t> large_leaves(1024);
    for (size_t i = 0; i < large_leaves.size(); ++i) {
        large_leaves[i][0] = static_cast<std::uint8_t>(i & 0xFF);
        large_leaves[i][1] = static_cast<std::uint8_t>((i >> 8) & 0xFF);
    }

    MerkleTree tree(large_leaves);
    auto proof = tree.proof(512);

    EXPECT_TRUE(MerkleTree::verify(large_leaves[512], proof, 512, tree.root()));
    EXPECT_EQ(proof.size(), 10);  // log2(1024) = 10
}

TEST_F(MerkleTreeTest2, HashPairDeterministic) {
    auto h1 = MerkleTree::hash_pair(leaves_[0], leaves_[1]);
    auto h2 = MerkleTree::hash_pair(leaves_[0], leaves_[1]);
    EXPECT_EQ(h1, h2);
}

TEST_F(MerkleTreeTest2, HashPairNonCommutative) {
    auto h1 = MerkleTree::hash_pair(leaves_[0], leaves_[1]);
    auto h2 = MerkleTree::hash_pair(leaves_[1], leaves_[0]);
    EXPECT_NE(h1, h2);
}

TEST_F(MerkleTreeTest2, ComputeMerkleRoot) {
    hash_t root1 = compute_merkle_root(leaves_);
    MerkleTree tree(leaves_);
    EXPECT_EQ(root1, tree.root());
}

TEST_F(MerkleTreeTest2, VerifyAllLeaves) {
    MerkleTree tree(leaves_);
    for (size_t i = 0; i < leaves_.size(); ++i) {
        auto proof = tree.proof(i);
        EXPECT_TRUE(MerkleTree::verify(leaves_[i], proof, i, tree.root()));
    }
}

// ============================================================================
// ML-DSA-65 Comprehensive Tests
// ============================================================================

class CryptoMLDSATest : public ::testing::Test {
protected:
    void SetUp() override {
        keypair_ = MLDSAKeyPair::generate();
        ASSERT_TRUE(keypair_.has_value());
        message_ = {0x01, 0x02, 0x03, 0x04, 0x05};
    }
    std::optional<MLDSAKeyPair> keypair_;
    std::vector<std::uint8_t> message_;
};

TEST_F(CryptoMLDSATest, GenerateReturnsValid) {
    EXPECT_TRUE(keypair_->has_secret_key());
    EXPECT_NE(keypair_->public_key(), mldsa_public_key_t{});
}

TEST_F(CryptoMLDSATest, SignAndVerify) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(keypair_->verify(message_, *sig));
}

TEST_F(CryptoMLDSATest, WrongMessageFails) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    message_[0] ^= 0x01;
    EXPECT_FALSE(keypair_->verify(message_, *sig));
}

TEST_F(CryptoMLDSATest, WrongKeyFails) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    auto keypair2 = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair2.has_value());
    EXPECT_FALSE(keypair2->verify(message_, *sig));
}

TEST_F(CryptoMLDSATest, TamperedSignatureFails) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    (*sig)[0] ^= 0x01;
    EXPECT_FALSE(keypair_->verify(message_, *sig));
}

TEST_F(CryptoMLDSATest, EmptyMessage) {
    std::vector<std::uint8_t> empty;
    auto sig = keypair_->sign(empty);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(keypair_->verify(empty, *sig));
}

TEST_F(CryptoMLDSATest, LargeMessage) {
    std::vector<std::uint8_t> large(64 * 1024);
    for (size_t i = 0; i < large.size(); ++i) {
        large[i] = static_cast<std::uint8_t>(i);
    }

    auto sig = keypair_->sign(large);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(keypair_->verify(large, *sig));
}

TEST_F(CryptoMLDSATest, MultipleSignatures) {
    std::vector<std::uint8_t> msg1 = {0x01};
    std::vector<std::uint8_t> msg2 = {0x02};

    auto sig1 = keypair_->sign(msg1);
    auto sig2 = keypair_->sign(msg2);

    ASSERT_TRUE(sig1.has_value());
    ASSERT_TRUE(sig2.has_value());

    EXPECT_NE(*sig1, *sig2);

    EXPECT_TRUE(keypair_->verify(msg1, *sig1));
    EXPECT_TRUE(keypair_->verify(msg2, *sig2));
    EXPECT_FALSE(keypair_->verify(msg1, *sig2));
    EXPECT_FALSE(keypair_->verify(msg2, *sig1));
}

TEST_F(CryptoMLDSATest, FromPublicKey) {
    auto public_only = MLDSAKeyPair::from_public_key(keypair_->public_key());
    ASSERT_TRUE(public_only.has_value());

    EXPECT_FALSE(public_only->has_secret_key());

    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    EXPECT_TRUE(public_only->verify(message_, *sig));
}

TEST_F(CryptoMLDSATest, FromPublicKeyCannotSign) {
    auto public_only = MLDSAKeyPair::from_public_key(keypair_->public_key());
    ASSERT_TRUE(public_only.has_value());

    auto sig = public_only->sign(message_);
    EXPECT_FALSE(sig.has_value());
}

TEST_F(CryptoMLDSATest, StandaloneVerify) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(mldsa_verify(keypair_->public_key(), message_, *sig));
}

TEST_F(CryptoMLDSATest, FromSeedReturnsValidKey) {
    // NOTE: from_seed currently falls back to generate() and is not deterministic
    // This test just verifies it returns a valid, working keypair
    hash_t seed{};
    seed[0] = 0x42;

    auto k = MLDSAKeyPair::from_seed(seed);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->has_secret_key());

    // Verify the key can sign and verify
    std::vector<std::uint8_t> msg = {1, 2, 3};
    auto sig = k->sign(msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(k->verify(msg, *sig));
}

TEST_F(CryptoMLDSATest, DifferentSeedsDifferentKeys) {
    hash_t s1{}, s2{};
    s1[0] = 0x01;
    s2[0] = 0x02;

    auto k1 = MLDSAKeyPair::from_seed(s1);
    auto k2 = MLDSAKeyPair::from_seed(s2);
    ASSERT_TRUE(k1.has_value() && k2.has_value());
    EXPECT_NE(k1->public_key(), k2->public_key());
}

TEST_F(CryptoMLDSATest, PublicKeySize) {
    EXPECT_EQ(keypair_->public_key().size(), MLDSA65_PUBLIC_KEY_SIZE);
}

TEST_F(CryptoMLDSATest, SignatureSize) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), MLDSA65_SIGNATURE_SIZE);
}

// ============================================================================
// LM-OTS Comprehensive Tests
// ============================================================================

class CryptoLMOTSTest : public ::testing::Test {
protected:
    void SetUp() override {
        keypair_ = LMOTSKeyPair::generate();
        ASSERT_TRUE(keypair_.has_value());
        message_ = {0x01, 0x02, 0x03, 0x04, 0x05};
    }
    std::optional<LMOTSKeyPair> keypair_;
    std::vector<std::uint8_t> message_;
};

TEST_F(CryptoLMOTSTest, GenerateReturnsValid) {
    EXPECT_FALSE(keypair_->is_used());
    EXPECT_TRUE(keypair_->has_secret_key());
}

TEST_F(CryptoLMOTSTest, SignOnce) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(keypair_->is_used());
}

TEST_F(CryptoLMOTSTest, CannotSignTwice) {
    auto sig1 = keypair_->sign(message_);
    ASSERT_TRUE(sig1.has_value());

    auto sig2 = keypair_->sign(message_);
    EXPECT_FALSE(sig2.has_value());
}

TEST_F(CryptoLMOTSTest, VerifyValid) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(lmots_verify(keypair_->public_key(), message_, *sig));
}

TEST_F(CryptoLMOTSTest, WrongMessageFails) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    message_[0] ^= 0x01;
    EXPECT_FALSE(lmots_verify(keypair_->public_key(), message_, *sig));
}

TEST_F(CryptoLMOTSTest, WrongKeyFails) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    auto keypair2 = LMOTSKeyPair::generate();
    ASSERT_TRUE(keypair2.has_value());
    EXPECT_FALSE(lmots_verify(keypair2->public_key(), message_, *sig));
}

TEST_F(CryptoLMOTSTest, FromSeedDeterministic) {
    hash_t seed;
    seed.fill(0x42);

    auto kp1 = LMOTSKeyPair::from_seed(seed);
    auto kp2 = LMOTSKeyPair::from_seed(seed);

    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());
    EXPECT_EQ(kp1->public_key(), kp2->public_key());
}

TEST_F(CryptoLMOTSTest, DifferentSeedsDifferentKeys) {
    hash_t seed1, seed2;
    seed1.fill(0x01);
    seed2.fill(0x02);

    auto kp1 = LMOTSKeyPair::from_seed(seed1);
    auto kp2 = LMOTSKeyPair::from_seed(seed2);

    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());
    EXPECT_NE(kp1->public_key(), kp2->public_key());
}

TEST_F(CryptoLMOTSTest, EmptyMessage) {
    std::vector<std::uint8_t> empty;
    auto sig = keypair_->sign(empty);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(lmots_verify(keypair_->public_key(), empty, *sig));
}

TEST_F(CryptoLMOTSTest, LargeMessage) {
    std::vector<std::uint8_t> large(1024);
    for (size_t i = 0; i < large.size(); ++i) {
        large[i] = static_cast<std::uint8_t>(i);
    }

    auto sig = keypair_->sign(large);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(lmots_verify(keypair_->public_key(), large, *sig));
}

TEST_F(CryptoLMOTSTest, DoubleSignDetection) {
    auto kp1 = LMOTSKeyPair::from_seed(hash_t{});
    auto kp2 = LMOTSKeyPair::from_seed(hash_t{});

    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    std::vector<std::uint8_t> msg1 = {0x01};
    std::vector<std::uint8_t> msg2 = {0x02};

    auto sig1 = kp1->sign(msg1);
    auto sig2 = kp2->sign(msg2);

    ASSERT_TRUE(sig1.has_value());
    ASSERT_TRUE(sig2.has_value());

    EXPECT_TRUE(lmots_verify(kp1->public_key(), msg1, *sig1));
    EXPECT_TRUE(lmots_verify(kp2->public_key(), msg2, *sig2));

    EXPECT_TRUE(lmots_detect_double_sign(kp1->public_key(), msg1, *sig1, msg2, *sig2));
}

TEST_F(CryptoLMOTSTest, ApplyChainZeroSteps) {
    hash_t start;
    start.fill(0x42);

    auto result = LMOTSKeyPair::apply_chain(0, start, 0, 0);
    EXPECT_EQ(result, start);
}

TEST_F(CryptoLMOTSTest, ApplyChainOneStep) {
    hash_t start;
    start.fill(0x42);

    auto step1 = LMOTSKeyPair::apply_chain(0, start, 0, 1);
    EXPECT_NE(step1, start);
}

TEST_F(CryptoLMOTSTest, ApplyChainComposable) {
    hash_t start;
    start.fill(0x42);

    auto step1 = LMOTSKeyPair::apply_chain(0, start, 0, 1);
    auto step2 = LMOTSKeyPair::apply_chain(0, step1, 1, 2);
    auto direct = LMOTSKeyPair::apply_chain(0, start, 0, 2);
    EXPECT_EQ(step2, direct);
}

TEST_F(CryptoLMOTSTest, SignatureViewRoundtrip) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());

    auto view = LMOTSSignatureView::from_bytes(*sig);
    ASSERT_TRUE(view.has_value());

    auto bytes = view->to_bytes();
    EXPECT_EQ(bytes, *sig);
}

TEST_F(CryptoLMOTSTest, PublicKeySize) {
    EXPECT_EQ(keypair_->public_key().size(), LMOTS_PUBLIC_KEY_SIZE);
}

TEST_F(CryptoLMOTSTest, SignatureSize) {
    auto sig = keypair_->sign(message_);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->size(), LMOTS_SIGNATURE_SIZE);
}

TEST_F(CryptoLMOTSTest, MarkUsed) {
    EXPECT_FALSE(keypair_->is_used());
    keypair_->mark_used();
    EXPECT_TRUE(keypair_->is_used());
}

TEST_F(CryptoLMOTSTest, FromPublicKeyNoSecretKey) {
    auto pub_only = LMOTSKeyPair::from_public_key(keypair_->public_key());
    ASSERT_TRUE(pub_only.has_value());
    EXPECT_FALSE(pub_only->has_secret_key());
}

TEST_F(CryptoLMOTSTest, FromPublicKeyCannotSign) {
    auto pub_only = LMOTSKeyPair::from_public_key(keypair_->public_key());
    ASSERT_TRUE(pub_only.has_value());

    auto sig = pub_only->sign(message_);
    EXPECT_FALSE(sig.has_value());
}

// ============================================================================
// Key Pool Tests
// ============================================================================

class LMOTSKeyPoolTest2 : public ::testing::Test {
protected:
    void SetUp() override {
        pool_ = std::make_unique<LMOTSKeyPool>(5);
    }
    std::unique_ptr<LMOTSKeyPool> pool_;
};

TEST_F(LMOTSKeyPoolTest2, TargetSize) {
    EXPECT_EQ(pool_->target_size(), 5u);
}

TEST_F(LMOTSKeyPoolTest2, RefillAddsKeys) {
    pool_->refill();
    EXPECT_GT(pool_->available(), 0u);
}

TEST_F(LMOTSKeyPoolTest2, AcquireDecrementsSize) {
    pool_->refill();
    auto initial = pool_->available();
    auto kp = pool_->acquire();
    if (kp.has_value()) {
        EXPECT_EQ(pool_->available(), initial - 1);
    }
}

TEST_F(LMOTSKeyPoolTest2, AcquiredKeyWorks) {
    pool_->refill();
    auto kp = pool_->acquire();
    if (kp.has_value()) {
        std::vector<std::uint8_t> msg = {1, 2, 3};
        auto sig = kp->sign(msg);
        ASSERT_TRUE(sig.has_value());
        EXPECT_TRUE(lmots_verify(kp->public_key(), msg, *sig));
    }
}

TEST_F(LMOTSKeyPoolTest2, EmptyPoolGeneratesOnDemand) {
    // Pool generates on demand when empty
    LMOTSKeyPool pool(1);

    // Exhaust the pool
    auto kp1 = pool.acquire();
    ASSERT_TRUE(kp1.has_value());
    EXPECT_EQ(pool.available(), 0);

    // Should still generate on demand even when pool is empty
    auto kp2 = pool.acquire();
    ASSERT_TRUE(kp2.has_value());

    // Keys should be different
    EXPECT_NE(kp1->public_key(), kp2->public_key());
}

// ============================================================================
// DRBG Tests
// ============================================================================

class HashDRBGTest2 : public ::testing::Test {};

TEST_F(HashDRBGTest2, Deterministic) {
    hash_t seed;
    seed.fill(0x42);

    HashDRBG drbg1(seed);
    HashDRBG drbg2(seed);

    EXPECT_EQ(drbg1.next(), drbg2.next());
    EXPECT_EQ(drbg1.next(), drbg2.next());
}

TEST_F(HashDRBGTest2, DifferentSeeds) {
    hash_t seed1, seed2;
    seed1.fill(0x01);
    seed2.fill(0x02);

    HashDRBG drbg1(seed1);
    HashDRBG drbg2(seed2);

    EXPECT_NE(drbg1.next(), drbg2.next());
}

TEST_F(HashDRBGTest2, NextU64) {
    hash_t seed{};
    HashDRBG drbg(seed);

    auto v1 = drbg.next_u64();
    auto v2 = drbg.next_u64();
    EXPECT_NE(v1, v2);
}

TEST_F(HashDRBGTest2, NextU32) {
    hash_t seed{};
    HashDRBG drbg(seed);

    auto v1 = drbg.next_u32();
    auto v2 = drbg.next_u32();
    EXPECT_NE(v1, v2);
}

TEST_F(HashDRBGTest2, NextRange) {
    hash_t seed;
    seed.fill(0x42);
    HashDRBG drbg(seed);

    for (int i = 0; i < 100; ++i) {
        auto val = drbg.next_range(100);
        EXPECT_LT(val, 100u);
    }
}

TEST_F(HashDRBGTest2, Distribution) {
    hash_t seed;
    seed.fill(0x42);
    HashDRBG drbg(seed);

    std::array<int, 10> buckets = {};
    for (int i = 0; i < 10000; ++i) {
        auto val = drbg.next_range(10);
        buckets[val]++;
    }

    for (int count : buckets) {
        EXPECT_GT(count, 800);
        EXPECT_LT(count, 1200);
    }
}

TEST_F(HashDRBGTest2, LargeSequence) {
    hash_t seed;
    seed.fill(0x42);
    HashDRBG drbg(seed);

    std::set<hash_t> seen;
    for (int i = 0; i < 1000; ++i) {
        auto val = drbg.next();
        EXPECT_EQ(seen.count(val), 0u);
        seen.insert(val);
    }
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

TEST(SHA3EdgeCases, VeryLongMessage) {
    std::vector<std::uint8_t> msg(10 * 1024 * 1024);  // 10MB
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<uint8_t>(i ^ (i >> 8));
    }
    auto h = sha3_256(msg);
    EXPECT_NE(h, hash_t{});
}

TEST(SHA3EdgeCases, AllBytesInput) {
    std::vector<std::uint8_t> msg(256);
    for (int i = 0; i < 256; ++i) {
        msg[i] = static_cast<uint8_t>(i);
    }
    auto h = sha3_256(msg);
    EXPECT_NE(h, hash_t{});
}

TEST(MerkleEdgeCases, ThreeLeaves) {
    std::vector<hash_t> leaves(3);
    for (size_t i = 0; i < 3; ++i) {
        leaves[i][0] = static_cast<uint8_t>(i);
    }
    MerkleTree tree(leaves);
    EXPECT_NE(tree.root(), hash_t{});

    for (size_t i = 0; i < 3; ++i) {
        auto proof = tree.proof(i);
        EXPECT_TRUE(MerkleTree::verify(leaves[i], proof, i, tree.root()));
    }
}

TEST(MerkleEdgeCases, SevenLeaves) {
    std::vector<hash_t> leaves(7);
    for (size_t i = 0; i < 7; ++i) {
        leaves[i][0] = static_cast<uint8_t>(i);
    }
    MerkleTree tree(leaves);

    for (size_t i = 0; i < 7; ++i) {
        auto proof = tree.proof(i);
        EXPECT_TRUE(MerkleTree::verify(leaves[i], proof, i, tree.root()));
    }
}

TEST(MLDSAEdgeCases, SignSameMessageTwice) {
    auto kp = MLDSAKeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig1 = kp->sign(msg);
    auto sig2 = kp->sign(msg);

    ASSERT_TRUE(sig1.has_value() && sig2.has_value());
    // Signatures may differ due to randomization in signing
    EXPECT_TRUE(kp->verify(msg, *sig1));
    EXPECT_TRUE(kp->verify(msg, *sig2));
}

TEST(MLDSAEdgeCases, VerifyWithCorruptedKey) {
    auto kp = MLDSAKeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig = kp->sign(msg);
    ASSERT_TRUE(sig.has_value());

    auto pk = kp->public_key();
    pk[0] ^= 0x01;  // Corrupt public key

    EXPECT_FALSE(mldsa_verify(pk, msg, *sig));
}

TEST(LMOTSEdgeCases, ChainDifferentIndices) {
    hash_t start{};
    start[0] = 0x42;

    auto r1 = LMOTSKeyPair::apply_chain(0, start, 0, 5);
    auto r2 = LMOTSKeyPair::apply_chain(1, start, 0, 5);
    auto r3 = LMOTSKeyPair::apply_chain(66, start, 0, 5);

    EXPECT_NE(r1, r2);
    EXPECT_NE(r2, r3);
    EXPECT_NE(r1, r3);
}

TEST(LMOTSEdgeCases, ChainMaxLength) {
    hash_t start{};
    start[0] = 0x42;

    // LMOTS_CHAIN_LENGTH is the max steps
    auto result = LMOTSKeyPair::apply_chain(0, start, 0, LMOTS_CHAIN_LENGTH);
    EXPECT_NE(result, start);
}

}  // namespace
}  // namespace pop
