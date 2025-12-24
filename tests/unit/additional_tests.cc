#include <gtest/gtest.h>
#include "core/types.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "crypto/lmots.hh"
#include "consensus/ordering.hh"
#include "consensus/vdf.hh"
#include "consensus/identity.hh"
#include "consensus/batch_receipt.hh"
#include "consensus/finality.hh"
#include "consensus/commit_reveal.hh"
#include "execution/wasm/access.hh"
#include <set>
#include <random>

namespace pop {
namespace {

// ============================================================================
// Additional Types Tests
// ============================================================================

TEST(AdditionalTypesTest, NodeIdEquality) {
    NodeId id1, id2;
    id1.public_key.fill(0x01);
    id2.public_key.fill(0x01);
    EXPECT_EQ(id1.public_key, id2.public_key);
}

TEST(AdditionalTypesTest, NodeIdHash) {
    NodeId id;
    id.public_key.fill(0x42);
    auto h = id.hash();
    EXPECT_NE(h, hash_t{});
}

TEST(AdditionalTypesTest, AddressEquality) {
    Address a1, a2;
    a1.bytes.fill(0xAB);
    a2.bytes.fill(0xAB);
    EXPECT_EQ(a1, a2);
}

TEST(AdditionalTypesTest, AddressInequality) {
    Address a1, a2;
    a1.bytes.fill(0xAB);
    a2.bytes.fill(0xCD);
    EXPECT_NE(a1, a2);
}

TEST(AdditionalTypesTest, EncodeDecodeU16Boundary) {
    std::array<std::uint8_t, 2> buf;
    encode_u16(buf.data(), 0);
    EXPECT_EQ(decode_u16(buf.data()), 0);

    encode_u16(buf.data(), 0xFFFF);
    EXPECT_EQ(decode_u16(buf.data()), 0xFFFF);
}

TEST(AdditionalTypesTest, EncodeDecodeU32Boundary) {
    std::array<std::uint8_t, 4> buf;
    encode_u32(buf.data(), 0);
    EXPECT_EQ(decode_u32(buf.data()), 0);

    encode_u32(buf.data(), 0xFFFFFFFF);
    EXPECT_EQ(decode_u32(buf.data()), 0xFFFFFFFF);
}

TEST(AdditionalTypesTest, EncodeDecodeU64Boundary) {
    std::array<std::uint8_t, 8> buf;
    encode_u64(buf.data(), 0);
    EXPECT_EQ(decode_u64(buf.data()), 0);

    encode_u64(buf.data(), 0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(decode_u64(buf.data()), 0xFFFFFFFFFFFFFFFF);
}

TEST(AdditionalTypesTest, BytesToHexEmpty) {
    std::vector<std::uint8_t> empty;
    EXPECT_EQ(bytes_to_hex(empty), "");
}

TEST(AdditionalTypesTest, BytesToHexSingle) {
    std::vector<std::uint8_t> single = {0xAB};
    EXPECT_EQ(bytes_to_hex(single), "ab");
}

TEST(AdditionalTypesTest, HexToBytesEmpty) {
    auto result = hex_to_bytes("");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(AdditionalTypesTest, HexToBytesUpperCase) {
    auto result = hex_to_bytes("ABCD");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 2);
    EXPECT_EQ((*result)[0], 0xAB);
    EXPECT_EQ((*result)[1], 0xCD);
}

TEST(AdditionalTypesTest, SlotToEpochBoundary) {
    EXPECT_EQ(slot_to_epoch(0), 0);
    EXPECT_EQ(slot_to_epoch(SLOTS_PER_EPOCH - 1), 0);
    EXPECT_EQ(slot_to_epoch(SLOTS_PER_EPOCH), 1);
}

TEST(AdditionalTypesTest, EpochStartSlotLarge) {
    EXPECT_EQ(epoch_start_slot(1000), 1000 * SLOTS_PER_EPOCH);
}

// ============================================================================
// Additional Hash Tests
// ============================================================================

TEST(AdditionalHashTest, SHA3ZeroInput) {
    std::vector<std::uint8_t> zeros(100, 0);
    auto hash = sha3_256(zeros);
    EXPECT_NE(hash, hash_t{});
}

TEST(AdditionalHashTest, MerkleTreeOddLeaves) {
    std::vector<hash_t> leaves(5);
    for (int i = 0; i < 5; ++i) {
        leaves[i].fill(static_cast<std::uint8_t>(i));
    }
    MerkleTree tree(leaves);
    EXPECT_NE(tree.root(), hash_t{});
}

TEST(AdditionalHashTest, MerkleTreePowerOfTwo) {
    std::vector<hash_t> leaves(8);
    for (int i = 0; i < 8; ++i) {
        leaves[i].fill(static_cast<std::uint8_t>(i));
    }
    MerkleTree tree(leaves);
    EXPECT_NE(tree.root(), hash_t{});
}

TEST(AdditionalHashTest, MerkleProofMiddle) {
    std::vector<hash_t> leaves(8);
    for (int i = 0; i < 8; ++i) {
        leaves[i].fill(static_cast<std::uint8_t>(i));
    }
    MerkleTree tree(leaves);
    auto proof = tree.proof(4);
    EXPECT_FALSE(proof.empty());
    EXPECT_TRUE(MerkleTree::verify(leaves[4], proof, 4, tree.root()));
}

TEST(AdditionalHashTest, HashMeetsDifficultyVariousBits) {
    hash_t h{};
    h[0] = 0x00;
    h[1] = 0x00;
    h[2] = 0x80;  // 1000 0000 - first bit is 1, so 16 leading zeros total
    EXPECT_TRUE(hash_meets_difficulty(h, 16));
    EXPECT_FALSE(hash_meets_difficulty(h, 17));
}

TEST(AdditionalHashTest, DRBGSequence) {
    hash_t seed{};
    seed.fill(0x42);
    HashDRBG drbg(seed);

    std::set<hash_t> seen;
    for (int i = 0; i < 100; ++i) {
        auto h = drbg.next();
        EXPECT_EQ(seen.count(h), 0);  // Should not repeat
        seen.insert(h);
    }
}

TEST(AdditionalHashTest, HashToPositionDistribution) {
    // Use more samples and fewer buckets for statistical stability
    std::vector<int> buckets(5, 0);
    for (int i = 0; i < 10000; ++i) {
        hash_t h{};
        h[0] = static_cast<std::uint8_t>(i >> 16);
        h[1] = static_cast<std::uint8_t>((i >> 8) & 0xFF);
        h[2] = static_cast<std::uint8_t>(i & 0xFF);
        auto pos = hash_to_position(h);
        buckets[pos / (POSITION_MODULUS / 5)]++;
    }
    // Check that each bucket has at least some entries (rough distribution)
    int non_empty = 0;
    for (int bucket : buckets) {
        if (bucket > 0) non_empty++;
    }
    // At least 3 of 5 buckets should have entries
    EXPECT_GE(non_empty, 3);
}

// ============================================================================
// Additional Signature Tests
// ============================================================================

TEST(AdditionalSignatureTest, MLDSAMultipleMessages) {
    auto kp = MLDSAKeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    for (int i = 0; i < 10; ++i) {
        std::vector<std::uint8_t> msg(100, static_cast<std::uint8_t>(i));
        auto sig = kp->sign(msg);
        ASSERT_TRUE(sig.has_value());
        EXPECT_TRUE(kp->verify(msg, *sig));
    }
}

TEST(AdditionalSignatureTest, MLDSADifferentLengths) {
    auto kp = MLDSAKeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    for (int len = 1; len <= 1000; len *= 10) {
        std::vector<std::uint8_t> msg(len, 0x42);
        auto sig = kp->sign(msg);
        ASSERT_TRUE(sig.has_value());
        EXPECT_TRUE(kp->verify(msg, *sig));
    }
}

TEST(AdditionalSignatureTest, AESGCMMultipleEncryptions) {
    aes_key_t key{};
    key.fill(0x42);

    for (int i = 0; i < 10; ++i) {
        std::vector<std::uint8_t> pt(100, static_cast<std::uint8_t>(i));
        auto enc = aes_256_gcm_encrypt(key, pt);
        ASSERT_TRUE(enc.has_value());
        auto dec = aes_256_gcm_decrypt(key, enc->nonce, enc->tag, enc->ciphertext);
        ASSERT_TRUE(dec.has_value());
        EXPECT_EQ(pt, *dec);
    }
}

TEST(AdditionalSignatureTest, AESGCMEmptyPlaintext) {
    aes_key_t key{};
    key.fill(0x42);

    std::vector<std::uint8_t> empty;
    auto enc = aes_256_gcm_encrypt(key, empty);
    ASSERT_TRUE(enc.has_value());
    auto dec = aes_256_gcm_decrypt(key, enc->nonce, enc->tag, enc->ciphertext);
    ASSERT_TRUE(dec.has_value());
    EXPECT_TRUE(dec->empty());
}

// ============================================================================
// Additional LMOTS Tests
// ============================================================================

TEST(AdditionalLMOTSTest, SignatureViewComponents) {
    auto kp = LMOTSKeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    std::vector<std::uint8_t> msg = {1, 2, 3};
    auto sig = kp->sign(msg);
    ASSERT_TRUE(sig.has_value());

    auto view = LMOTSSignatureView::from_bytes(*sig);
    ASSERT_TRUE(view.has_value());

    // Check C randomizer is non-zero (highly probable)
    bool c_nonzero = false;
    for (auto b : view->C) {
        if (b != 0) c_nonzero = true;
    }
    EXPECT_TRUE(c_nonzero);
}

TEST(AdditionalLMOTSTest, KeyPoolMultipleAcquireRefill) {
    LMOTSKeyPool pool(5);

    for (int i = 0; i < 3; ++i) {
        // Acquire all
        for (int j = 0; j < 5; ++j) {
            auto kp = pool.acquire();
            ASSERT_TRUE(kp.has_value());
        }
        EXPECT_EQ(pool.available(), 0);

        // Refill
        pool.refill();
        EXPECT_EQ(pool.available(), 5);
    }
}

// ============================================================================
// Additional VDF Tests
// ============================================================================

TEST(AdditionalVDFTest, StepProgression) {
    VDFTime t1{0};
    VDFTime t2{1};
    VDFTime t3{100};

    EXPECT_EQ(t1.step, 0);
    EXPECT_EQ(t2.step, 1);
    EXPECT_EQ(t3.step, 100);
}

TEST(AdditionalVDFTest, TimeToSlotConversion) {
    VDFTime t{VDF_STEPS_PER_SLOT * 5};  // 5 slots worth
    EXPECT_EQ(t.to_slot(), 5);
}

TEST(AdditionalVDFTest, TimeToEpochConversion) {
    VDFTime t{VDF_STEPS_PER_TX_EPOCH * 3};  // 3 epochs worth
    EXPECT_EQ(t.to_tx_epoch(), 3);
}

TEST(AdditionalVDFTest, BucketProgression) {
    VDFBucket bucket;
    bucket.epoch = 0;
    bucket.bucket_id = 0;

    // Next bucket in same epoch
    VDFBucket next = bucket;
    next.bucket_id = 1;
    EXPECT_EQ(next.epoch, bucket.epoch);

    // Wrap to next epoch
    next.bucket_id = 0;
    next.epoch = 1;
    EXPECT_GT(next.epoch, bucket.epoch);
}

// ============================================================================
// Additional Ordering Tests
// ============================================================================

TEST(AdditionalOrderingTest, PositionMiningEmptyRange) {
    CommitHeader header{};
    PositionMiningConfig config;
    config.target_position_start = 50000;
    config.target_position_end = 50001;  // Very small range
    config.max_attempts = 1000;

    auto result = mine_position(header, config);
    // May or may not find, just verify no crash
}

TEST(AdditionalOrderingTest, CollisionResolutionAllCases) {
    Position2D a{}, b{};
    a.position = 100;
    b.position = 200;
    EXPECT_EQ(resolve_collision(a, b), CollisionResult::NO_COLLISION);

    a.position = b.position = 100;
    a.subposition.fill(0x00);
    b.subposition.fill(0x00);
    EXPECT_EQ(resolve_collision(a, b), CollisionResult::DUPLICATE);

    a.subposition.fill(0xFF);
    EXPECT_EQ(resolve_collision(a, b), CollisionResult::WINNER);
    EXPECT_EQ(resolve_collision(b, a), CollisionResult::LOSER);
}

// ============================================================================
// Additional Access Tracking Tests
// ============================================================================

TEST(AdditionalAccessTest, AccessKeyComparison) {
    AccessKey k1, k2;
    k1.address.bytes.fill(0x01);
    k1.key.fill(0x02);
    k2.address.bytes.fill(0x01);
    k2.key.fill(0x02);
    EXPECT_EQ(k1, k2);

    k2.key.fill(0x03);
    EXPECT_NE(k1, k2);
}

TEST(AdditionalAccessTest, DeclaredAccessSetOverlapBothEmpty) {
    DeclaredAccessSet set1, set2;
    EXPECT_FALSE(set1.overlaps(set2));
}

TEST(AdditionalAccessTest, DeclaredAccessSetOverlapNoCommon) {
    DeclaredAccessSet set1, set2;
    AccessKey k1, k2;
    k1.address.bytes.fill(0x01);
    k2.address.bytes.fill(0x02);
    set1.write_set.push_back(k1);
    set2.write_set.push_back(k2);
    EXPECT_FALSE(set1.overlaps(set2));
}

TEST(AdditionalAccessTest, MeteringConfigConstants) {
    EXPECT_LT(MeteringConfig::COST_BASIC, MeteringConfig::COST_MEMORY_OP);
    EXPECT_LT(MeteringConfig::COST_MEMORY_OP, MeteringConfig::COST_CONTROL_FLOW);
    EXPECT_LT(MeteringConfig::COST_CONTROL_FLOW, MeteringConfig::COST_CALL);
    EXPECT_LT(MeteringConfig::COST_CALL, MeteringConfig::COST_SLOAD);
    EXPECT_LT(MeteringConfig::COST_SLOAD, MeteringConfig::COST_SSTORE);
}

TEST(AdditionalAccessTest, InstructionMeterReset) {
    InstructionMeter meter(1000);
    meter.count_instructions(500);
    EXPECT_EQ(meter.instructions_used(), 500);

    meter.reset(2000);
    EXPECT_EQ(meter.instructions_used(), 0);
    EXPECT_EQ(meter.declared_limit(), 2000);
}

TEST(AdditionalAccessTest, MemoryLimiterGrowth) {
    MemoryLimiter limiter(256);
    EXPECT_EQ(limiter.current_pages(), MemoryLimiter::INITIAL_MEMORY_PAGES);

    EXPECT_TRUE(limiter.request_grow(10));
    EXPECT_EQ(limiter.current_pages(), MemoryLimiter::INITIAL_MEMORY_PAGES + 10);
}

TEST(AdditionalAccessTest, MemoryLimiterMaxExceeded) {
    MemoryLimiter limiter(20);  // Max 20 pages
    EXPECT_FALSE(limiter.request_grow(100));  // Should fail
    EXPECT_EQ(limiter.current_pages(), MemoryLimiter::INITIAL_MEMORY_PAGES);
}

// ============================================================================
// Additional Identity Tests
// ============================================================================

TEST(AdditionalIdentityTest, RegistryEmpty) {
    IdentityRegistry registry;
    mldsa_public_key_t pk{};
    pk.fill(0x42);
    EXPECT_FALSE(registry.is_valid(pk, 0));
}

TEST(AdditionalIdentityTest, IdentityStructure) {
    Identity id;
    id.public_key.fill(0x42);
    id.nonce = 12345;
    id.epoch = 5;
    id.salt.fill(0xAB);
    id.identity_hash.fill(0xCD);

    EXPECT_EQ(id.nonce, 12345);
    EXPECT_EQ(id.epoch, 5);
}

TEST(AdditionalIdentityTest, IdentityAge) {
    Identity id;
    id.epoch = 5;

    // Age is (current - identity_epoch + 1), so:
    // At identity epoch, age is 1
    EXPECT_EQ(id.age(5), 1);

    // Age increases with later epochs
    EXPECT_EQ(id.age(6), 2);
    EXPECT_EQ(id.age(10), 6);
}

// ============================================================================
// Additional Commit-Reveal Tests
// ============================================================================

TEST(AdditionalCommitRevealTest, ExpectationSetEmpty) {
    ExpectationSet set;
    EXPECT_TRUE(set.expectations.empty());
}

TEST(AdditionalCommitRevealTest, ExpectationAddBalance) {
    ExpectationSet set;
    Address addr{};
    addr.bytes.fill(0x01);

    set.add_balance_eq(addr, 1000);
    EXPECT_EQ(set.expectations.size(), 1);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::BALANCE_EQ);
}

TEST(AdditionalCommitRevealTest, ExpectationAddMultiple) {
    ExpectationSet set;
    Address addr{};

    set.add_balance_ge(addr, 100);
    set.add_balance_le(addr, 1000);
    set.add_nonce_eq(addr, 5);

    EXPECT_EQ(set.expectations.size(), 3);
}

TEST(AdditionalCommitRevealTest, AccessKeyHash) {
    AccessKey k1, k2;
    k1.address.bytes.fill(0x01);
    k1.key.fill(0x02);
    k2 = k1;

    AccessKey::Hash hasher;
    EXPECT_EQ(hasher(k1), hasher(k2));

    k2.key[0] = 0xFF;
    EXPECT_NE(hasher(k1), hasher(k2));
}

// ============================================================================
// Additional Finality Tests
// ============================================================================

TEST(AdditionalFinalityTest, AttestationMessageBytes) {
    Attestation att;
    att.state_root.fill(0x11);
    att.epoch = 100;
    att.peer_id.fill(0x22);
    att.identity_age = 5;

    auto msg1 = att.message_bytes();
    auto msg2 = att.message_bytes();
    EXPECT_EQ(msg1, msg2);  // Deterministic
}

TEST(AdditionalFinalityTest, FinalityTrackerMultipleEpochs) {
    FinalityTracker tracker;
    hash_t root{};
    hash_t reveal{};

    for (tx_epoch_t e = 0; e < 10; ++e) {
        root.fill(static_cast<std::uint8_t>(e));
        tracker.record_soft_finality(e, root, reveal, e * 1000);
    }

    for (tx_epoch_t e = 0; e < 10; ++e) {
        EXPECT_TRUE(tracker.has_soft_finality(e));
    }
}

TEST(AdditionalFinalityTest, IBLTCellXOR) {
    IBLTCell cell;
    hash_t k1, v1, k2, v2;
    k1.fill(0x11);
    v1.fill(0x22);
    k2.fill(0x33);
    v2.fill(0x44);

    cell.insert(k1, v1);
    cell.insert(k2, v2);
    EXPECT_EQ(cell.count, 2);

    cell.remove(k1, v1);
    cell.remove(k2, v2);
    EXPECT_TRUE(cell.is_empty());
}

}  // namespace
}  // namespace pop
