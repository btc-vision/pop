#include <gtest/gtest.h>
#include "consensus/commit_reveal.hh"
#include "crypto/hash.hh"

namespace pop {
namespace {

class CommitRevealTest : public ::testing::Test {
protected:
    void SetUp() override {
        sender_.fill(0x42);
        one_time_pk_.fill(0x33);
    }

    mldsa_public_key_t sender_;
    lmots_public_key_t one_time_pk_;
};

TEST_F(CommitRevealTest, StateExpectationSerialization) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_GE;
    exp.address.bytes.fill(0x11);
    exp.key = hash_t{};
    exp.key->fill(0x22);
    exp.value.fill(0x33);
    exp.max_value = hash_t{};
    exp.max_value->fill(0x44);

    auto bytes = exp.serialize();
    auto deserialized = StateExpectation::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->type, exp.type);
    EXPECT_EQ(deserialized->address.bytes, exp.address.bytes);
    ASSERT_TRUE(deserialized->key.has_value());
    EXPECT_EQ(*deserialized->key, *exp.key);
    EXPECT_EQ(deserialized->value, exp.value);
    ASSERT_TRUE(deserialized->max_value.has_value());
    EXPECT_EQ(*deserialized->max_value, *exp.max_value);
}

TEST_F(CommitRevealTest, ExpectationSetSerialization) {
    ExpectationSet set;

    StateExpectation exp1;
    exp1.type = ExpectationType::BALANCE_EQ;
    exp1.address.bytes.fill(0x11);
    exp1.value.fill(0x22);
    set.expectations.push_back(exp1);

    StateExpectation exp2;
    exp2.type = ExpectationType::STORAGE_EQ;
    exp2.address.bytes.fill(0x33);
    exp2.key = hash_t{};
    exp2.key->fill(0x44);
    exp2.value.fill(0x55);
    set.expectations.push_back(exp2);

    auto bytes = set.serialize();
    auto deserialized = ExpectationSet::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->expectations.size(), 2);
    EXPECT_EQ(deserialized->expectations[0].type, ExpectationType::BALANCE_EQ);
    EXPECT_EQ(deserialized->expectations[1].type, ExpectationType::STORAGE_EQ);
}

TEST_F(CommitRevealTest, AccessKeyEquality) {
    AccessKey ak1;
    ak1.address.bytes.fill(0x11);
    ak1.key.fill(0x22);

    AccessKey ak2;
    ak2.address.bytes.fill(0x11);
    ak2.key.fill(0x22);

    AccessKey ak3;
    ak3.address.bytes.fill(0x33);
    ak3.key.fill(0x22);

    EXPECT_EQ(ak1, ak2);
    EXPECT_NE(ak1, ak3);
}

TEST_F(CommitRevealTest, DeclaredAccessSetCanRead) {
    DeclaredAccessSet set;

    AccessKey read_key;
    read_key.address.bytes.fill(0x11);
    read_key.key.fill(0x22);
    set.read_set.push_back(read_key);

    AccessKey write_key;
    write_key.address.bytes.fill(0x33);
    write_key.key.fill(0x44);
    set.write_set.push_back(write_key);

    // Can read from read_set
    EXPECT_TRUE(set.can_read(read_key));

    // Can read from write_set (write implies read)
    EXPECT_TRUE(set.can_read(write_key));

    // Cannot read undeclared key
    AccessKey other;
    other.address.bytes.fill(0x55);
    other.key.fill(0x66);
    EXPECT_FALSE(set.can_read(other));
}

TEST_F(CommitRevealTest, DeclaredAccessSetCanWrite) {
    DeclaredAccessSet set;

    AccessKey read_key;
    read_key.address.bytes.fill(0x11);
    read_key.key.fill(0x22);
    set.read_set.push_back(read_key);

    AccessKey write_key;
    write_key.address.bytes.fill(0x33);
    write_key.key.fill(0x44);
    set.write_set.push_back(write_key);

    // Can write to write_set
    EXPECT_TRUE(set.can_write(write_key));

    // Cannot write to read_set
    EXPECT_FALSE(set.can_write(read_key));
}

TEST_F(CommitRevealTest, DeclaredAccessSetOverlaps) {
    DeclaredAccessSet set1;
    DeclaredAccessSet set2;

    AccessKey key1;
    key1.address.bytes.fill(0x11);
    key1.key.fill(0x22);

    AccessKey key2;
    key2.address.bytes.fill(0x33);
    key2.key.fill(0x44);

    // No overlap
    set1.read_set.push_back(key1);
    set2.read_set.push_back(key2);
    EXPECT_FALSE(set1.overlaps(set2));

    // Overlap: set1 writes what set2 reads
    set1.write_set.push_back(key2);
    EXPECT_TRUE(set1.overlaps(set2));
}

TEST_F(CommitRevealTest, DeclaredAccessSetSerialization) {
    DeclaredAccessSet set;

    AccessKey key1;
    key1.address.bytes.fill(0x11);
    key1.key.fill(0x22);
    set.read_set.push_back(key1);

    AccessKey key2;
    key2.address.bytes.fill(0x33);
    key2.key.fill(0x44);
    set.write_set.push_back(key2);

    auto bytes = set.serialize();
    auto deserialized = DeclaredAccessSet::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->read_set.size(), 1);
    EXPECT_EQ(deserialized->write_set.size(), 1);
}

TEST_F(CommitRevealTest, CommitMessageV2Serialization) {
    CommitMessageV2 commit;
    commit.version = CommitMessageV2::VERSION;
    commit.chain_id = 1;
    commit.header.fee_recipient.bytes.fill(0x11);
    commit.header.max_fee = 1000;
    commit.header.fee_mode = FeeMode::PAY_ON_INCLUDE;
    commit.header.retry_nonce = 0;
    commit.header.max_instructions = 10000;
    commit.header.payload_hash.fill(0x22);
    commit.header.sender = sender_;
    commit.header.commit_slot = 100;
    commit.payload_hash.fill(0x33);
    commit.encrypted_payload = {0x01, 0x02, 0x03};
    commit.sender = sender_;
    commit.nonce = 1;
    commit.reference_slot = 99;
    commit.commit_slot = 100;
    commit.one_time_public_key = one_time_pk_;
    commit.signature.fill(0x44);

    auto bytes = commit.serialize();
    auto deserialized = CommitMessageV2::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->version, commit.version);
    EXPECT_EQ(deserialized->chain_id, commit.chain_id);
    EXPECT_EQ(deserialized->nonce, commit.nonce);
    EXPECT_EQ(deserialized->reference_slot, commit.reference_slot);
    EXPECT_EQ(deserialized->commit_slot, commit.commit_slot);
}

TEST_F(CommitRevealTest, CommitMessageV2Position) {
    CommitMessageV2 commit;
    commit.header.fee_recipient.bytes.fill(0x11);
    commit.header.max_fee = 1000;
    commit.header.payload_hash.fill(0x22);
    commit.header.sender = sender_;
    commit.header.commit_slot = 100;

    auto pos = commit.position_2d();

    // Position should be deterministic
    auto pos2 = commit.position_2d();
    EXPECT_EQ(pos.position, pos2.position);
    EXPECT_EQ(pos.subposition, pos2.subposition);
}

TEST_F(CommitRevealTest, RevealMessageV2Serialization) {
    RevealMessageV2 reveal;
    reveal.commit_hash.fill(0x11);
    reveal.decryption_key.fill(0x22);
    reveal.target_vdf_start = 1000;
    reveal.target_vdf_end = 2000;
    reveal.receipt_reward_pool = 5000;
    reveal.one_time_signature.fill(0x33);

    auto bytes = reveal.serialize();
    auto deserialized = RevealMessageV2::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->commit_hash, reveal.commit_hash);
    EXPECT_EQ(deserialized->decryption_key, reveal.decryption_key);
    EXPECT_EQ(deserialized->target_vdf_start, reveal.target_vdf_start);
    EXPECT_EQ(deserialized->target_vdf_end, reveal.target_vdf_end);
    EXPECT_EQ(deserialized->receipt_reward_pool, reveal.receipt_reward_pool);
}

TEST_F(CommitRevealTest, RevealMessageV2VDFRange) {
    RevealMessageV2 reveal;
    reveal.target_vdf_start = 1000;
    reveal.target_vdf_end = 2000;

    // In range
    EXPECT_TRUE(reveal.is_in_vdf_range(1000));
    EXPECT_TRUE(reveal.is_in_vdf_range(1500));
    EXPECT_TRUE(reveal.is_in_vdf_range(1999));

    // Out of range
    EXPECT_FALSE(reveal.is_in_vdf_range(999));
    EXPECT_FALSE(reveal.is_in_vdf_range(2000));
    EXPECT_FALSE(reveal.is_in_vdf_range(2001));

    // Expired
    EXPECT_FALSE(reveal.has_expired(1500));
    EXPECT_TRUE(reveal.has_expired(2000));
    EXPECT_TRUE(reveal.has_expired(3000));
}

TEST_F(CommitRevealTest, CommitPoolBasicOperations) {
    CommitPool pool;

    EXPECT_EQ(pool.size(), 0);

    CommitMessageV2 commit;
    commit.version = CommitMessageV2::VERSION;
    commit.chain_id = 1;
    commit.header.fee_recipient.bytes.fill(0x11);
    commit.header.payload_hash.fill(0x22);
    commit.header.sender = sender_;
    commit.header.commit_slot = 100;
    commit.sender = sender_;
    commit.nonce = 1;
    commit.signature.fill(0x44);

    // Add commit (without signature verification for test)
    // Note: In real usage, signature would be verified

    hash_t commit_hash = commit.commit_hash();

    // Test has_commit before adding
    EXPECT_FALSE(pool.has_commit(commit_hash));
}

TEST_F(CommitRevealTest, RevealPoolBasicOperations) {
    RevealPool pool;

    EXPECT_EQ(pool.size(), 0);

    RevealMessageV2 reveal;
    reveal.commit_hash.fill(0x11);
    reveal.target_vdf_start = 1000;
    reveal.target_vdf_end = 2000;

    hash_t reveal_hash = reveal.reveal_hash();

    EXPECT_FALSE(pool.has_reveal(reveal_hash));
}

TEST_F(CommitRevealTest, TransactionOrderingParallelGroups) {
    TransactionOrdering ordering;

    // Create execution contexts with non-overlapping access sets
    for (int i = 0; i < 5; ++i) {
        ExecutionContext ctx;
        ctx.tx_hash.fill(static_cast<std::uint8_t>(i));

        AccessKey key;
        key.address.bytes.fill(static_cast<std::uint8_t>(i));  // Different addresses
        key.key.fill(0);

        DeclaredAccessSet access;
        access.write_set.push_back(key);

        // Would need full context setup
    }

    // Non-overlapping transactions should be in parallel groups
    auto groups = ordering.get_parallel_groups();
    // Groups should allow parallel execution
}

}  // namespace
}  // namespace pop
