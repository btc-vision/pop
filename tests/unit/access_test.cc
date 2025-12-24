#include <gtest/gtest.h>
#include "execution/wasm/access.hh"
#include "crypto/hash.hh"

namespace pop {
namespace {

class AccessTest : public ::testing::Test {
protected:
    void SetUp() override {
        address_.bytes.fill(0x42);
        key_.fill(0x11);
    }

    Address address_;
    hash_t key_;
};

TEST_F(AccessTest, AccessKeySerialization) {
    AccessKey ak;
    ak.address = address_;
    ak.key = key_;

    auto bytes = ak.serialize();
    auto deserialized = AccessKey::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->address, ak.address);
    EXPECT_EQ(deserialized->key, ak.key);
}

TEST_F(AccessTest, AccessKeyHash) {
    AccessKey ak1;
    ak1.address = address_;
    ak1.key = key_;

    AccessKey ak2 = ak1;

    AccessKey::Hash hasher;
    EXPECT_EQ(hasher(ak1), hasher(ak2));

    ak2.key.fill(0x22);
    EXPECT_NE(hasher(ak1), hasher(ak2));
}

TEST_F(AccessTest, DeclaredAccessSetCanRead) {
    DeclaredAccessSet set;

    AccessKey read_key;
    read_key.address = address_;
    read_key.key = key_;
    set.read_set.push_back(read_key);

    EXPECT_TRUE(set.can_read(read_key));

    AccessKey other;
    other.address.bytes.fill(0xFF);
    other.key.fill(0xFF);
    EXPECT_FALSE(set.can_read(other));
}

TEST_F(AccessTest, DeclaredAccessSetCanWrite) {
    DeclaredAccessSet set;

    AccessKey write_key;
    write_key.address = address_;
    write_key.key = key_;
    set.write_set.push_back(write_key);

    EXPECT_TRUE(set.can_write(write_key));
    EXPECT_TRUE(set.can_read(write_key));  // Write implies read

    AccessKey other;
    other.address.bytes.fill(0xFF);
    other.key.fill(0xFF);
    EXPECT_FALSE(set.can_write(other));
}

TEST_F(AccessTest, DeclaredAccessSetOverlaps) {
    DeclaredAccessSet set1;
    DeclaredAccessSet set2;

    AccessKey key1;
    key1.address.bytes.fill(0x11);
    key1.key.fill(0x22);

    AccessKey key2;
    key2.address.bytes.fill(0x33);
    key2.key.fill(0x44);

    // No overlap - different keys
    set1.write_set.push_back(key1);
    set2.write_set.push_back(key2);
    EXPECT_FALSE(set1.overlaps(set2));

    // Overlap - set1 writes what set2 reads
    set2.read_set.push_back(key1);
    EXPECT_TRUE(set1.overlaps(set2));
}

TEST_F(AccessTest, DeclaredAccessSetFromAddresses) {
    std::vector<Address> read_addrs;
    std::vector<Address> write_addrs;

    Address r1, r2, w1;
    r1.bytes.fill(0x11);
    r2.bytes.fill(0x22);
    w1.bytes.fill(0x33);

    read_addrs.push_back(r1);
    read_addrs.push_back(r2);
    write_addrs.push_back(w1);

    auto set = DeclaredAccessSet::from_addresses(read_addrs, write_addrs);

    EXPECT_EQ(set.read_set.size(), 2);
    EXPECT_EQ(set.write_set.size(), 1);
}

TEST_F(AccessTest, AccessTrackerValidReads) {
    DeclaredAccessSet declared;
    AccessKey ak;
    ak.address = address_;
    ak.key = key_;
    declared.read_set.push_back(ak);

    AccessTracker tracker(declared);

    // Valid read
    auto result = tracker.check_read(address_, key_);
    EXPECT_EQ(result, AccessViolation::NONE);
    EXPECT_FALSE(tracker.has_violation());

    // Should be tracked in actual reads
    EXPECT_EQ(tracker.actual_reads().size(), 1);
}

TEST_F(AccessTest, AccessTrackerUndeclaredRead) {
    DeclaredAccessSet declared;
    // Empty declared set

    AccessTracker tracker(declared);

    // Undeclared read
    auto result = tracker.check_read(address_, key_);
    EXPECT_EQ(result, AccessViolation::UNDECLARED_READ);
    EXPECT_TRUE(tracker.has_violation());
    EXPECT_EQ(tracker.get_violation(), AccessViolation::UNDECLARED_READ);
}

TEST_F(AccessTest, AccessTrackerValidWrites) {
    DeclaredAccessSet declared;
    AccessKey ak;
    ak.address = address_;
    ak.key = key_;
    declared.write_set.push_back(ak);

    AccessTracker tracker(declared);

    // Valid write
    auto result = tracker.check_write(address_, key_);
    EXPECT_EQ(result, AccessViolation::NONE);
    EXPECT_FALSE(tracker.has_violation());

    EXPECT_EQ(tracker.actual_writes().size(), 1);
}

TEST_F(AccessTest, AccessTrackerUndeclaredWrite) {
    DeclaredAccessSet declared;
    AccessKey ak;
    ak.address = address_;
    ak.key = key_;
    declared.read_set.push_back(ak);  // Only read, not write

    AccessTracker tracker(declared);

    // Try to write - should fail
    auto result = tracker.check_write(address_, key_);
    EXPECT_EQ(result, AccessViolation::UNDECLARED_WRITE);
    EXPECT_TRUE(tracker.has_violation());
}

TEST_F(AccessTest, AccessTrackerReset) {
    DeclaredAccessSet declared;
    AccessKey ak;
    ak.address = address_;
    ak.key = key_;
    declared.read_set.push_back(ak);

    AccessTracker tracker(declared);

    tracker.check_read(address_, key_);
    EXPECT_EQ(tracker.actual_reads().size(), 1);

    tracker.reset();
    EXPECT_EQ(tracker.actual_reads().size(), 0);
    EXPECT_FALSE(tracker.has_violation());
}

TEST_F(AccessTest, InstructionMeterBasic) {
    InstructionMeter meter(1000);

    EXPECT_EQ(meter.instructions_used(), 0);
    EXPECT_EQ(meter.instructions_remaining(), 1000);
    EXPECT_FALSE(meter.should_halt());

    // Count some instructions
    EXPECT_TRUE(meter.count_instructions(100));
    EXPECT_EQ(meter.instructions_used(), 100);
    EXPECT_EQ(meter.instructions_remaining(), 900);
}

TEST_F(AccessTest, InstructionMeterExhaustion) {
    InstructionMeter meter(100);

    // Use exactly the limit
    EXPECT_TRUE(meter.count_instructions(100));
    EXPECT_FALSE(meter.should_halt());

    // Try to use more
    EXPECT_FALSE(meter.count_instructions(1));
    EXPECT_TRUE(meter.should_halt());
}

TEST_F(AccessTest, InstructionMeterOperationCosts) {
    InstructionMeter meter(100000);

    EXPECT_TRUE(meter.count_sload());
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_SLOAD);

    meter.reset(100000);
    EXPECT_TRUE(meter.count_sstore());
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_SSTORE);

    meter.reset(100000);
    EXPECT_TRUE(meter.count_sha3(64));  // 2 words
    std::uint64_t expected = MeteringConfig::COST_SHA3_BASE +
                             MeteringConfig::COST_SHA3_PER_WORD * 2;
    EXPECT_EQ(meter.instructions_used(), expected);
}

TEST_F(AccessTest, InstructionMeterFeeCalculation) {
    // Fee = declared_limit / 1000 * price
    std::uint64_t limit = 10000;
    std::uint64_t fee = InstructionMeter::calculate_fee(limit);
    std::uint64_t expected = (limit / MeteringConfig::INSTRUCTION_UNIT) *
                             MeteringConfig::INSTRUCTION_PRICE_SATOSHIS;
    EXPECT_EQ(fee, expected);
}

TEST_F(AccessTest, StateExpectationSerialization) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_GE;
    exp.address = address_;
    exp.key = key_;
    exp.value.fill(0x22);
    exp.max_value = hash_t{};
    exp.max_value->fill(0x33);

    auto bytes = exp.serialize();
    auto deserialized = StateExpectation::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->type, exp.type);
    EXPECT_EQ(deserialized->address, exp.address);
    ASSERT_TRUE(deserialized->key.has_value());
    EXPECT_EQ(*deserialized->key, *exp.key);
    EXPECT_EQ(deserialized->value, exp.value);
    ASSERT_TRUE(deserialized->max_value.has_value());
    EXPECT_EQ(*deserialized->max_value, *exp.max_value);
}

TEST_F(AccessTest, ExpectationSetHelpers) {
    ExpectationSet set;

    set.add_balance_eq(address_, 1000);
    EXPECT_EQ(set.expectations.size(), 1);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::BALANCE_EQ);

    set.add_balance_ge(address_, 500);
    EXPECT_EQ(set.expectations.size(), 2);
    EXPECT_EQ(set.expectations[1].type, ExpectationType::BALANCE_GE);

    hash_t storage_key, storage_value;
    storage_key.fill(0x11);
    storage_value.fill(0x22);
    set.add_storage_eq(address_, storage_key, storage_value);
    EXPECT_EQ(set.expectations.size(), 3);
    EXPECT_EQ(set.expectations[2].type, ExpectationType::STORAGE_EQ);

    set.add_nonce_eq(address_, 42);
    EXPECT_EQ(set.expectations.size(), 4);
    EXPECT_EQ(set.expectations[3].type, ExpectationType::NONCE_EQ);
}

TEST_F(AccessTest, ExpectationSetSerialization) {
    ExpectationSet set;
    set.add_balance_eq(address_, 1000);
    set.add_balance_ge(address_, 500);

    auto bytes = set.serialize();
    auto deserialized = ExpectationSet::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->expectations.size(), 2);
}

TEST_F(AccessTest, DependencyGraphBuild) {
    std::vector<DecoratedTransaction> txs;

    // Create two non-overlapping transactions
    DecoratedTransaction tx1;
    tx1.index = 0;
    tx1.position.position = 1000;
    tx1.position.subposition.fill(0x01);
    AccessKey ak1;
    ak1.address.bytes.fill(0x11);
    ak1.key.fill(0x22);
    tx1.access_set.write_set.push_back(ak1);

    DecoratedTransaction tx2;
    tx2.index = 1;
    tx2.position.position = 2000;
    tx2.position.subposition.fill(0x02);
    AccessKey ak2;
    ak2.address.bytes.fill(0x33);
    ak2.key.fill(0x44);
    tx2.access_set.write_set.push_back(ak2);

    txs.push_back(tx1);
    txs.push_back(tx2);

    DependencyGraph graph(txs);
    graph.build();

    // Both should be ready (no overlap)
    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 2);

    // Should be parallelizable
    EXPECT_TRUE(graph.can_parallelize(0, 1));
}

TEST_F(AccessTest, DependencyGraphWithDependency) {
    std::vector<DecoratedTransaction> txs;

    // Create two overlapping transactions
    DecoratedTransaction tx1;
    tx1.index = 0;
    tx1.position.position = 1000;
    tx1.position.subposition.fill(0x01);
    AccessKey ak;
    ak.address.bytes.fill(0x11);
    ak.key.fill(0x22);
    tx1.access_set.write_set.push_back(ak);

    DecoratedTransaction tx2;
    tx2.index = 1;
    tx2.position.position = 2000;
    tx2.position.subposition.fill(0x02);
    tx2.access_set.read_set.push_back(ak);  // Reads what tx1 writes

    txs.push_back(tx1);
    txs.push_back(tx2);

    DependencyGraph graph(txs);
    graph.build();

    // Only one should be ready initially (tx1, which has lower position)
    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1);

    // Should not be parallelizable
    EXPECT_FALSE(graph.can_parallelize(0, 1));

    // Mark first as complete
    graph.mark_complete(ready[0]);

    // Now second should be ready
    ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1);
}

TEST_F(AccessTest, DependencyGraphParallelSchedule) {
    std::vector<DecoratedTransaction> txs;

    // Create three transactions: tx0 and tx1 parallel, tx2 depends on both
    AccessKey ak0, ak1, ak2;
    ak0.address.bytes.fill(0x11);
    ak0.key.fill(0x11);
    ak1.address.bytes.fill(0x22);
    ak1.key.fill(0x22);
    ak2.address.bytes.fill(0x33);
    ak2.key.fill(0x33);

    DecoratedTransaction tx0;
    tx0.index = 0;
    tx0.position.position = 1000;
    tx0.access_set.write_set.push_back(ak0);

    DecoratedTransaction tx1;
    tx1.index = 1;
    tx1.position.position = 2000;
    tx1.access_set.write_set.push_back(ak1);

    DecoratedTransaction tx2;
    tx2.index = 2;
    tx2.position.position = 3000;
    tx2.access_set.read_set.push_back(ak0);
    tx2.access_set.read_set.push_back(ak1);

    txs.push_back(tx0);
    txs.push_back(tx1);
    txs.push_back(tx2);

    DependencyGraph graph(txs);
    graph.build();

    auto schedule = graph.get_parallel_schedule();

    // Should have at least 2 batches
    EXPECT_GE(schedule.size(), 2);

    // First batch should have tx0 and tx1
    EXPECT_EQ(schedule[0].size(), 2);
}

TEST_F(AccessTest, MemoryLimiterBasic) {
    MemoryLimiter limiter;

    EXPECT_EQ(limiter.current_pages(), MemoryLimiter::INITIAL_MEMORY_PAGES);
    EXPECT_EQ(limiter.max_pages(), MemoryLimiter::MAX_MEMORY_PAGES);
}

TEST_F(AccessTest, MemoryLimiterGrow) {
    MemoryLimiter limiter(32);  // Max 32 pages

    std::uint32_t initial = limiter.current_pages();

    // Grow by 10 pages
    EXPECT_TRUE(limiter.request_grow(10));
    EXPECT_EQ(limiter.current_pages(), initial + 10);

    // Try to grow beyond limit
    EXPECT_FALSE(limiter.request_grow(100));
    EXPECT_EQ(limiter.current_pages(), initial + 10);  // Unchanged
}

TEST_F(AccessTest, MemoryLimiterBytes) {
    MemoryLimiter limiter;

    std::size_t expected_bytes = static_cast<std::size_t>(limiter.current_pages()) *
                                  MemoryLimiter::PAGE_SIZE;
    EXPECT_EQ(limiter.current_bytes(), expected_bytes);
}

}  // namespace
}  // namespace pop
