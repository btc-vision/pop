#include <gtest/gtest.h>
#include "execution/wasm/access.hh"
#include "consensus/commit_reveal.hh"
#include "crypto/hash.hh"
#include <set>

namespace pop {
namespace {

// ============================================================================
// AccessKey Comprehensive Tests
// ============================================================================

class AccessKeyTest : public ::testing::Test {
protected:
    void SetUp() override {
        key1_.address.bytes.fill(0x11);
        key1_.key.fill(0x22);

        key2_.address.bytes.fill(0x33);
        key2_.key.fill(0x44);
    }
    AccessKey key1_, key2_;
};

TEST_F(AccessKeyTest, Equality) {
    AccessKey copy = key1_;
    EXPECT_EQ(key1_, copy);
    EXPECT_NE(key1_, key2_);
}

TEST_F(AccessKeyTest, HashConsistency) {
    AccessKey::Hash hasher;

    auto h1 = hasher(key1_);
    auto h2 = hasher(key1_);
    EXPECT_EQ(h1, h2);
}

TEST_F(AccessKeyTest, HashDifferent) {
    AccessKey::Hash hasher;

    auto h1 = hasher(key1_);
    auto h2 = hasher(key2_);
    EXPECT_NE(h1, h2);
}

TEST_F(AccessKeyTest, HashQuality) {
    AccessKey::Hash hasher;

    std::set<std::size_t> hashes;
    for (int i = 0; i < 1000; ++i) {
        AccessKey key;
        key.address.bytes.fill(static_cast<std::uint8_t>(i & 0xFF));
        key.key.fill(static_cast<std::uint8_t>((i >> 8) & 0xFF));

        hashes.insert(hasher(key));
    }

    EXPECT_GT(hashes.size(), 900u);
}

TEST_F(AccessKeyTest, Serialization) {
    auto bytes = key1_.serialize();
    EXPECT_EQ(bytes.size(), AccessKey::SERIALIZED_SIZE);

    auto restored = AccessKey::deserialize(bytes);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(*restored, key1_);
}

TEST_F(AccessKeyTest, SerializationRoundTrip) {
    for (int i = 0; i < 100; ++i) {
        AccessKey key;
        key.address.bytes.fill(static_cast<std::uint8_t>(i));
        key.key.fill(static_cast<std::uint8_t>(255 - i));

        auto bytes = key.serialize();
        auto restored = AccessKey::deserialize(bytes);

        ASSERT_TRUE(restored.has_value());
        EXPECT_EQ(*restored, key);
    }
}

TEST_F(AccessKeyTest, DeserializeInvalid) {
    std::vector<std::uint8_t> short_data(10);
    auto result = AccessKey::deserialize(short_data);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// DeclaredAccessSet Comprehensive Tests
// ============================================================================

class DeclaredAccessSetTest : public ::testing::Test {
protected:
    void SetUp() override {
        read_key_.address.bytes.fill(0x11);
        read_key_.key.fill(0x22);

        write_key_.address.bytes.fill(0x33);
        write_key_.key.fill(0x44);
    }
    AccessKey read_key_, write_key_;
};

TEST_F(DeclaredAccessSetTest, EmptySet) {
    DeclaredAccessSet set;
    EXPECT_FALSE(set.can_read(read_key_));
    EXPECT_FALSE(set.can_write(read_key_));
}

TEST_F(DeclaredAccessSetTest, ReadOnly) {
    DeclaredAccessSet set;
    set.read_set.push_back(read_key_);

    EXPECT_TRUE(set.can_read(read_key_));
    EXPECT_FALSE(set.can_write(read_key_));
    EXPECT_FALSE(set.can_read(write_key_));
}

TEST_F(DeclaredAccessSetTest, WriteImpliesRead) {
    DeclaredAccessSet set;
    set.write_set.push_back(write_key_);

    EXPECT_TRUE(set.can_write(write_key_));
    EXPECT_TRUE(set.can_read(write_key_));
}

TEST_F(DeclaredAccessSetTest, NoOverlapEmpty) {
    DeclaredAccessSet set1, set2;
    EXPECT_FALSE(set1.overlaps(set2));
}

TEST_F(DeclaredAccessSetTest, OverlapWriteRead) {
    DeclaredAccessSet set1, set2;
    set1.write_set.push_back(read_key_);
    set2.read_set.push_back(read_key_);

    EXPECT_TRUE(set1.overlaps(set2));
    EXPECT_TRUE(set2.overlaps(set1));
}

TEST_F(DeclaredAccessSetTest, OverlapWriteWrite) {
    DeclaredAccessSet set1, set2;
    set1.write_set.push_back(read_key_);
    set2.write_set.push_back(read_key_);

    EXPECT_TRUE(set1.overlaps(set2));
}

TEST_F(DeclaredAccessSetTest, NoOverlapDifferentKeys) {
    DeclaredAccessSet set1, set2;
    set1.write_set.push_back(read_key_);
    set2.write_set.push_back(write_key_);

    EXPECT_FALSE(set1.overlaps(set2));
}

TEST_F(DeclaredAccessSetTest, ReadReadNoOverlap) {
    DeclaredAccessSet set1, set2;
    set1.read_set.push_back(read_key_);
    set2.read_set.push_back(read_key_);

    EXPECT_FALSE(set1.overlaps(set2));
}

TEST_F(DeclaredAccessSetTest, Serialization) {
    DeclaredAccessSet set;
    set.read_set.push_back(read_key_);
    set.write_set.push_back(write_key_);

    auto bytes = set.serialize();
    auto restored = DeclaredAccessSet::deserialize(bytes);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->read_set.size(), 1u);
    EXPECT_EQ(restored->write_set.size(), 1u);
    EXPECT_TRUE(restored->can_read(read_key_));
    EXPECT_TRUE(restored->can_write(write_key_));
}

TEST_F(DeclaredAccessSetTest, FromAddresses) {
    std::vector<Address> read_addrs(2);
    read_addrs[0].bytes.fill(0x11);
    read_addrs[1].bytes.fill(0x22);

    std::vector<Address> write_addrs(1);
    write_addrs[0].bytes.fill(0x33);

    auto set = DeclaredAccessSet::from_addresses(read_addrs, write_addrs);

    EXPECT_EQ(set.read_set.size(), 2u);
    EXPECT_EQ(set.write_set.size(), 1u);
}

// ============================================================================
// AccessTracker Comprehensive Tests
// ============================================================================

class AccessTrackerTest : public ::testing::Test {
protected:
    void SetUp() override {
        address_.bytes.fill(0x42);
        key_.fill(0x11);

        AccessKey ak;
        ak.address = address_;
        ak.key = key_;

        declared_.read_set.push_back(ak);
        declared_.write_set.push_back(ak);
    }
    Address address_;
    hash_t key_;
    DeclaredAccessSet declared_;
};

TEST_F(AccessTrackerTest, ValidRead) {
    AccessTracker tracker(declared_);

    auto result = tracker.check_read(address_, key_);
    EXPECT_EQ(result, AccessViolation::NONE);
    EXPECT_FALSE(tracker.has_violation());
    EXPECT_EQ(tracker.actual_reads().size(), 1u);
}

TEST_F(AccessTrackerTest, ValidWrite) {
    AccessTracker tracker(declared_);

    auto result = tracker.check_write(address_, key_);
    EXPECT_EQ(result, AccessViolation::NONE);
    EXPECT_FALSE(tracker.has_violation());
    EXPECT_EQ(tracker.actual_writes().size(), 1u);
}

TEST_F(AccessTrackerTest, UndeclaredRead) {
    AccessTracker tracker(DeclaredAccessSet{});

    auto result = tracker.check_read(address_, key_);
    EXPECT_EQ(result, AccessViolation::UNDECLARED_READ);
    EXPECT_TRUE(tracker.has_violation());
}

TEST_F(AccessTrackerTest, UndeclaredWrite) {
    DeclaredAccessSet read_only;
    AccessKey ak;
    ak.address = address_;
    ak.key = key_;
    read_only.read_set.push_back(ak);

    AccessTracker tracker(read_only);

    auto result = tracker.check_write(address_, key_);
    EXPECT_EQ(result, AccessViolation::UNDECLARED_WRITE);
    EXPECT_TRUE(tracker.has_violation());
}

TEST_F(AccessTrackerTest, ViolationPersists) {
    AccessTracker tracker(DeclaredAccessSet{});

    tracker.check_read(address_, key_);

    auto result = tracker.check_read(address_, key_);
    EXPECT_EQ(result, AccessViolation::UNDECLARED_READ);
}

TEST_F(AccessTrackerTest, Reset) {
    AccessTracker tracker(declared_);

    tracker.check_read(address_, key_);
    tracker.check_write(address_, key_);

    EXPECT_EQ(tracker.actual_reads().size(), 1u);
    EXPECT_EQ(tracker.actual_writes().size(), 1u);

    tracker.reset();

    EXPECT_EQ(tracker.actual_reads().size(), 0u);
    EXPECT_EQ(tracker.actual_writes().size(), 0u);
    EXPECT_FALSE(tracker.has_violation());
}

TEST_F(AccessTrackerTest, BalanceRead) {
    hash_t balance_key;
    balance_key.fill(0xFF);

    AccessKey ak;
    ak.address = address_;
    ak.key = balance_key;

    DeclaredAccessSet set;
    set.read_set.push_back(ak);

    AccessTracker tracker(set);

    auto result = tracker.check_balance_read(address_);
    EXPECT_EQ(result, AccessViolation::NONE);
}

TEST_F(AccessTrackerTest, BalanceWrite) {
    hash_t balance_key;
    balance_key.fill(0xFF);

    AccessKey ak;
    ak.address = address_;
    ak.key = balance_key;

    DeclaredAccessSet set;
    set.write_set.push_back(ak);

    AccessTracker tracker(set);

    auto result = tracker.check_balance_write(address_);
    EXPECT_EQ(result, AccessViolation::NONE);
}

TEST_F(AccessTrackerTest, GetViolation) {
    AccessTracker tracker(DeclaredAccessSet{});

    EXPECT_EQ(tracker.get_violation(), AccessViolation::NONE);

    tracker.check_read(address_, key_);

    EXPECT_EQ(tracker.get_violation(), AccessViolation::UNDECLARED_READ);
}

// ============================================================================
// InstructionMeter Comprehensive Tests
// ============================================================================

class ExecInstructionMeterTest : public ::testing::Test {};

TEST_F(ExecInstructionMeterTest, InitialState) {
    InstructionMeter meter(1000);

    EXPECT_EQ(meter.instructions_used(), 0u);
    EXPECT_EQ(meter.instructions_remaining(), 1000u);
    EXPECT_EQ(meter.declared_limit(), 1000u);
    EXPECT_FALSE(meter.should_halt());
}

TEST_F(ExecInstructionMeterTest, CountInstructions) {
    InstructionMeter meter(1000);

    EXPECT_TRUE(meter.count_instructions(100));
    EXPECT_EQ(meter.instructions_used(), 100u);
    EXPECT_EQ(meter.instructions_remaining(), 900u);
}

TEST_F(ExecInstructionMeterTest, ExactLimit) {
    InstructionMeter meter(100);

    EXPECT_TRUE(meter.count_instructions(100));
    EXPECT_FALSE(meter.should_halt());
    EXPECT_EQ(meter.instructions_remaining(), 0u);
}

TEST_F(ExecInstructionMeterTest, ExceedLimit) {
    InstructionMeter meter(100);

    EXPECT_TRUE(meter.count_instructions(50));
    EXPECT_FALSE(meter.count_instructions(100));
    EXPECT_TRUE(meter.should_halt());
}

TEST_F(ExecInstructionMeterTest, CountAfterHalt) {
    InstructionMeter meter(100);

    // Exceeding limit returns false and sets halt flag
    EXPECT_FALSE(meter.count_instructions(200));
    EXPECT_TRUE(meter.should_halt());

    // Further counting after halt also returns false
    EXPECT_FALSE(meter.count_instructions(1));
}

TEST_F(ExecInstructionMeterTest, OperationCosts) {
    InstructionMeter meter(1000000);

    meter.count_sload();
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_SLOAD);

    meter.reset(1000000);
    meter.count_sstore();
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_SSTORE);

    meter.reset(1000000);
    meter.count_balance();
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_BALANCE);

    meter.reset(1000000);
    meter.count_call();
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_CALL);

    meter.reset(1000000);
    meter.count_create();
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_CREATE);

    meter.reset(1000000);
    meter.count_mldsa_verify();
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_MLDSA_VERIFY);
}

TEST_F(ExecInstructionMeterTest, SHA3Cost) {
    InstructionMeter meter(1000000);

    meter.count_sha3(0);
    EXPECT_EQ(meter.instructions_used(), MeteringConfig::COST_SHA3_BASE);

    meter.reset(1000000);
    meter.count_sha3(32);
    EXPECT_EQ(meter.instructions_used(),
              MeteringConfig::COST_SHA3_BASE + MeteringConfig::COST_SHA3_PER_WORD);

    meter.reset(1000000);
    meter.count_sha3(64);
    EXPECT_EQ(meter.instructions_used(),
              MeteringConfig::COST_SHA3_BASE + MeteringConfig::COST_SHA3_PER_WORD * 2);

    meter.reset(1000000);
    meter.count_sha3(33);
    EXPECT_EQ(meter.instructions_used(),
              MeteringConfig::COST_SHA3_BASE + MeteringConfig::COST_SHA3_PER_WORD * 2);
}

TEST_F(ExecInstructionMeterTest, Reset) {
    InstructionMeter meter(100);

    meter.count_instructions(150);
    EXPECT_TRUE(meter.should_halt());

    meter.reset(200);

    EXPECT_EQ(meter.instructions_used(), 0u);
    EXPECT_EQ(meter.declared_limit(), 200u);
    EXPECT_FALSE(meter.should_halt());
}

TEST_F(ExecInstructionMeterTest, FeeCalculation) {
    auto fee1 = InstructionMeter::calculate_fee(1000);
    EXPECT_EQ(fee1, 1 * MeteringConfig::INSTRUCTION_PRICE_SATOSHIS);

    auto fee2 = InstructionMeter::calculate_fee(10000);
    EXPECT_EQ(fee2, 10 * MeteringConfig::INSTRUCTION_PRICE_SATOSHIS);

    auto fee3 = InstructionMeter::calculate_fee(999);
    EXPECT_EQ(fee3, 0u);
}

// ============================================================================
// StateExpectation Comprehensive Tests
// ============================================================================

class StateExpectationTest : public ::testing::Test {
protected:
    void SetUp() override {
        address_.bytes.fill(0x42);
        key_.fill(0x11);
        value_.fill(0x22);
    }
    Address address_;
    hash_t key_, value_;
};

TEST_F(StateExpectationTest, BalanceEqSerialization) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_EQ;
    exp.address = address_;
    exp.value = value_;

    auto bytes = exp.serialize();
    auto restored = StateExpectation::deserialize(bytes);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->type, ExpectationType::BALANCE_EQ);
    EXPECT_EQ(restored->address, address_);
    EXPECT_EQ(restored->value, value_);
    EXPECT_FALSE(restored->key.has_value());
}

TEST_F(StateExpectationTest, StorageEqSerialization) {
    StateExpectation exp;
    exp.type = ExpectationType::STORAGE_EQ;
    exp.address = address_;
    exp.key = key_;
    exp.value = value_;

    auto bytes = exp.serialize();
    auto restored = StateExpectation::deserialize(bytes);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->type, ExpectationType::STORAGE_EQ);
    ASSERT_TRUE(restored->key.has_value());
    EXPECT_EQ(*restored->key, key_);
}

TEST_F(StateExpectationTest, BalanceRangeSerialization) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_RANGE;
    exp.address = address_;
    exp.value = value_;
    exp.max_value = hash_t{};
    exp.max_value->fill(0xFF);

    auto bytes = exp.serialize();
    auto restored = StateExpectation::deserialize(bytes);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->type, ExpectationType::BALANCE_RANGE);
    ASSERT_TRUE(restored->max_value.has_value());
    EXPECT_EQ((*restored->max_value)[0], 0xFFu);
}

// ============================================================================
// ExpectationSet Comprehensive Tests
// ============================================================================

class ExpectationSetTest : public ::testing::Test {
protected:
    void SetUp() override {
        address_.bytes.fill(0x42);
        key_.fill(0x11);
        value_.fill(0x22);
    }
    Address address_;
    hash_t key_, value_;
};

TEST_F(ExpectationSetTest, EmptySet) {
    ExpectationSet set;
    EXPECT_TRUE(set.expectations.empty());

    auto bytes = set.serialize();
    auto restored = ExpectationSet::deserialize(bytes);

    ASSERT_TRUE(restored.has_value());
    EXPECT_TRUE(restored->expectations.empty());
}

TEST_F(ExpectationSetTest, AddBalanceEq) {
    ExpectationSet set;
    set.add_balance_eq(address_, 1000);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::BALANCE_EQ);
}

TEST_F(ExpectationSetTest, AddBalanceGe) {
    ExpectationSet set;
    set.add_balance_ge(address_, 500);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::BALANCE_GE);
}

TEST_F(ExpectationSetTest, AddBalanceLe) {
    ExpectationSet set;
    set.add_balance_le(address_, 2000);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::BALANCE_LE);
}

TEST_F(ExpectationSetTest, AddBalanceRange) {
    ExpectationSet set;
    set.add_balance_range(address_, 100, 1000);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::BALANCE_RANGE);
}

TEST_F(ExpectationSetTest, AddStorageEq) {
    ExpectationSet set;
    set.add_storage_eq(address_, key_, value_);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::STORAGE_EQ);
}

TEST_F(ExpectationSetTest, AddStorageNe) {
    ExpectationSet set;
    set.add_storage_ne(address_, key_, value_);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::STORAGE_NE);
}

TEST_F(ExpectationSetTest, AddNonceEq) {
    ExpectationSet set;
    set.add_nonce_eq(address_, 42);

    EXPECT_EQ(set.expectations.size(), 1u);
    EXPECT_EQ(set.expectations[0].type, ExpectationType::NONCE_EQ);
}

TEST_F(ExpectationSetTest, MultipleExpectations) {
    ExpectationSet set;
    set.add_balance_eq(address_, 1000);
    set.add_balance_ge(address_, 500);
    set.add_storage_eq(address_, key_, value_);
    set.add_nonce_eq(address_, 1);

    EXPECT_EQ(set.expectations.size(), 4u);

    auto bytes = set.serialize();
    auto restored = ExpectationSet::deserialize(bytes);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->expectations.size(), 4u);
}

// ============================================================================
// DependencyGraph Comprehensive Tests
// ============================================================================

class DependencyGraphTest : public ::testing::Test {
protected:
    void SetUp() override {
        for (int i = 0; i < 5; ++i) {
            AccessKey key;
            key.address.bytes.fill(static_cast<std::uint8_t>(i));
            key.key.fill(static_cast<std::uint8_t>(i));
            keys_.push_back(key);
        }
    }

    DecoratedTransaction create_tx(std::uint32_t idx, position_t pos,
                                   std::vector<AccessKey> reads,
                                   std::vector<AccessKey> writes) {
        DecoratedTransaction tx;
        tx.index = idx;
        tx.position.position = pos;
        tx.position.subposition = {};
        tx.access_set.read_set = std::move(reads);
        tx.access_set.write_set = std::move(writes);
        return tx;
    }

    std::vector<AccessKey> keys_;
};

TEST_F(DependencyGraphTest, EmptyGraph) {
    std::vector<DecoratedTransaction> txs;
    DependencyGraph graph(txs);
    graph.build();

    EXPECT_TRUE(graph.get_ready().empty());
}

TEST_F(DependencyGraphTest, SingleTransaction) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));

    DependencyGraph graph(txs);
    graph.build();

    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1u);
    EXPECT_EQ(ready[0], 0u);
}

TEST_F(DependencyGraphTest, IndependentTransactions) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));
    txs.push_back(create_tx(1, 2000, {}, {keys_[1]}));
    txs.push_back(create_tx(2, 3000, {}, {keys_[2]}));

    DependencyGraph graph(txs);
    graph.build();

    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 3u);
    EXPECT_TRUE(graph.can_parallelize(0, 1));
    EXPECT_TRUE(graph.can_parallelize(1, 2));
    EXPECT_TRUE(graph.can_parallelize(0, 2));
}

TEST_F(DependencyGraphTest, WriteReadDependency) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));
    txs.push_back(create_tx(1, 2000, {keys_[0]}, {}));

    DependencyGraph graph(txs);
    graph.build();

    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1u);
    EXPECT_EQ(ready[0], 0u);
    EXPECT_FALSE(graph.can_parallelize(0, 1));
}

TEST_F(DependencyGraphTest, WriteWriteDependency) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));
    txs.push_back(create_tx(1, 2000, {}, {keys_[0]}));

    DependencyGraph graph(txs);
    graph.build();

    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1u);
    EXPECT_FALSE(graph.can_parallelize(0, 1));
}

TEST_F(DependencyGraphTest, MarkComplete) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));
    txs.push_back(create_tx(1, 2000, {keys_[0]}, {}));

    DependencyGraph graph(txs);
    graph.build();

    auto ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1u);

    graph.mark_complete(0);

    ready = graph.get_ready();
    EXPECT_EQ(ready.size(), 1u);
    EXPECT_EQ(ready[0], 1u);
}

TEST_F(DependencyGraphTest, ParallelSchedule) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));
    txs.push_back(create_tx(1, 2000, {}, {keys_[1]}));
    txs.push_back(create_tx(2, 3000, {keys_[0], keys_[1]}, {}));

    DependencyGraph graph(txs);
    graph.build();

    auto schedule = graph.get_parallel_schedule();

    EXPECT_GE(schedule.size(), 2u);
    EXPECT_EQ(schedule[0].size(), 2u);
    EXPECT_EQ(schedule[1].size(), 1u);
}

TEST_F(DependencyGraphTest, DiamondDependency) {
    std::vector<DecoratedTransaction> txs;
    txs.push_back(create_tx(0, 1000, {}, {keys_[0]}));
    txs.push_back(create_tx(1, 2000, {keys_[0]}, {keys_[1]}));
    txs.push_back(create_tx(2, 3000, {keys_[0]}, {keys_[2]}));
    txs.push_back(create_tx(3, 4000, {keys_[1], keys_[2]}, {}));

    DependencyGraph graph(txs);
    graph.build();

    auto schedule = graph.get_parallel_schedule();

    EXPECT_EQ(schedule.size(), 3u);
    EXPECT_EQ(schedule[0].size(), 1u);
    EXPECT_EQ(schedule[1].size(), 2u);
    EXPECT_EQ(schedule[2].size(), 1u);
}

// ============================================================================
// MemoryLimiter Comprehensive Tests
// ============================================================================

class MemoryLimiterTest : public ::testing::Test {};

TEST_F(MemoryLimiterTest, InitialState) {
    MemoryLimiter limiter;

    EXPECT_EQ(limiter.current_pages(), MemoryLimiter::INITIAL_MEMORY_PAGES);
    EXPECT_EQ(limiter.max_pages(), MemoryLimiter::MAX_MEMORY_PAGES);
}

TEST_F(MemoryLimiterTest, CustomMax) {
    MemoryLimiter limiter(32);

    EXPECT_EQ(limiter.max_pages(), 32u);
}

TEST_F(MemoryLimiterTest, GrowSuccess) {
    MemoryLimiter limiter(32);

    std::uint32_t initial = limiter.current_pages();
    EXPECT_TRUE(limiter.request_grow(5));
    EXPECT_EQ(limiter.current_pages(), initial + 5);
}

TEST_F(MemoryLimiterTest, GrowToMax) {
    MemoryLimiter limiter(20);

    std::uint32_t available = limiter.max_pages() - limiter.current_pages();
    EXPECT_TRUE(limiter.request_grow(available));
    EXPECT_EQ(limiter.current_pages(), limiter.max_pages());
}

TEST_F(MemoryLimiterTest, GrowBeyondMax) {
    MemoryLimiter limiter(20);

    std::uint32_t initial = limiter.current_pages();
    EXPECT_FALSE(limiter.request_grow(100));
    EXPECT_EQ(limiter.current_pages(), initial);
}

TEST_F(MemoryLimiterTest, CurrentBytes) {
    MemoryLimiter limiter;

    std::size_t expected = static_cast<std::size_t>(limiter.current_pages()) *
                            MemoryLimiter::PAGE_SIZE;
    EXPECT_EQ(limiter.current_bytes(), expected);
}

TEST_F(MemoryLimiterTest, IncrementalGrow) {
    MemoryLimiter limiter(50);

    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(limiter.request_grow(1));
    }

    EXPECT_EQ(limiter.current_pages(), MemoryLimiter::INITIAL_MEMORY_PAGES + 10);
}

// ============================================================================
// MeteringConfig Tests
// ============================================================================

TEST(MeteringConfigTest, DefaultLimit) {
    EXPECT_EQ(MeteringConfig::DEFAULT_INSTRUCTION_LIMIT, 10'000'000u);
}

TEST(MeteringConfigTest, MaxLimit) {
    EXPECT_EQ(MeteringConfig::MAX_INSTRUCTION_LIMIT, 100'000'000u);
}

TEST(MeteringConfigTest, InstructionUnit) {
    EXPECT_EQ(MeteringConfig::INSTRUCTION_UNIT, 1000u);
}

TEST(MeteringConfigTest, CostsAreNonZero) {
    EXPECT_GT(MeteringConfig::COST_BASIC, 0u);
    EXPECT_GT(MeteringConfig::COST_MEMORY_OP, 0u);
    EXPECT_GT(MeteringConfig::COST_CONTROL_FLOW, 0u);
    EXPECT_GT(MeteringConfig::COST_CALL, 0u);
    EXPECT_GT(MeteringConfig::COST_SLOAD, 0u);
    EXPECT_GT(MeteringConfig::COST_SSTORE, 0u);
    EXPECT_GT(MeteringConfig::COST_SHA3_BASE, 0u);
    EXPECT_GT(MeteringConfig::COST_SHA3_PER_WORD, 0u);
    EXPECT_GT(MeteringConfig::COST_BALANCE, 0u);
    EXPECT_GT(MeteringConfig::COST_CREATE, 0u);
    EXPECT_GT(MeteringConfig::COST_MLDSA_VERIFY, 0u);
}

// ============================================================================
// ExecutionResult Tests
// ============================================================================

TEST(ExecutionResultTest, DefaultSuccess) {
    ExecutionResult result;
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.status, ExecutionStatus::SUCCESS);
}

TEST(ExecutionResultTest, RevertIsNotSuccess) {
    ExecutionResult result;
    result.status = ExecutionStatus::REVERT;
    EXPECT_FALSE(result.is_success());
}

TEST(ExecutionResultTest, OutOfGasIsNotSuccess) {
    ExecutionResult result;
    result.status = ExecutionStatus::OUT_OF_GAS;
    EXPECT_FALSE(result.is_success());
}

TEST(ExecutionResultTest, AccessViolationIsNotSuccess) {
    ExecutionResult result;
    result.status = ExecutionStatus::ACCESS_VIOLATION;
    EXPECT_FALSE(result.is_success());
}

// ============================================================================
// WasmExecutionContext Tests
// ============================================================================

TEST(WasmExecutionContextTest, MaxCallDepth) {
    EXPECT_EQ(WasmExecutionContext::MAX_CALL_DEPTH, 1024u);
}

TEST(WasmExecutionContextTest, DefaultCallDepthZero) {
    WasmExecutionContext ctx;
    EXPECT_EQ(ctx.call_depth, 0u);
}

}  // namespace
}  // namespace pop
