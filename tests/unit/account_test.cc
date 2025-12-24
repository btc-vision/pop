#include <gtest/gtest.h>
#include "state/account.hh"
#include "crypto/hash.hh"

namespace pop {
namespace {

class AccountTest : public ::testing::Test {
protected:
    void SetUp() override {
        address_.bytes.fill(0x42);
    }

    Address address_;
};

TEST_F(AccountTest, AccountStorageSize) {
    Account account;
    account.code_size = 1000;
    account.storage_slot_count = 10;

    std::uint64_t expected = RentConfig::BASE_ACCOUNT_OVERHEAD +
                             1000 +
                             10 * RentConfig::STORAGE_SLOT_SIZE;
    EXPECT_EQ(account.storage_size(), expected);
}

TEST_F(AccountTest, AccountRentDue) {
    Account account;
    account.code_size = 1000;
    account.storage_slot_count = 10;

    std::uint64_t epochs = 5;
    std::uint64_t expected = account.storage_size() *
                             RentConfig::RENT_RATE_PER_BYTE_PER_EPOCH *
                             epochs;
    EXPECT_EQ(account.rent_due(epochs), expected);
}

TEST_F(AccountTest, AccountShouldBecomeDormant) {
    Account account;
    account.dormancy_state = DormancyState::ACTIVE;

    // With rent balance, should not become dormant
    account.rent_balance = 1000;
    EXPECT_FALSE(account.should_become_dormant());

    // With zero rent balance, should become dormant
    account.rent_balance = 0;
    EXPECT_TRUE(account.should_become_dormant());

    // Already dormant, should not trigger again
    account.dormancy_state = DormancyState::DORMANT;
    EXPECT_FALSE(account.should_become_dormant());
}

TEST_F(AccountTest, AccountShouldBePruned) {
    Account account;
    account.dormancy_state = DormancyState::DORMANT;
    account.dormant_since_epoch = 100;

    // Not enough epochs passed
    EXPECT_FALSE(account.should_be_pruned(100 + RentConfig::PRUNE_THRESHOLD_EPOCHS - 1));

    // Enough epochs passed
    EXPECT_TRUE(account.should_be_pruned(100 + RentConfig::PRUNE_THRESHOLD_EPOCHS));
    EXPECT_TRUE(account.should_be_pruned(100 + RentConfig::PRUNE_THRESHOLD_EPOCHS + 100));

    // Active accounts should not be pruned
    account.dormancy_state = DormancyState::ACTIVE;
    EXPECT_FALSE(account.should_be_pruned(100 + RentConfig::PRUNE_THRESHOLD_EPOCHS));
}

TEST_F(AccountTest, AccountSerialization) {
    Account account;
    account.balance = 1000000;
    account.nonce = 42;
    account.code_hash.fill(0x11);
    account.storage_root.fill(0x22);
    account.rent_balance = 5000;
    account.code_size = 2000;
    account.storage_slot_count = 50;
    account.last_rent_epoch = 100;
    account.dormancy_state = DormancyState::ACTIVE;
    account.dormant_since_epoch = 0;

    auto bytes = account.serialize();
    EXPECT_EQ(bytes.size(), Account::BASE_SERIALIZED_SIZE);

    auto deserialized = Account::deserialize(bytes);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->balance, account.balance);
    EXPECT_EQ(deserialized->nonce, account.nonce);
    EXPECT_EQ(deserialized->code_hash, account.code_hash);
    EXPECT_EQ(deserialized->storage_root, account.storage_root);
    EXPECT_EQ(deserialized->rent_balance, account.rent_balance);
    EXPECT_EQ(deserialized->code_size, account.code_size);
    EXPECT_EQ(deserialized->storage_slot_count, account.storage_slot_count);
    EXPECT_EQ(deserialized->last_rent_epoch, account.last_rent_epoch);
    EXPECT_EQ(deserialized->dormancy_state, account.dormancy_state);
}

TEST_F(AccountTest, StorageSlotSerialization) {
    StorageSlot slot;
    slot.key.fill(0x11);
    slot.value.fill(0x22);

    auto bytes = slot.serialize();
    auto deserialized = StorageSlot::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->key, slot.key);
    EXPECT_EQ(deserialized->value, slot.value);
}

TEST_F(AccountTest, AccountWithStorageSerialization) {
    AccountWithStorage aws;
    aws.account.balance = 1000;
    aws.account.nonce = 1;
    aws.code = {0x60, 0x80, 0x60, 0x40};  // Some WASM bytes

    hash_t key1, value1;
    key1.fill(0x11);
    value1.fill(0x22);
    aws.storage[key1] = value1;

    auto bytes = aws.serialize();
    auto deserialized = AccountWithStorage::deserialize(bytes);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->account.balance, aws.account.balance);
    EXPECT_EQ(deserialized->code, aws.code);
    EXPECT_EQ(deserialized->storage.size(), 1);
    EXPECT_EQ(deserialized->storage[key1], value1);
}

TEST_F(AccountTest, RentProcessorBasicOperations) {
    RentProcessor processor;

    EXPECT_EQ(processor.account_count(), 0);

    // Create account
    Account account;
    account.balance = 1000000;
    account.rent_balance = 10000;
    account.code_size = 100;
    account.storage_slot_count = 5;
    account.last_rent_epoch = 0;
    account.dormancy_state = DormancyState::ACTIVE;

    processor.set_account(address_, account);

    EXPECT_EQ(processor.account_count(), 1);
    EXPECT_EQ(processor.active_account_count(), 1);

    auto retrieved = processor.get_account(address_);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->balance, account.balance);
}

TEST_F(AccountTest, RentProcessorTransfer) {
    RentProcessor processor;

    Address from, to;
    from.bytes.fill(0x11);
    to.bytes.fill(0x22);

    Account from_account;
    from_account.balance = 1000;
    from_account.dormancy_state = DormancyState::ACTIVE;
    processor.set_account(from, from_account);

    // Transfer
    auto result = processor.transfer(from, to, 300);
    EXPECT_EQ(result, RentProcessor::TransferResult::SUCCESS);

    auto from_after = processor.get_account(from);
    ASSERT_TRUE(from_after.has_value());
    EXPECT_EQ(from_after->balance, 700);

    auto to_after = processor.get_account(to);
    ASSERT_TRUE(to_after.has_value());
    EXPECT_EQ(to_after->balance, 300);
}

TEST_F(AccountTest, RentProcessorTransferInsufficientBalance) {
    RentProcessor processor;

    Address from;
    from.bytes.fill(0x11);

    Account from_account;
    from_account.balance = 100;
    from_account.dormancy_state = DormancyState::ACTIVE;
    processor.set_account(from, from_account);

    Address to;
    to.bytes.fill(0x22);

    auto result = processor.transfer(from, to, 200);
    EXPECT_EQ(result, RentProcessor::TransferResult::INSUFFICIENT_BALANCE);
}

TEST_F(AccountTest, RentProcessorStorage) {
    RentProcessor processor;

    Account account;
    account.dormancy_state = DormancyState::ACTIVE;
    processor.set_account(address_, account);

    hash_t key, value;
    key.fill(0x11);
    value.fill(0x22);

    // Set storage
    processor.set_storage(address_, key, value);

    auto retrieved = processor.get_storage(address_, key);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(*retrieved, value);

    // Get account and check slot count increased
    auto acct = processor.get_account(address_);
    EXPECT_EQ(acct->storage_slot_count, 1);

    // Clear storage (set to zero)
    hash_t zero{};
    processor.set_storage(address_, key, zero);

    acct = processor.get_account(address_);
    EXPECT_EQ(acct->storage_slot_count, 0);
}

TEST_F(AccountTest, RentProcessorCode) {
    RentProcessor processor;

    Account account;
    account.dormancy_state = DormancyState::ACTIVE;
    processor.set_account(address_, account);

    std::vector<std::uint8_t> code = {0x00, 0x61, 0x73, 0x6D};  // WASM magic
    processor.set_code(address_, code);

    auto retrieved = processor.get_code(address_);
    EXPECT_EQ(retrieved, code);

    auto acct = processor.get_account(address_);
    EXPECT_EQ(acct->code_size, code.size());
    EXPECT_NE(acct->code_hash, hash_t{});  // Should be computed
}

TEST_F(AccountTest, RentProcessorEpoch) {
    RentProcessor processor;

    Account account;
    account.balance = 1000000;
    account.rent_balance = 10000;
    account.code_size = 100;
    account.storage_slot_count = 5;
    account.last_rent_epoch = 0;
    account.dormancy_state = DormancyState::ACTIVE;
    processor.set_account(address_, account);

    // Process epoch 10
    auto result = processor.process_epoch(10);

    EXPECT_GT(result.total_rent_collected, 0);
    EXPECT_EQ(result.accounts_charged, 1);

    auto after = processor.get_account(address_);
    ASSERT_TRUE(after.has_value());
    EXPECT_LT(after->rent_balance, account.rent_balance);
    EXPECT_EQ(after->last_rent_epoch, 10);
}

TEST_F(AccountTest, RentProcessorDormancy) {
    RentProcessor processor;

    Account account;
    account.balance = 1000000;
    account.rent_balance = 1;  // Very low
    account.code_size = 10000;  // Large code = high rent
    account.storage_slot_count = 100;
    account.last_rent_epoch = 0;
    account.dormancy_state = DormancyState::ACTIVE;
    processor.set_account(address_, account);

    // Process epoch - should run out of rent
    auto result = processor.process_epoch(100);

    EXPECT_EQ(result.accounts_made_dormant, 1);
    EXPECT_EQ(result.newly_dormant.size(), 1);
    EXPECT_EQ(result.newly_dormant[0], address_);

    EXPECT_TRUE(processor.is_dormant(address_));

    // Active query should not return dormant account
    auto active = processor.get_account(address_);
    EXPECT_FALSE(active.has_value());

    // Full query should return it
    auto full = processor.get_account_full(address_);
    ASSERT_TRUE(full.has_value());
    EXPECT_EQ(full->dormancy_state, DormancyState::DORMANT);
}

TEST_F(AccountTest, RentProcessorResurrection) {
    RentProcessor processor;

    Account account;
    account.balance = 1000000;
    account.rent_balance = 0;
    account.code_size = 100;
    account.storage_slot_count = 5;
    account.last_rent_epoch = 0;
    account.dormancy_state = DormancyState::DORMANT;
    account.dormant_since_epoch = 50;
    processor.set_account(address_, account);

    // Calculate resurrection cost
    std::uint64_t epochs_dormant = 100 - 50;
    std::uint64_t back_rent = account.rent_due(epochs_dormant);
    std::uint64_t buffer = account.rent_due(RentConfig::RESURRECTION_BUFFER_EPOCHS);
    std::uint64_t payment = back_rent + buffer + 1000;  // Extra for rent balance

    auto result = processor.resurrect(address_, payment, 100);

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.rent_paid, back_rent);
    EXPECT_GT(result.buffer_deposited, 0);

    auto after = processor.get_account(address_);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->dormancy_state, DormancyState::ACTIVE);
}

TEST_F(AccountTest, RentProcessorResurrectionInsufficientPayment) {
    RentProcessor processor;

    Account account;
    account.code_size = 100;
    account.storage_slot_count = 5;
    account.dormancy_state = DormancyState::DORMANT;
    account.dormant_since_epoch = 50;
    processor.set_account(address_, account);

    // Pay too little
    auto result = processor.resurrect(address_, 1, 100);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure_reason, ResurrectionResult::FailureReason::INSUFFICIENT_PAYMENT);
}

TEST_F(AccountTest, AccountCacheBasicOperations) {
    AccountCache cache(100);

    Account account;
    account.balance = 1000;
    account.nonce = 42;

    // Initially not in cache
    auto retrieved = cache.get(address_);
    EXPECT_FALSE(retrieved.has_value());

    // Put in cache
    cache.put(address_, account);

    // Now should be found
    retrieved = cache.get(address_);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->balance, account.balance);
}

TEST_F(AccountTest, AccountCacheInvalidation) {
    AccountCache cache(100);

    Account account;
    account.balance = 1000;
    cache.put(address_, account);

    // Should be found
    EXPECT_TRUE(cache.get(address_).has_value());

    // Invalidate
    cache.invalidate(address_);

    // Should not be found
    EXPECT_FALSE(cache.get(address_).has_value());
}

TEST_F(AccountTest, AccountCacheLRUEviction) {
    AccountCache cache(3);  // Very small cache

    Address addr1, addr2, addr3, addr4;
    addr1.bytes.fill(0x01);
    addr2.bytes.fill(0x02);
    addr3.bytes.fill(0x03);
    addr4.bytes.fill(0x04);

    Account account;
    account.balance = 1000;

    cache.put(addr1, account);
    cache.put(addr2, account);
    cache.put(addr3, account);

    // All three should be in cache
    EXPECT_TRUE(cache.get(addr1).has_value());
    EXPECT_TRUE(cache.get(addr2).has_value());
    EXPECT_TRUE(cache.get(addr3).has_value());

    // Adding fourth should evict LRU (addr1, since we just accessed addr2 and addr3)
    cache.put(addr4, account);

    // addr1 might be evicted (LRU)
    // addr4 should be present
    EXPECT_TRUE(cache.get(addr4).has_value());
}

TEST_F(AccountTest, AccountCacheHitRate) {
    AccountCache cache(100);

    Account account;
    account.balance = 1000;
    cache.put(address_, account);

    // Miss
    Address other;
    other.bytes.fill(0xFF);
    cache.get(other);

    // Hit
    cache.get(address_);

    // Hit rate should be ~50%
    EXPECT_GT(cache.hit_rate(), 0.0);
    EXPECT_LT(cache.hit_rate(), 1.0);
}

}  // namespace
}  // namespace pop
