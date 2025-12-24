#pragma once

#include "core/types.hh"
#include <unordered_map>
#include <vector>
#include <mutex>
#include <optional>

namespace pop {

// ============================================================================
// Rent Configuration
// ============================================================================

struct RentConfig {
    static constexpr std::uint64_t RENT_RATE_PER_BYTE_PER_EPOCH = 1;
    static constexpr std::uint64_t BASE_ACCOUNT_OVERHEAD = 128;
    static constexpr std::uint64_t STORAGE_SLOT_SIZE = 32;
    static constexpr tx_epoch_t DORMANCY_THRESHOLD_EPOCHS = 100;
    static constexpr tx_epoch_t PRUNE_THRESHOLD_EPOCHS = 1000;
    static constexpr tx_epoch_t RESURRECTION_BUFFER_EPOCHS = 50;
    static constexpr std::uint64_t MIN_RENT_BALANCE = 10000;
};

// ============================================================================
// Account State
// ============================================================================

struct Account {
    // Core state
    std::uint64_t balance = 0;
    std::uint64_t nonce = 0;
    hash_t code_hash;
    hash_t storage_root;

    // Rent fields
    std::uint64_t rent_balance = 0;
    std::uint64_t code_size = 0;
    std::uint64_t storage_slot_count = 0;
    tx_epoch_t last_rent_epoch = 0;
    DormancyState dormancy_state = DormancyState::ACTIVE;
    tx_epoch_t dormant_since_epoch = 0;

    // Calculate total storage size
    [[nodiscard]] std::uint64_t storage_size() const;

    // Calculate rent due for given epochs
    [[nodiscard]] std::uint64_t rent_due(std::uint64_t epochs) const;

    // Check if account should become dormant
    [[nodiscard]] bool should_become_dormant() const;

    // Check if account should be pruned
    [[nodiscard]] bool should_be_pruned(tx_epoch_t current_epoch) const;

    // Serialization
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<Account> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t BASE_SERIALIZED_SIZE =
        sizeof(std::uint64_t) * 5 +    // balance, nonce, rent_balance, code_size, storage_slot_count
        HASH_SIZE * 2 +                 // code_hash, storage_root
        sizeof(tx_epoch_t) * 2 +        // last_rent_epoch, dormant_since_epoch
        sizeof(DormancyState);          // dormancy_state
};

// ============================================================================
// Storage Slot
// ============================================================================

struct StorageSlot {
    hash_t key;
    hash_t value;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<StorageSlot> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Account with Storage - Full account state
// ============================================================================

struct AccountWithStorage {
    Account account;
    std::unordered_map<hash_t, hash_t> storage;
    std::vector<std::uint8_t> code;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<AccountWithStorage> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Rent Result
// ============================================================================

struct RentResult {
    std::uint64_t total_rent_collected = 0;
    std::size_t accounts_charged = 0;
    std::size_t accounts_made_dormant = 0;
    std::size_t accounts_pruned = 0;
    std::vector<Address> newly_dormant;
    std::vector<Address> newly_pruned;
};

// ============================================================================
// Resurrection Result
// ============================================================================

struct ResurrectionResult {
    bool success = false;
    std::uint64_t rent_paid = 0;
    std::uint64_t buffer_deposited = 0;

    enum class FailureReason {
        NONE,
        ACCOUNT_NOT_DORMANT,
        ACCOUNT_PRUNED,
        INSUFFICIENT_PAYMENT,
        ACCOUNT_NOT_FOUND,
        ARCHIVE_PROOF_INVALID,
    };
    FailureReason failure_reason = FailureReason::NONE;
};

// ============================================================================
// Archived Account - For pruned accounts
// ============================================================================

struct ArchivedAccount {
    Address address;
    AccountWithStorage state;
    tx_epoch_t pruned_at_epoch;
    hash_t archive_root;  // Merkle root for verification

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<ArchivedAccount> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Rent Processor
// ============================================================================

class RentProcessor {
public:
    RentProcessor() = default;

    // Process rent for an epoch
    RentResult process_epoch(tx_epoch_t epoch);

    // Make account dormant
    void make_dormant(const Address& addr, tx_epoch_t epoch);

    // Prune account to archive
    void prune_to_archive(const Address& addr, tx_epoch_t epoch);

    // Resurrect dormant account
    ResurrectionResult resurrect(
        const Address& addr,
        std::uint64_t payment,
        tx_epoch_t current_epoch);

    // Resurrect from archive with proof
    ResurrectionResult resurrect_from_archive(
        const Address& addr,
        const ArchivedAccount& archived,
        const std::vector<hash_t>& merkle_proof,
        std::uint64_t payment,
        tx_epoch_t current_epoch);

    // Get account (returns nullopt for dormant/pruned)
    [[nodiscard]] std::optional<Account> get_account(const Address& addr) const;

    // Get account state including dormancy info
    [[nodiscard]] std::optional<Account> get_account_full(const Address& addr) const;

    // Set account (for state updates)
    void set_account(const Address& addr, const Account& account);

    // Check dormancy status
    [[nodiscard]] bool is_dormant(const Address& addr) const;
    [[nodiscard]] bool is_pruned(const Address& addr) const;

    // Get storage
    [[nodiscard]] std::optional<hash_t> get_storage(
        const Address& addr,
        const hash_t& key) const;

    // Set storage
    void set_storage(
        const Address& addr,
        const hash_t& key,
        const hash_t& value);

    // Get code
    [[nodiscard]] std::vector<std::uint8_t> get_code(const Address& addr) const;

    // Set code
    void set_code(const Address& addr, std::span<const std::uint8_t> code);

    // Transfer balance
    enum class TransferResult {
        SUCCESS,
        INSUFFICIENT_BALANCE,
        SENDER_DORMANT,
        SENDER_NOT_FOUND,
    };
    TransferResult transfer(
        const Address& from,
        const Address& to,
        std::uint64_t amount);

    // Deposit rent
    void deposit_rent(const Address& addr, std::uint64_t amount);

    // Get total accounts
    [[nodiscard]] std::size_t account_count() const;

    // Get active accounts
    [[nodiscard]] std::size_t active_account_count() const;

    // Get dormant accounts
    [[nodiscard]] std::size_t dormant_account_count() const;

private:
    std::unordered_map<Address, AccountWithStorage> accounts_;
    std::unordered_map<Address, ArchivedAccount> archive_;
    mutable std::mutex mutex_;

    // Internal helpers
    void charge_rent(const Address& addr, tx_epoch_t current_epoch);
    std::uint64_t calculate_resurrection_cost(const Account& account, tx_epoch_t epochs_dormant) const;
};

// ============================================================================
// State Root Computation
// ============================================================================

class StateRootComputer {
public:
    explicit StateRootComputer(const RentProcessor& processor);

    // Compute Merkle root of all account states
    [[nodiscard]] hash_t compute_state_root() const;

    // Compute root for subset of accounts
    [[nodiscard]] hash_t compute_partial_root(
        const std::vector<Address>& addresses) const;

    // Generate proof for account
    [[nodiscard]] std::vector<hash_t> generate_account_proof(
        const Address& addr) const;

    // Verify account proof
    [[nodiscard]] bool verify_account_proof(
        const Address& addr,
        const Account& account,
        const std::vector<hash_t>& proof,
        const hash_t& state_root) const;

private:
    const RentProcessor& processor_;
};

// ============================================================================
// Account Cache - LRU cache for frequently accessed accounts
// ============================================================================

class AccountCache {
public:
    explicit AccountCache(std::size_t max_size = 10000);

    // Get from cache
    [[nodiscard]] std::optional<Account> get(const Address& addr) const;

    // Put in cache
    void put(const Address& addr, const Account& account);

    // Invalidate
    void invalidate(const Address& addr);

    // Clear all
    void clear();

    // Get hit rate
    [[nodiscard]] double hit_rate() const;

private:
    struct CacheEntry {
        Account account;
        std::uint64_t last_access;
    };

    std::unordered_map<Address, CacheEntry> cache_;
    std::size_t max_size_;
    mutable std::uint64_t access_counter_ = 0;
    mutable std::uint64_t hits_ = 0;
    mutable std::uint64_t misses_ = 0;
    mutable std::mutex mutex_;

    void evict_if_needed();
};

}  // namespace pop
