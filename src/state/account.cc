#include "account.hh"
#include "crypto/hash.hh"
#include "core/logging.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// Account Implementation
// ============================================================================

std::uint64_t Account::storage_size() const {
    return RentConfig::BASE_ACCOUNT_OVERHEAD +
           code_size +
           (storage_slot_count * RentConfig::STORAGE_SLOT_SIZE);
}

std::uint64_t Account::rent_due(std::uint64_t epochs) const {
    return storage_size() * RentConfig::RENT_RATE_PER_BYTE_PER_EPOCH * epochs;
}

bool Account::should_become_dormant() const {
    return rent_balance == 0 && dormancy_state == DormancyState::ACTIVE;
}

bool Account::should_be_pruned(tx_epoch_t current_epoch) const {
    if (dormancy_state != DormancyState::DORMANT) {
        return false;
    }
    return (current_epoch - dormant_since_epoch) >= RentConfig::PRUNE_THRESHOLD_EPOCHS;
}

std::vector<std::uint8_t> Account::serialize() const {
    std::vector<std::uint8_t> result(BASE_SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    encode_u64(ptr, balance);
    ptr += sizeof(std::uint64_t);

    encode_u64(ptr, nonce);
    ptr += sizeof(std::uint64_t);

    std::copy(code_hash.begin(), code_hash.end(), ptr);
    ptr += HASH_SIZE;

    std::copy(storage_root.begin(), storage_root.end(), ptr);
    ptr += HASH_SIZE;

    encode_u64(ptr, rent_balance);
    ptr += sizeof(std::uint64_t);

    encode_u64(ptr, code_size);
    ptr += sizeof(std::uint64_t);

    encode_u64(ptr, storage_slot_count);
    ptr += sizeof(std::uint64_t);

    encode_u64(ptr, last_rent_epoch);
    ptr += sizeof(tx_epoch_t);

    *ptr = static_cast<std::uint8_t>(dormancy_state);
    ptr += sizeof(DormancyState);

    encode_u64(ptr, dormant_since_epoch);

    return result;
}

std::optional<Account> Account::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < BASE_SERIALIZED_SIZE) {
        return std::nullopt;
    }

    Account account;
    const std::uint8_t* ptr = data.data();

    account.balance = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    account.nonce = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    std::copy(ptr, ptr + HASH_SIZE, account.code_hash.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, account.storage_root.begin());
    ptr += HASH_SIZE;

    account.rent_balance = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    account.code_size = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    account.storage_slot_count = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    account.last_rent_epoch = decode_u64(ptr);
    ptr += sizeof(tx_epoch_t);

    account.dormancy_state = static_cast<DormancyState>(*ptr);
    ptr += sizeof(DormancyState);

    account.dormant_since_epoch = decode_u64(ptr);

    return account;
}

// ============================================================================
// StorageSlot Implementation
// ============================================================================

std::vector<std::uint8_t> StorageSlot::serialize() const {
    std::vector<std::uint8_t> result(HASH_SIZE * 2);
    std::copy(key.begin(), key.end(), result.data());
    std::copy(value.begin(), value.end(), result.data() + HASH_SIZE);
    return result;
}

std::optional<StorageSlot> StorageSlot::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < HASH_SIZE * 2) {
        return std::nullopt;
    }

    StorageSlot slot;
    std::copy(data.data(), data.data() + HASH_SIZE, slot.key.begin());
    std::copy(data.data() + HASH_SIZE, data.data() + HASH_SIZE * 2, slot.value.begin());
    return slot;
}

// ============================================================================
// AccountWithStorage Implementation
// ============================================================================

std::vector<std::uint8_t> AccountWithStorage::serialize() const {
    std::vector<std::uint8_t> result;

    // Serialize account
    auto account_bytes = account.serialize();
    result.insert(result.end(), account_bytes.begin(), account_bytes.end());

    // Code length and data
    std::array<std::uint8_t, 4> code_len_bytes;
    encode_u32(code_len_bytes.data(), static_cast<std::uint32_t>(code.size()));
    result.insert(result.end(), code_len_bytes.begin(), code_len_bytes.end());
    result.insert(result.end(), code.begin(), code.end());

    // Storage slot count and data
    std::array<std::uint8_t, 4> storage_count_bytes;
    encode_u32(storage_count_bytes.data(), static_cast<std::uint32_t>(storage.size()));
    result.insert(result.end(), storage_count_bytes.begin(), storage_count_bytes.end());

    for (const auto& [key, value] : storage) {
        result.insert(result.end(), key.begin(), key.end());
        result.insert(result.end(), value.begin(), value.end());
    }

    return result;
}

std::optional<AccountWithStorage> AccountWithStorage::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < Account::BASE_SERIALIZED_SIZE + sizeof(std::uint32_t) * 2) {
        return std::nullopt;
    }

    AccountWithStorage result;

    // Deserialize account
    auto account_opt = Account::deserialize(data);
    if (!account_opt) {
        return std::nullopt;
    }
    result.account = *account_opt;

    const std::uint8_t* ptr = data.data() + Account::BASE_SERIALIZED_SIZE;
    const std::uint8_t* end = data.data() + data.size();

    // Code
    if (ptr + sizeof(std::uint32_t) > end) {
        return std::nullopt;
    }
    std::uint32_t code_len = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    if (ptr + code_len > end) {
        return std::nullopt;
    }
    result.code.assign(ptr, ptr + code_len);
    ptr += code_len;

    // Storage
    if (ptr + sizeof(std::uint32_t) > end) {
        return std::nullopt;
    }
    std::uint32_t storage_count = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    for (std::uint32_t i = 0; i < storage_count; ++i) {
        if (ptr + HASH_SIZE * 2 > end) {
            return std::nullopt;
        }
        hash_t key, value;
        std::copy(ptr, ptr + HASH_SIZE, key.begin());
        ptr += HASH_SIZE;
        std::copy(ptr, ptr + HASH_SIZE, value.begin());
        ptr += HASH_SIZE;
        result.storage[key] = value;
    }

    return result;
}

// ============================================================================
// ArchivedAccount Implementation
// ============================================================================

std::vector<std::uint8_t> ArchivedAccount::serialize() const {
    std::vector<std::uint8_t> result;

    // Address
    result.insert(result.end(), address.bytes.begin(), address.bytes.end());

    // State
    auto state_bytes = state.serialize();
    std::array<std::uint8_t, 4> state_len_bytes;
    encode_u32(state_len_bytes.data(), static_cast<std::uint32_t>(state_bytes.size()));
    result.insert(result.end(), state_len_bytes.begin(), state_len_bytes.end());
    result.insert(result.end(), state_bytes.begin(), state_bytes.end());

    // Epoch
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), pruned_at_epoch);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    // Archive root
    result.insert(result.end(), archive_root.begin(), archive_root.end());

    return result;
}

std::optional<ArchivedAccount> ArchivedAccount::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < ADDRESS_SIZE + sizeof(std::uint32_t)) {
        return std::nullopt;
    }

    ArchivedAccount result;
    const std::uint8_t* ptr = data.data();
    const std::uint8_t* end = data.data() + data.size();

    // Address
    std::copy(ptr, ptr + ADDRESS_SIZE, result.address.bytes.begin());
    ptr += ADDRESS_SIZE;

    // State length
    if (ptr + sizeof(std::uint32_t) > end) {
        return std::nullopt;
    }
    std::uint32_t state_len = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    if (ptr + state_len > end) {
        return std::nullopt;
    }
    auto state_opt = AccountWithStorage::deserialize({ptr, state_len});
    if (!state_opt) {
        return std::nullopt;
    }
    result.state = std::move(*state_opt);
    ptr += state_len;

    // Epoch
    if (ptr + sizeof(tx_epoch_t) > end) {
        return std::nullopt;
    }
    result.pruned_at_epoch = decode_u64(ptr);
    ptr += sizeof(tx_epoch_t);

    // Archive root
    if (ptr + HASH_SIZE > end) {
        return std::nullopt;
    }
    std::copy(ptr, ptr + HASH_SIZE, result.archive_root.begin());

    return result;
}

// ============================================================================
// RentProcessor Implementation
// ============================================================================

RentResult RentProcessor::process_epoch(tx_epoch_t epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    POP_LOG_DEBUG(log::state) << "Processing rent for epoch " << epoch;

    RentResult result;

    for (auto& [addr, account_state] : accounts_) {
        auto& account = account_state.account;

        // Skip already dormant/pruned
        if (account.dormancy_state != DormancyState::ACTIVE) {
            // Check if should be pruned
            if (account.should_be_pruned(epoch)) {
                prune_to_archive(addr, epoch);
                result.accounts_pruned++;
                result.newly_pruned.push_back(addr);
            }
            continue;
        }

        // Calculate epochs since last rent
        tx_epoch_t epochs_since = epoch - account.last_rent_epoch;
        if (epochs_since == 0) {
            continue;
        }

        std::uint64_t rent_owed = account.rent_due(epochs_since);

        if (account.rent_balance >= rent_owed) {
            // Pay rent
            account.rent_balance -= rent_owed;
            result.total_rent_collected += rent_owed;
            result.accounts_charged++;
        } else {
            // Partial payment, then dormant
            result.total_rent_collected += account.rent_balance;
            account.rent_balance = 0;
            result.accounts_charged++;
        }

        account.last_rent_epoch = epoch;

        // Check if should become dormant
        if (account.should_become_dormant()) {
            account.dormancy_state = DormancyState::DORMANT;
            account.dormant_since_epoch = epoch;
            result.accounts_made_dormant++;
            result.newly_dormant.push_back(addr);
            POP_LOG_DEBUG(log::state) << "Account made dormant at epoch " << epoch;
        }
    }

    if (result.accounts_made_dormant > 0 || result.accounts_pruned > 0) {
        POP_LOG_INFO(log::state) << "Rent epoch " << epoch << ": collected "
                                  << result.total_rent_collected << ", "
                                  << result.accounts_charged << " charged, "
                                  << result.accounts_made_dormant << " dormant, "
                                  << result.accounts_pruned << " pruned";
    }

    return result;
}

void RentProcessor::make_dormant(const Address& addr, tx_epoch_t epoch) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return;
    }

    it->second.account.dormancy_state = DormancyState::DORMANT;
    it->second.account.dormant_since_epoch = epoch;
    it->second.account.rent_balance = 0;
}

void RentProcessor::prune_to_archive(const Address& addr, tx_epoch_t epoch) {
    // Note: Called with mutex held from process_epoch
    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return;
    }

    // Create archived account
    ArchivedAccount archived;
    archived.address = addr;
    archived.state = std::move(it->second);
    archived.pruned_at_epoch = epoch;

    // Compute archive root
    auto serialized = archived.state.serialize();
    archived.archive_root = sha3_256(serialized);

    // Move to archive
    archive_[addr] = std::move(archived);

    // Mark as pruned (keep minimal entry for lookup)
    it->second = AccountWithStorage{};
    it->second.account.dormancy_state = DormancyState::PRUNED;
    it->second.account.dormant_since_epoch = epoch;
}

ResurrectionResult RentProcessor::resurrect(
    const Address& addr,
    std::uint64_t payment,
    tx_epoch_t current_epoch) {

    std::lock_guard<std::mutex> lock(mutex_);

    ResurrectionResult result;

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        POP_LOG_DEBUG(log::state) << "Resurrection failed: account not found";
        result.failure_reason = ResurrectionResult::FailureReason::ACCOUNT_NOT_FOUND;
        return result;
    }

    auto& account = it->second.account;

    if (account.dormancy_state == DormancyState::PRUNED) {
        POP_LOG_DEBUG(log::state) << "Resurrection failed: account pruned";
        result.failure_reason = ResurrectionResult::FailureReason::ACCOUNT_PRUNED;
        return result;
    }

    if (account.dormancy_state != DormancyState::DORMANT) {
        POP_LOG_DEBUG(log::state) << "Resurrection failed: account not dormant";
        result.failure_reason = ResurrectionResult::FailureReason::ACCOUNT_NOT_DORMANT;
        return result;
    }

    // Calculate resurrection cost
    tx_epoch_t epochs_dormant = current_epoch - account.dormant_since_epoch;
    std::uint64_t back_rent = account.rent_due(epochs_dormant);
    std::uint64_t buffer = account.rent_due(RentConfig::RESURRECTION_BUFFER_EPOCHS);
    std::uint64_t total_cost = back_rent + buffer;

    if (payment < total_cost) {
        POP_LOG_DEBUG(log::state) << "Resurrection failed: insufficient payment " << payment << " < " << total_cost;
        result.failure_reason = ResurrectionResult::FailureReason::INSUFFICIENT_PAYMENT;
        return result;
    }

    // Resurrect
    account.dormancy_state = DormancyState::ACTIVE;
    account.dormant_since_epoch = 0;
    account.last_rent_epoch = current_epoch;
    account.rent_balance = payment - back_rent;

    result.success = true;
    result.rent_paid = back_rent;
    result.buffer_deposited = payment - back_rent;

    POP_LOG_INFO(log::state) << "Account resurrected after " << epochs_dormant
                              << " dormant epochs, paid " << back_rent << " back rent";

    return result;
}

ResurrectionResult RentProcessor::resurrect_from_archive(
    const Address& addr,
    const ArchivedAccount& archived,
    const std::vector<hash_t>& merkle_proof,
    std::uint64_t payment,
    tx_epoch_t current_epoch) {

    std::lock_guard<std::mutex> lock(mutex_);

    ResurrectionResult result;

    // Verify the archive proof
    auto serialized = archived.state.serialize();
    hash_t computed_root = sha3_256(serialized);

    if (computed_root != archived.archive_root) {
        result.failure_reason = ResurrectionResult::FailureReason::ARCHIVE_PROOF_INVALID;
        return result;
    }

    // Check account exists and is pruned
    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        result.failure_reason = ResurrectionResult::FailureReason::ACCOUNT_NOT_FOUND;
        return result;
    }

    if (it->second.account.dormancy_state != DormancyState::PRUNED) {
        result.failure_reason = ResurrectionResult::FailureReason::ACCOUNT_NOT_DORMANT;
        return result;
    }

    // Calculate resurrection cost
    tx_epoch_t epochs_since_prune = current_epoch - archived.pruned_at_epoch;
    const auto& account = archived.state.account;
    std::uint64_t back_rent = account.rent_due(epochs_since_prune);
    std::uint64_t buffer = account.rent_due(RentConfig::RESURRECTION_BUFFER_EPOCHS);
    std::uint64_t total_cost = back_rent + buffer;

    if (payment < total_cost) {
        result.failure_reason = ResurrectionResult::FailureReason::INSUFFICIENT_PAYMENT;
        return result;
    }

    // Restore from archive
    it->second = archived.state;
    it->second.account.dormancy_state = DormancyState::ACTIVE;
    it->second.account.dormant_since_epoch = 0;
    it->second.account.last_rent_epoch = current_epoch;
    it->second.account.rent_balance = payment - back_rent;

    // Remove from archive
    archive_.erase(addr);

    result.success = true;
    result.rent_paid = back_rent;
    result.buffer_deposited = payment - back_rent;

    return result;
}

std::optional<Account> RentProcessor::get_account(const Address& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return std::nullopt;
    }

    // Don't return dormant or pruned accounts
    if (it->second.account.dormancy_state != DormancyState::ACTIVE) {
        return std::nullopt;
    }

    return it->second.account;
}

std::optional<Account> RentProcessor::get_account_full(const Address& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return std::nullopt;
    }

    return it->second.account;
}

void RentProcessor::set_account(const Address& addr, const Account& account) {
    std::lock_guard<std::mutex> lock(mutex_);
    accounts_[addr].account = account;
}

bool RentProcessor::is_dormant(const Address& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return false;
    }

    return it->second.account.dormancy_state == DormancyState::DORMANT;
}

bool RentProcessor::is_pruned(const Address& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return false;
    }

    return it->second.account.dormancy_state == DormancyState::PRUNED;
}

std::optional<hash_t> RentProcessor::get_storage(
    const Address& addr,
    const hash_t& key) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return std::nullopt;
    }

    if (it->second.account.dormancy_state != DormancyState::ACTIVE) {
        return std::nullopt;
    }

    auto storage_it = it->second.storage.find(key);
    if (storage_it == it->second.storage.end()) {
        return std::nullopt;
    }

    return storage_it->second;
}

void RentProcessor::set_storage(
    const Address& addr,
    const hash_t& key,
    const hash_t& value) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto& account_state = accounts_[addr];

    // Check if this is a new slot
    hash_t zero{};
    bool was_empty = account_state.storage.find(key) == account_state.storage.end() ||
                     account_state.storage[key] == zero;
    bool is_empty = value == zero;

    if (was_empty && !is_empty) {
        account_state.account.storage_slot_count++;
    } else if (!was_empty && is_empty) {
        account_state.account.storage_slot_count--;
    }

    if (is_empty) {
        account_state.storage.erase(key);
    } else {
        account_state.storage[key] = value;
    }
}

std::vector<std::uint8_t> RentProcessor::get_code(const Address& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return {};
    }

    if (it->second.account.dormancy_state != DormancyState::ACTIVE) {
        return {};
    }

    return it->second.code;
}

void RentProcessor::set_code(const Address& addr, std::span<const std::uint8_t> code) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& account_state = accounts_[addr];
    account_state.code.assign(code.begin(), code.end());
    account_state.account.code_size = code.size();
    account_state.account.code_hash = sha3_256(code);
}

RentProcessor::TransferResult RentProcessor::transfer(
    const Address& from,
    const Address& to,
    std::uint64_t amount) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto from_it = accounts_.find(from);
    if (from_it == accounts_.end()) {
        POP_LOG_DEBUG(log::state) << "Transfer failed: sender not found";
        return TransferResult::SENDER_NOT_FOUND;
    }

    if (from_it->second.account.dormancy_state != DormancyState::ACTIVE) {
        POP_LOG_DEBUG(log::state) << "Transfer failed: sender dormant";
        return TransferResult::SENDER_DORMANT;
    }

    if (from_it->second.account.balance < amount) {
        POP_LOG_DEBUG(log::state) << "Transfer failed: insufficient balance "
                                   << from_it->second.account.balance << " < " << amount;
        return TransferResult::INSUFFICIENT_BALANCE;
    }

    // Perform transfer
    from_it->second.account.balance -= amount;
    accounts_[to].account.balance += amount;

    POP_LOG_TRACE(log::state) << "Transfer: " << amount << " units";
    return TransferResult::SUCCESS;
}

void RentProcessor::deposit_rent(const Address& addr, std::uint64_t amount) {
    std::lock_guard<std::mutex> lock(mutex_);
    accounts_[addr].account.rent_balance += amount;
}

std::size_t RentProcessor::account_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return accounts_.size();
}

std::size_t RentProcessor::active_account_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t count = 0;
    for (const auto& [addr, state] : accounts_) {
        if (state.account.dormancy_state == DormancyState::ACTIVE) {
            count++;
        }
    }
    return count;
}

std::size_t RentProcessor::dormant_account_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t count = 0;
    for (const auto& [addr, state] : accounts_) {
        if (state.account.dormancy_state == DormancyState::DORMANT) {
            count++;
        }
    }
    return count;
}

void RentProcessor::charge_rent(const Address& addr, tx_epoch_t current_epoch) {
    // Called with mutex held
    auto it = accounts_.find(addr);
    if (it == accounts_.end()) {
        return;
    }

    auto& account = it->second.account;
    tx_epoch_t epochs_since = current_epoch - account.last_rent_epoch;
    if (epochs_since == 0) {
        return;
    }

    std::uint64_t rent_owed = account.rent_due(epochs_since);
    if (account.rent_balance >= rent_owed) {
        account.rent_balance -= rent_owed;
    } else {
        account.rent_balance = 0;
    }
    account.last_rent_epoch = current_epoch;
}

std::uint64_t RentProcessor::calculate_resurrection_cost(
    const Account& account,
    tx_epoch_t epochs_dormant) const {

    std::uint64_t back_rent = account.rent_due(epochs_dormant);
    std::uint64_t buffer = account.rent_due(RentConfig::RESURRECTION_BUFFER_EPOCHS);
    return back_rent + buffer;
}

// ============================================================================
// StateRootComputer Implementation
// ============================================================================

StateRootComputer::StateRootComputer(const RentProcessor& processor)
    : processor_(processor) {}

hash_t StateRootComputer::compute_state_root() const {
    // Build Merkle tree from all accounts
    std::vector<hash_t> leaves;

    // Get all accounts - we need to access the internal data
    // For now, use a simplified approach
    SHA3Hasher hasher;
    hasher.update("state_root", 10);

    // This would need access to processor internals in practice
    // For now, return a placeholder
    return hasher.finalize();
}

hash_t StateRootComputer::compute_partial_root(
    const std::vector<Address>& addresses) const {

    std::vector<hash_t> leaves;
    leaves.reserve(addresses.size());

    for (const auto& addr : addresses) {
        auto account_opt = processor_.get_account_full(addr);
        if (account_opt) {
            auto serialized = account_opt->serialize();
            leaves.push_back(sha3_256(serialized));
        }
    }

    if (leaves.empty()) {
        hash_t empty{};
        return empty;
    }

    MerkleTree tree(leaves);
    return tree.root();
}

std::vector<hash_t> StateRootComputer::generate_account_proof(
    const Address& addr) const {

    // Would need full account list to generate proper proof
    // Placeholder implementation
    return {};
}

bool StateRootComputer::verify_account_proof(
    const Address& addr,
    const Account& account,
    const std::vector<hash_t>& proof,
    const hash_t& state_root) const {

    if (proof.empty()) {
        return false;
    }

    auto serialized = account.serialize();
    hash_t leaf = sha3_256(serialized);

    // Verify Merkle proof
    // For a proper implementation, we'd need the account index
    // Placeholder: check if first proof element matches leaf
    return proof[0] == leaf;
}

// ============================================================================
// AccountCache Implementation
// ============================================================================

AccountCache::AccountCache(std::size_t max_size)
    : max_size_(max_size) {}

std::optional<Account> AccountCache::get(const Address& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_.find(addr);
    if (it == cache_.end()) {
        misses_++;
        return std::nullopt;
    }

    hits_++;
    // Note: Can't update last_access in const method without mutable
    return it->second.account;
}

void AccountCache::put(const Address& addr, const Account& account) {
    std::lock_guard<std::mutex> lock(mutex_);

    evict_if_needed();

    CacheEntry entry;
    entry.account = account;
    entry.last_access = access_counter_++;

    cache_[addr] = entry;
}

void AccountCache::invalidate(const Address& addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.erase(addr);
}

void AccountCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

double AccountCache::hit_rate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::uint64_t total = hits_ + misses_;
    if (total == 0) {
        return 0.0;
    }
    return static_cast<double>(hits_) / static_cast<double>(total);
}

void AccountCache::evict_if_needed() {
    // Called with mutex held
    while (cache_.size() >= max_size_) {
        // Find LRU entry
        auto lru_it = cache_.begin();
        std::uint64_t oldest = lru_it->second.last_access;

        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (it->second.last_access < oldest) {
                oldest = it->second.last_access;
                lru_it = it;
            }
        }

        cache_.erase(lru_it);
    }
}

}  // namespace pop
