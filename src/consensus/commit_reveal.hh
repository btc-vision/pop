#pragma once

#include "core/types.hh"
#include "ordering.hh"
#include "vdf.hh"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

namespace pop {

// ============================================================================
// State Expectation Types
// ============================================================================

enum class ExpectationType : std::uint8_t {
    BALANCE_EQ = 0,      // Balance equals value
    BALANCE_GE = 1,      // Balance >= value
    BALANCE_LE = 2,      // Balance <= value
    BALANCE_RANGE = 3,   // Balance in [value, max_value]
    STORAGE_EQ = 4,      // Storage slot equals value
    STORAGE_NE = 5,      // Storage slot not equals value
    NONCE_EQ = 6,        // Nonce equals value
    OUTPUT_IN_RANGE = 7, // Output in specified range
};

struct StateExpectation {
    ExpectationType type;
    Address address;
    std::optional<hash_t> key;          // For storage expectations
    hash_t value;
    std::optional<hash_t> max_value;    // For range expectations

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<StateExpectation> deserialize(
        std::span<const std::uint8_t> data);
};

struct ExpectationSet {
    std::vector<StateExpectation> expectations;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<ExpectationSet> deserialize(
        std::span<const std::uint8_t> data);

    // Helper methods to add expectations
    void add_balance_eq(const Address& addr, std::uint64_t value);
    void add_balance_ge(const Address& addr, std::uint64_t value);
    void add_balance_le(const Address& addr, std::uint64_t value);
    void add_balance_range(const Address& addr, std::uint64_t min_val, std::uint64_t max_val);
    void add_storage_eq(const Address& addr, const hash_t& key, const hash_t& value);
    void add_storage_ne(const Address& addr, const hash_t& key, const hash_t& value);
    void add_nonce_eq(const Address& addr, std::uint64_t nonce);
};

// ============================================================================
// Access Key - Address + Storage Key pair
// ============================================================================

struct AccessKey {
    Address address;
    hash_t key;

    auto operator<=>(const AccessKey&) const = default;

    struct Hash {
        std::size_t operator()(const AccessKey& ak) const {
            // FNV-1a hash
            constexpr std::size_t FNV_OFFSET = 14695981039346656037ULL;
            constexpr std::size_t FNV_PRIME = 1099511628211ULL;
            std::size_t h = FNV_OFFSET;
            for (auto b : ak.address.bytes) {
                h ^= b;
                h *= FNV_PRIME;
            }
            for (auto b : ak.key) {
                h ^= b;
                h *= FNV_PRIME;
            }
            return h;
        }
    };

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<AccessKey> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE = ADDRESS_SIZE + HASH_SIZE;
};

// ============================================================================
// Declared Access Set - Superset of possible reads/writes
// ============================================================================

struct DeclaredAccessSet {
    std::vector<AccessKey> read_set;   // Superset of possible reads
    std::vector<AccessKey> write_set;  // Superset of possible writes

    [[nodiscard]] bool can_read(const AccessKey& key) const;
    [[nodiscard]] bool can_write(const AccessKey& key) const;
    [[nodiscard]] bool overlaps(const DeclaredAccessSet& other) const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<DeclaredAccessSet> deserialize(
        std::span<const std::uint8_t> data);

    // Create from address lists (with empty keys)
    [[nodiscard]] static DeclaredAccessSet from_addresses(
        const std::vector<Address>& read_addrs,
        const std::vector<Address>& write_addrs);
};

// ============================================================================
// Commit Message V2
// ============================================================================

struct CommitMessageV2 {
    static constexpr std::uint8_t VERSION = 2;

    std::uint8_t version = VERSION;
    std::uint32_t chain_id;
    CommitHeader header;
    hash_t payload_hash;                     // SHA3(decrypted payload)
    std::vector<std::uint8_t> encrypted_payload;
    mldsa_public_key_t sender;
    nonce_t nonce;
    slot_t reference_slot;                   // For state reference
    slot_t commit_slot;
    lmots_public_key_t one_time_public_key;  // LM-OTS for reveal binding
    mldsa_signature_t signature;

    [[nodiscard]] Position2D position_2d() const;
    [[nodiscard]] hash_t commit_hash() const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<CommitMessageV2> deserialize(
        std::span<const std::uint8_t> data);

    [[nodiscard]] bool verify_signature() const;
};

// ============================================================================
// Reveal Message V2
// ============================================================================

struct RevealMessageV2 {
    hash_t commit_hash;
    aes_key_t decryption_key;
    std::uint64_t target_vdf_start;          // VDF step range for execution
    std::uint64_t target_vdf_end;
    ExpectationSet state_expectations;
    DeclaredAccessSet declared_access;
    std::uint64_t receipt_reward_pool;       // For batch receipt signers
    lmots_signature_t one_time_signature;    // Binds reveal to VDF range

    [[nodiscard]] hash_t reveal_hash() const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<RevealMessageV2> deserialize(
        std::span<const std::uint8_t> data);

    [[nodiscard]] bool verify_one_time_signature(
        const lmots_public_key_t& one_time_pk) const;

    [[nodiscard]] bool is_in_vdf_range(std::uint64_t current_step) const;
    [[nodiscard]] bool has_expired(std::uint64_t current_step) const;
};

// ============================================================================
// Commit Pool - Manages pending commits
// ============================================================================

class CommitPool {
public:
    CommitPool() = default;

    // Add a commit to the pool
    enum class AddResult {
        ADDED,
        DUPLICATE,
        INVALID_SIGNATURE,
        INVALID_NONCE,
        POOL_FULL,
    };
    AddResult add_commit(const CommitMessageV2& commit);

    // Get commit by hash
    [[nodiscard]] std::optional<CommitMessageV2> get_commit(const hash_t& commit_hash) const;

    // Check if commit exists
    [[nodiscard]] bool has_commit(const hash_t& commit_hash) const;

    // Get commits for a position
    [[nodiscard]] std::vector<CommitMessageV2> get_commits_at_position(position_t pos) const;

    // Remove commit
    bool remove_commit(const hash_t& commit_hash);

    // Get all commit hashes
    [[nodiscard]] std::vector<hash_t> get_all_hashes() const;

    // Pool size
    [[nodiscard]] std::size_t size() const;

    // Prune old commits
    void prune(slot_t before_slot);

private:
    std::unordered_map<hash_t, CommitMessageV2> commits_;
    std::unordered_map<position_t, std::vector<hash_t>> by_position_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Reveal Pool - Manages pending reveals
// ============================================================================

class RevealPool {
public:
    RevealPool() = default;

    // Add a reveal to the pool
    enum class AddResult {
        ADDED,
        DUPLICATE,
        COMMIT_NOT_FOUND,
        INVALID_SIGNATURE,
        EXPIRED,
        VDF_RANGE_INVALID,
    };
    AddResult add_reveal(
        const RevealMessageV2& reveal,
        const CommitPool& commit_pool,
        std::uint64_t current_vdf_step);

    // Get reveal by hash
    [[nodiscard]] std::optional<RevealMessageV2> get_reveal(const hash_t& reveal_hash) const;

    // Get reveal for a commit
    [[nodiscard]] std::optional<RevealMessageV2> get_reveal_for_commit(
        const hash_t& commit_hash) const;

    // Check if reveal exists
    [[nodiscard]] bool has_reveal(const hash_t& reveal_hash) const;

    // Get all reveals in VDF range
    [[nodiscard]] std::vector<RevealMessageV2> get_reveals_in_range(
        std::uint64_t vdf_start, std::uint64_t vdf_end) const;

    // Get all reveals for an epoch
    [[nodiscard]] std::vector<RevealMessageV2> get_epoch_reveals(tx_epoch_t epoch) const;

    // Remove reveal
    bool remove_reveal(const hash_t& reveal_hash);

    // Pool size
    [[nodiscard]] std::size_t size() const;

    // Prune expired reveals
    void prune_expired(std::uint64_t current_vdf_step);

private:
    std::unordered_map<hash_t, RevealMessageV2> reveals_;  // By reveal_hash
    std::unordered_map<hash_t, hash_t> by_commit_;         // commit_hash -> reveal_hash
    mutable std::mutex mutex_;
};

// ============================================================================
// Execution Context - What's needed to execute a transaction
// ============================================================================

struct ExecutionContext {
    CommitMessageV2 commit;
    RevealMessageV2 reveal;
    std::vector<std::uint8_t> decrypted_payload;
    Position2D position;

    // Computed fields
    hash_t tx_hash;
    Address sender_address;

    [[nodiscard]] static std::optional<ExecutionContext> create(
        const CommitMessageV2& commit,
        const RevealMessageV2& reveal);
};

// ============================================================================
// Transaction Ordering - Sort transactions for execution
// ============================================================================

class TransactionOrdering {
public:
    // Add an execution context
    void add(ExecutionContext ctx);

    // Get ordered transactions (sorted by position)
    [[nodiscard]] std::vector<ExecutionContext> get_ordered() const;

    // Identify parallel groups (non-overlapping access sets)
    [[nodiscard]] std::vector<std::vector<std::size_t>> get_parallel_groups() const;

    // Clear all
    void clear();

private:
    std::vector<ExecutionContext> contexts_;
    mutable std::mutex mutex_;
};

}  // namespace pop
