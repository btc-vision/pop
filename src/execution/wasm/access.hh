#pragma once

#include "core/types.hh"
#include "consensus/ordering.hh"
#include "consensus/commit_reveal.hh"
#include "state/account.hh"
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <optional>
#include <functional>

namespace pop {

// ============================================================================
// Access Violation
// ============================================================================

enum class AccessViolation : std::uint8_t {
    NONE = 0,
    UNDECLARED_READ = 1,
    UNDECLARED_WRITE = 2,
    DORMANT_ACCOUNT_ACCESS = 3,
    PRUNED_ACCOUNT_ACCESS = 4,
};

// ============================================================================
// Access Tracker - Enforces declared access sets during execution
// ============================================================================

class AccessTracker {
public:
    explicit AccessTracker(DeclaredAccessSet declared);

    // Check read access
    AccessViolation check_read(const Address& addr, const hash_t& key);

    // Check write access
    AccessViolation check_write(const Address& addr, const hash_t& key);

    // Check balance read (address only, no key)
    AccessViolation check_balance_read(const Address& addr);

    // Check balance write (transfer)
    AccessViolation check_balance_write(const Address& addr);

    // Check if any violation occurred
    [[nodiscard]] bool has_violation() const;

    // Get first violation
    [[nodiscard]] AccessViolation get_violation() const;

    // Get actual read set (subset of declared)
    [[nodiscard]] const std::unordered_set<AccessKey, AccessKey::Hash>& actual_reads() const;

    // Get actual write set (subset of declared)
    [[nodiscard]] const std::unordered_set<AccessKey, AccessKey::Hash>& actual_writes() const;

    // Reset tracker (for reuse)
    void reset();

private:
    DeclaredAccessSet declared_;
    std::unordered_set<AccessKey, AccessKey::Hash> actual_reads_;
    std::unordered_set<AccessKey, AccessKey::Hash> actual_writes_;
    AccessViolation violation_ = AccessViolation::NONE;

    // Build lookup sets for O(1) checks
    std::unordered_set<AccessKey, AccessKey::Hash> declared_reads_;
    std::unordered_set<AccessKey, AccessKey::Hash> declared_writes_;
};

// ============================================================================
// Metering Configuration
// ============================================================================

struct MeteringConfig {
    static constexpr std::uint64_t DEFAULT_INSTRUCTION_LIMIT = 10'000'000;
    static constexpr std::uint64_t MAX_INSTRUCTION_LIMIT = 100'000'000;
    static constexpr std::uint64_t INSTRUCTION_PRICE_SATOSHIS = 1;  // per 1000 instructions
    static constexpr std::uint64_t INSTRUCTION_UNIT = 1000;

    // Instruction costs
    static constexpr std::uint64_t COST_BASIC = 1;
    static constexpr std::uint64_t COST_MEMORY_OP = 2;
    static constexpr std::uint64_t COST_CONTROL_FLOW = 3;
    static constexpr std::uint64_t COST_CALL = 100;
    static constexpr std::uint64_t COST_SLOAD = 200;
    static constexpr std::uint64_t COST_SSTORE = 5000;
    static constexpr std::uint64_t COST_SHA3_BASE = 30;
    static constexpr std::uint64_t COST_SHA3_PER_WORD = 6;
    static constexpr std::uint64_t COST_BALANCE = 100;
    static constexpr std::uint64_t COST_EXTCODE = 700;
    static constexpr std::uint64_t COST_CREATE = 32000;
    static constexpr std::uint64_t COST_MLDSA_VERIFY = 50000;
};

// ============================================================================
// Instruction Meter - Tracks gas/instruction usage
// ============================================================================

class InstructionMeter {
public:
    explicit InstructionMeter(std::uint64_t limit);

    // Count instructions (returns false if limit exceeded)
    bool count_instructions(std::uint64_t count);

    // Count specific operation
    bool count_sload();
    bool count_sstore();
    bool count_sha3(std::size_t data_size);
    bool count_balance();
    bool count_call();
    bool count_mldsa_verify();
    bool count_create();

    // Check if should halt
    [[nodiscard]] bool should_halt() const;

    // Get instructions used
    [[nodiscard]] std::uint64_t instructions_used() const;

    // Get instructions remaining
    [[nodiscard]] std::uint64_t instructions_remaining() const;

    // Calculate fee (declared_limit * rate, no refunds!)
    [[nodiscard]] static std::uint64_t calculate_fee(std::uint64_t declared_limit);

    // Get declared limit
    [[nodiscard]] std::uint64_t declared_limit() const;

    // Reset meter
    void reset(std::uint64_t new_limit);

private:
    std::uint64_t limit_;
    std::uint64_t used_ = 0;
    bool halted_ = false;
};

// ============================================================================
// Expectation Evaluation Result
// ============================================================================

struct EvaluationResult {
    bool success = true;
    std::size_t first_failed_index = 0;
    ExpectationType failed_type = ExpectationType::BALANCE_EQ;
    std::string failure_reason;
};

// ============================================================================
// State Interface - Abstract interface for state access
// ============================================================================

class StateInterface {
public:
    virtual ~StateInterface() = default;

    virtual std::optional<Account> get_account(const Address& addr) const = 0;
    virtual std::optional<hash_t> get_storage(const Address& addr, const hash_t& key) const = 0;
    virtual std::vector<std::uint8_t> get_code(const Address& addr) const = 0;
    virtual bool is_dormant(const Address& addr) const = 0;
    virtual bool is_pruned(const Address& addr) const = 0;
};

// ============================================================================
// Expectation Evaluator - Pre-execution validation
// ============================================================================

class ExpectationEvaluator {
public:
    explicit ExpectationEvaluator(const StateInterface& state);

    // Evaluate single expectation
    [[nodiscard]] bool evaluate(const StateExpectation& exp) const;

    // Evaluate all expectations (fails fast on first failure)
    [[nodiscard]] EvaluationResult evaluate_all(const ExpectationSet& set) const;

private:
    const StateInterface& state_;

    bool evaluate_balance_eq(const StateExpectation& exp) const;
    bool evaluate_balance_ge(const StateExpectation& exp) const;
    bool evaluate_balance_le(const StateExpectation& exp) const;
    bool evaluate_balance_range(const StateExpectation& exp) const;
    bool evaluate_storage_eq(const StateExpectation& exp) const;
    bool evaluate_storage_ne(const StateExpectation& exp) const;
    bool evaluate_nonce_eq(const StateExpectation& exp) const;
};

// ============================================================================
// Execution Result
// ============================================================================

enum class ExecutionStatus : std::uint8_t {
    SUCCESS = 0,
    REVERT = 1,
    OUT_OF_GAS = 2,
    ACCESS_VIOLATION = 3,
    EXPECTATION_FAILED = 4,
    INVALID_OPCODE = 5,
    STACK_OVERFLOW = 6,
    STACK_UNDERFLOW = 7,
    INVALID_JUMP = 8,
    CALL_DEPTH_EXCEEDED = 9,
    CREATE_COLLISION = 10,
    WASM_TRAP = 11,
};

struct ExecutionResult {
    ExecutionStatus status = ExecutionStatus::SUCCESS;
    std::vector<std::uint8_t> return_data;
    std::uint64_t instructions_used = 0;
    std::uint64_t fee_charged = 0;
    AccessViolation access_violation = AccessViolation::NONE;
    std::string error_message;

    // State changes (only applied on SUCCESS)
    std::vector<std::pair<AccessKey, hash_t>> storage_writes;
    std::vector<std::pair<Address, std::int64_t>> balance_changes;

    [[nodiscard]] bool is_success() const { return status == ExecutionStatus::SUCCESS; }
};

// ============================================================================
// WASM Execution Context - All data needed to execute a WASM transaction
// ============================================================================

struct WasmExecutionContext {
    // Transaction data
    Address origin;           // Original sender
    Address caller;           // Current caller (for internal calls)
    Address contract;         // Contract being executed
    std::uint64_t value;      // Value transferred
    std::vector<std::uint8_t> input;  // Calldata

    // Environment
    slot_t current_slot;
    position_t position;
    hash_t prev_state_root;

    // Limits
    std::uint64_t instruction_limit;
    std::uint32_t call_depth = 0;
    static constexpr std::uint32_t MAX_CALL_DEPTH = 1024;

    // Access control
    DeclaredAccessSet declared_access;
    ExpectationSet expectations;

    // Computed fields
    hash_t tx_hash;
};

// ============================================================================
// Parallel Execution Support
// ============================================================================

struct DecoratedTransaction {
    hash_t commit_hash;
    Position2D position;
    DeclaredAccessSet access_set;
    ExpectationSet expectations;
    std::uint64_t instruction_limit;
    WasmExecutionContext context;
    std::uint32_t index;  // Original index in batch
};

class DependencyGraph {
public:
    explicit DependencyGraph(std::vector<DecoratedTransaction> txs);

    // Build dependency graph from declared access sets
    void build();

    // Get transactions ready to execute (no dependencies)
    [[nodiscard]] std::vector<std::uint32_t> get_ready() const;

    // Mark transaction as complete
    void mark_complete(std::uint32_t tx_index);

    // Get optimal parallel schedule
    [[nodiscard]] std::vector<std::vector<std::uint32_t>> get_parallel_schedule() const;

    // Check if two transactions can run in parallel
    [[nodiscard]] bool can_parallelize(std::uint32_t a, std::uint32_t b) const;

private:
    std::vector<DecoratedTransaction> txs_;
    std::vector<std::unordered_set<std::uint32_t>> dependencies_;  // tx -> depends on
    std::vector<std::unordered_set<std::uint32_t>> dependents_;    // tx -> blocks these
    std::unordered_set<std::uint32_t> completed_;
    std::unordered_set<std::uint32_t> ready_;

    bool check_overlap(const DeclaredAccessSet& a, const DeclaredAccessSet& b) const;
};

// ============================================================================
// Memory Limiter - Track WASM memory usage
// ============================================================================

class MemoryLimiter {
public:
    static constexpr std::uint32_t MAX_MEMORY_PAGES = 256;    // 16MB
    static constexpr std::uint32_t INITIAL_MEMORY_PAGES = 16; // 1MB
    static constexpr std::uint32_t PAGE_SIZE = 65536;         // 64KB

    explicit MemoryLimiter(std::uint32_t max_pages = MAX_MEMORY_PAGES);

    // Request memory growth (returns false if denied)
    bool request_grow(std::uint32_t additional_pages);

    // Get current page count
    [[nodiscard]] std::uint32_t current_pages() const;

    // Get max pages
    [[nodiscard]] std::uint32_t max_pages() const;

    // Get current memory size in bytes
    [[nodiscard]] std::size_t current_bytes() const;

private:
    std::uint32_t current_pages_;
    std::uint32_t max_pages_;
};

}  // namespace pop
