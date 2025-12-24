#include "access.hh"
#include "crypto/hash.hh"
#include "core/logging.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// AccessTracker Implementation
// ============================================================================

AccessTracker::AccessTracker(DeclaredAccessSet declared)
    : declared_(std::move(declared)) {
    // Build lookup sets
    for (const auto& key : declared_.read_set) {
        declared_reads_.insert(key);
    }
    for (const auto& key : declared_.write_set) {
        declared_writes_.insert(key);
        declared_reads_.insert(key);  // Write implies read
    }
}

AccessViolation AccessTracker::check_read(const Address& addr, const hash_t& key) {
    if (violation_ != AccessViolation::NONE) {
        return violation_;  // Already violated
    }

    AccessKey ak{addr, key};

    if (declared_reads_.find(ak) == declared_reads_.end()) {
        violation_ = AccessViolation::UNDECLARED_READ;
        log::execution.warn("Access violation: UNDECLARED_READ");
        return violation_;
    }

    actual_reads_.insert(ak);
    return AccessViolation::NONE;
}

AccessViolation AccessTracker::check_write(const Address& addr, const hash_t& key) {
    if (violation_ != AccessViolation::NONE) {
        return violation_;
    }

    AccessKey ak{addr, key};

    if (declared_writes_.find(ak) == declared_writes_.end()) {
        violation_ = AccessViolation::UNDECLARED_WRITE;
        log::execution.warn("Access violation: UNDECLARED_WRITE");
        return violation_;
    }

    actual_writes_.insert(ak);
    return AccessViolation::NONE;
}

AccessViolation AccessTracker::check_balance_read(const Address& addr) {
    // Balance reads use a special key
    hash_t balance_key;
    balance_key.fill(0xFF);  // Special marker for balance
    return check_read(addr, balance_key);
}

AccessViolation AccessTracker::check_balance_write(const Address& addr) {
    hash_t balance_key;
    balance_key.fill(0xFF);
    return check_write(addr, balance_key);
}

bool AccessTracker::has_violation() const {
    return violation_ != AccessViolation::NONE;
}

AccessViolation AccessTracker::get_violation() const {
    return violation_;
}

const std::unordered_set<AccessKey, AccessKey::Hash>& AccessTracker::actual_reads() const {
    return actual_reads_;
}

const std::unordered_set<AccessKey, AccessKey::Hash>& AccessTracker::actual_writes() const {
    return actual_writes_;
}

void AccessTracker::reset() {
    actual_reads_.clear();
    actual_writes_.clear();
    violation_ = AccessViolation::NONE;
}

// ============================================================================
// InstructionMeter Implementation
// ============================================================================

InstructionMeter::InstructionMeter(std::uint64_t limit)
    : limit_(limit) {}

bool InstructionMeter::count_instructions(std::uint64_t count) {
    if (halted_) {
        return false;
    }

    used_ += count;
    if (used_ > limit_) {
        halted_ = true;
        POP_LOG_DEBUG(log::execution) << "Instruction limit exceeded: " << used_ << " used > " << limit_ << " limit";
        return false;
    }
    return true;
}

bool InstructionMeter::count_sload() {
    return count_instructions(MeteringConfig::COST_SLOAD);
}

bool InstructionMeter::count_sstore() {
    return count_instructions(MeteringConfig::COST_SSTORE);
}

bool InstructionMeter::count_sha3(std::size_t data_size) {
    std::uint64_t words = (data_size + 31) / 32;
    return count_instructions(MeteringConfig::COST_SHA3_BASE +
                              MeteringConfig::COST_SHA3_PER_WORD * words);
}

bool InstructionMeter::count_balance() {
    return count_instructions(MeteringConfig::COST_BALANCE);
}

bool InstructionMeter::count_call() {
    return count_instructions(MeteringConfig::COST_CALL);
}

bool InstructionMeter::count_mldsa_verify() {
    return count_instructions(MeteringConfig::COST_MLDSA_VERIFY);
}

bool InstructionMeter::count_create() {
    return count_instructions(MeteringConfig::COST_CREATE);
}

bool InstructionMeter::should_halt() const {
    return halted_;
}

std::uint64_t InstructionMeter::instructions_used() const {
    return used_;
}

std::uint64_t InstructionMeter::instructions_remaining() const {
    if (used_ >= limit_) {
        return 0;
    }
    return limit_ - used_;
}

std::uint64_t InstructionMeter::calculate_fee(std::uint64_t declared_limit) {
    // No refunds! Fee is based on declared limit, not actual usage
    return (declared_limit / MeteringConfig::INSTRUCTION_UNIT) *
           MeteringConfig::INSTRUCTION_PRICE_SATOSHIS;
}

std::uint64_t InstructionMeter::declared_limit() const {
    return limit_;
}

void InstructionMeter::reset(std::uint64_t new_limit) {
    limit_ = new_limit;
    used_ = 0;
    halted_ = false;
}

// ============================================================================
// ExpectationEvaluator Implementation
// ============================================================================

ExpectationEvaluator::ExpectationEvaluator(const StateInterface& state)
    : state_(state) {}

bool ExpectationEvaluator::evaluate(const StateExpectation& exp) const {
    switch (exp.type) {
        case ExpectationType::BALANCE_EQ:
            return evaluate_balance_eq(exp);
        case ExpectationType::BALANCE_GE:
            return evaluate_balance_ge(exp);
        case ExpectationType::BALANCE_LE:
            return evaluate_balance_le(exp);
        case ExpectationType::BALANCE_RANGE:
            return evaluate_balance_range(exp);
        case ExpectationType::STORAGE_EQ:
            return evaluate_storage_eq(exp);
        case ExpectationType::STORAGE_NE:
            return evaluate_storage_ne(exp);
        case ExpectationType::NONCE_EQ:
            return evaluate_nonce_eq(exp);
        default:
            return false;
    }
}

EvaluationResult ExpectationEvaluator::evaluate_all(const ExpectationSet& set) const {
    EvaluationResult result;

    POP_LOG_TRACE(log::execution) << "Evaluating " << set.expectations.size() << " state expectations";

    for (std::size_t i = 0; i < set.expectations.size(); ++i) {
        if (!evaluate(set.expectations[i])) {
            result.success = false;
            result.first_failed_index = i;
            result.failed_type = set.expectations[i].type;
            result.failure_reason = "Expectation failed at index " + std::to_string(i);
            POP_LOG_DEBUG(log::execution) << "State expectation failed at index " << i
                                           << " (type " << static_cast<int>(set.expectations[i].type) << ")";
            return result;
        }
    }

    return result;
}

bool ExpectationEvaluator::evaluate_balance_eq(const StateExpectation& exp) const {
    auto account_opt = state_.get_account(exp.address);
    if (!account_opt) {
        return decode_u64(exp.value.data()) == 0;
    }
    return account_opt->balance == decode_u64(exp.value.data());
}

bool ExpectationEvaluator::evaluate_balance_ge(const StateExpectation& exp) const {
    auto account_opt = state_.get_account(exp.address);
    if (!account_opt) {
        return decode_u64(exp.value.data()) == 0;
    }
    return account_opt->balance >= decode_u64(exp.value.data());
}

bool ExpectationEvaluator::evaluate_balance_le(const StateExpectation& exp) const {
    auto account_opt = state_.get_account(exp.address);
    if (!account_opt) {
        return true;  // Zero balance <= any value
    }
    return account_opt->balance <= decode_u64(exp.value.data());
}

bool ExpectationEvaluator::evaluate_balance_range(const StateExpectation& exp) const {
    if (!exp.max_value.has_value()) {
        return false;
    }

    auto account_opt = state_.get_account(exp.address);
    std::uint64_t balance = account_opt ? account_opt->balance : 0;
    std::uint64_t min_val = decode_u64(exp.value.data());
    std::uint64_t max_val = decode_u64(exp.max_value->data());

    return balance >= min_val && balance <= max_val;
}

bool ExpectationEvaluator::evaluate_storage_eq(const StateExpectation& exp) const {
    if (!exp.key.has_value()) {
        return false;
    }

    auto storage_opt = state_.get_storage(exp.address, *exp.key);
    if (!storage_opt) {
        hash_t zero{};
        return exp.value == zero;
    }
    return *storage_opt == exp.value;
}

bool ExpectationEvaluator::evaluate_storage_ne(const StateExpectation& exp) const {
    if (!exp.key.has_value()) {
        return false;
    }

    auto storage_opt = state_.get_storage(exp.address, *exp.key);
    if (!storage_opt) {
        hash_t zero{};
        return exp.value != zero;
    }
    return *storage_opt != exp.value;
}

bool ExpectationEvaluator::evaluate_nonce_eq(const StateExpectation& exp) const {
    auto account_opt = state_.get_account(exp.address);
    if (!account_opt) {
        return decode_u64(exp.value.data()) == 0;
    }
    return account_opt->nonce == decode_u64(exp.value.data());
}

// ============================================================================
// DependencyGraph Implementation
// ============================================================================

DependencyGraph::DependencyGraph(std::vector<DecoratedTransaction> txs)
    : txs_(std::move(txs)) {
    dependencies_.resize(txs_.size());
    dependents_.resize(txs_.size());
}

void DependencyGraph::build() {
    POP_LOG_DEBUG(log::execution) << "Building dependency graph for " << txs_.size() << " transactions";

    // For each pair of transactions, check if they overlap
    std::size_t overlap_count = 0;
    for (std::size_t i = 0; i < txs_.size(); ++i) {
        for (std::size_t j = 0; j < i; ++j) {
            if (check_overlap(txs_[i].access_set, txs_[j].access_set)) {
                overlap_count++;
                // Earlier transaction (j) must complete before later (i)
                // Use position ordering
                if (txs_[j].position < txs_[i].position) {
                    dependencies_[i].insert(static_cast<std::uint32_t>(j));
                    dependents_[j].insert(static_cast<std::uint32_t>(i));
                } else {
                    dependencies_[j].insert(static_cast<std::uint32_t>(i));
                    dependents_[i].insert(static_cast<std::uint32_t>(j));
                }
            }
        }
    }

    // Find initially ready transactions
    for (std::size_t i = 0; i < txs_.size(); ++i) {
        if (dependencies_[i].empty()) {
            ready_.insert(static_cast<std::uint32_t>(i));
        }
    }

    POP_LOG_DEBUG(log::execution) << "Dependency graph built: " << overlap_count << " overlaps, "
                                   << ready_.size() << " initially ready";
}

std::vector<std::uint32_t> DependencyGraph::get_ready() const {
    return std::vector<std::uint32_t>(ready_.begin(), ready_.end());
}

void DependencyGraph::mark_complete(std::uint32_t tx_index) {
    completed_.insert(tx_index);
    ready_.erase(tx_index);

    // Check if any dependents are now ready
    for (std::uint32_t dep : dependents_[tx_index]) {
        if (completed_.find(dep) != completed_.end()) {
            continue;  // Already completed
        }

        bool all_deps_complete = true;
        for (std::uint32_t d : dependencies_[dep]) {
            if (completed_.find(d) == completed_.end()) {
                all_deps_complete = false;
                break;
            }
        }

        if (all_deps_complete) {
            ready_.insert(dep);
        }
    }
}

std::vector<std::vector<std::uint32_t>> DependencyGraph::get_parallel_schedule() const {
    std::vector<std::vector<std::uint32_t>> schedule;

    // Make a copy for simulation
    std::unordered_set<std::uint32_t> simulated_complete;
    std::unordered_set<std::uint32_t> simulated_ready = ready_;

    while (simulated_complete.size() < txs_.size()) {
        if (simulated_ready.empty()) {
            break;  // Shouldn't happen with correct dependency graph
        }

        // Current batch = all ready transactions
        std::vector<std::uint32_t> batch(simulated_ready.begin(), simulated_ready.end());
        schedule.push_back(batch);

        // Mark all as complete and update ready set
        for (std::uint32_t tx : batch) {
            simulated_complete.insert(tx);
        }
        simulated_ready.clear();

        // Find newly ready transactions
        for (std::size_t i = 0; i < txs_.size(); ++i) {
            if (simulated_complete.find(static_cast<std::uint32_t>(i)) != simulated_complete.end()) {
                continue;
            }

            bool all_deps_complete = true;
            for (std::uint32_t d : dependencies_[i]) {
                if (simulated_complete.find(d) == simulated_complete.end()) {
                    all_deps_complete = false;
                    break;
                }
            }

            if (all_deps_complete) {
                simulated_ready.insert(static_cast<std::uint32_t>(i));
            }
        }
    }

    return schedule;
}

bool DependencyGraph::can_parallelize(std::uint32_t a, std::uint32_t b) const {
    return !check_overlap(txs_[a].access_set, txs_[b].access_set);
}

bool DependencyGraph::check_overlap(
    const DeclaredAccessSet& a,
    const DeclaredAccessSet& b) const {
    return a.overlaps(b);
}

// ============================================================================
// MemoryLimiter Implementation
// ============================================================================

MemoryLimiter::MemoryLimiter(std::uint32_t max_pages)
    : current_pages_(INITIAL_MEMORY_PAGES)
    , max_pages_(max_pages) {}

bool MemoryLimiter::request_grow(std::uint32_t additional_pages) {
    if (current_pages_ + additional_pages > max_pages_) {
        return false;
    }
    current_pages_ += additional_pages;
    return true;
}

std::uint32_t MemoryLimiter::current_pages() const {
    return current_pages_;
}

std::uint32_t MemoryLimiter::max_pages() const {
    return max_pages_;
}

std::size_t MemoryLimiter::current_bytes() const {
    return static_cast<std::size_t>(current_pages_) * PAGE_SIZE;
}

}  // namespace pop
