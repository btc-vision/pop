#pragma once

#include "core/types.hh"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <thread>
#include <mutex>
#include <optional>

namespace pop {

// ============================================================================
// VDF Thread Configuration
// ============================================================================

struct VDFThreadConfig {
    // CPU core to pin the VDF thread to (-1 = no pinning)
    int cpu_affinity = -1;

    // Thread scheduling priority (0 = normal, higher = more priority)
    int priority = 0;

    // Whether to use real-time scheduling (requires root)
    bool realtime_scheduling = false;

    // Name for the thread (for debugging)
    std::string thread_name = "pop-vdf";

    // Checkpoint interval (save every N steps)
    std::uint64_t checkpoint_interval = 10000;

    // Yield after N steps to allow other threads to run
    std::uint64_t yield_interval = 1000;
};

// ============================================================================
// VDF Constants
// ============================================================================

// VDF steps per slot (calibrated for ~100ms on reference hardware)
inline constexpr std::uint64_t VDF_STEPS_PER_SLOT = 100'000;

// VDF steps per transaction epoch (K slots * S steps)
inline constexpr std::uint64_t VDF_STEPS_PER_TX_EPOCH =
    SLOTS_PER_TX_EPOCH * VDF_STEPS_PER_SLOT;

// VDF steps per identity epoch (~30 days)
inline constexpr std::uint64_t VDF_STEPS_PER_IDENTITY_EPOCH =
    IDENTITY_EPOCH_DAYS * 24 * 60 * 60 * 10 * VDF_STEPS_PER_SLOT;  // ~10 slots/sec

// Safety margin for bucket cutoff
inline constexpr std::uint64_t VDF_BUCKET_SAFETY_MARGIN = 3 * VDF_STEPS_PER_SLOT;

// ============================================================================
// VDF Step - Single computation unit
// ============================================================================

// VDF_step(0) = SHA3-256(genesis_seed)
// VDF_step(n) = SHA3-256(VDF_step(n-1))
// Strictly sequential. Cannot parallelize.

struct VDFStep {
    std::uint64_t step_number;
    hash_t value;

    [[nodiscard]] VDFStep next() const;
    [[nodiscard]] bool verify_next(const VDFStep& claimed_next) const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFStep> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE = sizeof(std::uint64_t) + HASH_SIZE;
};

// Compute VDF from genesis seed
[[nodiscard]] VDFStep vdf_genesis(const hash_t& genesis_seed);

// ============================================================================
// VDF Time - Convert VDF steps to protocol time units
// ============================================================================

struct VDFTime {
    std::uint64_t step;

    [[nodiscard]] slot_t to_slot() const {
        return step / VDF_STEPS_PER_SLOT;
    }

    [[nodiscard]] tx_epoch_t to_tx_epoch() const {
        return step / VDF_STEPS_PER_TX_EPOCH;
    }

    [[nodiscard]] identity_epoch_t to_identity_epoch() const {
        return step / VDF_STEPS_PER_IDENTITY_EPOCH;
    }

    [[nodiscard]] std::uint8_t to_vdf_bucket(std::uint64_t epoch_start_step) const {
        if (step < epoch_start_step) return 0;
        return static_cast<std::uint8_t>(
            (step - epoch_start_step) / VDF_STEPS_PER_SLOT);
    }

    [[nodiscard]] static VDFTime from_slot(slot_t slot) {
        return VDFTime{slot * VDF_STEPS_PER_SLOT};
    }

    [[nodiscard]] static VDFTime from_tx_epoch(tx_epoch_t epoch) {
        return VDFTime{epoch * VDF_STEPS_PER_TX_EPOCH};
    }

    [[nodiscard]] static VDFTime from_identity_epoch(identity_epoch_t epoch) {
        return VDFTime{epoch * VDF_STEPS_PER_IDENTITY_EPOCH};
    }

    auto operator<=>(const VDFTime&) const = default;
};

// ============================================================================
// VDF Chain - Running VDF computation
// ============================================================================

class VDFChain {
public:
    explicit VDFChain(const hash_t& genesis_seed,
                      VDFThreadConfig config = VDFThreadConfig{});
    ~VDFChain();

    VDFChain(const VDFChain&) = delete;
    VDFChain& operator=(const VDFChain&) = delete;

    // Start/stop the VDF computation thread
    void start();
    void stop();

    // Check if running
    [[nodiscard]] bool is_running() const { return running_.load(); }

    // Get thread info
    [[nodiscard]] std::thread::id thread_id() const;

    // Get current VDF state
    [[nodiscard]] VDFStep current() const;
    [[nodiscard]] VDFTime current_time() const;
    [[nodiscard]] std::uint64_t current_step() const;

    // Get step at specific number (if computed)
    [[nodiscard]] std::optional<VDFStep> get_step(std::uint64_t step_number) const;

    // Check if we've reached a specific step
    [[nodiscard]] bool has_reached(std::uint64_t step_number) const;

    // Wait until a specific step is reached
    void wait_for_step(std::uint64_t step_number) const;

    // Get VDF value at epoch boundary (for identity salt)
    [[nodiscard]] std::optional<hash_t> get_epoch_boundary_value(
        identity_epoch_t epoch) const;

    // Callback when slot boundary crossed
    using SlotCallback = std::function<void(slot_t)>;
    void on_slot_boundary(SlotCallback callback);

    // Callback when tx epoch boundary crossed
    using TxEpochCallback = std::function<void(tx_epoch_t)>;
    void on_tx_epoch_boundary(TxEpochCallback callback);

    // Checkpoint management for persistence
    struct Checkpoint {
        VDFStep step;
        std::vector<hash_t> epoch_boundary_values;  // For identity salts
    };
    [[nodiscard]] Checkpoint create_checkpoint() const;
    void restore_checkpoint(const Checkpoint& checkpoint);

private:
    void run_loop();
    void configure_thread();
    void set_thread_name();
    void set_thread_affinity();
    void set_thread_priority();

    hash_t genesis_seed_;
    VDFThreadConfig config_;
    VDFStep current_step_;
    mutable std::mutex mutex_;
    mutable std::condition_variable cv_;

    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::thread compute_thread_;

    // Epoch boundary values for identity salt derivation
    std::unordered_map<identity_epoch_t, hash_t> epoch_boundaries_;

    // Callbacks
    std::vector<SlotCallback> slot_callbacks_;
    std::vector<TxEpochCallback> tx_epoch_callbacks_;
    slot_t last_slot_ = 0;
    tx_epoch_t last_tx_epoch_ = 0;

    // Statistics
    std::atomic<std::uint64_t> steps_computed_{0};
    std::chrono::steady_clock::time_point start_time_;
};

// ============================================================================
// VDF Proof - STARK proof of VDF computation (for light clients)
// ============================================================================

// STARK proof that VDF_step(start) through VDF_step(end) was correctly computed
// as sequential SHA3-256 iterations.
//
// Proof size: O(polylog N)
// Verification time: O(polylog N)
// Post-quantum secure (relies on hash collision resistance)

struct VDFProof {
    std::uint64_t start_step;
    std::uint64_t end_step;
    hash_t start_value;
    hash_t end_value;
    std::vector<std::uint8_t> stark_proof;  // The actual STARK proof

    [[nodiscard]] bool verify() const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFProof> deserialize(
        std::span<const std::uint8_t> data);
};

// Generate STARK proof for a range of VDF steps
[[nodiscard]] std::optional<VDFProof> generate_vdf_proof(
    const VDFStep& start,
    const VDFStep& end,
    const std::vector<hash_t>& intermediate_values);

// ============================================================================
// VDF Bucket - For batch receipts
// ============================================================================

struct VDFBucket {
    tx_epoch_t epoch;
    std::uint8_t bucket_id;  // 0-19

    [[nodiscard]] std::uint64_t start_step() const {
        return epoch * VDF_STEPS_PER_TX_EPOCH +
               bucket_id * VDF_STEPS_PER_SLOT;
    }

    [[nodiscard]] std::uint64_t end_step() const {
        return start_step() + VDF_STEPS_PER_SLOT - 1;
    }

    [[nodiscard]] bool is_cutoff_bucket() const {
        return bucket_id == RECEIPT_CUTOFF_BUCKET;
    }

    [[nodiscard]] bool is_past_cutoff() const {
        return bucket_id > RECEIPT_CUTOFF_BUCKET;
    }

    [[nodiscard]] static VDFBucket from_step(std::uint64_t step) {
        tx_epoch_t epoch = step / VDF_STEPS_PER_TX_EPOCH;
        std::uint64_t epoch_start = epoch * VDF_STEPS_PER_TX_EPOCH;
        std::uint8_t bucket = static_cast<std::uint8_t>(
            (step - epoch_start) / VDF_STEPS_PER_SLOT);
        return VDFBucket{epoch, bucket};
    }

    auto operator<=>(const VDFBucket&) const = default;
};

// ============================================================================
// Pool Freeze Check
// ============================================================================

// Pool freezes at epoch end + 21 slots worth of VDF steps
[[nodiscard]] inline std::uint64_t pool_freeze_step(tx_epoch_t epoch) {
    return (epoch + 1) * VDF_STEPS_PER_TX_EPOCH + 21 * VDF_STEPS_PER_SLOT;
}

[[nodiscard]] inline bool is_pool_frozen(tx_epoch_t epoch, std::uint64_t current_step) {
    return current_step >= pool_freeze_step(epoch);
}

// ============================================================================
// Identity Salt Derivation
// ============================================================================

// Salt for identity epoch T+1 = SHA3("identity" || hard_state_root_at_end_of_T)
[[nodiscard]] hash_t compute_identity_salt(
    identity_epoch_t epoch,
    const hash_t& hard_finalized_state_root);

// Get VDF step at identity epoch boundary
[[nodiscard]] inline std::uint64_t identity_epoch_boundary_step(identity_epoch_t epoch) {
    return epoch * VDF_STEPS_PER_IDENTITY_EPOCH;
}

}  // namespace pop
