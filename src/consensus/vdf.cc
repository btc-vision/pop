#include "vdf.hh"
#include "crypto/hash.hh"
#include "core/logging.hh"
#include <cstring>
#include <sstream>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

namespace pop {

// ============================================================================
// VDFStep Implementation
// ============================================================================

VDFStep VDFStep::next() const {
    VDFStep result;
    result.step_number = step_number + 1;
    result.value = sha3_256(value);
    return result;
}

bool VDFStep::verify_next(const VDFStep& claimed_next) const {
    if (claimed_next.step_number != step_number + 1) {
        return false;
    }
    hash_t expected = sha3_256(value);
    return expected == claimed_next.value;
}

std::vector<std::uint8_t> VDFStep::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    encode_u64(result.data(), step_number);
    std::copy(value.begin(), value.end(), result.data() + sizeof(std::uint64_t));
    return result;
}

std::optional<VDFStep> VDFStep::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    VDFStep step;
    step.step_number = decode_u64(data.data());
    std::copy(data.data() + sizeof(std::uint64_t),
              data.data() + SERIALIZED_SIZE,
              step.value.begin());
    return step;
}

VDFStep vdf_genesis(const hash_t& genesis_seed) {
    VDFStep step;
    step.step_number = 0;
    step.value = sha3_256(genesis_seed);
    return step;
}

// ============================================================================
// VDFChain Implementation
// ============================================================================

VDFChain::VDFChain(const hash_t& genesis_seed, VDFThreadConfig config)
    : genesis_seed_(genesis_seed)
    , config_(std::move(config))
    , current_step_(vdf_genesis(genesis_seed)) {
    // Store genesis as epoch 0 boundary
    epoch_boundaries_[0] = current_step_.value;

    log::vdf.info() << "VDFChain initialized with genesis step 0";
}

VDFChain::~VDFChain() {
    stop();
}

void VDFChain::start() {
    if (running_.exchange(true)) {
        log::vdf.warn("VDFChain already running");
        return;
    }

    start_time_ = std::chrono::steady_clock::now();
    steps_computed_.store(0);

    log::vdf.info() << "Starting VDF computation thread";
    compute_thread_ = std::thread(&VDFChain::run_loop, this);
}

void VDFChain::stop() {
    if (!running_.exchange(false)) {
        return;  // Not running
    }

    log::vdf.info("Stopping VDF computation thread");

    cv_.notify_all();
    if (compute_thread_.joinable()) {
        compute_thread_.join();
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time_;
    auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (elapsed_sec > 0) {
        double rate = static_cast<double>(steps_computed_.load()) / static_cast<double>(elapsed_sec);
        log::vdf.info() << "VDF stopped after " << steps_computed_.load()
                        << " steps (" << rate << " steps/sec)";
    }
}

std::thread::id VDFChain::thread_id() const {
    return compute_thread_.get_id();
}

void VDFChain::configure_thread() {
    set_thread_name();
    set_thread_affinity();
    set_thread_priority();
}

void VDFChain::set_thread_name() {
#ifdef __linux__
    if (!config_.thread_name.empty()) {
        pthread_setname_np(pthread_self(), config_.thread_name.c_str());
        log::vdf.debug() << "Thread name set to: " << config_.thread_name;
    }
#endif
}

void VDFChain::set_thread_affinity() {
#ifdef __linux__
    if (config_.cpu_affinity >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(config_.cpu_affinity, &cpuset);

        int result = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        if (result == 0) {
            log::vdf.info() << "VDF thread pinned to CPU " << config_.cpu_affinity;
        } else {
            log::vdf.warn() << "Failed to set CPU affinity to " << config_.cpu_affinity
                            << ": error " << result;
        }
    }
#endif
}

void VDFChain::set_thread_priority() {
#ifdef __linux__
    if (config_.realtime_scheduling) {
        struct sched_param param;
        param.sched_priority = config_.priority;

        int result = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
        if (result == 0) {
            log::vdf.info() << "VDF thread set to SCHED_FIFO with priority " << config_.priority;
        } else {
            log::vdf.warn() << "Failed to set real-time scheduling: error " << result
                            << " (requires root)";
        }
    } else if (config_.priority != 0) {
        // Nice value (inverse priority)
        int nice_val = -config_.priority;
        errno = 0;
        int result = nice(nice_val);
        if (errno == 0) {
            log::vdf.debug() << "VDF thread nice value set to " << result;
        }
    }
#endif
}

void VDFChain::run_loop() {
    // Configure thread attributes
    configure_thread();

    log::vdf.info("VDF computation loop started");

    std::uint64_t yield_counter = 0;

    while (running_.load()) {
        // Check for pause
        while (paused_.load() && running_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (!running_.load()) {
            break;
        }

        VDFStep next;
        slot_t new_slot;
        tx_epoch_t new_tx_epoch;
        bool slot_crossed = false;
        bool tx_epoch_crossed = false;
        bool identity_epoch_crossed = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);

            // Compute next step
            next = current_step_.next();
            current_step_ = next;
            steps_computed_.fetch_add(1);

            // Check boundaries
            VDFTime current_time{next.step_number};
            new_slot = current_time.to_slot();
            new_tx_epoch = current_time.to_tx_epoch();

            if (new_slot > last_slot_) {
                slot_crossed = true;
                last_slot_ = new_slot;
            }

            if (new_tx_epoch > last_tx_epoch_) {
                tx_epoch_crossed = true;
                last_tx_epoch_ = new_tx_epoch;
            }

            // Store identity epoch boundaries
            if (next.step_number % VDF_STEPS_PER_IDENTITY_EPOCH == 0) {
                identity_epoch_t boundary_epoch = next.step_number / VDF_STEPS_PER_IDENTITY_EPOCH;
                epoch_boundaries_[boundary_epoch] = next.value;
                identity_epoch_crossed = true;

                log::vdf.info() << "Identity epoch " << boundary_epoch << " boundary reached at step "
                                << next.step_number;
            }
        }

        cv_.notify_all();

        // Fire callbacks outside lock
        if (slot_crossed) {
            POP_LOG_TRACE(log::vdf) << "Slot " << new_slot << " boundary crossed";
            for (const auto& cb : slot_callbacks_) {
                try {
                    cb(new_slot);
                } catch (const std::exception& e) {
                    log::vdf.error() << "Slot callback exception: " << e.what();
                }
            }
        }

        if (tx_epoch_crossed) {
            log::vdf.debug() << "TX epoch " << new_tx_epoch << " boundary crossed";
            for (const auto& cb : tx_epoch_callbacks_) {
                try {
                    cb(new_tx_epoch);
                } catch (const std::exception& e) {
                    log::vdf.error() << "TX epoch callback exception: " << e.what();
                }
            }
        }

        // Periodic yield to allow other threads to run
        if (++yield_counter >= config_.yield_interval) {
            yield_counter = 0;
            std::this_thread::yield();
        }

        // Periodic logging
        if (next.step_number % 1000000 == 0) {
            log::vdf.info() << "VDF progress: step " << next.step_number
                            << ", slot " << new_slot
                            << ", epoch " << new_tx_epoch;
        }
    }

    log::vdf.info("VDF computation loop exited");
}

VDFStep VDFChain::current() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_step_;
}

VDFTime VDFChain::current_time() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return VDFTime{current_step_.step_number};
}

std::uint64_t VDFChain::current_step() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_step_.step_number;
}

std::optional<VDFStep> VDFChain::get_step(std::uint64_t step_number) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (step_number > current_step_.step_number) {
        return std::nullopt;
    }
    // For now, we only have the current step
    // A full implementation would cache important steps
    if (step_number == current_step_.step_number) {
        return current_step_;
    }
    return std::nullopt;
}

bool VDFChain::has_reached(std::uint64_t step_number) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_step_.step_number >= step_number;
}

void VDFChain::wait_for_step(std::uint64_t step_number) const {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this, step_number]() {
        return current_step_.step_number >= step_number || !running_.load();
    });
}

std::optional<hash_t> VDFChain::get_epoch_boundary_value(identity_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = epoch_boundaries_.find(epoch);
    if (it == epoch_boundaries_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void VDFChain::on_slot_boundary(SlotCallback callback) {
    slot_callbacks_.push_back(std::move(callback));
    log::vdf.debug("Registered slot boundary callback");
}

void VDFChain::on_tx_epoch_boundary(TxEpochCallback callback) {
    tx_epoch_callbacks_.push_back(std::move(callback));
    log::vdf.debug("Registered TX epoch boundary callback");
}

VDFChain::Checkpoint VDFChain::create_checkpoint() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Checkpoint cp;
    cp.step = current_step_;

    for (const auto& [epoch, value] : epoch_boundaries_) {
        cp.epoch_boundary_values.push_back(value);
    }

    log::vdf.debug() << "Created checkpoint at step " << current_step_.step_number;
    return cp;
}

void VDFChain::restore_checkpoint(const Checkpoint& checkpoint) {
    std::lock_guard<std::mutex> lock(mutex_);

    current_step_ = checkpoint.step;
    last_slot_ = VDFTime{current_step_.step_number}.to_slot();
    last_tx_epoch_ = VDFTime{current_step_.step_number}.to_tx_epoch();

    // Restore epoch boundaries
    epoch_boundaries_.clear();
    for (std::size_t i = 0; i < checkpoint.epoch_boundary_values.size(); ++i) {
        epoch_boundaries_[static_cast<identity_epoch_t>(i)] =
            checkpoint.epoch_boundary_values[i];
    }

    log::vdf.info() << "Restored checkpoint at step " << checkpoint.step.step_number;
}

// ============================================================================
// VDFProof Implementation
// ============================================================================

bool VDFProof::verify() const {
    // Verify start and end values match the step numbers
    if (end_step <= start_step) {
        log::vdf.warn("VDFProof: invalid step range");
        return false;
    }

    // For now, we implement a simple verification that checks
    // a few intermediate values. A full STARK implementation
    // would use proper polynomial commitments.
    //
    // TODO: Implement full STARK proof verification
    // For MVP, we do direct verification for small ranges

    if (end_step - start_step <= 1000) {
        // Direct verification for small ranges
        hash_t current = start_value;
        for (std::uint64_t step = start_step; step < end_step; ++step) {
            current = sha3_256(current);
        }
        bool valid = current == end_value;
        if (!valid) {
            log::vdf.warn("VDFProof: direct verification failed");
        }
        return valid;
    }

    // For large ranges, rely on STARK proof
    // Placeholder: assume valid if proof data exists
    bool valid = !stark_proof.empty();
    if (!valid) {
        log::vdf.warn("VDFProof: no STARK proof data");
    }
    return valid;
}

std::vector<std::uint8_t> VDFProof::serialize() const {
    std::vector<std::uint8_t> result;

    // Reserve space
    result.reserve(sizeof(std::uint64_t) * 2 + HASH_SIZE * 2 +
                   sizeof(std::uint32_t) + stark_proof.size());

    // Start step
    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), start_step);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    // End step
    encode_u64(u64_bytes.data(), end_step);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    // Start value
    result.insert(result.end(), start_value.begin(), start_value.end());

    // End value
    result.insert(result.end(), end_value.begin(), end_value.end());

    // STARK proof length + data
    std::array<std::uint8_t, 4> u32_bytes;
    encode_u32(u32_bytes.data(), static_cast<std::uint32_t>(stark_proof.size()));
    result.insert(result.end(), u32_bytes.begin(), u32_bytes.end());
    result.insert(result.end(), stark_proof.begin(), stark_proof.end());

    return result;
}

std::optional<VDFProof> VDFProof::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < sizeof(std::uint64_t) * 2 + HASH_SIZE * 2 + sizeof(std::uint32_t)) {
        return std::nullopt;
    }

    VDFProof proof;
    const std::uint8_t* ptr = data.data();

    proof.start_step = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    proof.end_step = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    std::copy(ptr, ptr + HASH_SIZE, proof.start_value.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, proof.end_value.begin());
    ptr += HASH_SIZE;

    std::uint32_t proof_len = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    if (ptr + proof_len > data.data() + data.size()) {
        return std::nullopt;
    }

    proof.stark_proof.assign(ptr, ptr + proof_len);

    return proof;
}

std::optional<VDFProof> generate_vdf_proof(
    const VDFStep& start,
    const VDFStep& end,
    const std::vector<hash_t>& intermediate_values) {

    if (end.step_number <= start.step_number) {
        log::vdf.error("generate_vdf_proof: end <= start");
        return std::nullopt;
    }

    VDFProof proof;
    proof.start_step = start.step_number;
    proof.end_step = end.step_number;
    proof.start_value = start.value;
    proof.end_value = end.value;

    // TODO: Generate actual STARK proof using intermediate values
    // For now, create a placeholder that includes intermediate commitments

    SHA3Hasher hasher;
    hasher.update(start.value);
    hasher.update(end.value);
    for (const auto& h : intermediate_values) {
        hasher.update(h);
    }
    hash_t commitment = hasher.finalize();

    // Store commitment as placeholder proof
    proof.stark_proof.assign(commitment.begin(), commitment.end());

    log::vdf.debug() << "Generated VDF proof for steps " << start.step_number
                     << " to " << end.step_number;

    return proof;
}

// ============================================================================
// Identity Salt Implementation
// ============================================================================

hash_t compute_identity_salt(identity_epoch_t epoch, const hash_t& hard_finalized_state_root) {
    SHA3Hasher hasher;

    // Domain separator
    const char* domain = "identity";
    hasher.update(domain, std::strlen(domain));

    // Epoch number
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch);
    hasher.update(epoch_bytes);

    // Hard finalized state root from end of previous epoch
    hasher.update(hard_finalized_state_root);

    hash_t salt = hasher.finalize();

    log::vdf.debug() << "Computed identity salt for epoch " << epoch;

    return salt;
}

}  // namespace pop
