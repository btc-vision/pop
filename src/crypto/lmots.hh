#pragma once

#include "core/types.hh"
#include <memory>
#include <span>
#include <atomic>

namespace pop {

// ============================================================================
// LM-OTS Constants (Winternitz w=4)
// ============================================================================

// W=4: 4 bits per chain step
// P = ceil(8*N/lg(2^W-1)) + ceil(lg(P*(2^W-1))/lg(2^W-1))
// For N=32, W=4: P = 67 chains
// Signature size = N + P*N = 32 + 67*32 = 2176 bytes

inline constexpr std::size_t LMOTS_CHAIN_LENGTH = 15;  // 2^W - 1

// ============================================================================
// LM-OTS Key Pair
// ============================================================================

class LMOTSKeyPair {
public:
    ~LMOTSKeyPair();

    LMOTSKeyPair(const LMOTSKeyPair&) = delete;
    LMOTSKeyPair& operator=(const LMOTSKeyPair&) = delete;
    LMOTSKeyPair(LMOTSKeyPair&&) noexcept;
    LMOTSKeyPair& operator=(LMOTSKeyPair&&) noexcept;

    // Generate a new random key pair
    [[nodiscard]] static std::optional<LMOTSKeyPair> generate();

    // Generate from seed (deterministic)
    [[nodiscard]] static std::optional<LMOTSKeyPair> from_seed(const hash_t& seed);

    // Load public key only (for verification)
    [[nodiscard]] static std::optional<LMOTSKeyPair> from_public_key(
        const lmots_public_key_t& pk);

    [[nodiscard]] const lmots_public_key_t& public_key() const { return public_key_; }
    [[nodiscard]] bool has_secret_key() const { return has_secret_key_; }
    [[nodiscard]] bool is_used() const { return used_.load(); }

    // Sign a message (ONE-TIME ONLY!)
    // Returns nullopt if already used or no secret key
    [[nodiscard]] std::optional<lmots_signature_t> sign(std::span<const std::uint8_t> message);

    // Mark as used without signing (e.g., after loading state)
    void mark_used();

    // Apply hash chain from position start to end (public for verification)
    [[nodiscard]] static hash_t apply_chain(std::size_t i, const hash_t& start,
                                             std::size_t from, std::size_t to);

private:
    LMOTSKeyPair() = default;

    // Internal secret key structure (P chains of N bytes each)
    struct SecretKey {
        std::array<hash_t, LMOTS_P> chains;
    };

    lmots_public_key_t public_key_;
    std::unique_ptr<SecretKey> secret_key_;
    bool has_secret_key_ = false;
    std::atomic<bool> used_{false};

    // Compute public key from secret key
    void compute_public_key();

    // Hash chain function: H(i || j || input)
    [[nodiscard]] static hash_t chain_hash(std::size_t i, std::size_t j, const hash_t& input);
};

// ============================================================================
// Standalone Verification
// ============================================================================

[[nodiscard]] bool lmots_verify(
    const lmots_public_key_t& public_key,
    std::span<const std::uint8_t> message,
    const lmots_signature_t& signature);

// ============================================================================
// Double-Sign Detection
// ============================================================================

// Detect if two signatures were created with the same secret key on different messages
// This is possible because LM-OTS reveals partial secret key information
[[nodiscard]] bool lmots_detect_double_sign(
    const lmots_public_key_t& public_key,
    std::span<const std::uint8_t> message1,
    const lmots_signature_t& signature1,
    std::span<const std::uint8_t> message2,
    const lmots_signature_t& signature2);

// ============================================================================
// LM-OTS Signature Structure
// ============================================================================

struct LMOTSSignatureView {
    hash_t C;                               // Randomizer (32 bytes)
    std::array<hash_t, LMOTS_P> y;         // Chain values (67 * 32 = 2144 bytes)

    [[nodiscard]] static std::optional<LMOTSSignatureView> from_bytes(
        const lmots_signature_t& sig);

    [[nodiscard]] lmots_signature_t to_bytes() const;
};

// ============================================================================
// LM-OTS Key Pool (for pre-generation)
// ============================================================================

class LMOTSKeyPool {
public:
    explicit LMOTSKeyPool(std::size_t pool_size);
    ~LMOTSKeyPool();

    // Get a fresh key pair (removes from pool)
    [[nodiscard]] std::optional<LMOTSKeyPair> acquire();

    // Refill pool in background
    void refill();

    // Number of available keys
    [[nodiscard]] std::size_t available() const;

    // Target pool size
    [[nodiscard]] std::size_t target_size() const { return target_size_; }

private:
    std::size_t target_size_;
    std::vector<LMOTSKeyPair> pool_;
    mutable std::mutex mutex_;
};

}  // namespace pop
