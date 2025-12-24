#pragma once

#include "core/types.hh"
#include "crypto/hash.hh"
#include <cstring>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>
#include <mutex>

namespace pop {

// ============================================================================
// Identity Structure
// ============================================================================

struct Identity {
    mldsa_public_key_t public_key;
    std::uint64_t nonce;           // PoW nonce
    identity_epoch_t epoch;        // Epoch this identity is valid for
    hash_t salt;                   // SHA3("identity" || hard_state_root_at_end_of_T-1)
    hash_t identity_hash;          // SHA3(public_key || nonce || epoch || salt)

    // Verify that identity_hash meets difficulty requirement
    [[nodiscard]] bool verify_difficulty() const;

    // Check if identity is eligible at a given time
    // Eligibility starts at ramp hour = SHA3(public_key) mod 12
    [[nodiscard]] bool is_eligible(timestamp_t now, timestamp_t genesis) const;

    // Get identity age (consecutive valid epochs)
    [[nodiscard]] std::size_t age(identity_epoch_t current) const;

    // Compute identity hash
    void compute_hash();

    // Serialize/deserialize
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<Identity> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        MLDSA65_PUBLIC_KEY_SIZE +       // public_key
        sizeof(std::uint64_t) +          // nonce
        sizeof(identity_epoch_t) +       // epoch
        HASH_SIZE +                      // salt
        HASH_SIZE;                       // identity_hash
};

// ============================================================================
// Identity Announcement (for network propagation)
// ============================================================================

struct IdentityAnnouncement {
    Identity identity;
    mldsa_signature_t signature;     // Signed by the identity's key
    timestamp_t announced_at;

    [[nodiscard]] bool verify() const;
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<IdentityAnnouncement> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        Identity::SERIALIZED_SIZE +
        MLDSA65_SIGNATURE_SIZE +
        sizeof(std::uint64_t);           // announced_at (microseconds)
};

// ============================================================================
// Identity Miner
// ============================================================================

struct IdentityMiningResult {
    bool found;
    Identity identity;
    std::uint64_t attempts;
    std::chrono::microseconds duration;
};

class IdentityMiner {
public:
    // Mine identity for a given epoch
    // max_attempts = 0 means unlimited
    [[nodiscard]] static IdentityMiningResult mine(
        const mldsa_public_key_t& public_key,
        const hash_t& salt,
        identity_epoch_t epoch,
        std::uint64_t max_attempts = 0);

    // Mine with early termination callback
    [[nodiscard]] static IdentityMiningResult mine_interruptible(
        const mldsa_public_key_t& public_key,
        const hash_t& salt,
        identity_epoch_t epoch,
        std::function<bool()> should_stop);

    // Compute salt for an epoch given the finalized state root
    [[nodiscard]] static hash_t compute_salt(
        identity_epoch_t epoch,
        const hash_t& hard_state_root);
};

// ============================================================================
// Ban Reason (Design Refinement R7)
// ============================================================================

enum class BanReason : std::uint8_t {
    DOUBLE_SIGN = 0,              // LM-OTS key reuse detected
    INVALID_RECEIPT = 1,          // Malformed batch receipt
    EQUIVOCATION = 2,             // Signed conflicting attestations
};

[[nodiscard]] inline std::string_view ban_reason_string(BanReason reason) {
    switch (reason) {
        case BanReason::DOUBLE_SIGN: return "double_sign";
        case BanReason::INVALID_RECEIPT: return "invalid_receipt";
        case BanReason::EQUIVOCATION: return "equivocation";
    }
    return "unknown";
}

// ============================================================================
// Double-Sign Proof (for network propagation)
// ============================================================================

struct DoubleSignProof {
    lmots_public_key_t public_key;
    std::vector<std::uint8_t> message1;
    lmots_signature_t signature1;
    std::vector<std::uint8_t> message2;
    lmots_signature_t signature2;

    [[nodiscard]] bool verify() const;
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<DoubleSignProof> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Identity Registry
// ============================================================================

class IdentityRegistry {
public:
    IdentityRegistry() = default;

    // Register a new identity (validates PoW and epoch)
    enum class RegisterResult {
        SUCCESS,
        INVALID_DIFFICULTY,
        WRONG_EPOCH,
        WRONG_SALT,
        DUPLICATE,
        INVALID_SIGNATURE,
        SENDER_BANNED,            // Public key is banned (Design Refinement R7)
    };
    RegisterResult register_identity(const IdentityAnnouncement& ann);

    // Check if a public key has a valid identity for an epoch
    [[nodiscard]] bool is_valid(
        const mldsa_public_key_t& pk,
        identity_epoch_t epoch) const;

    // Get identity for a public key (if exists)
    [[nodiscard]] std::optional<Identity> get_identity(
        const mldsa_public_key_t& pk) const;

    // Get age of identity (consecutive epochs)
    [[nodiscard]] std::size_t get_age(
        const mldsa_public_key_t& pk,
        identity_epoch_t current_epoch) const;

    // Get all identities for an epoch
    [[nodiscard]] std::vector<Identity> get_epoch_identities(
        identity_epoch_t epoch) const;

    // Set the expected salt for epoch validation
    void set_epoch_salt(identity_epoch_t epoch, const hash_t& salt);

    // Transition to new epoch (prune old identities)
    void transition_epoch(identity_epoch_t new_epoch);

    // Get total count of valid identities
    [[nodiscard]] std::size_t total_identities() const;

    // ========================================================================
    // Ban List (Design Refinement R7)
    // ========================================================================

    // Ban a public key (permanent until explicit unban)
    enum class BanResult {
        SUCCESS,
        ALREADY_BANNED,
        INVALID_PROOF,
    };
    BanResult ban(const mldsa_public_key_t& pk, BanReason reason,
                  const std::optional<DoubleSignProof>& proof = std::nullopt);

    // Ban using a double-sign proof (verifies proof first)
    BanResult ban_with_proof(const DoubleSignProof& proof);

    // Check if a public key is banned
    [[nodiscard]] bool is_banned(const mldsa_public_key_t& pk) const;

    // Get ban reason for a public key
    [[nodiscard]] std::optional<BanReason> get_ban_reason(const mldsa_public_key_t& pk) const;

    // Get all banned public keys (for gossip propagation)
    [[nodiscard]] std::vector<std::pair<hash_t, BanReason>> get_ban_list() const;

    // Get count of banned identities
    [[nodiscard]] std::size_t banned_count() const;

    // Serialize/deserialize state
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<IdentityRegistry> deserialize(
        std::span<const std::uint8_t> data);

private:
    struct IdentityRecord {
        Identity identity;
        identity_epoch_t first_seen_epoch;
        std::vector<identity_epoch_t> valid_epochs;
    };

    struct BanRecord {
        BanReason reason;
        identity_epoch_t banned_at_epoch;
        std::optional<DoubleSignProof> proof;  // Evidence if available
    };

    std::unordered_map<hash_t, IdentityRecord> identities_;  // Keyed by SHA3(public_key)
    std::unordered_map<hash_t, BanRecord> ban_list_;         // Keyed by SHA3(public_key)
    std::unordered_map<identity_epoch_t, hash_t> epoch_salts_;
    identity_epoch_t current_epoch_ = 0;
    mutable std::unique_ptr<std::mutex> mutex_ = std::make_unique<std::mutex>();

    [[nodiscard]] hash_t pk_hash(const mldsa_public_key_t& pk) const;
};

// ============================================================================
// Eligibility Ramp Calculation
// ============================================================================

// Get the hour (0-11) when an identity becomes eligible in a new epoch
[[nodiscard]] inline std::uint8_t eligibility_ramp_hour(const mldsa_public_key_t& pk) {
    hash_t h = sha3_256(pk);
    return h[0] % RAMP_HOUR_MODULUS;
}

// Get the absolute time when an identity becomes eligible for an epoch
[[nodiscard]] timestamp_t eligibility_start_time(
    const mldsa_public_key_t& pk,
    identity_epoch_t epoch,
    timestamp_t genesis);

// Check if currently in the overlap period between epochs
[[nodiscard]] bool is_overlap_period(
    timestamp_t now,
    identity_epoch_t epoch,
    timestamp_t genesis);

}  // namespace pop
