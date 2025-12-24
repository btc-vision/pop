#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <chrono>
#include <compare>

namespace pop {

// ============================================================================
// Cryptographic Constants (Quantum-Proof)
// ============================================================================

// ML-DSA-65 (FIPS 204 / Dilithium Level 3)
// Security: ~192-bit classical, ~128-bit quantum
inline constexpr std::size_t MLDSA65_PUBLIC_KEY_SIZE = 1952;
inline constexpr std::size_t MLDSA65_SECRET_KEY_SIZE = 4032;
inline constexpr std::size_t MLDSA65_SIGNATURE_SIZE = 3309;  // From liboqs OQS_SIG_ml_dsa_65_length_signature

// ML-KEM-768 (FIPS 203 / Kyber Level 3)
// Security: ~192-bit classical, ~128-bit quantum
inline constexpr std::size_t MLKEM768_PUBLIC_KEY_SIZE = 1184;
inline constexpr std::size_t MLKEM768_SECRET_KEY_SIZE = 2400;
inline constexpr std::size_t MLKEM768_CIPHERTEXT_SIZE = 1088;
inline constexpr std::size_t MLKEM768_SHARED_SECRET_SIZE = 32;

// SHA3-256 output size
inline constexpr std::size_t HASH_SIZE = 32;

// Address size (same as hash for address derivation)
inline constexpr std::size_t ADDRESS_SIZE = HASH_SIZE;

// AES-256-GCM parameters
inline constexpr std::size_t AES_KEY_SIZE = 32;
inline constexpr std::size_t AES_NONCE_SIZE = 12;
inline constexpr std::size_t AES_TAG_SIZE = 16;

// LM-OTS (Lamport-Merkle One-Time Signatures) - Winternitz w=4
inline constexpr std::size_t LMOTS_W = 4;
inline constexpr std::size_t LMOTS_N = 32;
inline constexpr std::size_t LMOTS_P = 67;
inline constexpr std::size_t LMOTS_PUBLIC_KEY_SIZE = 32;
inline constexpr std::size_t LMOTS_SIGNATURE_SIZE = 2176;

// ============================================================================
// Timing Constants
// ============================================================================

inline constexpr std::uint64_t SLOT_DURATION_US = 100'000;        // 100ms
inline constexpr std::uint64_t GOSSIP_INTERVAL_US = 20'000;       // 20ms
inline constexpr std::uint64_t SLOTS_PER_EPOCH = 100;             // 10 seconds
inline constexpr std::uint64_t SLOTS_PER_TX_EPOCH = 100;          // 10 seconds

// Identity epoch timing
inline constexpr std::uint64_t IDENTITY_EPOCH_DAYS = 30;
inline constexpr std::uint64_t IDENTITY_OVERLAP_HOURS = 24;
inline constexpr std::uint64_t RAMP_HOUR_MODULUS = 12;
inline constexpr std::uint64_t SLOTS_PER_IDENTITY_EPOCH =
    IDENTITY_EPOCH_DAYS * 24 * 60 * 60 * 1'000'000 / SLOT_DURATION_US;

// Receipt bucket timing
inline constexpr std::size_t BUCKET_DURATION_MS = 100;
inline constexpr std::size_t BUCKETS_PER_TX_EPOCH = 20;
inline constexpr std::size_t RECEIPT_CUTOFF_BUCKET = 17;
inline constexpr std::size_t POOL_FREEZE_DELAY_MS = 2100;

// Finality timing
inline constexpr std::uint64_t SOFT_FINALITY_DELAY_MS = 12000;
inline constexpr std::uint64_t MIN_REVEAL_DELAY_SLOTS = 50;       // 5 seconds
inline constexpr std::uint64_t MAX_REVEAL_DELAY_SLOTS = 1000;     // 100 seconds
inline constexpr std::uint64_t MAX_REVEAL_WINDOW_SLOTS = 300;     // 30 seconds
inline constexpr std::uint64_t MAX_REFERENCE_AGE_SLOTS = 300;     // 30 seconds

// ============================================================================
// Capacity Constants
// ============================================================================

inline constexpr std::uint32_t POSITION_MODULUS = 100'000;
inline constexpr std::uint32_t MAX_COMMITS_IN_POOL = 1'000'000;
inline constexpr std::uint32_t MAX_NONCE_GAP = 100;
inline constexpr std::size_t MAX_PAYLOAD_SIZE = 100 * 1024;       // 100KB
inline constexpr std::uint32_t MAX_COMMITS_PER_SLOT = 50'000;

// Sybil resistance
inline constexpr std::size_t IDENTITY_DIFFICULTY_LEADING_ZEROS = 16;  // ~65536 attempts
inline constexpr std::size_t MIN_DISTINCT_PEER_RECEIPTS = 30;

// Spam prevention (Design Refinement R4)
inline constexpr std::uint32_t TARGET_POOL_SIZE = 100'000;            // Dynamic fee floor reference
inline constexpr std::uint32_t MAX_PENDING_PER_SENDER = 100;          // Per-sender pool limit

// VDF sync tolerances (Design Refinement R1)
inline constexpr std::uint32_t VDF_SOFT_TOLERANCE_SLOTS = 3;          // 300ms - can still participate
inline constexpr std::uint32_t VDF_HARD_TOLERANCE_SLOTS = 10;         // 1s - must sync before participation
inline constexpr std::uint32_t VDF_CHECKPOINT_VERIFY_STEPS = 1000;    // Steps to verify per checkpoint

// Access set limits (Design Refinement R8)
inline constexpr std::size_t MAX_ACCESS_SET_SIZE = 10'000;            // Max keys in declared access set
inline constexpr std::uint32_t MAX_CALL_DEPTH = 1024;                 // Max nested contract calls

// ============================================================================
// Network Constants
// ============================================================================

inline constexpr std::uint32_t TARGET_PEERS = 100;
inline constexpr std::uint32_t MAX_PEERS = 200;
inline constexpr std::size_t BLOOM_FILTER_SIZE = 2048;
inline constexpr std::size_t MAX_MESSAGE_SIZE = 1024 * 1024;      // 1MB
inline constexpr std::uint32_t WIRE_MAGIC = 0x504F5032;           // "POP2"

// IBLT parameters
inline constexpr std::size_t IBLT_CELL_COUNT = 1024;
inline constexpr std::size_t IBLT_HASH_COUNT = 4;
inline constexpr std::size_t IBLT_SIZE_BYTES = 68 * 1024;         // ~68KB

// ============================================================================
// Execution Constants
// ============================================================================

inline constexpr std::uint64_t MAX_INSTRUCTIONS_PER_COMMIT = 10'000'000;
inline constexpr std::uint64_t MAX_INSTRUCTIONS_PER_SLOT = 100'000'000;
inline constexpr std::uint64_t INSTRUCTION_PRICE_SATOSHIS = 1;    // per 1000 instructions
inline constexpr std::uint64_t MIN_INCLUSION_FEE = 1000;

// State rent
inline constexpr std::uint64_t RENT_RATE_PER_BYTE_PER_EPOCH = 1;
inline constexpr std::uint64_t BASE_ACCOUNT_OVERHEAD = 128;
inline constexpr std::uint64_t STORAGE_SLOT_SIZE = 32;
inline constexpr std::uint64_t DORMANCY_THRESHOLD_EPOCHS = 100;
inline constexpr std::uint64_t PRUNE_THRESHOLD_EPOCHS = 1000;
inline constexpr std::uint64_t RESURRECTION_BUFFER_EPOCHS = 50;

// ============================================================================
// Core Type Aliases
// ============================================================================

using hash_t = std::array<std::uint8_t, HASH_SIZE>;
using slot_t = std::uint64_t;
using position_t = std::uint32_t;
using nonce_t = std::uint64_t;
using epoch_t = std::uint64_t;
using identity_epoch_t = std::uint64_t;
using tx_epoch_t = std::uint64_t;

// ============================================================================
// Cryptographic Key Types
// ============================================================================

// ML-DSA-65 keys and signature
using mldsa_public_key_t = std::array<std::uint8_t, MLDSA65_PUBLIC_KEY_SIZE>;
using mldsa_secret_key_t = std::array<std::uint8_t, MLDSA65_SECRET_KEY_SIZE>;
using mldsa_signature_t = std::array<std::uint8_t, MLDSA65_SIGNATURE_SIZE>;

// ML-KEM-768 keys and ciphertext
using mlkem_public_key_t = std::array<std::uint8_t, MLKEM768_PUBLIC_KEY_SIZE>;
using mlkem_secret_key_t = std::array<std::uint8_t, MLKEM768_SECRET_KEY_SIZE>;
using mlkem_ciphertext_t = std::array<std::uint8_t, MLKEM768_CIPHERTEXT_SIZE>;
using shared_secret_t = std::array<std::uint8_t, MLKEM768_SHARED_SECRET_SIZE>;

// LM-OTS keys
using lmots_public_key_t = std::array<std::uint8_t, LMOTS_PUBLIC_KEY_SIZE>;
using lmots_signature_t = std::array<std::uint8_t, LMOTS_SIGNATURE_SIZE>;

// AES-256 key
using aes_key_t = std::array<std::uint8_t, AES_KEY_SIZE>;
using aes_nonce_t = std::array<std::uint8_t, AES_NONCE_SIZE>;
using aes_tag_t = std::array<std::uint8_t, AES_TAG_SIZE>;

// ============================================================================
// Node Identity
// ============================================================================

struct NodeId {
    mldsa_public_key_t public_key;

    [[nodiscard]] hash_t hash() const;
    [[nodiscard]] std::string to_hex() const;

    auto operator<=>(const NodeId&) const = default;
};

// ============================================================================
// Address (derived from public key hash)
// ============================================================================

struct Address {
    hash_t bytes;

    [[nodiscard]] static Address from_public_key(const mldsa_public_key_t& pk);
    [[nodiscard]] std::string to_hex() const;
    [[nodiscard]] static std::optional<Address> from_hex(std::string_view hex);

    [[nodiscard]] bool is_zero() const {
        for (auto b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }

    // Iterator support
    [[nodiscard]] auto begin() { return bytes.begin(); }
    [[nodiscard]] auto end() { return bytes.end(); }
    [[nodiscard]] auto begin() const { return bytes.begin(); }
    [[nodiscard]] auto end() const { return bytes.end(); }

    auto operator<=>(const Address&) const = default;
};

// ============================================================================
// Time Utilities
// ============================================================================

using timestamp_t = std::chrono::microseconds;
using steady_time_t = std::chrono::steady_clock::time_point;
using system_time_t = std::chrono::system_clock::time_point;

[[nodiscard]] inline slot_t time_to_slot(timestamp_t ts, timestamp_t genesis) {
    auto elapsed = ts - genesis;
    return static_cast<slot_t>(elapsed.count() / SLOT_DURATION_US);
}

[[nodiscard]] inline timestamp_t slot_to_time(slot_t slot, timestamp_t genesis) {
    return genesis + timestamp_t(slot * SLOT_DURATION_US);
}

[[nodiscard]] inline epoch_t slot_to_epoch(slot_t slot) {
    return slot / SLOTS_PER_EPOCH;
}

[[nodiscard]] inline slot_t epoch_start_slot(epoch_t epoch) {
    return epoch * SLOTS_PER_EPOCH;
}

[[nodiscard]] inline slot_t epoch_end_slot(epoch_t epoch) {
    return (epoch + 1) * SLOTS_PER_EPOCH - 1;
}

[[nodiscard]] inline tx_epoch_t slot_to_tx_epoch(slot_t slot) {
    return slot / SLOTS_PER_TX_EPOCH;
}

[[nodiscard]] inline identity_epoch_t slot_to_identity_epoch(slot_t slot) {
    return slot / SLOTS_PER_IDENTITY_EPOCH;
}

// ============================================================================
// Slot Phase
// ============================================================================

enum class SlotPhase : std::uint8_t {
    OPEN = 0,       // T+0ms to T+20ms
    GOSSIP_1 = 1,   // T+20ms to T+40ms
    GOSSIP_2 = 2,   // T+40ms to T+60ms
    GOSSIP_3 = 3,   // T+60ms to T+80ms
    GOSSIP_4 = 4,   // T+80ms to T+100ms
    CLOSED = 5,     // Slot boundary crossed
};

[[nodiscard]] inline SlotPhase get_slot_phase(timestamp_t current, timestamp_t slot_start) {
    auto offset = (current - slot_start).count();
    if (offset < 0 || offset >= static_cast<std::int64_t>(SLOT_DURATION_US)) {
        return SlotPhase::CLOSED;
    }
    return static_cast<SlotPhase>(offset / GOSSIP_INTERVAL_US);
}

// ============================================================================
// Message Types (Wire Protocol V2)
// ============================================================================

enum class MessageType : std::uint16_t {
    // Core messages
    COMMIT = 0x0001,
    REVEAL = 0x0002,
    GOSSIP = 0x0003,
    COMMIT_REQUEST = 0x0004,
    COMMIT_RESPONSE = 0x0005,
    STATE_REQUEST = 0x0006,
    STATE_RESPONSE = 0x0007,
    PEER_EXCHANGE = 0x0008,
    PING = 0x0009,
    PONG = 0x000A,
    ERROR = 0x000B,

    // Protocol V2
    COMMIT_V2 = 0x0010,
    REVEAL_V2 = 0x0011,
    BATCH_RECEIPT = 0x0012,
    RECEIPT_REQUEST = 0x0013,
    RECEIPT_RESPONSE = 0x0014,

    // Identity
    IDENTITY_ANNOUNCE = 0x0020,
    IDENTITY_REQUEST = 0x0021,
    IDENTITY_RESPONSE = 0x0022,

    // Finality
    ATTESTATION = 0x0030,
    IBLT_SYNC = 0x0031,
    IBLT_REQUEST = 0x0032,
    IBLT_RESPONSE = 0x0033,
    HASH_LIST_REQUEST = 0x0034,
    HASH_LIST_RESPONSE = 0x0035,

    // LM-OTS
    DOUBLE_SIGN_PROOF = 0x0041,

    // VDF Checkpoints
    VDF_CHECKPOINT = 0x0050,
    VDF_CHECKPOINT_REQUEST = 0x0051,
    VDF_CHECKPOINT_RESPONSE = 0x0052,

    // Peer Discovery
    PEER_EXCHANGE_REQUEST = 0x0061,
};

// ============================================================================
// Receipt Status Codes
// ============================================================================

enum class ReceiptStatus : std::uint8_t {
    SUCCESS = 0x00,
    REVERT = 0x01,
    OUT_OF_INSTRUCTIONS = 0x02,
    INVALID_NONCE = 0x03,
    INSUFFICIENT_BALANCE = 0x04,
    INVALID_PAYLOAD_HASH = 0x05,
    CONTRACT_NOT_FOUND = 0x06,
    NOT_REVEALED = 0x07,
    EXPIRED = 0x08,
    COLLISION_LOSER = 0x09,
    INVALID_SIGNATURE = 0x0A,
    EXECUTION_ERROR = 0x0B,
    ACCESS_VIOLATION = 0x0C,      // Undeclared read/write
    EXPECTATION_FAILED = 0x0D,    // State expectation not met
    INSUFFICIENT_RECEIPTS = 0x0E, // Less than 30 batch receipts
    DORMANT_ACCOUNT = 0x0F,       // Account is dormant
    PARTITION_REVERTED = 0x10,    // Reverted due to partition resolution (R2)
    SENDER_BANNED = 0x11,         // Sender banned for double-signing (R7)
};

[[nodiscard]] inline std::string_view receipt_status_string(ReceiptStatus status) {
    switch (status) {
        case ReceiptStatus::SUCCESS: return "success";
        case ReceiptStatus::REVERT: return "revert";
        case ReceiptStatus::OUT_OF_INSTRUCTIONS: return "out_of_instructions";
        case ReceiptStatus::INVALID_NONCE: return "invalid_nonce";
        case ReceiptStatus::INSUFFICIENT_BALANCE: return "insufficient_balance";
        case ReceiptStatus::INVALID_PAYLOAD_HASH: return "invalid_payload_hash";
        case ReceiptStatus::CONTRACT_NOT_FOUND: return "contract_not_found";
        case ReceiptStatus::NOT_REVEALED: return "not_revealed";
        case ReceiptStatus::EXPIRED: return "expired";
        case ReceiptStatus::COLLISION_LOSER: return "collision_loser";
        case ReceiptStatus::INVALID_SIGNATURE: return "invalid_signature";
        case ReceiptStatus::EXECUTION_ERROR: return "execution_error";
        case ReceiptStatus::ACCESS_VIOLATION: return "access_violation";
        case ReceiptStatus::EXPECTATION_FAILED: return "expectation_failed";
        case ReceiptStatus::INSUFFICIENT_RECEIPTS: return "insufficient_receipts";
        case ReceiptStatus::DORMANT_ACCOUNT: return "dormant_account";
        case ReceiptStatus::PARTITION_REVERTED: return "partition_reverted";
        case ReceiptStatus::SENDER_BANNED: return "sender_banned";
    }
    return "unknown";
}

// ============================================================================
// Commit State
// ============================================================================

enum class CommitState : std::uint8_t {
    PENDING = 0,        // In pool, not yet in closed slot
    LOCKED = 1,         // Slot closed, position immutable
    REVEALED = 2,       // Reveal received and validated
    EXECUTED = 3,       // Execution complete
    EXPIRED = 4,        // Reveal window passed
    COLLISION_LOSER = 5,// Lost collision resolution
    INVALID = 6,        // Failed validation
    DROPPED = 7,        // Access violation or expectation failure
};

// ============================================================================
// Dormancy State
// ============================================================================

enum class DormancyState : std::uint8_t {
    ACTIVE = 0,
    DORMANT = 1,
    PRUNED = 2,
};

// ============================================================================
// Finality Type
// ============================================================================

enum class FinalityType : std::uint8_t {
    NONE = 0,
    SOFT = 1,   // Time-based, binding
    HARD = 2,   // Convergence-based, confirmed
};

// ============================================================================
// Fee Mode
// ============================================================================

enum class FeeMode : std::uint8_t {
    PAY_ON_INCLUDE = 0,
    PAY_ON_EXECUTE = 1,
};

// ============================================================================
// Serialization Helpers
// ============================================================================

// Little-endian encoding
inline void encode_u16(std::uint8_t* dst, std::uint16_t val) {
    dst[0] = static_cast<std::uint8_t>(val);
    dst[1] = static_cast<std::uint8_t>(val >> 8);
}

inline void encode_u32(std::uint8_t* dst, std::uint32_t val) {
    dst[0] = static_cast<std::uint8_t>(val);
    dst[1] = static_cast<std::uint8_t>(val >> 8);
    dst[2] = static_cast<std::uint8_t>(val >> 16);
    dst[3] = static_cast<std::uint8_t>(val >> 24);
}

inline void encode_u64(std::uint8_t* dst, std::uint64_t val) {
    dst[0] = static_cast<std::uint8_t>(val);
    dst[1] = static_cast<std::uint8_t>(val >> 8);
    dst[2] = static_cast<std::uint8_t>(val >> 16);
    dst[3] = static_cast<std::uint8_t>(val >> 24);
    dst[4] = static_cast<std::uint8_t>(val >> 32);
    dst[5] = static_cast<std::uint8_t>(val >> 40);
    dst[6] = static_cast<std::uint8_t>(val >> 48);
    dst[7] = static_cast<std::uint8_t>(val >> 56);
}

[[nodiscard]] inline std::uint16_t decode_u16(const std::uint8_t* src) {
    return static_cast<std::uint16_t>(src[0]) |
           (static_cast<std::uint16_t>(src[1]) << 8);
}

[[nodiscard]] inline std::uint32_t decode_u32(const std::uint8_t* src) {
    return static_cast<std::uint32_t>(src[0]) |
           (static_cast<std::uint32_t>(src[1]) << 8) |
           (static_cast<std::uint32_t>(src[2]) << 16) |
           (static_cast<std::uint32_t>(src[3]) << 24);
}

[[nodiscard]] inline std::uint64_t decode_u64(const std::uint8_t* src) {
    return static_cast<std::uint64_t>(src[0]) |
           (static_cast<std::uint64_t>(src[1]) << 8) |
           (static_cast<std::uint64_t>(src[2]) << 16) |
           (static_cast<std::uint64_t>(src[3]) << 24) |
           (static_cast<std::uint64_t>(src[4]) << 32) |
           (static_cast<std::uint64_t>(src[5]) << 40) |
           (static_cast<std::uint64_t>(src[6]) << 48) |
           (static_cast<std::uint64_t>(src[7]) << 56);
}

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

[[nodiscard]] std::string bytes_to_hex(std::span<const std::uint8_t> bytes);
[[nodiscard]] std::optional<std::vector<std::uint8_t>> hex_to_bytes(std::string_view hex);

// ============================================================================
// Zero Memory (for sensitive data)
// ============================================================================

void secure_zero(void* ptr, std::size_t len);

template<typename T>
void secure_zero(T& container) {
    secure_zero(container.data(), container.size());
}

}  // namespace pop

// ============================================================================
// Hash specialization for hash_t (enables use in unordered_map/unordered_set)
// ============================================================================

namespace std {

template<>
struct hash<pop::hash_t> {
    std::size_t operator()(const pop::hash_t& h) const noexcept {
        // Use first 8 bytes as hash (already cryptographic quality)
        std::size_t result = 0;
        for (std::size_t i = 0; i < sizeof(std::size_t) && i < h.size(); ++i) {
            result |= static_cast<std::size_t>(h[i]) << (i * 8);
        }
        return result;
    }
};

template<>
struct hash<pop::Address> {
    std::size_t operator()(const pop::Address& addr) const noexcept {
        return std::hash<pop::hash_t>{}(addr.bytes);
    }
};

}  // namespace std
