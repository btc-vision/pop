#pragma once

#include "core/types.hh"
#include "consensus/identity.hh"
#include "consensus/batch_receipt.hh"
#include "consensus/finality.hh"
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pop {

// MessageType is defined in core/types.hh

// Helper function for message type to string conversion
[[nodiscard]] inline std::string_view message_type_string(MessageType type) {
    switch (type) {
        case MessageType::COMMIT: return "commit";
        case MessageType::REVEAL: return "reveal";
        case MessageType::GOSSIP: return "gossip";
        case MessageType::COMMIT_REQUEST: return "commit_request";
        case MessageType::COMMIT_RESPONSE: return "commit_response";
        case MessageType::STATE_REQUEST: return "state_request";
        case MessageType::STATE_RESPONSE: return "state_response";
        case MessageType::PEER_EXCHANGE: return "peer_exchange";
        case MessageType::PING: return "ping";
        case MessageType::PONG: return "pong";
        case MessageType::ERROR: return "error";
        case MessageType::COMMIT_V2: return "commit_v2";
        case MessageType::REVEAL_V2: return "reveal_v2";
        case MessageType::BATCH_RECEIPT: return "batch_receipt";
        case MessageType::RECEIPT_REQUEST: return "receipt_request";
        case MessageType::RECEIPT_RESPONSE: return "receipt_response";
        case MessageType::IDENTITY_ANNOUNCE: return "identity_announce";
        case MessageType::IDENTITY_REQUEST: return "identity_request";
        case MessageType::IDENTITY_RESPONSE: return "identity_response";
        case MessageType::ATTESTATION: return "attestation";
        case MessageType::IBLT_SYNC: return "iblt_sync";
        case MessageType::IBLT_REQUEST: return "iblt_request";
        case MessageType::IBLT_RESPONSE: return "iblt_response";
        case MessageType::HASH_LIST_REQUEST: return "hash_list_request";
        case MessageType::HASH_LIST_RESPONSE: return "hash_list_response";
        case MessageType::DOUBLE_SIGN_PROOF: return "double_sign_proof";
        case MessageType::VDF_CHECKPOINT: return "vdf_checkpoint";
        case MessageType::VDF_CHECKPOINT_REQUEST: return "vdf_checkpoint_request";
        case MessageType::VDF_CHECKPOINT_RESPONSE: return "vdf_checkpoint_response";
        case MessageType::PEER_EXCHANGE_REQUEST: return "peer_exchange_request";
    }
    return "unknown";
}

// ============================================================================
// Message Header
// ============================================================================

struct MessageHeader {
    static constexpr std::uint32_t MAGIC = WIRE_MAGIC;  // "POP2"
    static constexpr std::size_t SIZE = 12;

    std::uint32_t magic;
    MessageType type;
    std::uint16_t flags;
    std::uint32_t payload_length;

    [[nodiscard]] bool is_valid() const { return magic == MAGIC; }

    [[nodiscard]] std::array<std::uint8_t, SIZE> serialize() const;
    [[nodiscard]] static std::optional<MessageHeader> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Gossip Message (V2)
// ============================================================================

struct GossipMessage {
    hash_t node_id;
    std::uint64_t timestamp_us;
    slot_t current_slot;
    std::uint8_t cycle_number;

    // Commit pool info
    std::uint32_t commit_count;
    std::array<std::uint8_t, BLOOM_FILTER_SIZE> commit_bloom;

    // Execution state
    slot_t executed_slot;
    hash_t state_root;

    // PoP extensions
    epoch_t executed_epoch;
    std::uint32_t receipt_count;
    std::uint32_t identity_age;
    hash_t reveal_commitment;  // Merkle root of pending reveals
    std::array<std::uint8_t, BLOOM_FILTER_SIZE> reveal_bloom;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<GossipMessage> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        HASH_SIZE +                     // node_id
        sizeof(std::uint64_t) +         // timestamp_us
        sizeof(slot_t) +                // current_slot
        sizeof(std::uint8_t) +          // cycle_number
        sizeof(std::uint32_t) +         // commit_count
        BLOOM_FILTER_SIZE +             // commit_bloom
        sizeof(slot_t) +                // executed_slot
        HASH_SIZE +                     // state_root
        sizeof(epoch_t) +               // executed_epoch
        sizeof(std::uint32_t) +         // receipt_count
        sizeof(std::uint32_t) +         // identity_age
        HASH_SIZE +                     // reveal_commitment
        BLOOM_FILTER_SIZE;              // reveal_bloom
};

// ============================================================================
// Ping/Pong Messages
// ============================================================================

struct PingMessage {
    std::uint64_t nonce;
    std::uint64_t timestamp_us;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<PingMessage> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE = 16;
};

struct PongMessage {
    std::uint64_t nonce;           // Echo from ping
    std::uint64_t request_time_us; // Echo from ping
    std::uint64_t response_time_us;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<PongMessage> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE = 24;
};

// ============================================================================
// VDF Checkpoint Message
// ============================================================================

struct VDFCheckpointMessage {
    slot_t slot;
    hash_t vdf_output;
    std::uint64_t step_count;
    mldsa_signature_t signature;  // Signed by sender

    [[nodiscard]] bool verify(const mldsa_public_key_t& pk) const;
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<VDFCheckpointMessage> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        sizeof(slot_t) +
        HASH_SIZE +
        sizeof(std::uint64_t) +
        MLDSA65_SIGNATURE_SIZE;
};

// ============================================================================
// Peer Exchange Message
// ============================================================================

struct PeerInfo {
    hash_t node_id;
    std::string address;       // IP:port
    std::uint32_t identity_age;
    std::uint64_t last_seen_us;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<PeerInfo> deserialize(
        std::span<const std::uint8_t> data);
};

struct PeerExchangeMessage {
    std::vector<PeerInfo> peers;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<PeerExchangeMessage> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Error Message
// ============================================================================

enum class ErrorCode : std::uint16_t {
    OK = 0,
    UNKNOWN_MESSAGE_TYPE = 1,
    INVALID_SIGNATURE = 2,
    MESSAGE_TOO_LARGE = 3,
    RATE_LIMITED = 4,
    PEER_BANNED = 5,
    INTERNAL_ERROR = 6,
    NOT_FOUND = 7,
    INVALID_EPOCH = 8,
    STALE_MESSAGE = 9,
};

[[nodiscard]] inline std::string_view error_code_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::OK: return "ok";
        case ErrorCode::UNKNOWN_MESSAGE_TYPE: return "unknown_message_type";
        case ErrorCode::INVALID_SIGNATURE: return "invalid_signature";
        case ErrorCode::MESSAGE_TOO_LARGE: return "message_too_large";
        case ErrorCode::RATE_LIMITED: return "rate_limited";
        case ErrorCode::PEER_BANNED: return "peer_banned";
        case ErrorCode::INTERNAL_ERROR: return "internal_error";
        case ErrorCode::NOT_FOUND: return "not_found";
        case ErrorCode::INVALID_EPOCH: return "invalid_epoch";
        case ErrorCode::STALE_MESSAGE: return "stale_message";
    }
    return "unknown";
}

struct ErrorMessage {
    ErrorCode code;
    std::string message;
    std::optional<hash_t> related_hash;  // For context

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<ErrorMessage> deserialize(
        std::span<const std::uint8_t> data);
};

}  // namespace pop
