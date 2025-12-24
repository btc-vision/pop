#pragma once

#include "core/types.hh"
#include <span>
#include <vector>
#include <compare>

namespace pop {

// ============================================================================
// Two-Dimensional Position
// ============================================================================

struct Position2D {
    position_t position;      // SHA3(commit_header) mod 100,000
    hash_t subposition;       // SHA3(commit_header || 0x01) - full 256-bit

    // Lexicographic ordering: position first, then subposition
    [[nodiscard]] auto operator<=>(const Position2D& other) const {
        if (position != other.position) {
            return position <=> other.position;
        }
        return subposition <=> other.subposition;
    }

    [[nodiscard]] bool operator==(const Position2D& other) const = default;

    // Compute position from commit header bytes
    [[nodiscard]] static Position2D compute(std::span<const std::uint8_t> header);

    // Compute position with retry nonce for position grinding
    [[nodiscard]] static Position2D compute_with_nonce(
        std::span<const std::uint8_t> base,
        std::uint64_t retry_nonce);

    // Serialize to bytes
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<Position2D> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE = sizeof(position_t) + HASH_SIZE;
};

// ============================================================================
// Commit Header (determines position)
// ============================================================================

struct CommitHeader {
    Address fee_recipient;           // Who receives priority fees
    std::uint64_t max_fee;           // Maximum total fee willing to pay
    FeeMode fee_mode;                // PAY_ON_INCLUDE or PAY_ON_EXECUTE
    std::uint64_t retry_nonce;       // For position grinding
    std::uint64_t max_instructions;  // Instruction limit for execution
    hash_t payload_hash;             // SHA3(decrypted payload)
    mldsa_public_key_t sender;       // Sender's public key
    slot_t commit_slot;              // Slot when committed

    // Compute the two-dimensional position for this header
    [[nodiscard]] Position2D position() const;

    // Compute canonical hash of this header
    [[nodiscard]] hash_t hash() const;

    // Serialize to bytes (canonical format)
    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<CommitHeader> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        HASH_SIZE +                          // fee_recipient
        sizeof(std::uint64_t) +              // max_fee
        sizeof(FeeMode) +                    // fee_mode
        sizeof(std::uint64_t) +              // retry_nonce
        sizeof(std::uint64_t) +              // max_instructions
        HASH_SIZE +                          // payload_hash
        MLDSA65_PUBLIC_KEY_SIZE +            // sender
        sizeof(slot_t);                      // commit_slot
};

// ============================================================================
// Ordered Commit List
// ============================================================================

class OrderedCommitList {
public:
    struct Entry {
        Position2D position;
        hash_t commit_hash;
    };

    OrderedCommitList() = default;

    // Insert a commit, maintaining sorted order
    void insert(const Position2D& position, const hash_t& commit_hash);

    // Remove a commit by hash
    bool remove(const hash_t& commit_hash);

    // Check if a position would collide (same position, different subposition wins)
    [[nodiscard]] bool would_collide(const Position2D& position) const;

    // Get all entries in order
    [[nodiscard]] const std::vector<Entry>& entries() const { return entries_; }

    // Get entry at specific position (nullptr if not found)
    [[nodiscard]] const Entry* at_position(position_t pos) const;

    // Get winning entry at position (highest subposition)
    [[nodiscard]] const Entry* winner_at_position(position_t pos) const;

    // Get all losers at a position (all but the winner)
    [[nodiscard]] std::vector<Entry> losers_at_position(position_t pos) const;

    // Count of entries
    [[nodiscard]] std::size_t size() const { return entries_.size(); }

    // Clear all entries
    void clear() { entries_.clear(); }

private:
    std::vector<Entry> entries_;  // Sorted by Position2D
};

// ============================================================================
// Position Collision Resolution
// ============================================================================

enum class CollisionResult {
    NO_COLLISION,      // Different positions
    WINNER,            // This commit wins (higher subposition)
    LOSER,             // This commit loses (lower subposition)
    DUPLICATE,         // Same position and subposition (impossible in practice)
};

// Compare two positions for collision resolution
[[nodiscard]] CollisionResult resolve_collision(
    const Position2D& a, const Position2D& b);

// ============================================================================
// Position Mining (for retry_nonce optimization)
// ============================================================================

struct PositionMiningConfig {
    std::uint32_t target_position_start = 0;
    std::uint32_t target_position_end = POSITION_MODULUS;
    std::uint64_t max_attempts = 1'000'000;
};

struct PositionMiningResult {
    bool found;
    std::uint64_t retry_nonce;
    Position2D position;
    std::uint64_t attempts;
};

// Mine for a position in target range
[[nodiscard]] PositionMiningResult mine_position(
    const CommitHeader& base_header,
    const PositionMiningConfig& config);

// Mine for a position with minimum subposition (to win collisions)
[[nodiscard]] PositionMiningResult mine_high_subposition(
    const CommitHeader& base_header,
    position_t target_position,
    const hash_t& current_best_subposition,
    std::uint64_t max_attempts);

}  // namespace pop
