#include "ordering.hh"
#include "crypto/hash.hh"
#include "core/logging.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// Position2D Implementation
// ============================================================================

Position2D Position2D::compute(std::span<const std::uint8_t> header) {
    Position2D result;

    // Primary position: SHA3(header) mod POSITION_MODULUS
    hash_t primary_hash = sha3_256(header);
    result.position = hash_to_position(primary_hash);

    // Subposition: SHA3(header || 0x01)
    SHA3Hasher hasher;
    hasher.update(header);
    std::array<std::uint8_t, 1> suffix = {0x01};
    hasher.update(suffix);
    result.subposition = hasher.finalize();

    return result;
}

Position2D Position2D::compute_with_nonce(
    std::span<const std::uint8_t> base,
    std::uint64_t retry_nonce) {

    // Append nonce to base before hashing
    SHA3Hasher hasher;
    hasher.update(base);
    std::array<std::uint8_t, 8> nonce_bytes;
    encode_u64(nonce_bytes.data(), retry_nonce);
    hasher.update(nonce_bytes);

    hash_t combined_hash = hasher.finalize();

    Position2D result;
    result.position = hash_to_position(combined_hash);

    // Subposition with nonce
    SHA3Hasher sub_hasher;
    sub_hasher.update(base);
    sub_hasher.update(nonce_bytes);
    std::array<std::uint8_t, 1> suffix = {0x01};
    sub_hasher.update(suffix);
    result.subposition = sub_hasher.finalize();

    return result;
}

std::vector<std::uint8_t> Position2D::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    encode_u32(result.data(), position);
    std::copy(subposition.begin(), subposition.end(), result.data() + sizeof(position_t));
    return result;
}

std::optional<Position2D> Position2D::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        POP_LOG_DEBUG(log::consensus) << "Position2D deserialization failed: insufficient data";
        return std::nullopt;
    }

    Position2D result;
    result.position = decode_u32(data.data());
    std::copy(data.data() + sizeof(position_t),
              data.data() + sizeof(position_t) + HASH_SIZE,
              result.subposition.begin());
    return result;
}

// ============================================================================
// CommitHeader Implementation
// ============================================================================

Position2D CommitHeader::position() const {
    auto serialized = serialize();
    return Position2D::compute_with_nonce(serialized, retry_nonce);
}

hash_t CommitHeader::hash() const {
    return sha3_256(serialize());
}

std::vector<std::uint8_t> CommitHeader::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    // fee_recipient
    std::copy(fee_recipient.bytes.begin(), fee_recipient.bytes.end(), ptr);
    ptr += HASH_SIZE;

    // max_fee
    encode_u64(ptr, max_fee);
    ptr += sizeof(std::uint64_t);

    // fee_mode
    *ptr++ = static_cast<std::uint8_t>(fee_mode);

    // retry_nonce
    encode_u64(ptr, retry_nonce);
    ptr += sizeof(std::uint64_t);

    // max_instructions
    encode_u64(ptr, max_instructions);
    ptr += sizeof(std::uint64_t);

    // payload_hash
    std::copy(payload_hash.begin(), payload_hash.end(), ptr);
    ptr += HASH_SIZE;

    // sender
    std::copy(sender.begin(), sender.end(), ptr);
    ptr += MLDSA65_PUBLIC_KEY_SIZE;

    // commit_slot
    encode_u64(ptr, commit_slot);

    return result;
}

std::optional<CommitHeader> CommitHeader::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    CommitHeader header;
    const std::uint8_t* ptr = data.data();

    // fee_recipient
    std::copy(ptr, ptr + HASH_SIZE, header.fee_recipient.bytes.begin());
    ptr += HASH_SIZE;

    // max_fee
    header.max_fee = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    // fee_mode
    header.fee_mode = static_cast<FeeMode>(*ptr++);

    // retry_nonce
    header.retry_nonce = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    // max_instructions
    header.max_instructions = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    // payload_hash
    std::copy(ptr, ptr + HASH_SIZE, header.payload_hash.begin());
    ptr += HASH_SIZE;

    // sender
    std::copy(ptr, ptr + MLDSA65_PUBLIC_KEY_SIZE, header.sender.begin());
    ptr += MLDSA65_PUBLIC_KEY_SIZE;

    // commit_slot
    header.commit_slot = decode_u64(ptr);

    return header;
}

// ============================================================================
// OrderedCommitList Implementation
// ============================================================================

void OrderedCommitList::insert(const Position2D& position, const hash_t& commit_hash) {
    Entry entry{position, commit_hash};

    // Find insertion point (sorted by Position2D)
    auto it = std::lower_bound(entries_.begin(), entries_.end(), entry,
        [](const Entry& a, const Entry& b) {
            return a.position < b.position;
        });

    entries_.insert(it, entry);
    POP_LOG_TRACE(log::consensus) << "Inserted commit at position " << position.position
                                   << ", list size now " << entries_.size();
}

bool OrderedCommitList::remove(const hash_t& commit_hash) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&commit_hash](const Entry& e) {
            return e.commit_hash == commit_hash;
        });

    if (it != entries_.end()) {
        POP_LOG_TRACE(log::consensus) << "Removed commit from position " << it->position.position;
        entries_.erase(it);
        return true;
    }
    return false;
}

bool OrderedCommitList::would_collide(const Position2D& position) const {
    for (const auto& entry : entries_) {
        if (entry.position.position == position.position) {
            return true;
        }
    }
    return false;
}

const OrderedCommitList::Entry* OrderedCommitList::at_position(position_t pos) const {
    for (const auto& entry : entries_) {
        if (entry.position.position == pos) {
            return &entry;
        }
    }
    return nullptr;
}

const OrderedCommitList::Entry* OrderedCommitList::winner_at_position(position_t pos) const {
    const Entry* winner = nullptr;

    for (const auto& entry : entries_) {
        if (entry.position.position == pos) {
            if (!winner || entry.position.subposition > winner->position.subposition) {
                winner = &entry;
            }
        }
    }

    return winner;
}

std::vector<OrderedCommitList::Entry> OrderedCommitList::losers_at_position(position_t pos) const {
    std::vector<Entry> result;
    const Entry* winner = winner_at_position(pos);

    if (!winner) {
        return result;
    }

    for (const auto& entry : entries_) {
        if (entry.position.position == pos &&
            entry.commit_hash != winner->commit_hash) {
            result.push_back(entry);
        }
    }

    return result;
}

// ============================================================================
// Collision Resolution
// ============================================================================

CollisionResult resolve_collision(const Position2D& a, const Position2D& b) {
    if (a.position != b.position) {
        return CollisionResult::NO_COLLISION;
    }

    if (a.subposition == b.subposition) {
        return CollisionResult::DUPLICATE;
    }

    // Higher subposition wins
    return (a.subposition > b.subposition)
        ? CollisionResult::WINNER
        : CollisionResult::LOSER;
}

// ============================================================================
// Position Mining
// ============================================================================

PositionMiningResult mine_position(
    const CommitHeader& base_header,
    const PositionMiningConfig& config) {

    PositionMiningResult result;
    result.found = false;
    result.attempts = 0;

    POP_LOG_TRACE(log::consensus) << "Mining position in range ["
                                   << config.target_position_start << ", "
                                   << config.target_position_end << ")";

    CommitHeader header = base_header;
    auto base_serialized = header.serialize();

    for (std::uint64_t nonce = 0; nonce < config.max_attempts; ++nonce) {
        result.attempts++;

        Position2D pos = Position2D::compute_with_nonce(base_serialized, nonce);

        if (pos.position >= config.target_position_start &&
            pos.position < config.target_position_end) {
            result.found = true;
            result.retry_nonce = nonce;
            result.position = pos;
            POP_LOG_DEBUG(log::consensus) << "Position found at " << pos.position
                                           << " after " << result.attempts << " attempts";
            return result;
        }
    }

    POP_LOG_DEBUG(log::consensus) << "Position mining exhausted " << result.attempts << " attempts";
    return result;
}

PositionMiningResult mine_high_subposition(
    const CommitHeader& base_header,
    position_t target_position,
    const hash_t& current_best_subposition,
    std::uint64_t max_attempts) {

    PositionMiningResult result;
    result.found = false;
    result.attempts = 0;

    POP_LOG_TRACE(log::consensus) << "Mining high subposition at position " << target_position;

    auto base_serialized = base_header.serialize();
    hash_t best_subposition = current_best_subposition;

    for (std::uint64_t nonce = 0; nonce < max_attempts; ++nonce) {
        result.attempts++;

        Position2D pos = Position2D::compute_with_nonce(base_serialized, nonce);

        if (pos.position == target_position && pos.subposition > best_subposition) {
            result.found = true;
            result.retry_nonce = nonce;
            result.position = pos;
            best_subposition = pos.subposition;
            POP_LOG_TRACE(log::consensus) << "Found better subposition at nonce " << nonce;
        }
    }

    if (result.found) {
        POP_LOG_DEBUG(log::consensus) << "High subposition mining found improvement after "
                                       << result.attempts << " attempts";
    }
    return result;
}

}  // namespace pop
