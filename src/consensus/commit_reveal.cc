#include "commit_reveal.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "crypto/lmots.hh"
#include "core/logging.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// StateExpectation Implementation
// ============================================================================

std::vector<std::uint8_t> StateExpectation::serialize() const {
    std::vector<std::uint8_t> result;

    result.push_back(static_cast<std::uint8_t>(type));
    result.insert(result.end(), address.bytes.begin(), address.bytes.end());

    result.push_back(key.has_value() ? 1 : 0);
    if (key.has_value()) {
        result.insert(result.end(), key->begin(), key->end());
    }

    result.insert(result.end(), value.begin(), value.end());

    result.push_back(max_value.has_value() ? 1 : 0);
    if (max_value.has_value()) {
        result.insert(result.end(), max_value->begin(), max_value->end());
    }

    return result;
}

std::optional<StateExpectation> StateExpectation::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < 1 + HASH_SIZE + 1 + HASH_SIZE + 1) {
        return std::nullopt;
    }

    StateExpectation exp;
    const std::uint8_t* ptr = data.data();

    exp.type = static_cast<ExpectationType>(*ptr++);

    std::copy(ptr, ptr + HASH_SIZE, exp.address.bytes.begin());
    ptr += HASH_SIZE;

    bool has_key = (*ptr++ != 0);
    if (has_key) {
        exp.key = hash_t{};
        std::copy(ptr, ptr + HASH_SIZE, exp.key->begin());
        ptr += HASH_SIZE;
    }

    std::copy(ptr, ptr + HASH_SIZE, exp.value.begin());
    ptr += HASH_SIZE;

    bool has_max = (*ptr++ != 0);
    if (has_max) {
        exp.max_value = hash_t{};
        std::copy(ptr, ptr + HASH_SIZE, exp.max_value->begin());
    }

    return exp;
}

// ============================================================================
// ExpectationSet Implementation
// ============================================================================

void ExpectationSet::add_balance_eq(const Address& addr, std::uint64_t value) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_EQ;
    exp.address = addr;
    encode_u64(exp.value.data(), value);
    expectations.push_back(exp);
}

void ExpectationSet::add_balance_ge(const Address& addr, std::uint64_t value) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_GE;
    exp.address = addr;
    encode_u64(exp.value.data(), value);
    expectations.push_back(exp);
}

void ExpectationSet::add_balance_le(const Address& addr, std::uint64_t value) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_LE;
    exp.address = addr;
    encode_u64(exp.value.data(), value);
    expectations.push_back(exp);
}

void ExpectationSet::add_balance_range(const Address& addr, std::uint64_t min_val, std::uint64_t max_val) {
    StateExpectation exp;
    exp.type = ExpectationType::BALANCE_RANGE;
    exp.address = addr;
    encode_u64(exp.value.data(), min_val);
    exp.max_value = hash_t{};
    encode_u64(exp.max_value->data(), max_val);
    expectations.push_back(exp);
}

void ExpectationSet::add_storage_eq(const Address& addr, const hash_t& key, const hash_t& value) {
    StateExpectation exp;
    exp.type = ExpectationType::STORAGE_EQ;
    exp.address = addr;
    exp.key = key;
    exp.value = value;
    expectations.push_back(exp);
}

void ExpectationSet::add_storage_ne(const Address& addr, const hash_t& key, const hash_t& value) {
    StateExpectation exp;
    exp.type = ExpectationType::STORAGE_NE;
    exp.address = addr;
    exp.key = key;
    exp.value = value;
    expectations.push_back(exp);
}

void ExpectationSet::add_nonce_eq(const Address& addr, std::uint64_t nonce) {
    StateExpectation exp;
    exp.type = ExpectationType::NONCE_EQ;
    exp.address = addr;
    encode_u64(exp.value.data(), nonce);
    expectations.push_back(exp);
}

std::vector<std::uint8_t> ExpectationSet::serialize() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 4> count_bytes;
    encode_u32(count_bytes.data(), static_cast<std::uint32_t>(expectations.size()));
    result.insert(result.end(), count_bytes.begin(), count_bytes.end());

    for (const auto& exp : expectations) {
        auto exp_bytes = exp.serialize();
        encode_u32(count_bytes.data(), static_cast<std::uint32_t>(exp_bytes.size()));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());
        result.insert(result.end(), exp_bytes.begin(), exp_bytes.end());
    }

    return result;
}

std::optional<ExpectationSet> ExpectationSet::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < 4) {
        return std::nullopt;
    }

    ExpectationSet set;
    const std::uint8_t* ptr = data.data();

    std::uint32_t count = decode_u32(ptr);
    ptr += 4;

    for (std::uint32_t i = 0; i < count; ++i) {
        if (ptr + 4 > data.data() + data.size()) {
            return std::nullopt;
        }

        std::uint32_t exp_size = decode_u32(ptr);
        ptr += 4;

        if (ptr + exp_size > data.data() + data.size()) {
            return std::nullopt;
        }

        auto exp = StateExpectation::deserialize({ptr, exp_size});
        if (!exp) {
            return std::nullopt;
        }

        set.expectations.push_back(*exp);
        ptr += exp_size;
    }

    return set;
}

// ============================================================================
// AccessKey Implementation
// ============================================================================

std::vector<std::uint8_t> AccessKey::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(SERIALIZED_SIZE);
    result.insert(result.end(), address.bytes.begin(), address.bytes.end());
    result.insert(result.end(), key.begin(), key.end());
    return result;
}

std::optional<AccessKey> AccessKey::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    AccessKey ak;
    const std::uint8_t* ptr = data.data();

    std::copy(ptr, ptr + ADDRESS_SIZE, ak.address.bytes.begin());
    ptr += ADDRESS_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, ak.key.begin());

    return ak;
}

// ============================================================================
// DeclaredAccessSet Implementation
// ============================================================================

bool DeclaredAccessSet::can_read(const AccessKey& key) const {
    // Write implies read
    if (std::find(write_set.begin(), write_set.end(), key) != write_set.end()) {
        return true;
    }
    return std::find(read_set.begin(), read_set.end(), key) != read_set.end();
}

bool DeclaredAccessSet::can_write(const AccessKey& key) const {
    return std::find(write_set.begin(), write_set.end(), key) != write_set.end();
}

bool DeclaredAccessSet::overlaps(const DeclaredAccessSet& other) const {
    // Check if any write in this overlaps with read/write in other
    for (const auto& write_key : write_set) {
        if (std::find(other.read_set.begin(), other.read_set.end(), write_key)
            != other.read_set.end()) {
            return true;
        }
        if (std::find(other.write_set.begin(), other.write_set.end(), write_key)
            != other.write_set.end()) {
            return true;
        }
    }

    // Check if any read in this overlaps with write in other
    for (const auto& read_key : read_set) {
        if (std::find(other.write_set.begin(), other.write_set.end(), read_key)
            != other.write_set.end()) {
            return true;
        }
    }

    return false;
}

std::vector<std::uint8_t> DeclaredAccessSet::serialize() const {
    std::vector<std::uint8_t> result;

    auto serialize_key_set = [&](const std::vector<AccessKey>& keys) {
        std::array<std::uint8_t, 4> count_bytes;
        encode_u32(count_bytes.data(), static_cast<std::uint32_t>(keys.size()));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());

        for (const auto& key : keys) {
            result.insert(result.end(), key.address.bytes.begin(), key.address.bytes.end());
            result.insert(result.end(), key.key.begin(), key.key.end());
        }
    };

    serialize_key_set(read_set);
    serialize_key_set(write_set);

    return result;
}

std::optional<DeclaredAccessSet> DeclaredAccessSet::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    DeclaredAccessSet set;
    const std::uint8_t* ptr = data.data();

    auto deserialize_key_set = [&](std::vector<AccessKey>& keys) -> bool {
        if (ptr + 4 > data.data() + data.size()) return false;

        std::uint32_t count = decode_u32(ptr);
        ptr += 4;

        for (std::uint32_t i = 0; i < count; ++i) {
            if (ptr + HASH_SIZE * 2 > data.data() + data.size()) return false;

            AccessKey key;
            std::copy(ptr, ptr + HASH_SIZE, key.address.bytes.begin());
            ptr += HASH_SIZE;
            std::copy(ptr, ptr + HASH_SIZE, key.key.begin());
            ptr += HASH_SIZE;

            keys.push_back(key);
        }
        return true;
    };

    if (!deserialize_key_set(set.read_set)) return std::nullopt;
    if (!deserialize_key_set(set.write_set)) return std::nullopt;

    return set;
}

DeclaredAccessSet DeclaredAccessSet::from_addresses(
    const std::vector<Address>& read_addrs,
    const std::vector<Address>& write_addrs) {

    DeclaredAccessSet set;

    for (const auto& addr : read_addrs) {
        AccessKey ak;
        ak.address = addr;
        ak.key.fill(0);  // Empty key for address-level access
        set.read_set.push_back(ak);
    }

    for (const auto& addr : write_addrs) {
        AccessKey ak;
        ak.address = addr;
        ak.key.fill(0);  // Empty key for address-level access
        set.write_set.push_back(ak);
    }

    return set;
}

// ============================================================================
// CommitMessageV2 Implementation
// ============================================================================

Position2D CommitMessageV2::position_2d() const {
    return header.position();
}

hash_t CommitMessageV2::commit_hash() const {
    SHA3Hasher hasher;

    hasher.update(&version, 1);

    std::array<std::uint8_t, 4> u32_bytes;
    encode_u32(u32_bytes.data(), chain_id);
    hasher.update(u32_bytes);

    auto header_bytes = header.serialize();
    hasher.update(header_bytes);

    hasher.update(payload_hash);
    hasher.update(sender);

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), nonce);
    hasher.update(u64_bytes);

    encode_u64(u64_bytes.data(), reference_slot);
    hasher.update(u64_bytes);

    encode_u64(u64_bytes.data(), commit_slot);
    hasher.update(u64_bytes);

    hasher.update(one_time_public_key);

    return hasher.finalize();
}

std::vector<std::uint8_t> CommitMessageV2::serialize() const {
    std::vector<std::uint8_t> result;

    result.push_back(version);

    std::array<std::uint8_t, 4> u32_bytes;
    encode_u32(u32_bytes.data(), chain_id);
    result.insert(result.end(), u32_bytes.begin(), u32_bytes.end());

    auto header_bytes = header.serialize();
    encode_u32(u32_bytes.data(), static_cast<std::uint32_t>(header_bytes.size()));
    result.insert(result.end(), u32_bytes.begin(), u32_bytes.end());
    result.insert(result.end(), header_bytes.begin(), header_bytes.end());

    result.insert(result.end(), payload_hash.begin(), payload_hash.end());

    encode_u32(u32_bytes.data(), static_cast<std::uint32_t>(encrypted_payload.size()));
    result.insert(result.end(), u32_bytes.begin(), u32_bytes.end());
    result.insert(result.end(), encrypted_payload.begin(), encrypted_payload.end());

    result.insert(result.end(), sender.begin(), sender.end());

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), nonce);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    encode_u64(u64_bytes.data(), reference_slot);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    encode_u64(u64_bytes.data(), commit_slot);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    result.insert(result.end(), one_time_public_key.begin(), one_time_public_key.end());
    result.insert(result.end(), signature.begin(), signature.end());

    return result;
}

std::optional<CommitMessageV2> CommitMessageV2::deserialize(
    std::span<const std::uint8_t> data) {
    // Minimum size check
    if (data.size() < 1 + 4 + 4) {  // version + chain_id + header_size
        return std::nullopt;
    }

    CommitMessageV2 msg;
    const std::uint8_t* ptr = data.data();
    const std::uint8_t* end = data.data() + data.size();

    // Version
    msg.version = *ptr++;
    if (msg.version != VERSION) {
        return std::nullopt;
    }

    // Chain ID
    msg.chain_id = decode_u32(ptr);
    ptr += 4;

    // Header
    std::uint32_t header_size = decode_u32(ptr);
    ptr += 4;
    if (ptr + header_size > end) return std::nullopt;
    auto header_opt = CommitHeader::deserialize({ptr, header_size});
    if (!header_opt) return std::nullopt;
    msg.header = *header_opt;
    ptr += header_size;

    // Payload hash
    if (ptr + HASH_SIZE > end) return std::nullopt;
    std::copy(ptr, ptr + HASH_SIZE, msg.payload_hash.begin());
    ptr += HASH_SIZE;

    // Encrypted payload
    if (ptr + 4 > end) return std::nullopt;
    std::uint32_t payload_size = decode_u32(ptr);
    ptr += 4;
    if (ptr + payload_size > end) return std::nullopt;
    msg.encrypted_payload.assign(ptr, ptr + payload_size);
    ptr += payload_size;

    // Sender
    if (ptr + MLDSA65_PUBLIC_KEY_SIZE > end) return std::nullopt;
    std::copy(ptr, ptr + MLDSA65_PUBLIC_KEY_SIZE, msg.sender.begin());
    ptr += MLDSA65_PUBLIC_KEY_SIZE;

    // Nonce
    if (ptr + 8 > end) return std::nullopt;
    msg.nonce = decode_u64(ptr);
    ptr += 8;

    // Reference slot
    if (ptr + 8 > end) return std::nullopt;
    msg.reference_slot = decode_u64(ptr);
    ptr += 8;

    // Commit slot
    if (ptr + 8 > end) return std::nullopt;
    msg.commit_slot = decode_u64(ptr);
    ptr += 8;

    // One-time public key
    if (ptr + LMOTS_PUBLIC_KEY_SIZE > end) return std::nullopt;
    std::copy(ptr, ptr + LMOTS_PUBLIC_KEY_SIZE, msg.one_time_public_key.begin());
    ptr += LMOTS_PUBLIC_KEY_SIZE;

    // Signature
    if (ptr + MLDSA65_SIGNATURE_SIZE > end) return std::nullopt;
    std::copy(ptr, ptr + MLDSA65_SIGNATURE_SIZE, msg.signature.begin());

    return msg;
}

bool CommitMessageV2::verify_signature() const {
    auto msg_bytes = serialize();
    // Remove signature from end for verification
    msg_bytes.resize(msg_bytes.size() - MLDSA65_SIGNATURE_SIZE);
    return mldsa_verify(sender, msg_bytes, signature);
}

// ============================================================================
// RevealMessageV2 Implementation
// ============================================================================

hash_t RevealMessageV2::reveal_hash() const {
    SHA3Hasher hasher;

    hasher.update(commit_hash);
    hasher.update(decryption_key);

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), target_vdf_start);
    hasher.update(u64_bytes);

    encode_u64(u64_bytes.data(), target_vdf_end);
    hasher.update(u64_bytes);

    auto exp_bytes = state_expectations.serialize();
    hasher.update(exp_bytes);

    auto access_bytes = declared_access.serialize();
    hasher.update(access_bytes);

    encode_u64(u64_bytes.data(), receipt_reward_pool);
    hasher.update(u64_bytes);

    return hasher.finalize();
}

std::vector<std::uint8_t> RevealMessageV2::serialize() const {
    std::vector<std::uint8_t> result;

    result.insert(result.end(), commit_hash.begin(), commit_hash.end());
    result.insert(result.end(), decryption_key.begin(), decryption_key.end());

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), target_vdf_start);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    encode_u64(u64_bytes.data(), target_vdf_end);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    auto exp_bytes = state_expectations.serialize();
    std::array<std::uint8_t, 4> u32_bytes;
    encode_u32(u32_bytes.data(), static_cast<std::uint32_t>(exp_bytes.size()));
    result.insert(result.end(), u32_bytes.begin(), u32_bytes.end());
    result.insert(result.end(), exp_bytes.begin(), exp_bytes.end());

    auto access_bytes = declared_access.serialize();
    encode_u32(u32_bytes.data(), static_cast<std::uint32_t>(access_bytes.size()));
    result.insert(result.end(), u32_bytes.begin(), u32_bytes.end());
    result.insert(result.end(), access_bytes.begin(), access_bytes.end());

    encode_u64(u64_bytes.data(), receipt_reward_pool);
    result.insert(result.end(), u64_bytes.begin(), u64_bytes.end());

    result.insert(result.end(), one_time_signature.begin(), one_time_signature.end());

    return result;
}

std::optional<RevealMessageV2> RevealMessageV2::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < HASH_SIZE + AES_KEY_SIZE + 16 + 4 + 4 + 8 + LMOTS_SIGNATURE_SIZE) {
        return std::nullopt;
    }

    RevealMessageV2 msg;
    const std::uint8_t* ptr = data.data();

    std::copy(ptr, ptr + HASH_SIZE, msg.commit_hash.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + AES_KEY_SIZE, msg.decryption_key.begin());
    ptr += AES_KEY_SIZE;

    msg.target_vdf_start = decode_u64(ptr);
    ptr += 8;

    msg.target_vdf_end = decode_u64(ptr);
    ptr += 8;

    // Parse expectations
    std::uint32_t exp_size = decode_u32(ptr);
    ptr += 4;
    auto exp_opt = ExpectationSet::deserialize({ptr, exp_size});
    if (!exp_opt) return std::nullopt;
    msg.state_expectations = *exp_opt;
    ptr += exp_size;

    // Parse access set
    std::uint32_t access_size = decode_u32(ptr);
    ptr += 4;
    auto access_opt = DeclaredAccessSet::deserialize({ptr, access_size});
    if (!access_opt) return std::nullopt;
    msg.declared_access = *access_opt;
    ptr += access_size;

    msg.receipt_reward_pool = decode_u64(ptr);
    ptr += 8;

    std::copy(ptr, ptr + LMOTS_SIGNATURE_SIZE, msg.one_time_signature.begin());

    return msg;
}

bool RevealMessageV2::verify_one_time_signature(const lmots_public_key_t& one_time_pk) const {
    // Message for LM-OTS: reveal_hash || target_vdf_start || target_vdf_end
    std::vector<std::uint8_t> msg;

    hash_t rh = reveal_hash();
    msg.insert(msg.end(), rh.begin(), rh.end());

    std::array<std::uint8_t, 8> u64_bytes;
    encode_u64(u64_bytes.data(), target_vdf_start);
    msg.insert(msg.end(), u64_bytes.begin(), u64_bytes.end());

    encode_u64(u64_bytes.data(), target_vdf_end);
    msg.insert(msg.end(), u64_bytes.begin(), u64_bytes.end());

    return lmots_verify(one_time_pk, msg, one_time_signature);
}

bool RevealMessageV2::is_in_vdf_range(std::uint64_t current_step) const {
    // Range is [start, end) - end is exclusive
    return current_step >= target_vdf_start && current_step < target_vdf_end;
}

bool RevealMessageV2::has_expired(std::uint64_t current_step) const {
    return current_step >= target_vdf_end;
}

// ============================================================================
// CommitPool Implementation
// ============================================================================

CommitPool::AddResult CommitPool::add_commit(const CommitMessageV2& commit) {
    std::lock_guard<std::mutex> lock(mutex_);

    hash_t ch = commit.commit_hash();

    if (commits_.count(ch) > 0) {
        POP_LOG_TRACE(log::consensus) << "Commit skipped: duplicate";
        return AddResult::DUPLICATE;
    }

    if (!commit.verify_signature()) {
        POP_LOG_DEBUG(log::consensus) << "Commit rejected: invalid signature";
        return AddResult::INVALID_SIGNATURE;
    }

    if (commits_.size() >= MAX_COMMITS_IN_POOL) {
        POP_LOG_WARN(log::consensus) << "Commit rejected: pool full (" << commits_.size() << " commits)";
        return AddResult::POOL_FULL;
    }

    commits_[ch] = commit;
    by_position_[commit.position_2d().position].push_back(ch);

    POP_LOG_TRACE(log::consensus) << "Commit added at position " << commit.position_2d().position
                                   << ", pool size now " << commits_.size();
    return AddResult::ADDED;
}

std::optional<CommitMessageV2> CommitPool::get_commit(const hash_t& commit_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = commits_.find(commit_hash);
    if (it == commits_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool CommitPool::has_commit(const hash_t& commit_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return commits_.count(commit_hash) > 0;
}

std::vector<CommitMessageV2> CommitPool::get_commits_at_position(position_t pos) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<CommitMessageV2> result;
    auto it = by_position_.find(pos);
    if (it == by_position_.end()) {
        return result;
    }

    for (const auto& ch : it->second) {
        auto commit_it = commits_.find(ch);
        if (commit_it != commits_.end()) {
            result.push_back(commit_it->second);
        }
    }

    return result;
}

bool CommitPool::remove_commit(const hash_t& commit_hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = commits_.find(commit_hash);
    if (it == commits_.end()) {
        return false;
    }

    position_t pos = it->second.position_2d().position;
    commits_.erase(it);

    auto pos_it = by_position_.find(pos);
    if (pos_it != by_position_.end()) {
        auto& hashes = pos_it->second;
        hashes.erase(std::remove(hashes.begin(), hashes.end(), commit_hash), hashes.end());
        if (hashes.empty()) {
            by_position_.erase(pos_it);
        }
    }

    return true;
}

std::vector<hash_t> CommitPool::get_all_hashes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<hash_t> result;
    result.reserve(commits_.size());
    for (const auto& [hash, commit] : commits_) {
        result.push_back(hash);
    }
    return result;
}

std::size_t CommitPool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return commits_.size();
}

void CommitPool::prune(slot_t before_slot) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<hash_t> to_remove;
    for (const auto& [hash, commit] : commits_) {
        if (commit.commit_slot < before_slot) {
            to_remove.push_back(hash);
        }
    }

    for (const auto& hash : to_remove) {
        auto it = commits_.find(hash);
        if (it != commits_.end()) {
            position_t pos = it->second.position_2d().position;
            commits_.erase(it);

            auto pos_it = by_position_.find(pos);
            if (pos_it != by_position_.end()) {
                auto& hashes = pos_it->second;
                hashes.erase(std::remove(hashes.begin(), hashes.end(), hash), hashes.end());
            }
        }
    }
}

// ============================================================================
// RevealPool Implementation
// ============================================================================

RevealPool::AddResult RevealPool::add_reveal(
    const RevealMessageV2& reveal,
    const CommitPool& commit_pool,
    std::uint64_t current_vdf_step) {

    std::lock_guard<std::mutex> lock(mutex_);

    hash_t rh = reveal.reveal_hash();

    if (reveals_.count(rh) > 0) {
        POP_LOG_TRACE(log::consensus) << "Reveal skipped: duplicate";
        return AddResult::DUPLICATE;
    }

    // Check commit exists
    auto commit = commit_pool.get_commit(reveal.commit_hash);
    if (!commit) {
        POP_LOG_DEBUG(log::consensus) << "Reveal rejected: commit not found";
        return AddResult::COMMIT_NOT_FOUND;
    }

    // Verify LM-OTS signature
    if (!reveal.verify_one_time_signature(commit->one_time_public_key)) {
        POP_LOG_DEBUG(log::consensus) << "Reveal rejected: invalid LM-OTS signature";
        return AddResult::INVALID_SIGNATURE;
    }

    // Check VDF range
    if (reveal.has_expired(current_vdf_step)) {
        POP_LOG_DEBUG(log::consensus) << "Reveal rejected: expired (current VDF step " << current_vdf_step
                                       << " > target end " << reveal.target_vdf_end << ")";
        return AddResult::EXPIRED;
    }

    if (reveal.target_vdf_end <= reveal.target_vdf_start) {
        POP_LOG_DEBUG(log::consensus) << "Reveal rejected: invalid VDF range";
        return AddResult::VDF_RANGE_INVALID;
    }

    reveals_[rh] = reveal;
    by_commit_[reveal.commit_hash] = rh;

    POP_LOG_TRACE(log::consensus) << "Reveal added for VDF range [" << reveal.target_vdf_start
                                   << ", " << reveal.target_vdf_end << "], pool size now " << reveals_.size();
    return AddResult::ADDED;
}

std::optional<RevealMessageV2> RevealPool::get_reveal(const hash_t& reveal_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reveals_.find(reveal_hash);
    if (it == reveals_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<RevealMessageV2> RevealPool::get_reveal_for_commit(
    const hash_t& commit_hash) const {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = by_commit_.find(commit_hash);
    if (it == by_commit_.end()) {
        return std::nullopt;
    }

    auto reveal_it = reveals_.find(it->second);
    if (reveal_it == reveals_.end()) {
        return std::nullopt;
    }

    return reveal_it->second;
}

bool RevealPool::has_reveal(const hash_t& reveal_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reveals_.count(reveal_hash) > 0;
}

std::vector<RevealMessageV2> RevealPool::get_reveals_in_range(
    std::uint64_t vdf_start, std::uint64_t vdf_end) const {

    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RevealMessageV2> result;
    for (const auto& [hash, reveal] : reveals_) {
        if (reveal.target_vdf_start <= vdf_end && reveal.target_vdf_end >= vdf_start) {
            result.push_back(reveal);
        }
    }
    return result;
}

std::vector<RevealMessageV2> RevealPool::get_epoch_reveals(tx_epoch_t epoch) const {
    std::uint64_t start = epoch * VDF_STEPS_PER_TX_EPOCH;
    std::uint64_t end = (epoch + 1) * VDF_STEPS_PER_TX_EPOCH - 1;
    return get_reveals_in_range(start, end);
}

bool RevealPool::remove_reveal(const hash_t& reveal_hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reveals_.find(reveal_hash);
    if (it == reveals_.end()) {
        return false;
    }

    by_commit_.erase(it->second.commit_hash);
    reveals_.erase(it);

    return true;
}

std::size_t RevealPool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reveals_.size();
}

void RevealPool::prune_expired(std::uint64_t current_vdf_step) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<hash_t> to_remove;
    for (const auto& [hash, reveal] : reveals_) {
        if (reveal.has_expired(current_vdf_step)) {
            to_remove.push_back(hash);
        }
    }

    for (const auto& hash : to_remove) {
        auto it = reveals_.find(hash);
        if (it != reveals_.end()) {
            by_commit_.erase(it->second.commit_hash);
            reveals_.erase(it);
        }
    }
}

// ============================================================================
// ExecutionContext Implementation
// ============================================================================

std::optional<ExecutionContext> ExecutionContext::create(
    const CommitMessageV2& commit,
    const RevealMessageV2& reveal) {

    ExecutionContext ctx;
    ctx.commit = commit;
    ctx.reveal = reveal;
    ctx.position = commit.position_2d();
    ctx.tx_hash = commit.commit_hash();
    ctx.sender_address = Address::from_public_key(commit.sender);

    // Decrypt payload
    // In a real implementation, we'd use AES-GCM here
    // For now, just copy the encrypted payload
    ctx.decrypted_payload = commit.encrypted_payload;

    return ctx;
}

// ============================================================================
// TransactionOrdering Implementation
// ============================================================================

void TransactionOrdering::add(ExecutionContext ctx) {
    std::lock_guard<std::mutex> lock(mutex_);
    contexts_.push_back(std::move(ctx));
}

std::vector<ExecutionContext> TransactionOrdering::get_ordered() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ExecutionContext> result = contexts_;

    // Sort by Position2D (lexicographic: position first, then subposition)
    std::sort(result.begin(), result.end(),
        [](const ExecutionContext& a, const ExecutionContext& b) {
            return a.position < b.position;
        });

    return result;
}

std::vector<std::vector<std::size_t>> TransactionOrdering::get_parallel_groups() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::vector<std::size_t>> groups;
    std::vector<bool> assigned(contexts_.size(), false);

    for (std::size_t i = 0; i < contexts_.size(); ++i) {
        if (assigned[i]) continue;

        std::vector<std::size_t> group;
        group.push_back(i);
        assigned[i] = true;

        // Find all non-overlapping transactions
        for (std::size_t j = i + 1; j < contexts_.size(); ++j) {
            if (assigned[j]) continue;

            bool can_add = true;
            for (auto k : group) {
                if (contexts_[j].reveal.declared_access.overlaps(
                        contexts_[k].reveal.declared_access)) {
                    can_add = false;
                    break;
                }
            }

            if (can_add) {
                group.push_back(j);
                assigned[j] = true;
            }
        }

        groups.push_back(group);
    }

    return groups;
}

void TransactionOrdering::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    contexts_.clear();
}

}  // namespace pop
