#include "identity.hh"
#include "crypto/hash.hh"
#include "crypto/signature.hh"
#include "crypto/lmots.hh"
#include "core/logging.hh"
#include <algorithm>
#include <chrono>

namespace pop {

// ============================================================================
// Identity Implementation
// ============================================================================

bool Identity::verify_difficulty() const {
    return hash_meets_difficulty(identity_hash, IDENTITY_DIFFICULTY_LEADING_ZEROS);
}

bool Identity::is_eligible(timestamp_t now, timestamp_t genesis) const {
    // Calculate when this identity becomes eligible in its epoch
    auto start = eligibility_start_time(public_key, epoch, genesis);
    return now >= start;
}

std::size_t Identity::age(identity_epoch_t current) const {
    if (current < epoch) {
        return 0;
    }
    return static_cast<std::size_t>(current - epoch + 1);
}

void Identity::compute_hash() {
    SHA3Hasher hasher;
    hasher.update(public_key);

    std::array<std::uint8_t, 8> nonce_bytes;
    encode_u64(nonce_bytes.data(), nonce);
    hasher.update(nonce_bytes);

    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch);
    hasher.update(epoch_bytes);

    hasher.update(salt);

    identity_hash = hasher.finalize();
}

std::vector<std::uint8_t> Identity::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    std::copy(public_key.begin(), public_key.end(), ptr);
    ptr += MLDSA65_PUBLIC_KEY_SIZE;

    encode_u64(ptr, nonce);
    ptr += sizeof(std::uint64_t);

    encode_u64(ptr, epoch);
    ptr += sizeof(identity_epoch_t);

    std::copy(salt.begin(), salt.end(), ptr);
    ptr += HASH_SIZE;

    std::copy(identity_hash.begin(), identity_hash.end(), ptr);

    return result;
}

std::optional<Identity> Identity::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    Identity id;
    const std::uint8_t* ptr = data.data();

    std::copy(ptr, ptr + MLDSA65_PUBLIC_KEY_SIZE, id.public_key.begin());
    ptr += MLDSA65_PUBLIC_KEY_SIZE;

    id.nonce = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    id.epoch = decode_u64(ptr);
    ptr += sizeof(identity_epoch_t);

    std::copy(ptr, ptr + HASH_SIZE, id.salt.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + HASH_SIZE, id.identity_hash.begin());

    return id;
}

// ============================================================================
// DoubleSignProof Implementation
// ============================================================================

bool DoubleSignProof::verify() const {
    // Verify that both signatures are valid for their respective messages
    bool sig1_valid = lmots_verify(public_key, message1, signature1);
    bool sig2_valid = lmots_verify(public_key, message2, signature2);

    if (!sig1_valid || !sig2_valid) {
        return false;
    }

    // Verify that the messages are different (same message = not double-sign)
    if (message1 == message2) {
        return false;
    }

    // Both signatures valid for different messages = double-sign detected
    return lmots_detect_double_sign(public_key, message1, signature1, message2, signature2);
}

std::vector<std::uint8_t> DoubleSignProof::serialize() const {
    std::vector<std::uint8_t> result;

    // Public key
    result.insert(result.end(), public_key.begin(), public_key.end());

    // Message 1 length + data
    std::array<std::uint8_t, 4> len_bytes;
    encode_u32(len_bytes.data(), static_cast<std::uint32_t>(message1.size()));
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    result.insert(result.end(), message1.begin(), message1.end());

    // Signature 1
    result.insert(result.end(), signature1.begin(), signature1.end());

    // Message 2 length + data
    encode_u32(len_bytes.data(), static_cast<std::uint32_t>(message2.size()));
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    result.insert(result.end(), message2.begin(), message2.end());

    // Signature 2
    result.insert(result.end(), signature2.begin(), signature2.end());

    return result;
}

std::optional<DoubleSignProof> DoubleSignProof::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < LMOTS_PUBLIC_KEY_SIZE + 4) {
        return std::nullopt;
    }

    DoubleSignProof proof;
    const std::uint8_t* ptr = data.data();
    const std::uint8_t* end = data.data() + data.size();

    // Public key
    std::copy(ptr, ptr + LMOTS_PUBLIC_KEY_SIZE, proof.public_key.begin());
    ptr += LMOTS_PUBLIC_KEY_SIZE;

    // Message 1
    if (ptr + 4 > end) return std::nullopt;
    std::uint32_t msg1_len = decode_u32(ptr);
    ptr += 4;

    if (ptr + msg1_len > end) return std::nullopt;
    proof.message1.assign(ptr, ptr + msg1_len);
    ptr += msg1_len;

    // Signature 1
    if (ptr + LMOTS_SIGNATURE_SIZE > end) return std::nullopt;
    std::copy(ptr, ptr + LMOTS_SIGNATURE_SIZE, proof.signature1.begin());
    ptr += LMOTS_SIGNATURE_SIZE;

    // Message 2
    if (ptr + 4 > end) return std::nullopt;
    std::uint32_t msg2_len = decode_u32(ptr);
    ptr += 4;

    if (ptr + msg2_len > end) return std::nullopt;
    proof.message2.assign(ptr, ptr + msg2_len);
    ptr += msg2_len;

    // Signature 2
    if (ptr + LMOTS_SIGNATURE_SIZE > end) return std::nullopt;
    std::copy(ptr, ptr + LMOTS_SIGNATURE_SIZE, proof.signature2.begin());

    return proof;
}

// ============================================================================
// IdentityAnnouncement Implementation
// ============================================================================

bool IdentityAnnouncement::verify() const {
    // Verify PoW difficulty
    if (!identity.verify_difficulty()) {
        POP_LOG_DEBUG(log::consensus) << "Identity announcement failed: insufficient PoW difficulty";
        return false;
    }

    // Verify signature
    auto id_bytes = identity.serialize();
    bool valid = mldsa_verify(identity.public_key, id_bytes, signature);
    if (!valid) {
        POP_LOG_DEBUG(log::consensus) << "Identity announcement failed: invalid signature";
    }
    return valid;
}

std::vector<std::uint8_t> IdentityAnnouncement::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    auto id_bytes = identity.serialize();
    std::copy(id_bytes.begin(), id_bytes.end(), ptr);
    ptr += Identity::SERIALIZED_SIZE;

    std::copy(signature.begin(), signature.end(), ptr);
    ptr += MLDSA65_SIGNATURE_SIZE;

    encode_u64(ptr, static_cast<std::uint64_t>(announced_at.count()));

    return result;
}

std::optional<IdentityAnnouncement> IdentityAnnouncement::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    IdentityAnnouncement ann;
    const std::uint8_t* ptr = data.data();

    auto id_opt = Identity::deserialize({ptr, Identity::SERIALIZED_SIZE});
    if (!id_opt) {
        return std::nullopt;
    }
    ann.identity = *id_opt;
    ptr += Identity::SERIALIZED_SIZE;

    std::copy(ptr, ptr + MLDSA65_SIGNATURE_SIZE, ann.signature.begin());
    ptr += MLDSA65_SIGNATURE_SIZE;

    ann.announced_at = timestamp_t(decode_u64(ptr));

    return ann;
}

// ============================================================================
// IdentityMiner Implementation
// ============================================================================

IdentityMiningResult IdentityMiner::mine(
    const mldsa_public_key_t& public_key,
    const hash_t& salt,
    identity_epoch_t epoch,
    std::uint64_t max_attempts) {

    auto start_time = std::chrono::steady_clock::now();

    POP_LOG_DEBUG(log::consensus) << "Starting identity mining for epoch " << epoch;

    IdentityMiningResult result;
    result.found = false;
    result.attempts = 0;

    Identity candidate;
    candidate.public_key = public_key;
    candidate.epoch = epoch;
    candidate.salt = salt;

    for (std::uint64_t nonce = 0; max_attempts == 0 || nonce < max_attempts; ++nonce) {
        candidate.nonce = nonce;
        candidate.compute_hash();
        result.attempts++;

        if (candidate.verify_difficulty()) {
            result.found = true;
            result.identity = candidate;
            break;
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);

    if (result.found) {
        POP_LOG_INFO(log::consensus) << "Identity mined for epoch " << epoch
                                      << " after " << result.attempts << " attempts ("
                                      << result.duration.count() << " us)";
    } else {
        POP_LOG_DEBUG(log::consensus) << "Identity mining exhausted " << result.attempts
                                       << " attempts for epoch " << epoch;
    }

    return result;
}

IdentityMiningResult IdentityMiner::mine_interruptible(
    const mldsa_public_key_t& public_key,
    const hash_t& salt,
    identity_epoch_t epoch,
    std::function<bool()> should_stop) {

    auto start_time = std::chrono::steady_clock::now();

    IdentityMiningResult result;
    result.found = false;
    result.attempts = 0;

    Identity candidate;
    candidate.public_key = public_key;
    candidate.epoch = epoch;
    candidate.salt = salt;

    for (std::uint64_t nonce = 0; !should_stop(); ++nonce) {
        candidate.nonce = nonce;
        candidate.compute_hash();
        result.attempts++;

        if (candidate.verify_difficulty()) {
            result.found = true;
            result.identity = candidate;
            break;
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);

    return result;
}

hash_t IdentityMiner::compute_salt(identity_epoch_t epoch, const hash_t& hard_state_root) {
    SHA3Hasher hasher;

    // Domain separator
    const char* domain = "identity";
    hasher.update(domain, std::strlen(domain));

    // Epoch
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch);
    hasher.update(epoch_bytes);

    // Hard finalized state root from previous epoch
    hasher.update(hard_state_root);

    return hasher.finalize();
}

// ============================================================================
// IdentityRegistry Implementation
// ============================================================================

IdentityRegistry::RegisterResult IdentityRegistry::register_identity(
    const IdentityAnnouncement& ann) {

    std::lock_guard<std::mutex> lock(*mutex_);

    // Check if sender is banned (Design Refinement R7)
    hash_t pk_h = pk_hash(ann.identity.public_key);
    if (ban_list_.find(pk_h) != ban_list_.end()) {
        POP_LOG_DEBUG(log::consensus) << "Identity registration rejected: sender banned";
        return RegisterResult::SENDER_BANNED;
    }

    // Verify signature and PoW
    if (!ann.verify()) {
        if (!ann.identity.verify_difficulty()) {
            POP_LOG_DEBUG(log::consensus) << "Identity registration rejected: invalid difficulty";
            return RegisterResult::INVALID_DIFFICULTY;
        }
        POP_LOG_DEBUG(log::consensus) << "Identity registration rejected: invalid signature";
        return RegisterResult::INVALID_SIGNATURE;
    }

    // Check epoch is current or next
    if (ann.identity.epoch != current_epoch_ &&
        ann.identity.epoch != current_epoch_ + 1) {
        POP_LOG_DEBUG(log::consensus) << "Identity registration rejected: wrong epoch "
                                       << ann.identity.epoch << " (current: " << current_epoch_ << ")";
        return RegisterResult::WRONG_EPOCH;
    }

    // Check salt if we have it
    auto salt_it = epoch_salts_.find(ann.identity.epoch);
    if (salt_it != epoch_salts_.end() &&
        salt_it->second != ann.identity.salt) {
        POP_LOG_DEBUG(log::consensus) << "Identity registration rejected: wrong salt";
        return RegisterResult::WRONG_SALT;
    }

    // Check for duplicate (pk_h computed above for ban check)
    auto it = identities_.find(pk_h);
    if (it != identities_.end()) {
        // Check if already registered for this epoch
        auto& epochs = it->second.valid_epochs;
        if (std::find(epochs.begin(), epochs.end(), ann.identity.epoch) != epochs.end()) {
            POP_LOG_TRACE(log::consensus) << "Identity registration skipped: duplicate";
            return RegisterResult::DUPLICATE;
        }
        // Add new epoch to existing record
        epochs.push_back(ann.identity.epoch);
        it->second.identity = ann.identity;  // Update to latest
        POP_LOG_DEBUG(log::consensus) << "Identity renewed for epoch " << ann.identity.epoch;
    } else {
        // New identity
        IdentityRecord record;
        record.identity = ann.identity;
        record.first_seen_epoch = ann.identity.epoch;
        record.valid_epochs.push_back(ann.identity.epoch);
        identities_[pk_h] = std::move(record);
        POP_LOG_INFO(log::consensus) << "New identity registered for epoch " << ann.identity.epoch
                                      << ", total identities: " << identities_.size();
    }

    return RegisterResult::SUCCESS;
}

bool IdentityRegistry::is_valid(
    const mldsa_public_key_t& pk,
    identity_epoch_t epoch) const {

    std::lock_guard<std::mutex> lock(*mutex_);

    hash_t pk_h = pk_hash(pk);
    auto it = identities_.find(pk_h);
    if (it == identities_.end()) {
        return false;
    }

    const auto& epochs = it->second.valid_epochs;
    return std::find(epochs.begin(), epochs.end(), epoch) != epochs.end();
}

std::optional<Identity> IdentityRegistry::get_identity(
    const mldsa_public_key_t& pk) const {

    std::lock_guard<std::mutex> lock(*mutex_);

    hash_t pk_h = pk_hash(pk);
    auto it = identities_.find(pk_h);
    if (it == identities_.end()) {
        return std::nullopt;
    }

    return it->second.identity;
}

std::size_t IdentityRegistry::get_age(
    const mldsa_public_key_t& pk,
    identity_epoch_t current_epoch) const {

    std::lock_guard<std::mutex> lock(*mutex_);

    hash_t pk_h = pk_hash(pk);
    auto it = identities_.find(pk_h);
    if (it == identities_.end()) {
        return 0;
    }

    // Count consecutive epochs from first_seen to current
    const auto& record = it->second;
    if (record.valid_epochs.empty()) {
        return 0;
    }

    // Sort epochs and count consecutive from most recent
    auto epochs = record.valid_epochs;
    std::sort(epochs.begin(), epochs.end());

    std::size_t age = 0;
    for (auto rit = epochs.rbegin(); rit != epochs.rend(); ++rit) {
        if (*rit <= current_epoch) {
            if (age == 0 || *rit == (*(rit - 1) - 1)) {
                age++;
            } else {
                break;
            }
        }
    }

    return age;
}

std::vector<Identity> IdentityRegistry::get_epoch_identities(identity_epoch_t epoch) const {
    std::lock_guard<std::mutex> lock(*mutex_);

    std::vector<Identity> result;
    for (const auto& [pk_h, record] : identities_) {
        if (std::find(record.valid_epochs.begin(), record.valid_epochs.end(), epoch)
            != record.valid_epochs.end()) {
            result.push_back(record.identity);
        }
    }

    return result;
}

void IdentityRegistry::set_epoch_salt(identity_epoch_t epoch, const hash_t& salt) {
    std::lock_guard<std::mutex> lock(*mutex_);
    epoch_salts_[epoch] = salt;
}

void IdentityRegistry::transition_epoch(identity_epoch_t new_epoch) {
    std::lock_guard<std::mutex> lock(*mutex_);

    POP_LOG_INFO(log::consensus) << "Identity epoch transition: " << current_epoch_ << " -> " << new_epoch;
    current_epoch_ = new_epoch;

    // Prune identities that haven't been renewed in 2+ epochs
    std::vector<hash_t> to_remove;
    for (auto& [pk_h, record] : identities_) {
        // Remove epochs older than new_epoch - 1
        auto& epochs = record.valid_epochs;
        epochs.erase(
            std::remove_if(epochs.begin(), epochs.end(),
                [new_epoch](identity_epoch_t e) {
                    return e + 2 <= new_epoch;
                }),
            epochs.end());

        if (epochs.empty()) {
            to_remove.push_back(pk_h);
        }
    }

    for (const auto& pk_h : to_remove) {
        identities_.erase(pk_h);
    }

    if (!to_remove.empty()) {
        POP_LOG_DEBUG(log::consensus) << "Pruned " << to_remove.size() << " stale identities";
    }

    // Clean up old salts
    std::vector<identity_epoch_t> old_epochs;
    for (const auto& [epoch, salt] : epoch_salts_) {
        if (epoch + 2 <= new_epoch) {
            old_epochs.push_back(epoch);
        }
    }
    for (auto epoch : old_epochs) {
        epoch_salts_.erase(epoch);
    }

    POP_LOG_DEBUG(log::consensus) << "Identity registry now has " << identities_.size() << " identities";
}

std::size_t IdentityRegistry::total_identities() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    return identities_.size();
}

// ============================================================================
// Ban List Implementation (Design Refinement R7)
// ============================================================================

IdentityRegistry::BanResult IdentityRegistry::ban(
    const mldsa_public_key_t& pk,
    BanReason reason,
    const std::optional<DoubleSignProof>& proof) {

    std::lock_guard<std::mutex> lock(*mutex_);

    hash_t pk_h = pk_hash(pk);

    // Check if already banned
    if (ban_list_.find(pk_h) != ban_list_.end()) {
        POP_LOG_TRACE(log::consensus) << "Ban skipped: already banned";
        return BanResult::ALREADY_BANNED;
    }

    // Add to ban list
    BanRecord record;
    record.reason = reason;
    record.banned_at_epoch = current_epoch_;
    record.proof = proof;
    ban_list_[pk_h] = std::move(record);

    // Remove from active identities
    identities_.erase(pk_h);

    POP_LOG_WARN(log::consensus) << "Identity banned: reason=" << ban_reason_string(reason)
                                  << ", total banned: " << ban_list_.size();

    return BanResult::SUCCESS;
}

IdentityRegistry::BanResult IdentityRegistry::ban_with_proof(const DoubleSignProof& proof) {
    // Verify the proof first (outside lock to avoid holding lock during verification)
    if (!proof.verify()) {
        POP_LOG_DEBUG(log::consensus) << "Ban rejected: invalid double-sign proof";
        return BanResult::INVALID_PROOF;
    }

    // Convert LM-OTS public key to a suitable format for our hash
    // Note: LM-OTS public key is 32 bytes, we hash it directly
    mldsa_public_key_t pk{};
    std::copy(proof.public_key.begin(), proof.public_key.end(), pk.begin());

    return ban(pk, BanReason::DOUBLE_SIGN, proof);
}

bool IdentityRegistry::is_banned(const mldsa_public_key_t& pk) const {
    std::lock_guard<std::mutex> lock(*mutex_);
    hash_t pk_h = pk_hash(pk);
    return ban_list_.find(pk_h) != ban_list_.end();
}

std::optional<BanReason> IdentityRegistry::get_ban_reason(const mldsa_public_key_t& pk) const {
    std::lock_guard<std::mutex> lock(*mutex_);
    hash_t pk_h = pk_hash(pk);
    auto it = ban_list_.find(pk_h);
    if (it == ban_list_.end()) {
        return std::nullopt;
    }
    return it->second.reason;
}

std::vector<std::pair<hash_t, BanReason>> IdentityRegistry::get_ban_list() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    std::vector<std::pair<hash_t, BanReason>> result;
    result.reserve(ban_list_.size());
    for (const auto& [pk_h, record] : ban_list_) {
        result.emplace_back(pk_h, record.reason);
    }
    return result;
}

std::size_t IdentityRegistry::banned_count() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    return ban_list_.size();
}

hash_t IdentityRegistry::pk_hash(const mldsa_public_key_t& pk) const {
    return sha3_256(pk);
}

std::vector<std::uint8_t> IdentityRegistry::serialize() const {
    std::lock_guard<std::mutex> lock(*mutex_);

    std::vector<std::uint8_t> result;

    // Current epoch
    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), current_epoch_);
    result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

    // Number of identities
    std::array<std::uint8_t, 4> count_bytes;
    encode_u32(count_bytes.data(), static_cast<std::uint32_t>(identities_.size()));
    result.insert(result.end(), count_bytes.begin(), count_bytes.end());

    // Each identity record
    for (const auto& [pk_h, record] : identities_) {
        auto id_bytes = record.identity.serialize();
        result.insert(result.end(), id_bytes.begin(), id_bytes.end());

        encode_u64(epoch_bytes.data(), record.first_seen_epoch);
        result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());

        encode_u32(count_bytes.data(), static_cast<std::uint32_t>(record.valid_epochs.size()));
        result.insert(result.end(), count_bytes.begin(), count_bytes.end());

        for (auto epoch : record.valid_epochs) {
            encode_u64(epoch_bytes.data(), epoch);
            result.insert(result.end(), epoch_bytes.begin(), epoch_bytes.end());
        }
    }

    return result;
}

std::optional<IdentityRegistry> IdentityRegistry::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < 12) {  // epoch + count
        return std::nullopt;
    }

    IdentityRegistry reg;
    const std::uint8_t* ptr = data.data();

    reg.current_epoch_ = decode_u64(ptr);
    ptr += 8;

    std::uint32_t count = decode_u32(ptr);
    ptr += 4;

    for (std::uint32_t i = 0; i < count; ++i) {
        if (ptr + Identity::SERIALIZED_SIZE > data.data() + data.size()) {
            return std::nullopt;
        }

        auto id_opt = Identity::deserialize({ptr, Identity::SERIALIZED_SIZE});
        if (!id_opt) {
            return std::nullopt;
        }
        ptr += Identity::SERIALIZED_SIZE;

        IdentityRegistry::IdentityRecord record;
        record.identity = *id_opt;

        record.first_seen_epoch = decode_u64(ptr);
        ptr += 8;

        std::uint32_t epoch_count = decode_u32(ptr);
        ptr += 4;

        for (std::uint32_t j = 0; j < epoch_count; ++j) {
            record.valid_epochs.push_back(decode_u64(ptr));
            ptr += 8;
        }

        hash_t pk_h = reg.pk_hash(record.identity.public_key);
        reg.identities_[pk_h] = std::move(record);
    }

    return std::move(reg);
}

// ============================================================================
// Eligibility Functions
// ============================================================================

timestamp_t eligibility_start_time(
    const mldsa_public_key_t& pk,
    identity_epoch_t epoch,
    timestamp_t genesis) {

    // Epoch start time
    slot_t epoch_start = epoch * SLOTS_PER_IDENTITY_EPOCH;
    timestamp_t epoch_start_time = slot_to_time(epoch_start, genesis);

    // Add ramp delay
    std::uint8_t ramp_hour = eligibility_ramp_hour(pk);
    auto ramp_delay = std::chrono::hours(ramp_hour);

    return epoch_start_time + std::chrono::duration_cast<timestamp_t>(ramp_delay);
}

bool is_overlap_period(timestamp_t now, identity_epoch_t epoch, timestamp_t genesis) {
    // Last 24 hours of epoch
    slot_t epoch_end = (epoch + 1) * SLOTS_PER_IDENTITY_EPOCH;
    timestamp_t epoch_end_time = slot_to_time(epoch_end, genesis);

    auto overlap_start = epoch_end_time -
        std::chrono::duration_cast<timestamp_t>(std::chrono::hours(IDENTITY_OVERLAP_HOURS));

    return now >= overlap_start && now < epoch_end_time;
}

}  // namespace pop
