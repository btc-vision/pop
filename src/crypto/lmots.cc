#include "lmots.hh"
#include "hash.hh"
#include "core/logging.hh"
#include <openssl/rand.h>
#include <cstring>
#include <mutex>

namespace pop {

// ============================================================================
// LMOTSKeyPair Implementation
// ============================================================================

LMOTSKeyPair::~LMOTSKeyPair() {
    if (secret_key_) {
        for (auto& chain : secret_key_->chains) {
            secure_zero(chain);
        }
    }
}

LMOTSKeyPair::LMOTSKeyPair(LMOTSKeyPair&& other) noexcept
    : public_key_(other.public_key_)
    , secret_key_(std::move(other.secret_key_))
    , has_secret_key_(other.has_secret_key_)
    , used_(other.used_.load()) {
    other.has_secret_key_ = false;
    other.used_.store(true);
}

LMOTSKeyPair& LMOTSKeyPair::operator=(LMOTSKeyPair&& other) noexcept {
    if (this != &other) {
        if (secret_key_) {
            for (auto& chain : secret_key_->chains) {
                secure_zero(chain);
            }
        }
        public_key_ = other.public_key_;
        secret_key_ = std::move(other.secret_key_);
        has_secret_key_ = other.has_secret_key_;
        used_.store(other.used_.load());
        other.has_secret_key_ = false;
        other.used_.store(true);
    }
    return *this;
}

std::optional<LMOTSKeyPair> LMOTSKeyPair::generate() {
    LMOTSKeyPair keypair;
    keypair.secret_key_ = std::make_unique<SecretKey>();
    keypair.has_secret_key_ = true;

    // Generate random secret key chains
    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        if (RAND_bytes(keypair.secret_key_->chains[i].data(), LMOTS_N) != 1) {
            POP_LOG_ERROR(log::crypto) << "LM-OTS key generation failed: RNG error at chain " << i;
            return std::nullopt;
        }
    }

    // Compute public key
    keypair.compute_public_key();
    log::crypto.debug("Generated LM-OTS keypair");
    return keypair;
}

std::optional<LMOTSKeyPair> LMOTSKeyPair::from_seed(const hash_t& seed) {
    LMOTSKeyPair keypair;
    keypair.secret_key_ = std::make_unique<SecretKey>();
    keypair.has_secret_key_ = true;

    // Derive secret key chains from seed using DRBG
    HashDRBG drbg(seed);
    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        keypair.secret_key_->chains[i] = drbg.next();
    }

    // Compute public key
    keypair.compute_public_key();
    log::crypto.debug("Generated LM-OTS keypair from seed");
    return keypair;
}

std::optional<LMOTSKeyPair> LMOTSKeyPair::from_public_key(const lmots_public_key_t& pk) {
    LMOTSKeyPair keypair;
    keypair.public_key_ = pk;
    keypair.has_secret_key_ = false;
    keypair.used_.store(true);  // Can't sign anyway
    return keypair;
}

void LMOTSKeyPair::compute_public_key() {
    // Public key = H(H(x[0]^(2^W-1)) || H(x[1]^(2^W-1)) || ... || H(x[P-1]^(2^W-1)))
    // where x[i]^j means applying chain hash j times

    SHA3Hasher hasher;

    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        hash_t chain_end = apply_chain(i, secret_key_->chains[i], 0, LMOTS_CHAIN_LENGTH);
        hasher.update(chain_end);
    }

    public_key_ = hasher.finalize();
}

hash_t LMOTSKeyPair::chain_hash(std::size_t i, std::size_t j, const hash_t& input) {
    SHA3Hasher hasher;

    // H(i || j || input)
    std::array<std::uint8_t, 8> i_bytes, j_bytes;
    encode_u64(i_bytes.data(), static_cast<std::uint64_t>(i));
    encode_u64(j_bytes.data(), static_cast<std::uint64_t>(j));

    hasher.update(i_bytes);
    hasher.update(j_bytes);
    hasher.update(input);

    return hasher.finalize();
}

hash_t LMOTSKeyPair::apply_chain(std::size_t i, const hash_t& start,
                                  std::size_t from, std::size_t to) {
    hash_t current = start;
    for (std::size_t j = from; j < to; ++j) {
        current = chain_hash(i, j, current);
    }
    return current;
}

std::optional<lmots_signature_t> LMOTSKeyPair::sign(std::span<const std::uint8_t> message) {
    // Check if already used (atomic compare-exchange)
    bool expected = false;
    if (!used_.compare_exchange_strong(expected, true)) {
        log::crypto.warn("LM-OTS key already used - refusing to sign (one-time key reuse attempt)");
        return std::nullopt;  // Already used!
    }

    if (!has_secret_key_ || !secret_key_) {
        log::crypto.error("LM-OTS sign failed: no secret key available");
        used_.store(false);  // Restore state on failure
        return std::nullopt;
    }

    lmots_signature_t signature;
    std::uint8_t* sig_ptr = signature.data();

    // Generate randomizer C
    hash_t C;
    if (RAND_bytes(C.data(), LMOTS_N) != 1) {
        log::crypto.error("LM-OTS sign failed: RNG error generating randomizer");
        used_.store(false);
        return std::nullopt;
    }

    // Copy C to signature
    std::copy(C.begin(), C.end(), sig_ptr);
    sig_ptr += LMOTS_N;

    // Compute Q = H(C || message)
    hash_t Q;
    {
        SHA3Hasher hasher;
        hasher.update(C);
        hasher.update(message);
        Q = hasher.finalize();
    }

    // Compute checksum
    std::uint16_t checksum = 0;
    for (std::size_t i = 0; i < LMOTS_N; ++i) {
        // Extract 4-bit nibbles
        std::uint8_t high = (Q[i] >> 4) & 0x0F;
        std::uint8_t low = Q[i] & 0x0F;
        checksum += static_cast<std::uint16_t>(LMOTS_CHAIN_LENGTH - high);
        checksum += static_cast<std::uint16_t>(LMOTS_CHAIN_LENGTH - low);
    }

    // Append checksum to Q (as 3 additional nibbles)
    std::array<std::uint8_t, 34> Q_with_checksum;
    std::copy(Q.begin(), Q.end(), Q_with_checksum.begin());
    Q_with_checksum[32] = static_cast<std::uint8_t>((checksum >> 8) & 0xFF);
    Q_with_checksum[33] = static_cast<std::uint8_t>(checksum & 0xFF);

    // For each chain, compute y[i] = x[i]^a[i] where a[i] is the nibble value
    std::size_t nibble_idx = 0;
    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        std::uint8_t a;
        if (nibble_idx < 64) {
            // Message nibbles
            std::size_t byte_idx = nibble_idx / 2;
            if (nibble_idx % 2 == 0) {
                a = (Q[byte_idx] >> 4) & 0x0F;
            } else {
                a = Q[byte_idx] & 0x0F;
            }
        } else {
            // Checksum nibbles
            std::size_t cs_nibble = nibble_idx - 64;
            std::size_t byte_idx = 32 + cs_nibble / 2;
            if (cs_nibble % 2 == 0) {
                a = (Q_with_checksum[byte_idx] >> 4) & 0x0F;
            } else {
                a = Q_with_checksum[byte_idx] & 0x0F;
            }
        }

        hash_t y = apply_chain(i, secret_key_->chains[i], 0, a);
        std::copy(y.begin(), y.end(), sig_ptr);
        sig_ptr += LMOTS_N;
        nibble_idx++;
    }

    // Securely erase secret key after use
    for (auto& chain : secret_key_->chains) {
        secure_zero(chain);
    }

    POP_LOG_TRACE(log::crypto) << "LM-OTS signed message of " << message.size() << " bytes (key now consumed)";
    return signature;
}

void LMOTSKeyPair::mark_used() {
    used_.store(true);
}

// ============================================================================
// Standalone Verification
// ============================================================================

bool lmots_verify(const lmots_public_key_t& public_key,
                  std::span<const std::uint8_t> message,
                  const lmots_signature_t& signature) {
    const std::uint8_t* sig_ptr = signature.data();

    // Extract C
    hash_t C;
    std::copy(sig_ptr, sig_ptr + LMOTS_N, C.begin());
    sig_ptr += LMOTS_N;

    // Compute Q = H(C || message)
    hash_t Q;
    {
        SHA3Hasher hasher;
        hasher.update(C);
        hasher.update(message);
        Q = hasher.finalize();
    }

    // Compute checksum
    std::uint16_t checksum = 0;
    for (std::size_t i = 0; i < LMOTS_N; ++i) {
        std::uint8_t high = (Q[i] >> 4) & 0x0F;
        std::uint8_t low = Q[i] & 0x0F;
        checksum += static_cast<std::uint16_t>(LMOTS_CHAIN_LENGTH - high);
        checksum += static_cast<std::uint16_t>(LMOTS_CHAIN_LENGTH - low);
    }

    std::array<std::uint8_t, 34> Q_with_checksum;
    std::copy(Q.begin(), Q.end(), Q_with_checksum.begin());
    Q_with_checksum[32] = static_cast<std::uint8_t>((checksum >> 8) & 0xFF);
    Q_with_checksum[33] = static_cast<std::uint8_t>(checksum & 0xFF);

    // Recompute public key from signature
    SHA3Hasher pk_hasher;

    std::size_t nibble_idx = 0;
    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        std::uint8_t a;
        if (nibble_idx < 64) {
            std::size_t byte_idx = nibble_idx / 2;
            if (nibble_idx % 2 == 0) {
                a = (Q[byte_idx] >> 4) & 0x0F;
            } else {
                a = Q[byte_idx] & 0x0F;
            }
        } else {
            std::size_t cs_nibble = nibble_idx - 64;
            std::size_t byte_idx = 32 + cs_nibble / 2;
            if (cs_nibble % 2 == 0) {
                a = (Q_with_checksum[byte_idx] >> 4) & 0x0F;
            } else {
                a = Q_with_checksum[byte_idx] & 0x0F;
            }
        }

        // Extract y[i] from signature
        hash_t y;
        std::copy(sig_ptr, sig_ptr + LMOTS_N, y.begin());
        sig_ptr += LMOTS_N;

        // Complete the chain: z[i] = y[i]^(2^W - 1 - a)
        hash_t z = LMOTSKeyPair::apply_chain(i, y, a, LMOTS_CHAIN_LENGTH);
        pk_hasher.update(z);

        nibble_idx++;
    }

    hash_t computed_pk = pk_hasher.finalize();
    bool valid = computed_pk == public_key;
    if (!valid) {
        POP_LOG_DEBUG(log::crypto) << "LM-OTS signature verification failed";
    }
    return valid;
}

// ============================================================================
// Double-Sign Detection
// ============================================================================

bool lmots_detect_double_sign(const lmots_public_key_t& public_key,
                               std::span<const std::uint8_t> message1,
                               const lmots_signature_t& signature1,
                               std::span<const std::uint8_t> message2,
                               const lmots_signature_t& signature2) {
    // If the same key signed two different messages, we can detect it
    // by checking if the signatures reveal inconsistent chain values

    POP_LOG_TRACE(log::crypto) << "Checking for LM-OTS double-sign";

    // First verify both signatures
    if (!lmots_verify(public_key, message1, signature1) ||
        !lmots_verify(public_key, message2, signature2)) {
        POP_LOG_DEBUG(log::crypto) << "Double-sign check: one or both signatures invalid";
        return false;  // Invalid signatures
    }

    // Same message = not a double sign
    if (std::equal(message1.begin(), message1.end(), message2.begin(), message2.end())) {
        POP_LOG_TRACE(log::crypto) << "Double-sign check: same message (not a double sign)";
        return false;
    }

    // Extract C values
    hash_t C1, C2;
    std::copy(signature1.data(), signature1.data() + LMOTS_N, C1.begin());
    std::copy(signature2.data(), signature2.data() + LMOTS_N, C2.begin());

    // Compute Q values
    hash_t Q1, Q2;
    {
        SHA3Hasher hasher;
        hasher.update(C1);
        hasher.update(message1);
        Q1 = hasher.finalize();
    }
    {
        SHA3Hasher hasher;
        hasher.update(C2);
        hasher.update(message2);
        Q2 = hasher.finalize();
    }

    // For each position, check if the revealed chain values are consistent
    // If a[i] in sig1 > a[i] in sig2, then y1[i] should be derivable from y2[i]
    const std::uint8_t* y1_ptr = signature1.data() + LMOTS_N;
    const std::uint8_t* y2_ptr = signature2.data() + LMOTS_N;

    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        std::size_t byte_idx = i / 2;
        std::uint8_t a1, a2;

        if (i < 64) {
            if (i % 2 == 0) {
                a1 = (Q1[byte_idx] >> 4) & 0x0F;
                a2 = (Q2[byte_idx] >> 4) & 0x0F;
            } else {
                a1 = Q1[byte_idx] & 0x0F;
                a2 = Q2[byte_idx] & 0x0F;
            }
        } else {
            // Checksums would need similar handling
            // For simplicity, we'll check message nibbles only
            y1_ptr += LMOTS_N;
            y2_ptr += LMOTS_N;
            continue;
        }

        hash_t y1, y2;
        std::copy(y1_ptr, y1_ptr + LMOTS_N, y1.begin());
        std::copy(y2_ptr, y2_ptr + LMOTS_N, y2.begin());

        // If a1 > a2, then y1 should equal chain(y2, a2, a1)
        if (a1 > a2) {
            hash_t expected = LMOTSKeyPair::apply_chain(i, y2, a2, a1);
            if (expected != y1) {
                POP_LOG_WARN(log::crypto) << "LM-OTS DOUBLE-SIGN DETECTED: inconsistent chain values at position " << i;
                return true;  // Inconsistent = double sign detected
            }
        } else if (a2 > a1) {
            hash_t expected = LMOTSKeyPair::apply_chain(i, y1, a1, a2);
            if (expected != y2) {
                POP_LOG_WARN(log::crypto) << "LM-OTS DOUBLE-SIGN DETECTED: inconsistent chain values at position " << i;
                return true;  // Inconsistent = double sign detected
            }
        }

        y1_ptr += LMOTS_N;
        y2_ptr += LMOTS_N;
    }

    // Both signatures verified and are consistent
    // This means the same OTS key was used twice (double sign)
    log::crypto.warn("LM-OTS DOUBLE-SIGN DETECTED: same key used for two different messages");
    return true;
}

// ============================================================================
// LMOTSSignatureView Implementation
// ============================================================================

std::optional<LMOTSSignatureView> LMOTSSignatureView::from_bytes(const lmots_signature_t& sig) {
    LMOTSSignatureView view;
    const std::uint8_t* ptr = sig.data();

    std::copy(ptr, ptr + LMOTS_N, view.C.begin());
    ptr += LMOTS_N;

    for (std::size_t i = 0; i < LMOTS_P; ++i) {
        std::copy(ptr, ptr + LMOTS_N, view.y[i].begin());
        ptr += LMOTS_N;
    }

    return view;
}

lmots_signature_t LMOTSSignatureView::to_bytes() const {
    lmots_signature_t sig;
    std::uint8_t* ptr = sig.data();

    std::copy(C.begin(), C.end(), ptr);
    ptr += LMOTS_N;

    for (const auto& yi : y) {
        std::copy(yi.begin(), yi.end(), ptr);
        ptr += LMOTS_N;
    }

    return sig;
}

// ============================================================================
// LMOTSKeyPool Implementation
// ============================================================================

LMOTSKeyPool::LMOTSKeyPool(std::size_t pool_size) : target_size_(pool_size) {
    pool_.reserve(pool_size);
    POP_LOG_DEBUG(log::crypto) << "Creating LM-OTS key pool with target size " << pool_size;
    refill();
}

LMOTSKeyPool::~LMOTSKeyPool() = default;

std::optional<LMOTSKeyPair> LMOTSKeyPool::acquire() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pool_.empty()) {
        // Generate on demand if pool is empty
        POP_LOG_DEBUG(log::crypto) << "LM-OTS key pool empty, generating key on-demand";
        return LMOTSKeyPair::generate();
    }

    auto keypair = std::move(pool_.back());
    pool_.pop_back();
    POP_LOG_TRACE(log::crypto) << "Acquired LM-OTS key from pool, " << pool_.size() << " remaining";
    return keypair;
}

void LMOTSKeyPool::refill() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t initial_size = pool_.size();
    while (pool_.size() < target_size_) {
        auto keypair = LMOTSKeyPair::generate();
        if (keypair) {
            pool_.push_back(std::move(*keypair));
        } else {
            log::crypto.error("LM-OTS key pool refill failed during generation");
            break;  // Generation failed
        }
    }
    std::size_t added = pool_.size() - initial_size;
    if (added > 0) {
        POP_LOG_TRACE(log::crypto) << "LM-OTS key pool refilled with " << added << " keys, total " << pool_.size();
    }
}

std::size_t LMOTSKeyPool::available() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
}

}  // namespace pop
