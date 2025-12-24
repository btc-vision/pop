#include "signature.hh"
#include "hash.hh"
#include "core/logging.hh"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace pop {

// ============================================================================
// ML-DSA-65 Implementation
// ============================================================================

MLDSAKeyPair::~MLDSAKeyPair() {
    if (secret_key_) {
        secure_zero(*secret_key_);
    }
}

MLDSAKeyPair::MLDSAKeyPair(MLDSAKeyPair&& other) noexcept
    : public_key_(other.public_key_)
    , secret_key_(std::move(other.secret_key_))
    , has_secret_key_(other.has_secret_key_) {
    other.has_secret_key_ = false;
}

MLDSAKeyPair& MLDSAKeyPair::operator=(MLDSAKeyPair&& other) noexcept {
    if (this != &other) {
        if (secret_key_) {
            secure_zero(*secret_key_);
        }
        public_key_ = other.public_key_;
        secret_key_ = std::move(other.secret_key_);
        has_secret_key_ = other.has_secret_key_;
        other.has_secret_key_ = false;
    }
    return *this;
}

std::optional<MLDSAKeyPair> MLDSAKeyPair::generate() {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) {
        log::crypto.error("Failed to create ML-DSA-65 signature context");
        return std::nullopt;
    }

    MLDSAKeyPair keypair;
    keypair.secret_key_ = std::make_unique<mldsa_secret_key_t>();
    keypair.has_secret_key_ = true;

    if (OQS_SIG_keypair(sig, keypair.public_key_.data(),
                        keypair.secret_key_->data()) != OQS_SUCCESS) {
        log::crypto.error("ML-DSA-65 key generation failed");
        OQS_SIG_free(sig);
        return std::nullopt;
    }

    OQS_SIG_free(sig);
    log::crypto.debug("Generated ML-DSA-65 keypair");
    return keypair;
}

std::optional<MLDSAKeyPair> MLDSAKeyPair::from_seed(const hash_t& seed) {
    // Use seed to initialize RNG deterministically
    // Note: liboqs uses system RNG, so we need to derive keys differently
    // We'll hash the seed multiple times to generate enough entropy
    SHA3Hasher hasher;
    hasher.update(seed);
    std::array<std::uint8_t, 1> counter = {0};
    hasher.update(counter);
    auto derived = hasher.finalize();

    // For true deterministic key generation, we'd need a DRBG
    // For now, fall back to regular generation
    // TODO: Implement deterministic key derivation
    return generate();
}

std::optional<MLDSAKeyPair> MLDSAKeyPair::from_keys(
    const mldsa_public_key_t& pk, const mldsa_secret_key_t& sk) {
    MLDSAKeyPair keypair;
    keypair.public_key_ = pk;
    keypair.secret_key_ = std::make_unique<mldsa_secret_key_t>(sk);
    keypair.has_secret_key_ = true;
    return keypair;
}

std::optional<MLDSAKeyPair> MLDSAKeyPair::from_public_key(
    const mldsa_public_key_t& pk) {
    MLDSAKeyPair keypair;
    keypair.public_key_ = pk;
    keypair.has_secret_key_ = false;
    return keypair;
}

const mldsa_secret_key_t* MLDSAKeyPair::secret_key() const {
    return has_secret_key_ ? secret_key_.get() : nullptr;
}

std::optional<mldsa_signature_t> MLDSAKeyPair::sign(
    std::span<const std::uint8_t> message) const {
    if (!has_secret_key_) {
        log::crypto.warn("Attempted to sign without secret key");
        return std::nullopt;
    }

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) {
        log::crypto.error("Failed to create ML-DSA-65 signature context for signing");
        return std::nullopt;
    }

    mldsa_signature_t signature;
    std::size_t sig_len = MLDSA65_SIGNATURE_SIZE;

    if (OQS_SIG_sign(sig, signature.data(), &sig_len,
                     message.data(), message.size(),
                     secret_key_->data()) != OQS_SUCCESS) {
        log::crypto.error("ML-DSA-65 signing failed");
        OQS_SIG_free(sig);
        return std::nullopt;
    }

    OQS_SIG_free(sig);
    POP_LOG_TRACE(log::crypto) << "Signed message of " << message.size() << " bytes";
    return signature;
}

bool MLDSAKeyPair::verify(std::span<const std::uint8_t> message,
                          const mldsa_signature_t& signature) const {
    return mldsa_verify(public_key_, message, signature);
}

Address MLDSAKeyPair::address() const {
    return Address::from_public_key(public_key_);
}

NodeId MLDSAKeyPair::node_id() const {
    return NodeId{public_key_};
}

bool mldsa_verify(const mldsa_public_key_t& public_key,
                  std::span<const std::uint8_t> message,
                  const mldsa_signature_t& signature) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) {
        log::crypto.error("Failed to create ML-DSA-65 context for verification");
        return false;
    }

    bool result = OQS_SIG_verify(sig, message.data(), message.size(),
                                  signature.data(), MLDSA65_SIGNATURE_SIZE,
                                  public_key.data()) == OQS_SUCCESS;

    OQS_SIG_free(sig);

    if (!result) {
        POP_LOG_DEBUG(log::crypto) << "ML-DSA-65 signature verification failed";
    }
    return result;
}

// ============================================================================
// ML-KEM-768 Implementation
// ============================================================================

MLKEMKeyPair::~MLKEMKeyPair() {
    if (secret_key_) {
        secure_zero(*secret_key_);
    }
}

MLKEMKeyPair::MLKEMKeyPair(MLKEMKeyPair&& other) noexcept
    : public_key_(other.public_key_)
    , secret_key_(std::move(other.secret_key_))
    , has_secret_key_(other.has_secret_key_) {
    other.has_secret_key_ = false;
}

MLKEMKeyPair& MLKEMKeyPair::operator=(MLKEMKeyPair&& other) noexcept {
    if (this != &other) {
        if (secret_key_) {
            secure_zero(*secret_key_);
        }
        public_key_ = other.public_key_;
        secret_key_ = std::move(other.secret_key_);
        has_secret_key_ = other.has_secret_key_;
        other.has_secret_key_ = false;
    }
    return *this;
}

std::optional<MLKEMKeyPair> MLKEMKeyPair::generate() {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        log::crypto.error("Failed to create ML-KEM-768 context");
        return std::nullopt;
    }

    MLKEMKeyPair keypair;
    keypair.secret_key_ = std::make_unique<mlkem_secret_key_t>();
    keypair.has_secret_key_ = true;

    if (OQS_KEM_keypair(kem, keypair.public_key_.data(),
                        keypair.secret_key_->data()) != OQS_SUCCESS) {
        log::crypto.error("ML-KEM-768 key generation failed");
        OQS_KEM_free(kem);
        return std::nullopt;
    }

    OQS_KEM_free(kem);
    log::crypto.debug("Generated ML-KEM-768 keypair");
    return keypair;
}

std::optional<MLKEMKeyPair> MLKEMKeyPair::from_keys(
    const mlkem_public_key_t& pk, const mlkem_secret_key_t& sk) {
    MLKEMKeyPair keypair;
    keypair.public_key_ = pk;
    keypair.secret_key_ = std::make_unique<mlkem_secret_key_t>(sk);
    keypair.has_secret_key_ = true;
    return keypair;
}

std::optional<MLKEMKeyPair> MLKEMKeyPair::from_public_key(
    const mlkem_public_key_t& pk) {
    MLKEMKeyPair keypair;
    keypair.public_key_ = pk;
    keypair.has_secret_key_ = false;
    return keypair;
}

const mlkem_secret_key_t* MLKEMKeyPair::secret_key() const {
    return has_secret_key_ ? secret_key_.get() : nullptr;
}

std::optional<MLKEMKeyPair::EncapsulationResult> MLKEMKeyPair::encapsulate() const {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        log::crypto.error("Failed to create ML-KEM-768 context for encapsulation");
        return std::nullopt;
    }

    EncapsulationResult result;

    if (OQS_KEM_encaps(kem, result.ciphertext.data(), result.shared_secret.data(),
                       public_key_.data()) != OQS_SUCCESS) {
        log::crypto.error("ML-KEM-768 encapsulation failed");
        OQS_KEM_free(kem);
        return std::nullopt;
    }

    OQS_KEM_free(kem);
    POP_LOG_TRACE(log::crypto) << "ML-KEM-768 encapsulation successful";
    return result;
}

std::optional<shared_secret_t> MLKEMKeyPair::decapsulate(
    const mlkem_ciphertext_t& ciphertext) const {
    if (!has_secret_key_) {
        log::crypto.warn("Attempted to decapsulate without secret key");
        return std::nullopt;
    }

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        log::crypto.error("Failed to create ML-KEM-768 context for decapsulation");
        return std::nullopt;
    }

    shared_secret_t shared_secret;

    if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(),
                       secret_key_->data()) != OQS_SUCCESS) {
        log::crypto.error("ML-KEM-768 decapsulation failed");
        OQS_KEM_free(kem);
        return std::nullopt;
    }

    OQS_KEM_free(kem);
    POP_LOG_TRACE(log::crypto) << "ML-KEM-768 decapsulation successful";
    return shared_secret;
}

// ============================================================================
// AES-256-GCM Implementation
// ============================================================================

std::optional<AESEncryptResult> aes_256_gcm_encrypt(
    const aes_key_t& key,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> additional_data) {

    AESEncryptResult result;
    result.ciphertext.resize(plaintext.size());

    // Generate random nonce
    if (RAND_bytes(result.nonce.data(), AES_NONCE_SIZE) != 1) {
        log::crypto.error("Failed to generate random nonce for AES-GCM");
        return std::nullopt;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log::crypto.error("Failed to create AES-GCM cipher context");
        return std::nullopt;
    }

    int len;
    bool success = true;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        success = false;
    }

    if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, nullptr) != 1) {
        success = false;
    }

    if (success && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.nonce.data()) != 1) {
        success = false;
    }

    if (success && !additional_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len,
                              additional_data.data(), static_cast<int>(additional_data.size())) != 1) {
            success = false;
        }
    }

    if (success && EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                                      plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        success = false;
    }

    int ciphertext_len = len;

    if (success && EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) {
        success = false;
    }

    ciphertext_len += len;
    result.ciphertext.resize(static_cast<std::size_t>(ciphertext_len));

    if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, result.tag.data()) != 1) {
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        log::crypto.error("AES-256-GCM encryption failed");
        return std::nullopt;
    }

    POP_LOG_TRACE(log::crypto) << "AES-256-GCM encrypted " << plaintext.size() << " bytes";
    return result;
}

std::optional<std::vector<std::uint8_t>> aes_256_gcm_decrypt(
    const aes_key_t& key,
    const aes_nonce_t& nonce,
    const aes_tag_t& tag,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> additional_data) {

    std::vector<std::uint8_t> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log::crypto.error("Failed to create AES-GCM cipher context for decryption");
        return std::nullopt;
    }

    int len;
    bool success = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        success = false;
    }

    if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, nullptr) != 1) {
        success = false;
    }

    if (success && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        success = false;
    }

    if (success && !additional_data.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len,
                              additional_data.data(), static_cast<int>(additional_data.size())) != 1) {
            success = false;
        }
    }

    if (success && EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                      ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        success = false;
    }

    int plaintext_len = len;

    // Set expected tag
    if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                                        const_cast<std::uint8_t*>(tag.data())) != 1) {
        success = false;
    }

    // Verify tag and finalize
    if (success && EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        success = false;  // Tag verification failed
    }

    plaintext_len += len;
    plaintext.resize(static_cast<std::size_t>(plaintext_len));

    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        log::crypto.warn("AES-256-GCM decryption failed (authentication failure)");
        return std::nullopt;
    }

    POP_LOG_TRACE(log::crypto) << "AES-256-GCM decrypted " << ciphertext.size() << " bytes";
    return plaintext;
}

std::optional<AESEncryptResult> aes_256_gcm_encrypt_with_counter(
    const aes_key_t& key,
    std::uint64_t counter,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> additional_data) {

    AESEncryptResult result;
    result.ciphertext.resize(plaintext.size());

    // Derive nonce from counter
    std::fill(result.nonce.begin(), result.nonce.end(), 0);
    encode_u64(result.nonce.data(), counter);
    // Remaining 4 bytes are zero

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log::crypto.error("Failed to create AES-GCM cipher context for counter-based encryption");
        return std::nullopt;
    }

    int len;
    bool success = true;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        success = false;
    }

    if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, nullptr) != 1) {
        success = false;
    }

    if (success && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.nonce.data()) != 1) {
        success = false;
    }

    if (success && !additional_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len,
                              additional_data.data(), static_cast<int>(additional_data.size())) != 1) {
            success = false;
        }
    }

    if (success && EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                                      plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        success = false;
    }

    int ciphertext_len = len;

    if (success && EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) {
        success = false;
    }

    ciphertext_len += len;
    result.ciphertext.resize(static_cast<std::size_t>(ciphertext_len));

    if (success && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, result.tag.data()) != 1) {
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        log::crypto.error("AES-256-GCM counter-based encryption failed");
        return std::nullopt;
    }

    POP_LOG_TRACE(log::crypto) << "AES-256-GCM encrypted " << plaintext.size() << " bytes with counter " << counter;
    return result;
}

}  // namespace pop
