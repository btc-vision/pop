#pragma once

#include "core/types.hh"
#include <memory>
#include <span>

namespace pop {

// ============================================================================
// ML-DSA-65 Key Pair
// ============================================================================

class MLDSAKeyPair {
public:
    ~MLDSAKeyPair();

    MLDSAKeyPair(const MLDSAKeyPair&) = delete;
    MLDSAKeyPair& operator=(const MLDSAKeyPair&) = delete;
    MLDSAKeyPair(MLDSAKeyPair&&) noexcept;
    MLDSAKeyPair& operator=(MLDSAKeyPair&&) noexcept;

    // Generate a new random key pair
    [[nodiscard]] static std::optional<MLDSAKeyPair> generate();

    // Generate from seed (deterministic)
    [[nodiscard]] static std::optional<MLDSAKeyPair> from_seed(const hash_t& seed);

    // Load from existing keys
    [[nodiscard]] static std::optional<MLDSAKeyPair> from_keys(
        const mldsa_public_key_t& pk, const mldsa_secret_key_t& sk);

    // Load public key only (for verification)
    [[nodiscard]] static std::optional<MLDSAKeyPair> from_public_key(
        const mldsa_public_key_t& pk);

    [[nodiscard]] const mldsa_public_key_t& public_key() const { return public_key_; }
    [[nodiscard]] const mldsa_secret_key_t* secret_key() const;
    [[nodiscard]] bool has_secret_key() const { return has_secret_key_; }

    // Sign a message (requires secret key)
    [[nodiscard]] std::optional<mldsa_signature_t> sign(std::span<const std::uint8_t> message) const;

    // Verify a signature (only requires public key)
    [[nodiscard]] bool verify(std::span<const std::uint8_t> message,
                               const mldsa_signature_t& signature) const;

    // Get derived address
    [[nodiscard]] Address address() const;

    // Get node ID
    [[nodiscard]] NodeId node_id() const;

private:
    MLDSAKeyPair() = default;

    mldsa_public_key_t public_key_;
    std::unique_ptr<mldsa_secret_key_t> secret_key_;
    bool has_secret_key_ = false;
};

// ============================================================================
// Standalone Verification
// ============================================================================

[[nodiscard]] bool mldsa_verify(
    const mldsa_public_key_t& public_key,
    std::span<const std::uint8_t> message,
    const mldsa_signature_t& signature);

// ============================================================================
// ML-KEM-768 Key Encapsulation
// ============================================================================

class MLKEMKeyPair {
public:
    ~MLKEMKeyPair();

    MLKEMKeyPair(const MLKEMKeyPair&) = delete;
    MLKEMKeyPair& operator=(const MLKEMKeyPair&) = delete;
    MLKEMKeyPair(MLKEMKeyPair&&) noexcept;
    MLKEMKeyPair& operator=(MLKEMKeyPair&&) noexcept;

    // Generate a new random key pair
    [[nodiscard]] static std::optional<MLKEMKeyPair> generate();

    // Load from existing keys
    [[nodiscard]] static std::optional<MLKEMKeyPair> from_keys(
        const mlkem_public_key_t& pk, const mlkem_secret_key_t& sk);

    // Load public key only (for encapsulation)
    [[nodiscard]] static std::optional<MLKEMKeyPair> from_public_key(
        const mlkem_public_key_t& pk);

    [[nodiscard]] const mlkem_public_key_t& public_key() const { return public_key_; }
    [[nodiscard]] const mlkem_secret_key_t* secret_key() const;
    [[nodiscard]] bool has_secret_key() const { return has_secret_key_; }

    // Encapsulate: generate shared secret and ciphertext (only requires public key)
    struct EncapsulationResult {
        shared_secret_t shared_secret;
        mlkem_ciphertext_t ciphertext;
    };
    [[nodiscard]] std::optional<EncapsulationResult> encapsulate() const;

    // Decapsulate: recover shared secret from ciphertext (requires secret key)
    [[nodiscard]] std::optional<shared_secret_t> decapsulate(
        const mlkem_ciphertext_t& ciphertext) const;

private:
    MLKEMKeyPair() = default;

    mlkem_public_key_t public_key_;
    std::unique_ptr<mlkem_secret_key_t> secret_key_;
    bool has_secret_key_ = false;
};

// ============================================================================
// AES-256-GCM Encryption
// ============================================================================

struct AESEncryptResult {
    std::vector<std::uint8_t> ciphertext;
    aes_nonce_t nonce;
    aes_tag_t tag;
};

[[nodiscard]] std::optional<AESEncryptResult> aes_256_gcm_encrypt(
    const aes_key_t& key,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> additional_data = {});

[[nodiscard]] std::optional<std::vector<std::uint8_t>> aes_256_gcm_decrypt(
    const aes_key_t& key,
    const aes_nonce_t& nonce,
    const aes_tag_t& tag,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> additional_data = {});

// Encrypt with nonce derived from counter (for deterministic encryption)
[[nodiscard]] std::optional<AESEncryptResult> aes_256_gcm_encrypt_with_counter(
    const aes_key_t& key,
    std::uint64_t counter,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> additional_data = {});

}  // namespace pop
