#include <gtest/gtest.h>
#include "crypto/signature.hh"
#include "crypto/hash.hh"

using namespace pop;

// ============================================================================
// ML-DSA-65 Tests
// ============================================================================

TEST(MLDSATest, Generate) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());
    EXPECT_TRUE(keypair->has_secret_key());
}

TEST(MLDSATest, SignAndVerify) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message = {1, 2, 3, 4, 5};

    auto sig = keypair->sign(message);
    ASSERT_TRUE(sig.has_value());

    EXPECT_TRUE(keypair->verify(message, *sig));
}

TEST(MLDSATest, VerifyWrongMessage) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message1 = {1, 2, 3};
    std::vector<std::uint8_t> message2 = {1, 2, 4};

    auto sig = keypair->sign(message1);
    ASSERT_TRUE(sig.has_value());

    EXPECT_FALSE(keypair->verify(message2, *sig));
}

TEST(MLDSATest, VerifyWrongKey) {
    auto keypair1 = MLDSAKeyPair::generate();
    auto keypair2 = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());

    std::vector<std::uint8_t> message = {1, 2, 3};

    auto sig = keypair1->sign(message);
    ASSERT_TRUE(sig.has_value());

    EXPECT_FALSE(keypair2->verify(message, *sig));
}

TEST(MLDSATest, PublicKeyOnly) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    auto pk_only = MLDSAKeyPair::from_public_key(keypair->public_key());
    ASSERT_TRUE(pk_only.has_value());

    EXPECT_FALSE(pk_only->has_secret_key());

    // Can't sign without secret key
    std::vector<std::uint8_t> message = {1, 2, 3};
    EXPECT_FALSE(pk_only->sign(message).has_value());

    // But can verify
    auto sig = keypair->sign(message);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(pk_only->verify(message, *sig));
}

TEST(MLDSATest, StandaloneVerify) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    std::vector<std::uint8_t> message = {1, 2, 3};
    auto sig = keypair->sign(message);
    ASSERT_TRUE(sig.has_value());

    EXPECT_TRUE(mldsa_verify(keypair->public_key(), message, *sig));
}

TEST(MLDSATest, Address) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    Address addr = keypair->address();
    EXPECT_FALSE(addr.is_zero());

    // Address should be SHA3-256 of public key
    Address expected = Address::from_public_key(keypair->public_key());
    EXPECT_EQ(addr.bytes, expected.bytes);
}

TEST(MLDSATest, NodeId) {
    auto keypair = MLDSAKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    NodeId id = keypair->node_id();
    EXPECT_EQ(id.public_key, keypair->public_key());
}

// ============================================================================
// ML-KEM-768 Tests
// ============================================================================

TEST(MLKEMTest, Generate) {
    auto keypair = MLKEMKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());
    EXPECT_TRUE(keypair->has_secret_key());
}

TEST(MLKEMTest, EncapsDecaps) {
    auto keypair = MLKEMKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    // Encapsulate (generate shared secret and ciphertext)
    auto encap_result = keypair->encapsulate();
    ASSERT_TRUE(encap_result.has_value());

    // Decapsulate (recover shared secret from ciphertext)
    auto shared_secret = keypair->decapsulate(encap_result->ciphertext);
    ASSERT_TRUE(shared_secret.has_value());

    // Both should produce the same shared secret
    EXPECT_EQ(encap_result->shared_secret, *shared_secret);
}

TEST(MLKEMTest, PublicKeyOnlyEncaps) {
    auto keypair = MLKEMKeyPair::generate();
    ASSERT_TRUE(keypair.has_value());

    auto pk_only = MLKEMKeyPair::from_public_key(keypair->public_key());
    ASSERT_TRUE(pk_only.has_value());

    // Can encapsulate with public key only
    auto encap_result = pk_only->encapsulate();
    ASSERT_TRUE(encap_result.has_value());

    // Can't decapsulate without secret key
    EXPECT_FALSE(pk_only->decapsulate(encap_result->ciphertext).has_value());

    // But original keypair can decapsulate
    auto shared_secret = keypair->decapsulate(encap_result->ciphertext);
    ASSERT_TRUE(shared_secret.has_value());
    EXPECT_EQ(encap_result->shared_secret, *shared_secret);
}

// ============================================================================
// AES-256-GCM Tests
// ============================================================================

TEST(AESGCMTest, EncryptDecrypt) {
    aes_key_t key{};
    key[0] = 0x42;

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    auto encrypted = aes_256_gcm_encrypt(key, plaintext);
    ASSERT_TRUE(encrypted.has_value());

    auto decrypted = aes_256_gcm_decrypt(
        key, encrypted->nonce, encrypted->tag, encrypted->ciphertext);
    ASSERT_TRUE(decrypted.has_value());

    EXPECT_EQ(plaintext, *decrypted);
}

TEST(AESGCMTest, WrongKeyFails) {
    aes_key_t key1{}, key2{};
    key1[0] = 0x01;
    key2[0] = 0x02;

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    auto encrypted = aes_256_gcm_encrypt(key1, plaintext);
    ASSERT_TRUE(encrypted.has_value());

    auto decrypted = aes_256_gcm_decrypt(
        key2, encrypted->nonce, encrypted->tag, encrypted->ciphertext);
    EXPECT_FALSE(decrypted.has_value());
}

TEST(AESGCMTest, TamperedCiphertextFails) {
    aes_key_t key{};
    key[0] = 0x42;

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    auto encrypted = aes_256_gcm_encrypt(key, plaintext);
    ASSERT_TRUE(encrypted.has_value());

    // Tamper with ciphertext
    encrypted->ciphertext[0] ^= 0xFF;

    auto decrypted = aes_256_gcm_decrypt(
        key, encrypted->nonce, encrypted->tag, encrypted->ciphertext);
    EXPECT_FALSE(decrypted.has_value());
}

TEST(AESGCMTest, AdditionalData) {
    aes_key_t key{};
    key[0] = 0x42;

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> aad = {'A', 'D'};

    auto encrypted = aes_256_gcm_encrypt(key, plaintext, aad);
    ASSERT_TRUE(encrypted.has_value());

    // Decrypt with same AAD
    auto decrypted = aes_256_gcm_decrypt(
        key, encrypted->nonce, encrypted->tag, encrypted->ciphertext, aad);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(plaintext, *decrypted);

    // Wrong AAD fails
    std::vector<std::uint8_t> wrong_aad = {'X', 'Y'};
    auto failed = aes_256_gcm_decrypt(
        key, encrypted->nonce, encrypted->tag, encrypted->ciphertext, wrong_aad);
    EXPECT_FALSE(failed.has_value());
}

TEST(AESGCMTest, EncryptWithCounter) {
    aes_key_t key{};
    key[0] = 0x42;

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    auto encrypted1 = aes_256_gcm_encrypt_with_counter(key, 1, plaintext);
    auto encrypted2 = aes_256_gcm_encrypt_with_counter(key, 1, plaintext);

    ASSERT_TRUE(encrypted1.has_value());
    ASSERT_TRUE(encrypted2.has_value());

    // Same counter = same nonce = same ciphertext (deterministic)
    EXPECT_EQ(encrypted1->nonce, encrypted2->nonce);
    EXPECT_EQ(encrypted1->ciphertext, encrypted2->ciphertext);

    // Different counter = different ciphertext
    auto encrypted3 = aes_256_gcm_encrypt_with_counter(key, 2, plaintext);
    ASSERT_TRUE(encrypted3.has_value());
    EXPECT_NE(encrypted1->ciphertext, encrypted3->ciphertext);
}
