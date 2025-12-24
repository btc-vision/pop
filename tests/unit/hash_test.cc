#include <gtest/gtest.h>
#include "crypto/hash.hh"

using namespace pop;

// ============================================================================
// SHA3-256 Tests
// ============================================================================

TEST(SHA3Test, EmptyInput) {
    auto hash = sha3_256(std::span<const std::uint8_t>{});
    EXPECT_EQ(hash.size(), HASH_SIZE);

    // Known SHA3-256 hash of empty string
    // a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    EXPECT_EQ(hash[0], 0xa7);
    EXPECT_EQ(hash[1], 0xff);
}

TEST(SHA3Test, SimpleInput) {
    std::vector<std::uint8_t> input = {'a', 'b', 'c'};
    auto hash = sha3_256(input);
    EXPECT_EQ(hash.size(), HASH_SIZE);
}

TEST(SHA3Test, Deterministic) {
    std::vector<std::uint8_t> input = {1, 2, 3, 4, 5};
    auto hash1 = sha3_256(input);
    auto hash2 = sha3_256(input);
    EXPECT_EQ(hash1, hash2);
}

TEST(SHA3Test, DifferentInputsDifferentHashes) {
    std::vector<std::uint8_t> input1 = {1, 2, 3};
    std::vector<std::uint8_t> input2 = {1, 2, 4};
    auto hash1 = sha3_256(input1);
    auto hash2 = sha3_256(input2);
    EXPECT_NE(hash1, hash2);
}

// ============================================================================
// SHA3Hasher Tests
// ============================================================================

TEST(SHA3HasherTest, IncrementalHashing) {
    std::vector<std::uint8_t> input = {1, 2, 3, 4, 5, 6};

    // Hash all at once
    auto direct_hash = sha3_256(input);

    // Hash incrementally
    SHA3Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(input.data(), 3));
    hasher.update(std::span<const std::uint8_t>(input.data() + 3, 3));
    auto incremental_hash = hasher.finalize();

    EXPECT_EQ(direct_hash, incremental_hash);
}

TEST(SHA3HasherTest, Reset) {
    std::vector<std::uint8_t> input = {1, 2, 3};

    SHA3Hasher hasher;
    hasher.update(input);
    auto hash1 = hasher.finalize();

    hasher.reset();
    hasher.update(input);
    auto hash2 = hasher.finalize();

    EXPECT_EQ(hash1, hash2);
}

TEST(SHA3HasherTest, MultiHash) {
    std::vector<std::uint8_t> a = {1, 2, 3};
    std::vector<std::uint8_t> b = {4, 5, 6};

    auto hash = sha3_256_multi(a, b);

    SHA3Hasher hasher;
    hasher.update(a);
    hasher.update(b);
    auto expected = hasher.finalize();

    EXPECT_EQ(hash, expected);
}

// ============================================================================
// Merkle Tree Tests
// ============================================================================

TEST(MerkleTreeTest, SingleLeaf) {
    hash_t leaf{};
    leaf[0] = 0x42;

    MerkleTree tree({leaf});
    EXPECT_EQ(tree.root(), leaf);
}

TEST(MerkleTreeTest, TwoLeaves) {
    hash_t leaf1{}, leaf2{};
    leaf1[0] = 0x01;
    leaf2[0] = 0x02;

    MerkleTree tree({leaf1, leaf2});
    auto root = tree.root();

    // Root should be H(leaf1 || leaf2)
    SHA3Hasher hasher;
    hasher.update(leaf1);
    hasher.update(leaf2);
    auto expected = hasher.finalize();

    EXPECT_EQ(root, expected);
}

TEST(MerkleTreeTest, ProofVerification) {
    std::vector<hash_t> leaves(4);
    for (int i = 0; i < 4; ++i) {
        leaves[i][0] = static_cast<std::uint8_t>(i);
    }

    MerkleTree tree(leaves);
    auto root = tree.root();

    for (std::size_t i = 0; i < leaves.size(); ++i) {
        auto proof = tree.proof(i);
        EXPECT_TRUE(MerkleTree::verify(leaves[i], proof, i, root));
    }
}

TEST(MerkleTreeTest, InvalidProofFails) {
    std::vector<hash_t> leaves(4);
    for (int i = 0; i < 4; ++i) {
        leaves[i][0] = static_cast<std::uint8_t>(i);
    }

    MerkleTree tree(leaves);
    auto root = tree.root();

    // Get proof for index 0, but try to verify with leaf at index 1
    auto proof = tree.proof(0);
    EXPECT_FALSE(MerkleTree::verify(leaves[1], proof, 0, root));
}

TEST(MerkleTreeTest, ComputeRootDirect) {
    std::vector<hash_t> leaves(8);
    for (int i = 0; i < 8; ++i) {
        leaves[i][0] = static_cast<std::uint8_t>(i);
    }

    MerkleTree tree(leaves);
    auto root = compute_merkle_root(leaves);

    EXPECT_EQ(tree.root(), root);
}

// ============================================================================
// Difficulty Tests
// ============================================================================

TEST(DifficultyTest, ZeroLeadingZeros) {
    hash_t h{};
    h[0] = 0xFF;  // All 1s
    EXPECT_TRUE(hash_meets_difficulty(h, 0));
}

TEST(DifficultyTest, OneLeadingZero) {
    hash_t h{};
    h[0] = 0x7F;  // 0111 1111
    EXPECT_TRUE(hash_meets_difficulty(h, 1));
    EXPECT_FALSE(hash_meets_difficulty(h, 2));
}

TEST(DifficultyTest, EightLeadingZeros) {
    hash_t h{};
    h[0] = 0x00;
    h[1] = 0xFF;
    EXPECT_TRUE(hash_meets_difficulty(h, 8));
    EXPECT_FALSE(hash_meets_difficulty(h, 9));
}

TEST(DifficultyTest, AllZeros) {
    hash_t h{};
    EXPECT_TRUE(hash_meets_difficulty(h, 256));
}

// ============================================================================
// HashDRBG Tests
// ============================================================================

TEST(HashDRBGTest, Deterministic) {
    hash_t seed{};
    seed[0] = 0x42;

    HashDRBG drbg1(seed);
    HashDRBG drbg2(seed);

    EXPECT_EQ(drbg1.next(), drbg2.next());
    EXPECT_EQ(drbg1.next(), drbg2.next());
}

TEST(HashDRBGTest, DifferentSeedsDifferentOutput) {
    hash_t seed1{}, seed2{};
    seed1[0] = 0x01;
    seed2[0] = 0x02;

    HashDRBG drbg1(seed1);
    HashDRBG drbg2(seed2);

    EXPECT_NE(drbg1.next(), drbg2.next());
}

TEST(HashDRBGTest, NextRange) {
    hash_t seed{};
    HashDRBG drbg(seed);

    for (int i = 0; i < 100; ++i) {
        auto val = drbg.next_range(10);
        EXPECT_LT(val, 10);
    }
}

// ============================================================================
// Position Utilities Tests
// ============================================================================

TEST(PositionTest, HashToPosition) {
    hash_t h{};
    h[0] = 0x00;
    h[1] = 0x00;
    h[2] = 0x01;
    h[3] = 0x00;

    auto pos = hash_to_position(h);
    EXPECT_LT(pos, POSITION_MODULUS);
}

TEST(PositionTest, PositionInRange) {
    for (int i = 0; i < 100; ++i) {
        hash_t h{};
        h[0] = static_cast<std::uint8_t>(i);
        auto pos = hash_to_position(h);
        EXPECT_LT(pos, POSITION_MODULUS);
    }
}
