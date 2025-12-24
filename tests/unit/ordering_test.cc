#include <gtest/gtest.h>
#include "consensus/ordering.hh"
#include "crypto/hash.hh"

using namespace pop;

// ============================================================================
// Position2D Tests
// ============================================================================

TEST(Position2DTest, Compute) {
    std::vector<std::uint8_t> header = {1, 2, 3, 4, 5};
    auto pos = Position2D::compute(header);

    EXPECT_LT(pos.position, POSITION_MODULUS);
    EXPECT_EQ(pos.subposition.size(), HASH_SIZE);
}

TEST(Position2DTest, Deterministic) {
    std::vector<std::uint8_t> header = {1, 2, 3, 4, 5};
    auto pos1 = Position2D::compute(header);
    auto pos2 = Position2D::compute(header);

    EXPECT_EQ(pos1.position, pos2.position);
    EXPECT_EQ(pos1.subposition, pos2.subposition);
}

TEST(Position2DTest, DifferentInputsDifferentPositions) {
    std::vector<std::uint8_t> header1 = {1, 2, 3};
    std::vector<std::uint8_t> header2 = {1, 2, 4};

    auto pos1 = Position2D::compute(header1);
    auto pos2 = Position2D::compute(header2);

    // Very likely different (probabilistically)
    EXPECT_TRUE(pos1.position != pos2.position || pos1.subposition != pos2.subposition);
}

TEST(Position2DTest, ComputeWithNonce) {
    std::vector<std::uint8_t> base = {1, 2, 3};

    auto pos1 = Position2D::compute_with_nonce(base, 0);
    auto pos2 = Position2D::compute_with_nonce(base, 1);

    // Different nonces should produce different positions
    EXPECT_TRUE(pos1.position != pos2.position || pos1.subposition != pos2.subposition);
}

TEST(Position2DTest, LexicographicOrdering) {
    Position2D pos1{}, pos2{}, pos3{};

    // Same position, different subposition
    pos1.position = 100;
    pos2.position = 100;
    pos1.subposition[0] = 0x01;
    pos2.subposition[0] = 0x02;

    EXPECT_LT(pos1, pos2);

    // Different positions
    pos3.position = 99;
    pos3.subposition[0] = 0xFF;  // Higher subposition but lower position

    EXPECT_LT(pos3, pos1);
}

TEST(Position2DTest, SerializeDeserialize) {
    Position2D original;
    original.position = 12345;
    original.subposition[0] = 0xAB;
    original.subposition[31] = 0xCD;

    auto serialized = original.serialize();
    EXPECT_EQ(serialized.size(), Position2D::SERIALIZED_SIZE);

    auto restored = Position2D::deserialize(serialized);
    ASSERT_TRUE(restored.has_value());

    EXPECT_EQ(original.position, restored->position);
    EXPECT_EQ(original.subposition, restored->subposition);
}

// ============================================================================
// CommitHeader Tests
// ============================================================================

TEST(CommitHeaderTest, Position) {
    CommitHeader header{};
    header.fee_recipient.bytes[0] = 0x01;
    header.max_fee = 1000;
    header.fee_mode = FeeMode::PAY_ON_INCLUDE;
    header.retry_nonce = 0;
    header.max_instructions = 1'000'000;
    header.commit_slot = 42;

    auto pos = header.position();
    EXPECT_LT(pos.position, POSITION_MODULUS);
}

TEST(CommitHeaderTest, DifferentNoncesDifferentPositions) {
    CommitHeader header{};
    header.fee_recipient.bytes[0] = 0x01;
    header.max_fee = 1000;
    header.retry_nonce = 0;

    auto pos1 = header.position();

    header.retry_nonce = 1;
    auto pos2 = header.position();

    // Very likely different
    EXPECT_TRUE(pos1.position != pos2.position || pos1.subposition != pos2.subposition);
}

TEST(CommitHeaderTest, Hash) {
    CommitHeader header{};
    header.fee_recipient.bytes[0] = 0x01;
    header.max_fee = 1000;

    auto hash1 = header.hash();
    auto hash2 = header.hash();

    EXPECT_EQ(hash1, hash2);
}

TEST(CommitHeaderTest, SerializeDeserialize) {
    CommitHeader original{};
    original.fee_recipient.bytes[0] = 0xAB;
    original.max_fee = 123456789;
    original.fee_mode = FeeMode::PAY_ON_EXECUTE;
    original.retry_nonce = 42;
    original.max_instructions = 10'000'000;
    original.payload_hash[0] = 0xCD;
    original.sender[0] = 0xEF;
    original.commit_slot = 9999;

    auto serialized = original.serialize();
    EXPECT_EQ(serialized.size(), CommitHeader::SERIALIZED_SIZE);

    auto restored = CommitHeader::deserialize(serialized);
    ASSERT_TRUE(restored.has_value());

    EXPECT_EQ(original.fee_recipient.bytes, restored->fee_recipient.bytes);
    EXPECT_EQ(original.max_fee, restored->max_fee);
    EXPECT_EQ(original.fee_mode, restored->fee_mode);
    EXPECT_EQ(original.retry_nonce, restored->retry_nonce);
    EXPECT_EQ(original.max_instructions, restored->max_instructions);
    EXPECT_EQ(original.payload_hash, restored->payload_hash);
    EXPECT_EQ(original.sender, restored->sender);
    EXPECT_EQ(original.commit_slot, restored->commit_slot);
}

// ============================================================================
// OrderedCommitList Tests
// ============================================================================

TEST(OrderedCommitListTest, Insert) {
    OrderedCommitList list;

    Position2D pos1{}, pos2{};
    pos1.position = 100;
    pos2.position = 50;

    hash_t hash1{}, hash2{};
    hash1[0] = 0x01;
    hash2[0] = 0x02;

    list.insert(pos1, hash1);
    list.insert(pos2, hash2);

    EXPECT_EQ(list.size(), 2);

    // Should be sorted by position
    EXPECT_EQ(list.entries()[0].position.position, 50);
    EXPECT_EQ(list.entries()[1].position.position, 100);
}

TEST(OrderedCommitListTest, Remove) {
    OrderedCommitList list;

    Position2D pos{};
    pos.position = 100;

    hash_t hash{};
    hash[0] = 0x01;

    list.insert(pos, hash);
    EXPECT_EQ(list.size(), 1);

    bool removed = list.remove(hash);
    EXPECT_TRUE(removed);
    EXPECT_EQ(list.size(), 0);
}

TEST(OrderedCommitListTest, WinnerAtPosition) {
    OrderedCommitList list;

    Position2D pos1{}, pos2{};
    pos1.position = 100;
    pos2.position = 100;
    pos1.subposition[0] = 0x01;  // Lower
    pos2.subposition[0] = 0x02;  // Higher - wins

    hash_t hash1{}, hash2{};
    hash1[0] = 0x01;
    hash2[0] = 0x02;

    list.insert(pos1, hash1);
    list.insert(pos2, hash2);

    auto winner = list.winner_at_position(100);
    ASSERT_NE(winner, nullptr);
    EXPECT_EQ(winner->commit_hash, hash2);  // Higher subposition wins
}

TEST(OrderedCommitListTest, LosersAtPosition) {
    OrderedCommitList list;

    Position2D pos1{}, pos2{}, pos3{};
    pos1.position = pos2.position = pos3.position = 100;
    pos1.subposition[0] = 0x01;
    pos2.subposition[0] = 0x02;
    pos3.subposition[0] = 0x03;  // Wins

    hash_t hash1{}, hash2{}, hash3{};
    hash1[0] = 0x01;
    hash2[0] = 0x02;
    hash3[0] = 0x03;

    list.insert(pos1, hash1);
    list.insert(pos2, hash2);
    list.insert(pos3, hash3);

    auto losers = list.losers_at_position(100);
    EXPECT_EQ(losers.size(), 2);
}

// ============================================================================
// Collision Resolution Tests
// ============================================================================

TEST(CollisionTest, NoCollision) {
    Position2D pos1{}, pos2{};
    pos1.position = 100;
    pos2.position = 200;

    EXPECT_EQ(resolve_collision(pos1, pos2), CollisionResult::NO_COLLISION);
}

TEST(CollisionTest, Winner) {
    Position2D pos1{}, pos2{};
    pos1.position = pos2.position = 100;
    pos1.subposition[0] = 0x02;  // Higher
    pos2.subposition[0] = 0x01;

    EXPECT_EQ(resolve_collision(pos1, pos2), CollisionResult::WINNER);
}

TEST(CollisionTest, Loser) {
    Position2D pos1{}, pos2{};
    pos1.position = pos2.position = 100;
    pos1.subposition[0] = 0x01;  // Lower
    pos2.subposition[0] = 0x02;

    EXPECT_EQ(resolve_collision(pos1, pos2), CollisionResult::LOSER);
}

TEST(CollisionTest, Duplicate) {
    Position2D pos1{}, pos2{};
    pos1.position = pos2.position = 100;
    pos1.subposition = pos2.subposition = hash_t{};

    EXPECT_EQ(resolve_collision(pos1, pos2), CollisionResult::DUPLICATE);
}

// ============================================================================
// Position Mining Tests
// ============================================================================

TEST(PositionMiningTest, MineInRange) {
    CommitHeader header{};
    header.fee_recipient.bytes[0] = 0x01;

    PositionMiningConfig config;
    config.target_position_start = 0;
    config.target_position_end = 1000;  // First 1000 positions
    config.max_attempts = 100'000;

    auto result = mine_position(header, config);

    if (result.found) {
        EXPECT_GE(result.position.position, config.target_position_start);
        EXPECT_LT(result.position.position, config.target_position_end);
    }
}

TEST(PositionMiningTest, MineHighSubposition) {
    CommitHeader header{};
    header.fee_recipient.bytes[0] = 0x01;

    hash_t current_best{};
    current_best[0] = 0x50;  // Moderate

    auto result = mine_high_subposition(header, 0, current_best, 10'000);

    if (result.found) {
        EXPECT_GT(result.position.subposition, current_best);
    }
}
