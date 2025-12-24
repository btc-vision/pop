#include <gtest/gtest.h>
#include "core/types.hh"

using namespace pop;

// ============================================================================
// Hex Encoding Tests
// ============================================================================

TEST(TypesTest, BytesToHex) {
    std::vector<std::uint8_t> bytes = {0x00, 0x01, 0x0a, 0xff};
    std::string hex = bytes_to_hex(bytes);
    EXPECT_EQ(hex, "00010aff");
}

TEST(TypesTest, HexToBytes) {
    auto result = hex_to_bytes("00010aff");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
    EXPECT_EQ((*result)[0], 0x00);
    EXPECT_EQ((*result)[1], 0x01);
    EXPECT_EQ((*result)[2], 0x0a);
    EXPECT_EQ((*result)[3], 0xff);
}

TEST(TypesTest, HexToBytesWithPrefix) {
    auto result = hex_to_bytes("0x00010aff");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 4);
}

TEST(TypesTest, HexToBytesInvalid) {
    EXPECT_FALSE(hex_to_bytes("0xgg").has_value());
    EXPECT_FALSE(hex_to_bytes("123").has_value());  // Odd length
}

// ============================================================================
// Encoding Tests
// ============================================================================

TEST(TypesTest, EncodeDecodeU16) {
    std::array<std::uint8_t, 2> buf;
    encode_u16(buf.data(), 0x1234);
    EXPECT_EQ(decode_u16(buf.data()), 0x1234);
}

TEST(TypesTest, EncodeDecodeU32) {
    std::array<std::uint8_t, 4> buf;
    encode_u32(buf.data(), 0x12345678);
    EXPECT_EQ(decode_u32(buf.data()), 0x12345678);
}

TEST(TypesTest, EncodeDecodeU64) {
    std::array<std::uint8_t, 8> buf;
    encode_u64(buf.data(), 0x123456789ABCDEF0ULL);
    EXPECT_EQ(decode_u64(buf.data()), 0x123456789ABCDEF0ULL);
}

// ============================================================================
// Address Tests
// ============================================================================

TEST(AddressTest, IsZero) {
    Address addr{};
    EXPECT_TRUE(addr.is_zero());

    addr.bytes[0] = 1;
    EXPECT_FALSE(addr.is_zero());
}

TEST(AddressTest, ToHex) {
    Address addr{};
    addr.bytes[0] = 0xAB;
    addr.bytes[31] = 0xCD;

    std::string hex = addr.to_hex();
    EXPECT_TRUE(hex.starts_with("0x"));
    EXPECT_EQ(hex.size(), 66);  // "0x" + 64 hex chars
}

TEST(AddressTest, FromHex) {
    std::string hex = "0xab00000000000000000000000000000000000000000000000000000000000000";
    auto addr = Address::from_hex(hex);
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(addr->bytes[0], 0xAB);
}

TEST(AddressTest, FromHexInvalidLength) {
    auto addr = Address::from_hex("0x1234");
    EXPECT_FALSE(addr.has_value());
}

// ============================================================================
// Time Utilities Tests
// ============================================================================

TEST(TimeTest, SlotToEpoch) {
    EXPECT_EQ(slot_to_epoch(0), 0);
    EXPECT_EQ(slot_to_epoch(99), 0);
    EXPECT_EQ(slot_to_epoch(100), 1);
    EXPECT_EQ(slot_to_epoch(199), 1);
}

TEST(TimeTest, EpochSlotBoundaries) {
    EXPECT_EQ(epoch_start_slot(0), 0);
    EXPECT_EQ(epoch_start_slot(1), 100);
    EXPECT_EQ(epoch_end_slot(0), 99);
    EXPECT_EQ(epoch_end_slot(1), 199);
}

TEST(TimeTest, TimeToSlot) {
    timestamp_t genesis(0);
    timestamp_t t1(100'000);  // 100ms = 1 slot
    timestamp_t t2(250'000);  // 250ms = 2.5 slots

    EXPECT_EQ(time_to_slot(genesis, genesis), 0);
    EXPECT_EQ(time_to_slot(t1, genesis), 1);
    EXPECT_EQ(time_to_slot(t2, genesis), 2);
}

TEST(TimeTest, SlotToTime) {
    timestamp_t genesis(1'000'000);  // 1 second
    timestamp_t expected = genesis + timestamp_t(200'000);  // 2 slots later

    EXPECT_EQ(slot_to_time(2, genesis), expected);
}

// ============================================================================
// Slot Phase Tests
// ============================================================================

TEST(SlotPhaseTest, Phases) {
    timestamp_t slot_start(0);

    EXPECT_EQ(get_slot_phase(timestamp_t(0), slot_start), SlotPhase::OPEN);
    EXPECT_EQ(get_slot_phase(timestamp_t(19'999), slot_start), SlotPhase::OPEN);
    EXPECT_EQ(get_slot_phase(timestamp_t(20'000), slot_start), SlotPhase::GOSSIP_1);
    EXPECT_EQ(get_slot_phase(timestamp_t(40'000), slot_start), SlotPhase::GOSSIP_2);
    EXPECT_EQ(get_slot_phase(timestamp_t(60'000), slot_start), SlotPhase::GOSSIP_3);
    EXPECT_EQ(get_slot_phase(timestamp_t(80'000), slot_start), SlotPhase::GOSSIP_4);
    EXPECT_EQ(get_slot_phase(timestamp_t(100'000), slot_start), SlotPhase::CLOSED);
}

// ============================================================================
// Constants Validation Tests
// ============================================================================

TEST(ConstantsTest, CryptoSizes) {
    EXPECT_EQ(MLDSA65_PUBLIC_KEY_SIZE, 1952);
    EXPECT_EQ(MLDSA65_SECRET_KEY_SIZE, 4032);
    EXPECT_EQ(MLDSA65_SIGNATURE_SIZE, 3309);  // From liboqs OQS_SIG_ml_dsa_65_length_signature
    EXPECT_EQ(HASH_SIZE, 32);
}

TEST(ConstantsTest, TimingConstants) {
    EXPECT_EQ(SLOT_DURATION_US, 100'000);
    EXPECT_EQ(GOSSIP_INTERVAL_US, 20'000);
    EXPECT_EQ(SLOTS_PER_EPOCH, 100);
}

TEST(ConstantsTest, PositionModulus) {
    EXPECT_EQ(POSITION_MODULUS, 100'000);
}
