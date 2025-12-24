#include "network/message.hh"
#include "network/peer.hh"
#include "network/gossip.hh"
#include "crypto/hash.hh"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

namespace pop {
namespace {

// ============================================================================
// MessageHeader Tests
// ============================================================================

class MessageHeaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        header_.magic = MessageHeader::MAGIC;
        header_.type = MessageType::GOSSIP;
        header_.flags = 0;
        header_.payload_length = 1024;
    }

    MessageHeader header_;
};

TEST_F(MessageHeaderTest, SerializeDeserialize) {
    auto serialized = header_.serialize();
    EXPECT_EQ(serialized.size(), MessageHeader::SIZE);

    auto deserialized = MessageHeader::deserialize(serialized);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->magic, header_.magic);
    EXPECT_EQ(deserialized->type, header_.type);
    EXPECT_EQ(deserialized->flags, header_.flags);
    EXPECT_EQ(deserialized->payload_length, header_.payload_length);
}

TEST_F(MessageHeaderTest, IsValid) {
    EXPECT_TRUE(header_.is_valid());

    header_.magic = 0x12345678;
    EXPECT_FALSE(header_.is_valid());
}

TEST_F(MessageHeaderTest, DeserializeInvalidData) {
    std::array<std::uint8_t, 4> short_data = {0, 1, 2, 3};
    auto result = MessageHeader::deserialize(short_data);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// PingPongMessage Tests
// ============================================================================

class PingPongTest : public ::testing::Test {};

TEST_F(PingPongTest, PingSerializeDeserialize) {
    PingMessage ping;
    ping.nonce = 0x123456789ABCDEF0;
    ping.timestamp_us = 1000000;

    auto serialized = ping.serialize();
    EXPECT_EQ(serialized.size(), PingMessage::SERIALIZED_SIZE);

    auto deserialized = PingMessage::deserialize(serialized);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->nonce, ping.nonce);
    EXPECT_EQ(deserialized->timestamp_us, ping.timestamp_us);
}

TEST_F(PingPongTest, PongSerializeDeserialize) {
    PongMessage pong;
    pong.nonce = 0xFEDCBA9876543210;
    pong.request_time_us = 1000000;
    pong.response_time_us = 1005000;

    auto serialized = pong.serialize();
    EXPECT_EQ(serialized.size(), PongMessage::SERIALIZED_SIZE);

    auto deserialized = PongMessage::deserialize(serialized);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->nonce, pong.nonce);
    EXPECT_EQ(deserialized->request_time_us, pong.request_time_us);
    EXPECT_EQ(deserialized->response_time_us, pong.response_time_us);
}

// ============================================================================
// GossipMessage Tests
// ============================================================================

class GossipMessageTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::fill(msg_.node_id.begin(), msg_.node_id.end(), 0x42);
        msg_.timestamp_us = 1609459200000000;
        msg_.current_slot = 100;
        msg_.cycle_number = 2;
        msg_.commit_count = 50;
        std::fill(msg_.commit_bloom.begin(), msg_.commit_bloom.end(), 0xAA);
        msg_.executed_slot = 95;
        std::fill(msg_.state_root.begin(), msg_.state_root.end(), 0xBB);
        msg_.executed_epoch = 10;
        msg_.receipt_count = 25;
        msg_.identity_age = 5;
        std::fill(msg_.reveal_commitment.begin(), msg_.reveal_commitment.end(), 0xCC);
        std::fill(msg_.reveal_bloom.begin(), msg_.reveal_bloom.end(), 0xDD);
    }

    GossipMessage msg_;
};

TEST_F(GossipMessageTest, SerializeDeserialize) {
    auto serialized = msg_.serialize();
    EXPECT_EQ(serialized.size(), GossipMessage::SERIALIZED_SIZE);

    auto deserialized = GossipMessage::deserialize(serialized);
    ASSERT_TRUE(deserialized.has_value());

    EXPECT_EQ(deserialized->node_id, msg_.node_id);
    EXPECT_EQ(deserialized->timestamp_us, msg_.timestamp_us);
    EXPECT_EQ(deserialized->current_slot, msg_.current_slot);
    EXPECT_EQ(deserialized->cycle_number, msg_.cycle_number);
    EXPECT_EQ(deserialized->commit_count, msg_.commit_count);
    EXPECT_EQ(deserialized->commit_bloom, msg_.commit_bloom);
    EXPECT_EQ(deserialized->executed_slot, msg_.executed_slot);
    EXPECT_EQ(deserialized->state_root, msg_.state_root);
    EXPECT_EQ(deserialized->executed_epoch, msg_.executed_epoch);
    EXPECT_EQ(deserialized->receipt_count, msg_.receipt_count);
    EXPECT_EQ(deserialized->identity_age, msg_.identity_age);
    EXPECT_EQ(deserialized->reveal_commitment, msg_.reveal_commitment);
    EXPECT_EQ(deserialized->reveal_bloom, msg_.reveal_bloom);
}

// ============================================================================
// ErrorMessage Tests
// ============================================================================

class ErrorMessageTest : public ::testing::Test {};

TEST_F(ErrorMessageTest, SerializeDeserialize) {
    ErrorMessage msg;
    msg.code = ErrorCode::RATE_LIMITED;
    msg.message = "Too many requests";
    msg.related_hash = std::nullopt;

    auto serialized = msg.serialize();
    auto deserialized = ErrorMessage::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->code, msg.code);
    EXPECT_EQ(deserialized->message, msg.message);
    EXPECT_FALSE(deserialized->related_hash.has_value());
}

TEST_F(ErrorMessageTest, SerializeWithRelatedHash) {
    ErrorMessage msg;
    msg.code = ErrorCode::NOT_FOUND;
    msg.message = "Commit not found";
    msg.related_hash = hash_t{};
    std::fill(msg.related_hash->begin(), msg.related_hash->end(), 0x99);

    auto serialized = msg.serialize();
    auto deserialized = ErrorMessage::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    ASSERT_TRUE(deserialized->related_hash.has_value());
    EXPECT_EQ(*deserialized->related_hash, *msg.related_hash);
}

// ============================================================================
// MessageTypeString Tests
// ============================================================================

TEST(MessageTypeStringTest, AllTypes) {
    EXPECT_EQ(message_type_string(MessageType::COMMIT), "commit");
    EXPECT_EQ(message_type_string(MessageType::REVEAL), "reveal");
    EXPECT_EQ(message_type_string(MessageType::GOSSIP), "gossip");
    EXPECT_EQ(message_type_string(MessageType::PING), "ping");
    EXPECT_EQ(message_type_string(MessageType::PONG), "pong");
    EXPECT_EQ(message_type_string(MessageType::BATCH_RECEIPT), "batch_receipt");
    EXPECT_EQ(message_type_string(MessageType::IDENTITY_ANNOUNCE), "identity_announce");
    EXPECT_EQ(message_type_string(MessageType::ATTESTATION), "attestation");
    EXPECT_EQ(message_type_string(MessageType::DOUBLE_SIGN_PROOF), "double_sign_proof");
    EXPECT_EQ(message_type_string(MessageType::VDF_CHECKPOINT), "vdf_checkpoint");
}

TEST(ErrorCodeStringTest, AllCodes) {
    EXPECT_EQ(error_code_string(ErrorCode::OK), "ok");
    EXPECT_EQ(error_code_string(ErrorCode::RATE_LIMITED), "rate_limited");
    EXPECT_EQ(error_code_string(ErrorCode::PEER_BANNED), "peer_banned");
    EXPECT_EQ(error_code_string(ErrorCode::INVALID_SIGNATURE), "invalid_signature");
}

// ============================================================================
// Peer Tests
// ============================================================================

class PeerTest : public ::testing::Test {
protected:
    void SetUp() override {
        node_id_.fill(0x11);
        peer_ = std::make_shared<Peer>(node_id_, "192.168.1.1:8080");
    }

    hash_t node_id_;
    std::shared_ptr<Peer> peer_;
};

TEST_F(PeerTest, BasicProperties) {
    EXPECT_EQ(peer_->node_id(), node_id_);
    EXPECT_EQ(peer_->address(), "192.168.1.1:8080");
    EXPECT_EQ(peer_->state(), PeerState::DISCONNECTED);
}

TEST_F(PeerTest, StateTransition) {
    peer_->set_state(PeerState::CONNECTING);
    EXPECT_EQ(peer_->state(), PeerState::CONNECTING);

    peer_->set_state(PeerState::HANDSHAKING);
    EXPECT_EQ(peer_->state(), PeerState::HANDSHAKING);

    peer_->set_state(PeerState::CONNECTED);
    EXPECT_EQ(peer_->state(), PeerState::CONNECTED);
}

TEST_F(PeerTest, MessageStats) {
    peer_->record_message_sent(100);
    peer_->record_message_sent(200);
    peer_->record_message_received(150);

    const auto& stats = peer_->stats();
    EXPECT_EQ(stats.messages_sent, 2u);
    EXPECT_EQ(stats.bytes_sent, 300u);
    EXPECT_EQ(stats.messages_received, 1u);
    EXPECT_EQ(stats.bytes_received, 150u);
}

TEST_F(PeerTest, PingLatency) {
    peer_->record_ping_latency(1000);
    EXPECT_EQ(peer_->stats().last_ping_latency_us, 1000u);
    EXPECT_EQ(peer_->stats().avg_ping_latency_us, 1000u);
    EXPECT_EQ(peer_->stats().ping_count, 1u);

    peer_->record_ping_latency(2000);
    EXPECT_EQ(peer_->stats().last_ping_latency_us, 2000u);
    EXPECT_EQ(peer_->stats().avg_ping_latency_us, 1500u);
    EXPECT_EQ(peer_->stats().ping_count, 2u);
}

TEST_F(PeerTest, RateLimiting) {
    for (int i = 0; i < 10; i++) {
        EXPECT_TRUE(peer_->check_rate_limit(10));
    }
    EXPECT_FALSE(peer_->check_rate_limit(10));
}

TEST_F(PeerTest, ToPeerInfo) {
    peer_->set_identity_age(5);

    auto info = peer_->to_peer_info();
    EXPECT_EQ(info.node_id, node_id_);
    EXPECT_EQ(info.address, "192.168.1.1:8080");
    EXPECT_EQ(info.identity_age, 5u);
}

TEST_F(PeerTest, GossipUpdate) {
    EXPECT_FALSE(peer_->last_gossip().has_value());

    GossipMessage msg;
    msg.current_slot = 100;
    msg.identity_age = 3;
    peer_->update_gossip(msg);

    auto last = peer_->last_gossip();
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ(last->current_slot, 100u);
    EXPECT_EQ(peer_->identity_age(), 3u);
}

TEST(PeerStateStringTest, AllStates) {
    EXPECT_EQ(peer_state_string(PeerState::DISCONNECTED), "disconnected");
    EXPECT_EQ(peer_state_string(PeerState::CONNECTING), "connecting");
    EXPECT_EQ(peer_state_string(PeerState::HANDSHAKING), "handshaking");
    EXPECT_EQ(peer_state_string(PeerState::CONNECTED), "connected");
    EXPECT_EQ(peer_state_string(PeerState::BANNED), "banned");
}

// ============================================================================
// PeerManager Tests
// ============================================================================

class PeerManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager_ = std::make_unique<PeerManager>(10);
    }

    hash_t make_node_id(std::uint8_t value) {
        hash_t id;
        id.fill(value);
        return id;
    }

    std::unique_ptr<PeerManager> manager_;
};

TEST_F(PeerManagerTest, AddAndGetPeer) {
    auto id = make_node_id(0x01);
    auto peer = manager_->add_peer(id, "192.168.1.1:8080");

    ASSERT_NE(peer, nullptr);
    EXPECT_EQ(peer->node_id(), id);

    auto found = manager_->get_peer(id);
    EXPECT_EQ(found, peer);
}

TEST_F(PeerManagerTest, AddDuplicatePeer) {
    auto id = make_node_id(0x01);
    auto peer1 = manager_->add_peer(id, "192.168.1.1:8080");
    auto peer2 = manager_->add_peer(id, "192.168.1.2:8080");

    EXPECT_EQ(peer1, peer2);  // Should return existing peer
}

TEST_F(PeerManagerTest, RemovePeer) {
    auto id = make_node_id(0x01);
    manager_->add_peer(id, "192.168.1.1:8080");

    manager_->remove_peer(id);
    EXPECT_EQ(manager_->get_peer(id), nullptr);
    EXPECT_EQ(manager_->peer_count(), 0u);
}

TEST_F(PeerManagerTest, PeerCount) {
    EXPECT_EQ(manager_->peer_count(), 0u);

    manager_->add_peer(make_node_id(0x01), "addr1");
    EXPECT_EQ(manager_->peer_count(), 1u);

    manager_->add_peer(make_node_id(0x02), "addr2");
    EXPECT_EQ(manager_->peer_count(), 2u);
}

TEST_F(PeerManagerTest, MaxPeersLimit) {
    PeerManager small_manager(2);

    EXPECT_NE(small_manager.add_peer(make_node_id(0x01), "addr1"), nullptr);
    EXPECT_NE(small_manager.add_peer(make_node_id(0x02), "addr2"), nullptr);
    EXPECT_EQ(small_manager.add_peer(make_node_id(0x03), "addr3"), nullptr);
}

TEST_F(PeerManagerTest, GetConnectedPeers) {
    auto peer1 = manager_->add_peer(make_node_id(0x01), "addr1");
    auto peer2 = manager_->add_peer(make_node_id(0x02), "addr2");
    auto peer3 = manager_->add_peer(make_node_id(0x03), "addr3");

    peer1->set_state(PeerState::CONNECTED);
    peer3->set_state(PeerState::CONNECTED);

    auto connected = manager_->get_connected_peers();
    EXPECT_EQ(connected.size(), 2u);
    EXPECT_EQ(manager_->connected_count(), 2u);
}

TEST_F(PeerManagerTest, GetAllPeers) {
    manager_->add_peer(make_node_id(0x01), "addr1");
    manager_->add_peer(make_node_id(0x02), "addr2");
    manager_->add_peer(make_node_id(0x03), "addr3");

    auto all = manager_->get_all_peers();
    EXPECT_EQ(all.size(), 3u);
}

TEST_F(PeerManagerTest, RandomConnectedPeer) {
    auto peer1 = manager_->add_peer(make_node_id(0x01), "addr1");
    peer1->set_state(PeerState::CONNECTED);

    auto random = manager_->random_connected_peer();
    EXPECT_EQ(random, peer1);
}

TEST_F(PeerManagerTest, RandomConnectedPeerEmpty) {
    auto random = manager_->random_connected_peer();
    EXPECT_EQ(random, nullptr);
}

TEST_F(PeerManagerTest, RandomConnectedPeers) {
    for (int i = 0; i < 5; i++) {
        auto peer = manager_->add_peer(make_node_id(i + 1), "addr" + std::to_string(i));
        peer->set_state(PeerState::CONNECTED);
    }

    auto random = manager_->random_connected_peers(3);
    EXPECT_EQ(random.size(), 3u);

    auto all = manager_->random_connected_peers(10);
    EXPECT_EQ(all.size(), 5u);
}

TEST_F(PeerManagerTest, BanPeer) {
    auto id = make_node_id(0x01);
    auto peer = manager_->add_peer(id, "addr");
    peer->set_state(PeerState::CONNECTED);

    manager_->ban_peer(id, BanReason::DOUBLE_SIGN);

    EXPECT_TRUE(manager_->is_banned(id));
    EXPECT_EQ(manager_->get_peer(id), nullptr);  // Removed
    EXPECT_EQ(manager_->add_peer(id, "addr2"), nullptr);  // Can't re-add
}

TEST_F(PeerManagerTest, UpdatePeerState) {
    auto id = make_node_id(0x01);
    auto peer = manager_->add_peer(id, "addr");

    manager_->update_peer_state(id, PeerState::CONNECTED);
    EXPECT_EQ(peer->state(), PeerState::CONNECTED);
}

TEST_F(PeerManagerTest, PeerExchangeList) {
    auto peer1 = manager_->add_peer(make_node_id(0x01), "addr1");
    auto peer2 = manager_->add_peer(make_node_id(0x02), "addr2");
    peer1->set_state(PeerState::CONNECTED);
    peer2->set_state(PeerState::CONNECTED);

    auto list = manager_->get_peer_exchange_list(10);
    EXPECT_EQ(list.size(), 2u);

    auto limited = manager_->get_peer_exchange_list(1);
    EXPECT_EQ(limited.size(), 1u);
}

TEST_F(PeerManagerTest, ProcessPeerExchange) {
    PeerInfo info;
    info.node_id = make_node_id(0x99);
    info.address = "new_addr";
    info.identity_age = 5;

    manager_->process_peer_exchange({info});
    EXPECT_EQ(manager_->peer_count(), 1u);
    EXPECT_NE(manager_->get_peer(info.node_id), nullptr);
}

TEST_F(PeerManagerTest, ProcessPeerExchangeBanned) {
    auto id = make_node_id(0x99);
    manager_->ban_peer(id, BanReason::EQUIVOCATION);

    PeerInfo info;
    info.node_id = id;
    info.address = "addr";

    manager_->process_peer_exchange({info});
    EXPECT_EQ(manager_->peer_count(), 0u);  // Banned peer not added
}

// ============================================================================
// MessageDeduplicator Tests
// ============================================================================

class MessageDeduplicatorTest : public ::testing::Test {
protected:
    MessageDeduplicator dedup_{100};

    hash_t make_hash(std::uint8_t value) {
        hash_t h;
        h.fill(value);
        return h;
    }
};

TEST_F(MessageDeduplicatorTest, CheckAndMarkNew) {
    auto hash = make_hash(0x01);
    EXPECT_TRUE(dedup_.check_and_mark(hash));
    EXPECT_EQ(dedup_.size(), 1u);
}

TEST_F(MessageDeduplicatorTest, CheckAndMarkDuplicate) {
    auto hash = make_hash(0x01);
    EXPECT_TRUE(dedup_.check_and_mark(hash));
    EXPECT_FALSE(dedup_.check_and_mark(hash));
    EXPECT_EQ(dedup_.size(), 1u);
}

TEST_F(MessageDeduplicatorTest, MaxSizeEnforcement) {
    MessageDeduplicator small_dedup(5);

    for (int i = 0; i < 10; i++) {
        small_dedup.check_and_mark(make_hash(i));
    }

    EXPECT_LE(small_dedup.size(), 5u);
}

TEST_F(MessageDeduplicatorTest, Prune) {
    for (int i = 0; i < 50; i++) {
        dedup_.check_and_mark(make_hash(i));
    }
    EXPECT_EQ(dedup_.size(), 50u);

    dedup_.prune(10);
    EXPECT_LE(dedup_.size(), 10u);
}

// ============================================================================
// GossipProtocol Tests
// ============================================================================

class GossipProtocolTest : public ::testing::Test {
protected:
    void SetUp() override {
        peer_manager_ = std::make_unique<PeerManager>(100);
        identity_registry_ = std::make_unique<IdentityRegistry>();
        gossip_ = std::make_unique<GossipProtocol>(*peer_manager_, *identity_registry_);

        // Add some connected peers
        for (int i = 0; i < 5; i++) {
            hash_t id;
            id.fill(i + 1);
            auto peer = peer_manager_->add_peer(id, "addr" + std::to_string(i));
            peer->set_state(PeerState::CONNECTED);
        }
    }

    hash_t make_hash(std::uint8_t value) {
        hash_t h;
        h.fill(value);
        return h;
    }

    std::unique_ptr<PeerManager> peer_manager_;
    std::unique_ptr<IdentityRegistry> identity_registry_;
    std::unique_ptr<GossipProtocol> gossip_;
};

TEST_F(GossipProtocolTest, RegisterHandler) {
    bool handler_called = false;
    gossip_->register_handler(MessageType::COMMIT_V2, [&](const hash_t&, MessageType, std::span<const std::uint8_t>) {
        handler_called = true;
    });

    hash_t peer_id;
    peer_id.fill(1);
    std::vector<std::uint8_t> payload = {1, 2, 3};
    gossip_->on_message(peer_id, MessageType::COMMIT_V2, payload);

    EXPECT_TRUE(handler_called);
}

TEST_F(GossipProtocolTest, MessageFromBannedPeer) {
    hash_t banned_id;
    banned_id.fill(0xFF);
    peer_manager_->ban_peer(banned_id, BanReason::DOUBLE_SIGN);

    bool handler_called = false;
    gossip_->register_handler(MessageType::COMMIT_V2, [&](const hash_t&, MessageType, std::span<const std::uint8_t>) {
        handler_called = true;
    });

    std::vector<std::uint8_t> payload = {1, 2, 3};
    gossip_->on_message(banned_id, MessageType::COMMIT_V2, payload);

    EXPECT_FALSE(handler_called);  // Handler not called for banned peer
}

TEST_F(GossipProtocolTest, Stats) {
    hash_t peer_id;
    peer_id.fill(1);
    std::vector<std::uint8_t> payload = {1, 2, 3};

    gossip_->on_message(peer_id, MessageType::GOSSIP, payload);

    auto stats = gossip_->stats();
    EXPECT_EQ(stats.messages_received, 1u);
}

TEST_F(GossipProtocolTest, GossipCommitDeduplication) {
    auto hash = make_hash(0x42);
    std::vector<std::uint8_t> data = {1, 2, 3, 4};

    gossip_->gossip_commit(hash, data);
    auto stats1 = gossip_->stats();

    gossip_->gossip_commit(hash, data);  // Duplicate
    auto stats2 = gossip_->stats();

    EXPECT_EQ(stats1.messages_sent, stats2.messages_sent);  // No additional sends
}

TEST_F(GossipProtocolTest, GossipRevealDeduplication) {
    auto hash = make_hash(0x43);
    std::vector<std::uint8_t> data = {5, 6, 7, 8};

    gossip_->gossip_reveal(hash, data);
    gossip_->gossip_reveal(hash, data);

    // Second call should not send (deduplication)
}

// ============================================================================
// VDFCheckpointManager Tests
// ============================================================================

class VDFCheckpointManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        peer_manager_ = std::make_unique<PeerManager>(100);
        identity_registry_ = std::make_unique<IdentityRegistry>();
        gossip_ = std::make_unique<GossipProtocol>(*peer_manager_, *identity_registry_);
        checkpoint_manager_ = std::make_unique<VDFCheckpointManager>(*gossip_, *peer_manager_);
    }

    hash_t make_hash(std::uint8_t value) {
        hash_t h;
        h.fill(value);
        return h;
    }

    std::unique_ptr<PeerManager> peer_manager_;
    std::unique_ptr<IdentityRegistry> identity_registry_;
    std::unique_ptr<GossipProtocol> gossip_;
    std::unique_ptr<VDFCheckpointManager> checkpoint_manager_;
};

TEST_F(VDFCheckpointManagerTest, RecordLocalCheckpoint) {
    checkpoint_manager_->record_local_checkpoint(100, make_hash(0x42), 1000000);

    auto cp = checkpoint_manager_->get_checkpoint(100);
    ASSERT_TRUE(cp.has_value());
    EXPECT_EQ(cp->slot, 100u);
    EXPECT_EQ(cp->vdf_output, make_hash(0x42));
    EXPECT_EQ(cp->step_count, 1000000u);
}

TEST_F(VDFCheckpointManagerTest, GetNonexistentCheckpoint) {
    auto cp = checkpoint_manager_->get_checkpoint(999);
    EXPECT_FALSE(cp.has_value());
}

TEST_F(VDFCheckpointManagerTest, IsSynced) {
    checkpoint_manager_->record_local_checkpoint(100, make_hash(0x42), 1000000);

    EXPECT_TRUE(checkpoint_manager_->is_synced(100));
    EXPECT_TRUE(checkpoint_manager_->is_synced(100 + VDF_SOFT_TOLERANCE_SLOTS));
    EXPECT_FALSE(checkpoint_manager_->is_synced(100 + VDF_SOFT_TOLERANCE_SLOTS + 1));
}

TEST_F(VDFCheckpointManagerTest, SlotsBehind) {
    checkpoint_manager_->record_local_checkpoint(100, make_hash(0x42), 1000000);

    EXPECT_EQ(checkpoint_manager_->slots_behind(100), 0u);
    EXPECT_EQ(checkpoint_manager_->slots_behind(105), 5u);
    EXPECT_EQ(checkpoint_manager_->slots_behind(50), 0u);  // Current is ahead
}

TEST_F(VDFCheckpointManagerTest, ProcessCheckpointAccepted) {
    VDFCheckpointMessage cp;
    cp.slot = 100;
    cp.vdf_output = make_hash(0x42);
    cp.step_count = 1000000;

    auto result = checkpoint_manager_->process_checkpoint(make_hash(0x01), cp);
    EXPECT_EQ(result, VDFCheckpointManager::CheckpointResult::ACCEPTED);

    auto stored = checkpoint_manager_->get_checkpoint(100);
    ASSERT_TRUE(stored.has_value());
}

TEST_F(VDFCheckpointManagerTest, ProcessCheckpointDuplicate) {
    VDFCheckpointMessage cp;
    cp.slot = 100;
    cp.vdf_output = make_hash(0x42);
    cp.step_count = 1000000;

    checkpoint_manager_->process_checkpoint(make_hash(0x01), cp);
    auto result = checkpoint_manager_->process_checkpoint(make_hash(0x02), cp);

    EXPECT_EQ(result, VDFCheckpointManager::CheckpointResult::DUPLICATE);
}

TEST_F(VDFCheckpointManagerTest, ProcessCheckpointTooOld) {
    // Record a recent checkpoint
    checkpoint_manager_->record_local_checkpoint(100, make_hash(0x42), 1000000);

    VDFCheckpointMessage old_cp;
    old_cp.slot = 100 - VDF_HARD_TOLERANCE_SLOTS - 10;  // Too old
    old_cp.vdf_output = make_hash(0x43);
    old_cp.step_count = 500000;

    auto result = checkpoint_manager_->process_checkpoint(make_hash(0x01), old_cp);
    EXPECT_EQ(result, VDFCheckpointManager::CheckpointResult::TOO_OLD);
}

// ============================================================================
// PeerInfo Serialization Tests
// ============================================================================

class PeerInfoTest : public ::testing::Test {};

TEST_F(PeerInfoTest, SerializeDeserialize) {
    PeerInfo info;
    info.node_id.fill(0x42);
    info.address = "192.168.1.100:8080";
    info.identity_age = 10;
    info.last_seen_us = 1609459200000000;

    auto serialized = info.serialize();
    auto deserialized = PeerInfo::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->node_id, info.node_id);
    EXPECT_EQ(deserialized->address, info.address);
    EXPECT_EQ(deserialized->identity_age, info.identity_age);
    EXPECT_EQ(deserialized->last_seen_us, info.last_seen_us);
}

// ============================================================================
// PeerExchangeMessage Tests
// ============================================================================

TEST(PeerExchangeMessageTest, SerializeDeserializeEmpty) {
    PeerExchangeMessage msg;

    auto serialized = msg.serialize();
    auto deserialized = PeerExchangeMessage::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_TRUE(deserialized->peers.empty());
}

TEST(PeerExchangeMessageTest, SerializeDeserializeWithPeers) {
    PeerExchangeMessage msg;

    PeerInfo peer1;
    peer1.node_id.fill(0x01);
    peer1.address = "addr1";
    peer1.identity_age = 5;

    PeerInfo peer2;
    peer2.node_id.fill(0x02);
    peer2.address = "addr2";
    peer2.identity_age = 10;

    msg.peers = {peer1, peer2};

    auto serialized = msg.serialize();
    auto deserialized = PeerExchangeMessage::deserialize(serialized);

    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->peers.size(), 2u);
    EXPECT_EQ(deserialized->peers[0].node_id, peer1.node_id);
    EXPECT_EQ(deserialized->peers[1].address, peer2.address);
}

}  // namespace
}  // namespace pop
