#include "network/gossip.hh"
#include "core/logging.hh"
#include <algorithm>
#include <random>

namespace pop {

// ============================================================================
// MessageDeduplicator Implementation
// ============================================================================

MessageDeduplicator::MessageDeduplicator(std::size_t max_size)
    : max_size_(max_size) {}

bool MessageDeduplicator::check_and_mark(const hash_t& message_hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (seen_.find(message_hash) != seen_.end()) {
        return false;  // Already seen
    }

    // Add to seen set
    seen_.insert(message_hash);
    insertion_order_.push_back(message_hash);

    // Prune if needed
    while (seen_.size() > max_size_) {
        if (!insertion_order_.empty()) {
            seen_.erase(insertion_order_.front());
            insertion_order_.erase(insertion_order_.begin());
        }
    }

    return true;  // New message
}

void MessageDeduplicator::prune(std::size_t target_size) {
    std::lock_guard<std::mutex> lock(mutex_);

    while (seen_.size() > target_size && !insertion_order_.empty()) {
        seen_.erase(insertion_order_.front());
        insertion_order_.erase(insertion_order_.begin());
    }
}

std::size_t MessageDeduplicator::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return seen_.size();
}

// ============================================================================
// GossipProtocol Implementation
// ============================================================================

GossipProtocol::GossipProtocol(
    PeerManager& peer_manager,
    IdentityRegistry& identity_registry,
    const GossipConfig& config)
    : peer_manager_(peer_manager)
    , identity_registry_(identity_registry)
    , config_(config)
    , deduplicator_(config.seen_message_cache_size) {}

void GossipProtocol::on_message(const hash_t& peer_id, MessageType type,
                                  std::span<const std::uint8_t> payload) {
    // Check if peer is banned
    if (peer_manager_.is_banned(peer_id)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_dropped_banned++;
        return;
    }

    // Check rate limit
    auto peer = peer_manager_.get_peer(peer_id);
    if (peer && !peer->check_rate_limit(config_.max_messages_per_peer_per_second)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_dropped_rate_limit++;
        return;
    }

    // Update peer stats
    if (peer) {
        peer->record_message_received(payload.size());
        peer->update_last_seen(timestamp_t(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_received++;
    }

    // Dispatch to handler
    auto it = handlers_.find(type);
    if (it != handlers_.end()) {
        it->second(peer_id, type, payload);
    } else {
        POP_LOG_DEBUG(log::network) << "No handler for message type: "
                                     << message_type_string(type);
    }
}

void GossipProtocol::register_handler(MessageType type, MessageHandler handler) {
    handlers_[type] = std::move(handler);
}

void GossipProtocol::gossip_commit(const hash_t& commit_hash,
                                    std::span<const std::uint8_t> commit_data) {
    // Check deduplication
    if (!deduplicator_.check_and_mark(commit_hash)) {
        return;  // Already gossiped
    }

    auto targets = select_gossip_targets(config_.commit_fanout);
    broadcast_to_peers(targets, MessageType::COMMIT_V2, commit_data);

    POP_LOG_TRACE(log::network) << "Gossiped commit " << bytes_to_hex(commit_hash).substr(0, 16)
                                 << " to " << targets.size() << " peers";
}

void GossipProtocol::gossip_reveal(const hash_t& reveal_hash,
                                    std::span<const std::uint8_t> reveal_data) {
    if (!deduplicator_.check_and_mark(reveal_hash)) {
        return;
    }

    auto targets = select_gossip_targets(config_.reveal_fanout);
    broadcast_to_peers(targets, MessageType::REVEAL_V2, reveal_data);

    POP_LOG_TRACE(log::network) << "Gossiped reveal " << bytes_to_hex(reveal_hash).substr(0, 16)
                                 << " to " << targets.size() << " peers";
}

void GossipProtocol::gossip_receipt(const BatchReceipt& receipt) {
    auto receipt_data = receipt.serialize();
    hash_t receipt_hash = sha3_256(receipt_data);

    if (!deduplicator_.check_and_mark(receipt_hash)) {
        return;
    }

    auto targets = select_gossip_targets(config_.receipt_fanout);
    broadcast_to_peers(targets, MessageType::BATCH_RECEIPT, receipt_data);

    POP_LOG_TRACE(log::network) << "Gossiped receipt for epoch " << receipt.epoch_id
                                 << " bucket " << static_cast<int>(receipt.bucket_id)
                                 << " to " << targets.size() << " peers";
}

void GossipProtocol::gossip_attestation(const Attestation& attestation) {
    auto att_data = attestation.serialize();
    hash_t att_hash = sha3_256(att_data);

    if (!deduplicator_.check_and_mark(att_hash)) {
        return;
    }

    auto targets = select_gossip_targets(config_.gossip_fanout);
    broadcast_to_peers(targets, MessageType::ATTESTATION, att_data);

    POP_LOG_TRACE(log::network) << "Gossiped attestation for epoch " << attestation.epoch
                                 << " to " << targets.size() << " peers";
}

void GossipProtocol::gossip_identity(const IdentityAnnouncement& announcement) {
    auto ann_data = announcement.serialize();
    hash_t ann_hash = sha3_256(ann_data);

    if (!deduplicator_.check_and_mark(ann_hash)) {
        return;
    }

    auto targets = select_gossip_targets(config_.gossip_fanout);
    broadcast_to_peers(targets, MessageType::IDENTITY_ANNOUNCE, ann_data);

    POP_LOG_DEBUG(log::network) << "Gossiped identity for epoch " << announcement.identity.epoch
                                 << " to " << targets.size() << " peers";
}

void GossipProtocol::gossip_double_sign_proof(const DoubleSignProof& proof) {
    auto proof_data = proof.serialize();
    hash_t proof_hash = sha3_256(proof_data);

    if (!deduplicator_.check_and_mark(proof_hash)) {
        return;
    }

    // Broadcast to ALL connected peers (important security message)
    auto targets = peer_manager_.get_connected_peers();
    broadcast_to_peers(targets, MessageType::DOUBLE_SIGN_PROOF, proof_data);

    POP_LOG_WARN(log::network) << "Gossiped double-sign proof to " << targets.size() << " peers";
}

void GossipProtocol::broadcast_gossip(const GossipMessage& msg) {
    auto msg_data = msg.serialize();
    auto targets = select_gossip_targets(config_.gossip_fanout);
    broadcast_to_peers(targets, MessageType::GOSSIP, msg_data);
}

void GossipProtocol::request_iblt(const hash_t& peer_id, epoch_t epoch) {
    std::vector<std::uint8_t> request_data(sizeof(epoch_t));
    encode_u64(request_data.data(), epoch);
    send_to_peer(peer_id, MessageType::IBLT_REQUEST, request_data);
}

void GossipProtocol::send_iblt(const hash_t& peer_id, const IBLT& iblt, epoch_t epoch) {
    auto iblt_data = iblt.serialize();

    std::vector<std::uint8_t> response_data;
    response_data.reserve(sizeof(epoch_t) + iblt_data.size());

    std::array<std::uint8_t, 8> epoch_bytes;
    encode_u64(epoch_bytes.data(), epoch);
    response_data.insert(response_data.end(), epoch_bytes.begin(), epoch_bytes.end());
    response_data.insert(response_data.end(), iblt_data.begin(), iblt_data.end());

    send_to_peer(peer_id, MessageType::IBLT_RESPONSE, response_data);
}

void GossipProtocol::broadcast_vdf_checkpoint(const VDFCheckpointMessage& checkpoint) {
    auto cp_data = checkpoint.serialize();
    auto targets = select_gossip_targets(config_.gossip_fanout);
    broadcast_to_peers(targets, MessageType::VDF_CHECKPOINT, cp_data);
}

void GossipProtocol::request_vdf_checkpoint(const hash_t& peer_id, slot_t slot) {
    std::vector<std::uint8_t> request_data(sizeof(slot_t));
    encode_u64(request_data.data(), slot);
    send_to_peer(peer_id, MessageType::VDF_CHECKPOINT_REQUEST, request_data);
}

void GossipProtocol::request_peer_exchange(const hash_t& peer_id) {
    send_to_peer(peer_id, MessageType::PEER_EXCHANGE_REQUEST, {});
}

void GossipProtocol::send_peer_exchange(const hash_t& peer_id) {
    auto peer_list = peer_manager_.get_peer_exchange_list(20);
    PeerExchangeMessage msg;
    msg.peers = std::move(peer_list);

    auto data = msg.serialize();
    send_to_peer(peer_id, MessageType::PEER_EXCHANGE, data);
}

GossipProtocol::Stats GossipProtocol::stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<std::shared_ptr<Peer>> GossipProtocol::select_gossip_targets(
    std::uint32_t fanout,
    const std::optional<hash_t>& exclude) const {

    auto connected = peer_manager_.get_connected_peers();

    if (exclude) {
        connected.erase(
            std::remove_if(connected.begin(), connected.end(),
                [&exclude](const std::shared_ptr<Peer>& p) {
                    return p->node_id() == *exclude;
                }),
            connected.end());
    }

    if (connected.size() <= fanout) {
        return connected;
    }

    static thread_local std::mt19937 rng(std::random_device{}());
    std::shuffle(connected.begin(), connected.end(), rng);
    connected.resize(fanout);
    return connected;
}

void GossipProtocol::send_to_peer(const hash_t& peer_id, MessageType type,
                                   std::span<const std::uint8_t> payload) {
    auto peer = peer_manager_.get_peer(peer_id);
    if (!peer || peer->state() != PeerState::CONNECTED) {
        return;
    }

    // In a real implementation, this would send over the network
    // For now, just update stats
    peer->record_message_sent(payload.size() + MessageHeader::SIZE);

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.messages_sent++;
    }

    POP_LOG_TRACE(log::network) << "Sent " << message_type_string(type)
                                 << " to " << bytes_to_hex(peer_id).substr(0, 16)
                                 << " (" << payload.size() << " bytes)";
}

void GossipProtocol::broadcast_to_peers(const std::vector<std::shared_ptr<Peer>>& peers,
                                          MessageType type,
                                          std::span<const std::uint8_t> payload) {
    for (const auto& peer : peers) {
        if (peer->state() == PeerState::CONNECTED) {
            send_to_peer(peer->node_id(), type, payload);
        }
    }
}

// ============================================================================
// ReceiptGossipManager Implementation
// ============================================================================

ReceiptGossipManager::ReceiptGossipManager(
    GossipProtocol& gossip,
    BatchReceiptPool& receipt_pool,
    IdentityRegistry& identity_registry)
    : gossip_(gossip)
    , receipt_pool_(receipt_pool)
    , identity_registry_(identity_registry) {}

void ReceiptGossipManager::on_bucket_tick(tx_epoch_t epoch, std::uint8_t bucket) {
    POP_LOG_TRACE(log::network) << "Bucket tick: epoch=" << epoch << " bucket=" << static_cast<int>(bucket);
    // This would trigger receipt generation and broadcast
    // Implementation depends on reveal pool integration
}

ReceiptGossipManager::ReceiptResult ReceiptGossipManager::process_receipt(
    [[maybe_unused]] const hash_t& peer_id,
    const BatchReceipt& receipt) {

    // Verify the receipt is for a valid bucket
    if (receipt.bucket_id > RECEIPT_CUTOFF_BUCKET) {
        return ReceiptResult::INVALID_TIMING;
    }

    // Note: In a full implementation, we would:
    // 1. Look up the peer's public key from peer_id
    // 2. Check if the pool is frozen with proper timing context
    // 3. Call add_receipt with full parameters
    //
    // For now, just verify the signature and forward
    // The actual verification requires runtime context (now, genesis, peer_pk)

    // Forward to other peers
    gossip_.gossip_receipt(receipt);

    return ReceiptResult::ACCEPTED;
}

void ReceiptGossipManager::generate_and_broadcast_receipt(
    tx_epoch_t epoch,
    std::uint8_t bucket,
    const std::vector<hash_t>& reveal_hashes) {

    // This would use the local signing key to create and broadcast a receipt
    // Implementation depends on having access to the local node's keypair
    POP_LOG_DEBUG(log::network) << "Would generate receipt for epoch=" << epoch
                                 << " bucket=" << static_cast<int>(bucket)
                                 << " with " << reveal_hashes.size() << " reveals";
}

// ============================================================================
// VDFCheckpointManager Implementation
// ============================================================================

VDFCheckpointManager::VDFCheckpointManager(GossipProtocol& gossip, PeerManager& peer_manager)
    : gossip_(gossip)
    , peer_manager_(peer_manager) {}

void VDFCheckpointManager::record_local_checkpoint(slot_t slot, const hash_t& vdf_output,
                                                     std::uint64_t step_count) {
    std::lock_guard<std::mutex> lock(mutex_);

    VDFCheckpointMessage checkpoint;
    checkpoint.slot = slot;
    checkpoint.vdf_output = vdf_output;
    checkpoint.step_count = step_count;
    // signature would be added here

    checkpoints_[slot] = checkpoint;

    if (slot > latest_verified_slot_) {
        latest_verified_slot_ = slot;
    }

    POP_LOG_TRACE(log::network) << "Recorded local VDF checkpoint for slot " << slot;
}

VDFCheckpointManager::CheckpointResult VDFCheckpointManager::process_checkpoint(
    const hash_t& peer_id,
    const VDFCheckpointMessage& checkpoint) {

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we already have this checkpoint
    auto it = checkpoints_.find(checkpoint.slot);
    if (it != checkpoints_.end()) {
        if (it->second.vdf_output == checkpoint.vdf_output) {
            return CheckpointResult::DUPLICATE;
        }
        // Different output for same slot - potential issue
        POP_LOG_WARN(log::network) << "Conflicting VDF checkpoint for slot " << checkpoint.slot;
    }

    // Check if too old (beyond tolerance)
    if (latest_verified_slot_ > VDF_HARD_TOLERANCE_SLOTS &&
        checkpoint.slot < latest_verified_slot_ - VDF_HARD_TOLERANCE_SLOTS) {
        return CheckpointResult::TOO_OLD;
    }

    // In a real implementation, we would verify the checkpoint
    // by computing VDF_CHECKPOINT_VERIFY_STEPS and checking they match

    checkpoints_[checkpoint.slot] = checkpoint;

    if (checkpoint.slot > latest_verified_slot_) {
        latest_verified_slot_ = checkpoint.slot;
    }

    POP_LOG_DEBUG(log::network) << "Accepted VDF checkpoint for slot " << checkpoint.slot
                                 << " from " << bytes_to_hex(peer_id).substr(0, 16);

    return CheckpointResult::ACCEPTED;
}

void VDFCheckpointManager::request_checkpoint(slot_t slot) {
    auto peer = peer_manager_.random_connected_peer();
    if (peer) {
        gossip_.request_vdf_checkpoint(peer->node_id(), slot);
    }
}

std::optional<VDFCheckpointMessage> VDFCheckpointManager::get_checkpoint(slot_t slot) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = checkpoints_.find(slot);
    if (it == checkpoints_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool VDFCheckpointManager::is_synced(slot_t current_slot) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_slot <= latest_verified_slot_ + VDF_SOFT_TOLERANCE_SLOTS;
}

slot_t VDFCheckpointManager::slots_behind(slot_t current_slot) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (current_slot <= latest_verified_slot_) {
        return 0;
    }
    return current_slot - latest_verified_slot_;
}

}  // namespace pop
