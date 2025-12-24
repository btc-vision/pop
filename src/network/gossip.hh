#pragma once

#include "core/types.hh"
#include "network/message.hh"
#include "network/peer.hh"
#include "consensus/identity.hh"
#include "consensus/batch_receipt.hh"
#include "consensus/finality.hh"
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>

namespace pop {

// Forward declarations
class CommitPool;
class RevealPool;
class BatchReceiptPool;

// ============================================================================
// Gossip Configuration
// ============================================================================

struct GossipConfig {
    // Timing
    std::uint64_t gossip_interval_us = GOSSIP_INTERVAL_US;  // 20ms
    std::uint64_t ping_interval_us = 5'000'000;              // 5 seconds
    std::uint64_t stale_peer_threshold_us = 60'000'000;      // 60 seconds

    // Fanout (number of peers to gossip to)
    std::uint32_t gossip_fanout = 8;
    std::uint32_t commit_fanout = 4;
    std::uint32_t reveal_fanout = 4;
    std::uint32_t receipt_fanout = 6;

    // Rate limiting
    std::uint32_t max_messages_per_peer_per_second = 100;
    std::uint32_t max_iblt_requests_per_peer_per_epoch = 10;

    // Deduplication
    std::size_t seen_message_cache_size = 100'000;
};

// ============================================================================
// Message Deduplication
// ============================================================================

class MessageDeduplicator {
public:
    explicit MessageDeduplicator(std::size_t max_size = 100'000);

    // Returns true if message is new (not seen before)
    [[nodiscard]] bool check_and_mark(const hash_t& message_hash);

    // Clear old entries
    void prune(std::size_t target_size);

    [[nodiscard]] std::size_t size() const;

private:
    std::unordered_set<hash_t> seen_;
    std::vector<hash_t> insertion_order_;  // For FIFO eviction
    std::size_t max_size_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Gossip Protocol Handler
// ============================================================================

class GossipProtocol {
public:
    using MessageHandler = std::function<void(const hash_t& peer_id,
                                               MessageType type,
                                               std::span<const std::uint8_t> payload)>;

    GossipProtocol(
        PeerManager& peer_manager,
        IdentityRegistry& identity_registry,
        const GossipConfig& config = GossipConfig{});

    // Message handling
    void on_message(const hash_t& peer_id, MessageType type,
                    std::span<const std::uint8_t> payload);

    void register_handler(MessageType type, MessageHandler handler);

    // Gossip sending
    void gossip_commit(const hash_t& commit_hash, std::span<const std::uint8_t> commit_data);
    void gossip_reveal(const hash_t& reveal_hash, std::span<const std::uint8_t> reveal_data);
    void gossip_receipt(const BatchReceipt& receipt);
    void gossip_attestation(const Attestation& attestation);
    void gossip_identity(const IdentityAnnouncement& announcement);
    void gossip_double_sign_proof(const DoubleSignProof& proof);

    // Periodic gossip
    void broadcast_gossip(const GossipMessage& msg);

    // IBLT reconciliation
    void request_iblt(const hash_t& peer_id, epoch_t epoch);
    void send_iblt(const hash_t& peer_id, const IBLT& iblt, epoch_t epoch);

    // VDF checkpoints
    void broadcast_vdf_checkpoint(const VDFCheckpointMessage& checkpoint);
    void request_vdf_checkpoint(const hash_t& peer_id, slot_t slot);

    // Peer exchange
    void request_peer_exchange(const hash_t& peer_id);
    void send_peer_exchange(const hash_t& peer_id);

    // Statistics
    struct Stats {
        std::uint64_t messages_sent = 0;
        std::uint64_t messages_received = 0;
        std::uint64_t messages_dropped_duplicate = 0;
        std::uint64_t messages_dropped_rate_limit = 0;
        std::uint64_t messages_dropped_banned = 0;
    };
    [[nodiscard]] Stats stats() const;

private:
    PeerManager& peer_manager_;
    IdentityRegistry& identity_registry_;
    GossipConfig config_;

    std::unordered_map<MessageType, MessageHandler> handlers_;
    MessageDeduplicator deduplicator_;

    Stats stats_;
    mutable std::mutex stats_mutex_;

    // Helper methods
    [[nodiscard]] std::vector<std::shared_ptr<Peer>> select_gossip_targets(
        std::uint32_t fanout,
        const std::optional<hash_t>& exclude = std::nullopt) const;

    void send_to_peer(const hash_t& peer_id, MessageType type,
                      std::span<const std::uint8_t> payload);

    void broadcast_to_peers(const std::vector<std::shared_ptr<Peer>>& peers,
                            MessageType type,
                            std::span<const std::uint8_t> payload);
};

// ============================================================================
// Receipt Gossip Manager
// ============================================================================

class ReceiptGossipManager {
public:
    ReceiptGossipManager(
        GossipProtocol& gossip,
        BatchReceiptPool& receipt_pool,
        IdentityRegistry& identity_registry);

    // Called every 100ms (bucket boundary)
    void on_bucket_tick(tx_epoch_t epoch, std::uint8_t bucket);

    // Handle incoming receipt
    enum class ReceiptResult {
        ACCEPTED,
        DUPLICATE,
        INVALID_SIGNATURE,
        INVALID_TIMING,
        PEER_NOT_ELIGIBLE,
        BUCKET_FROZEN,
    };
    ReceiptResult process_receipt(const hash_t& peer_id, const BatchReceipt& receipt);

    // Generate and broadcast our receipt for this bucket
    void generate_and_broadcast_receipt(tx_epoch_t epoch, std::uint8_t bucket,
                                         const std::vector<hash_t>& reveal_hashes);

private:
    GossipProtocol& gossip_;
    BatchReceiptPool& receipt_pool_;
    IdentityRegistry& identity_registry_;
};

// ============================================================================
// VDF Checkpoint Gossip Manager
// ============================================================================

class VDFCheckpointManager {
public:
    VDFCheckpointManager(GossipProtocol& gossip, PeerManager& peer_manager);

    // Record a checkpoint we've computed
    void record_local_checkpoint(slot_t slot, const hash_t& vdf_output, std::uint64_t step_count);

    // Handle incoming checkpoint
    enum class CheckpointResult {
        ACCEPTED,
        DUPLICATE,
        INVALID_SIGNATURE,
        VERIFICATION_FAILED,
        TOO_OLD,
    };
    CheckpointResult process_checkpoint(const hash_t& peer_id,
                                          const VDFCheckpointMessage& checkpoint);

    // Request checkpoint from peers (when behind)
    void request_checkpoint(slot_t slot);

    // Get latest verified checkpoint
    [[nodiscard]] std::optional<VDFCheckpointMessage> get_checkpoint(slot_t slot) const;

    // Check sync status
    [[nodiscard]] bool is_synced(slot_t current_slot) const;
    [[nodiscard]] slot_t slots_behind(slot_t current_slot) const;

private:
    GossipProtocol& gossip_;
    PeerManager& peer_manager_;

    std::unordered_map<slot_t, VDFCheckpointMessage> checkpoints_;
    slot_t latest_verified_slot_ = 0;
    mutable std::mutex mutex_;
};

}  // namespace pop
