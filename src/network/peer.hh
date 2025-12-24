#pragma once

#include "core/types.hh"
#include "network/message.hh"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace pop {

// ============================================================================
// Peer State
// ============================================================================

enum class PeerState : std::uint8_t {
    DISCONNECTED = 0,
    CONNECTING = 1,
    HANDSHAKING = 2,
    CONNECTED = 3,
    BANNED = 4,
};

[[nodiscard]] inline std::string_view peer_state_string(PeerState state) {
    switch (state) {
        case PeerState::DISCONNECTED: return "disconnected";
        case PeerState::CONNECTING: return "connecting";
        case PeerState::HANDSHAKING: return "handshaking";
        case PeerState::CONNECTED: return "connected";
        case PeerState::BANNED: return "banned";
    }
    return "unknown";
}

// ============================================================================
// Peer Statistics
// ============================================================================

struct PeerStats {
    std::uint64_t messages_sent = 0;
    std::uint64_t messages_received = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    std::uint64_t commits_received = 0;
    std::uint64_t reveals_received = 0;
    std::uint64_t receipts_received = 0;
    std::uint64_t errors_received = 0;

    // Latency tracking
    std::uint64_t last_ping_latency_us = 0;
    std::uint64_t avg_ping_latency_us = 0;
    std::uint32_t ping_count = 0;

    // Rate limiting
    std::uint64_t last_message_time_us = 0;
    std::uint32_t messages_this_second = 0;
};

// ============================================================================
// Peer
// ============================================================================

class Peer {
public:
    Peer(hash_t node_id, std::string address);

    // Identity
    [[nodiscard]] const hash_t& node_id() const { return node_id_; }
    [[nodiscard]] const std::string& address() const { return address_; }

    // State management
    [[nodiscard]] PeerState state() const { return state_.load(); }
    void set_state(PeerState state);

    // Connection times
    void set_connected_at(timestamp_t time) { connected_at_ = time; }
    [[nodiscard]] timestamp_t connected_at() const { return connected_at_; }
    [[nodiscard]] timestamp_t last_seen() const { return last_seen_; }
    void update_last_seen(timestamp_t time) { last_seen_ = time; }

    // Identity information (from gossip)
    void set_identity_age(std::uint32_t age) { identity_age_ = age; }
    [[nodiscard]] std::uint32_t identity_age() const { return identity_age_; }

    // Latest gossip state
    void update_gossip(const GossipMessage& msg);
    [[nodiscard]] std::optional<GossipMessage> last_gossip() const;

    // Statistics
    void record_message_sent(std::size_t bytes);
    void record_message_received(std::size_t bytes);
    void record_ping_latency(std::uint64_t latency_us);
    [[nodiscard]] const PeerStats& stats() const { return stats_; }

    // Rate limiting
    [[nodiscard]] bool check_rate_limit(std::uint32_t max_per_second);

    // Serialization for peer exchange
    [[nodiscard]] PeerInfo to_peer_info() const;

private:
    hash_t node_id_;
    std::string address_;
    std::atomic<PeerState> state_{PeerState::DISCONNECTED};

    timestamp_t connected_at_{0};
    timestamp_t last_seen_{0};
    std::uint32_t identity_age_ = 0;

    std::optional<GossipMessage> last_gossip_;
    mutable std::mutex gossip_mutex_;

    PeerStats stats_;
    mutable std::mutex stats_mutex_;
};

// ============================================================================
// Peer Manager
// ============================================================================

class PeerManager {
public:
    explicit PeerManager(std::uint32_t max_peers = MAX_PEERS);

    // Peer lifecycle
    std::shared_ptr<Peer> add_peer(const hash_t& node_id, const std::string& address);
    void remove_peer(const hash_t& node_id);
    [[nodiscard]] std::shared_ptr<Peer> get_peer(const hash_t& node_id) const;

    // Peer lookup
    [[nodiscard]] std::vector<std::shared_ptr<Peer>> get_connected_peers() const;
    [[nodiscard]] std::vector<std::shared_ptr<Peer>> get_all_peers() const;
    [[nodiscard]] std::size_t peer_count() const;
    [[nodiscard]] std::size_t connected_count() const;

    // Random peer selection
    [[nodiscard]] std::shared_ptr<Peer> random_connected_peer() const;
    [[nodiscard]] std::vector<std::shared_ptr<Peer>> random_connected_peers(std::size_t count) const;

    // Peer exchange
    [[nodiscard]] std::vector<PeerInfo> get_peer_exchange_list(std::size_t max_count = 20) const;
    void process_peer_exchange(const std::vector<PeerInfo>& peers);

    // Maintenance
    void prune_disconnected(timestamp_t stale_threshold);
    void update_peer_state(const hash_t& node_id, PeerState state);

    // Ban management
    void ban_peer(const hash_t& node_id, BanReason reason);
    [[nodiscard]] bool is_banned(const hash_t& node_id) const;

private:
    std::unordered_map<hash_t, std::shared_ptr<Peer>> peers_;
    std::unordered_map<hash_t, BanReason> banned_peers_;
    std::uint32_t max_peers_;
    mutable std::mutex mutex_;
};

}  // namespace pop
