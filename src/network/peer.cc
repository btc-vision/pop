#include "network/peer.hh"
#include "core/logging.hh"
#include <algorithm>
#include <random>

namespace pop {

// ============================================================================
// Peer Implementation
// ============================================================================

Peer::Peer(hash_t node_id, std::string address)
    : node_id_(std::move(node_id))
    , address_(std::move(address)) {}

void Peer::set_state(PeerState state) {
    PeerState old_state = state_.exchange(state);
    if (old_state != state) {
        POP_LOG_DEBUG(log::network) << "Peer " << bytes_to_hex(node_id_).substr(0, 16)
                                     << " state: " << peer_state_string(old_state)
                                     << " -> " << peer_state_string(state);
    }
}

void Peer::update_gossip(const GossipMessage& msg) {
    std::lock_guard<std::mutex> lock(gossip_mutex_);
    last_gossip_ = msg;
    identity_age_ = msg.identity_age;
}

std::optional<GossipMessage> Peer::last_gossip() const {
    std::lock_guard<std::mutex> lock(gossip_mutex_);
    return last_gossip_;
}

void Peer::record_message_sent(std::size_t bytes) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.messages_sent++;
    stats_.bytes_sent += bytes;
}

void Peer::record_message_received(std::size_t bytes) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.messages_received++;
    stats_.bytes_received += bytes;
}

void Peer::record_ping_latency(std::uint64_t latency_us) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.last_ping_latency_us = latency_us;
    stats_.ping_count++;

    // Rolling average
    if (stats_.ping_count == 1) {
        stats_.avg_ping_latency_us = latency_us;
    } else {
        stats_.avg_ping_latency_us =
            (stats_.avg_ping_latency_us * (stats_.ping_count - 1) + latency_us) /
            stats_.ping_count;
    }
}

bool Peer::check_rate_limit(std::uint32_t max_per_second) {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Reset counter if more than 1 second has passed
    if (now_us - stats_.last_message_time_us >= 1'000'000) {
        stats_.messages_this_second = 0;
        stats_.last_message_time_us = now_us;
    }

    if (stats_.messages_this_second >= max_per_second) {
        return false;  // Rate limited
    }

    stats_.messages_this_second++;
    return true;
}

PeerInfo Peer::to_peer_info() const {
    PeerInfo info;
    info.node_id = node_id_;
    info.address = address_;
    info.identity_age = identity_age_;
    info.last_seen_us = static_cast<std::uint64_t>(last_seen_.count());
    return info;
}

// ============================================================================
// PeerManager Implementation
// ============================================================================

PeerManager::PeerManager(std::uint32_t max_peers)
    : max_peers_(max_peers) {}

std::shared_ptr<Peer> PeerManager::add_peer(const hash_t& node_id, const std::string& address) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if banned
    if (banned_peers_.find(node_id) != banned_peers_.end()) {
        POP_LOG_DEBUG(log::network) << "Rejecting banned peer: "
                                     << bytes_to_hex(node_id).substr(0, 16);
        return nullptr;
    }

    // Check if already exists
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        return it->second;
    }

    // Check capacity
    if (peers_.size() >= max_peers_) {
        POP_LOG_DEBUG(log::network) << "Peer manager at capacity (" << max_peers_ << ")";
        return nullptr;
    }

    auto peer = std::make_shared<Peer>(node_id, address);
    peers_[node_id] = peer;

    POP_LOG_INFO(log::network) << "Added peer: " << bytes_to_hex(node_id).substr(0, 16)
                                << " at " << address
                                << ", total: " << peers_.size();

    return peer;
}

void PeerManager::remove_peer(const hash_t& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        it->second->set_state(PeerState::DISCONNECTED);
        peers_.erase(it);
        POP_LOG_INFO(log::network) << "Removed peer: " << bytes_to_hex(node_id).substr(0, 16)
                                    << ", total: " << peers_.size();
    }
}

std::shared_ptr<Peer> PeerManager::get_peer(const hash_t& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = peers_.find(node_id);
    if (it == peers_.end()) {
        return nullptr;
    }
    return it->second;
}

std::vector<std::shared_ptr<Peer>> PeerManager::get_connected_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<Peer>> result;
    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::CONNECTED) {
            result.push_back(peer);
        }
    }
    return result;
}

std::vector<std::shared_ptr<Peer>> PeerManager::get_all_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<Peer>> result;
    result.reserve(peers_.size());
    for (const auto& [id, peer] : peers_) {
        result.push_back(peer);
    }
    return result;
}

std::size_t PeerManager::peer_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peers_.size();
}

std::size_t PeerManager::connected_count() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::size_t count = 0;
    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::CONNECTED) {
            count++;
        }
    }
    return count;
}

std::shared_ptr<Peer> PeerManager::random_connected_peer() const {
    auto peers = get_connected_peers();
    if (peers.empty()) {
        return nullptr;
    }

    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<std::size_t> dist(0, peers.size() - 1);
    return peers[dist(rng)];
}

std::vector<std::shared_ptr<Peer>> PeerManager::random_connected_peers(std::size_t count) const {
    auto peers = get_connected_peers();
    if (peers.empty()) {
        return {};
    }

    if (peers.size() <= count) {
        return peers;
    }

    static thread_local std::mt19937 rng(std::random_device{}());
    std::shuffle(peers.begin(), peers.end(), rng);
    peers.resize(count);
    return peers;
}

std::vector<PeerInfo> PeerManager::get_peer_exchange_list(std::size_t max_count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PeerInfo> result;
    result.reserve(std::min(max_count, peers_.size()));

    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::CONNECTED) {
            result.push_back(peer->to_peer_info());
            if (result.size() >= max_count) {
                break;
            }
        }
    }

    return result;
}

void PeerManager::process_peer_exchange(const std::vector<PeerInfo>& peers) {
    for (const auto& info : peers) {
        // Skip banned peers
        if (is_banned(info.node_id)) {
            continue;
        }

        // Try to add new peer
        add_peer(info.node_id, info.address);
    }
}

void PeerManager::prune_disconnected(timestamp_t stale_threshold) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::duration_cast<timestamp_t>(
        std::chrono::steady_clock::now().time_since_epoch());

    std::vector<hash_t> to_remove;
    for (const auto& [id, peer] : peers_) {
        if (peer->state() == PeerState::DISCONNECTED &&
            (now - peer->last_seen()) > stale_threshold) {
            to_remove.push_back(id);
        }
    }

    for (const auto& id : to_remove) {
        peers_.erase(id);
    }

    if (!to_remove.empty()) {
        POP_LOG_DEBUG(log::network) << "Pruned " << to_remove.size() << " stale peers";
    }
}

void PeerManager::update_peer_state(const hash_t& node_id, PeerState state) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        it->second->set_state(state);
    }
}

void PeerManager::ban_peer(const hash_t& node_id, BanReason reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    banned_peers_[node_id] = reason;

    // Remove from active peers
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        it->second->set_state(PeerState::BANNED);
        peers_.erase(it);
    }

    POP_LOG_WARN(log::network) << "Banned peer: " << bytes_to_hex(node_id).substr(0, 16)
                                << ", reason: " << ban_reason_string(reason);
}

bool PeerManager::is_banned(const hash_t& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return banned_peers_.find(node_id) != banned_peers_.end();
}

}  // namespace pop
