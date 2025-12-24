#include "network/message.hh"
#include "crypto/signature.hh"
#include <cstring>

namespace pop {

// ============================================================================
// MessageHeader Implementation
// ============================================================================

std::array<std::uint8_t, MessageHeader::SIZE> MessageHeader::serialize() const {
    std::array<std::uint8_t, SIZE> result{};
    encode_u32(result.data(), magic);
    encode_u16(result.data() + 4, static_cast<std::uint16_t>(type));
    encode_u16(result.data() + 6, flags);
    encode_u32(result.data() + 8, payload_length);
    return result;
}

std::optional<MessageHeader> MessageHeader::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SIZE) {
        return std::nullopt;
    }

    MessageHeader header;
    header.magic = decode_u32(data.data());
    header.type = static_cast<MessageType>(decode_u16(data.data() + 4));
    header.flags = decode_u16(data.data() + 6);
    header.payload_length = decode_u32(data.data() + 8);

    return header;
}

// ============================================================================
// GossipMessage Implementation
// ============================================================================

std::vector<std::uint8_t> GossipMessage::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    std::copy(node_id.begin(), node_id.end(), ptr);
    ptr += HASH_SIZE;

    encode_u64(ptr, timestamp_us);
    ptr += sizeof(std::uint64_t);

    encode_u64(ptr, current_slot);
    ptr += sizeof(slot_t);

    *ptr++ = cycle_number;

    encode_u32(ptr, commit_count);
    ptr += sizeof(std::uint32_t);

    std::copy(commit_bloom.begin(), commit_bloom.end(), ptr);
    ptr += BLOOM_FILTER_SIZE;

    encode_u64(ptr, executed_slot);
    ptr += sizeof(slot_t);

    std::copy(state_root.begin(), state_root.end(), ptr);
    ptr += HASH_SIZE;

    encode_u64(ptr, executed_epoch);
    ptr += sizeof(epoch_t);

    encode_u32(ptr, receipt_count);
    ptr += sizeof(std::uint32_t);

    encode_u32(ptr, identity_age);
    ptr += sizeof(std::uint32_t);

    std::copy(reveal_commitment.begin(), reveal_commitment.end(), ptr);
    ptr += HASH_SIZE;

    std::copy(reveal_bloom.begin(), reveal_bloom.end(), ptr);

    return result;
}

std::optional<GossipMessage> GossipMessage::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    GossipMessage msg;
    const std::uint8_t* ptr = data.data();

    std::copy(ptr, ptr + HASH_SIZE, msg.node_id.begin());
    ptr += HASH_SIZE;

    msg.timestamp_us = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    msg.current_slot = decode_u64(ptr);
    ptr += sizeof(slot_t);

    msg.cycle_number = *ptr++;

    msg.commit_count = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    std::copy(ptr, ptr + BLOOM_FILTER_SIZE, msg.commit_bloom.begin());
    ptr += BLOOM_FILTER_SIZE;

    msg.executed_slot = decode_u64(ptr);
    ptr += sizeof(slot_t);

    std::copy(ptr, ptr + HASH_SIZE, msg.state_root.begin());
    ptr += HASH_SIZE;

    msg.executed_epoch = decode_u64(ptr);
    ptr += sizeof(epoch_t);

    msg.receipt_count = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    msg.identity_age = decode_u32(ptr);
    ptr += sizeof(std::uint32_t);

    std::copy(ptr, ptr + HASH_SIZE, msg.reveal_commitment.begin());
    ptr += HASH_SIZE;

    std::copy(ptr, ptr + BLOOM_FILTER_SIZE, msg.reveal_bloom.begin());

    return msg;
}

// ============================================================================
// PingMessage Implementation
// ============================================================================

std::vector<std::uint8_t> PingMessage::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    encode_u64(result.data(), nonce);
    encode_u64(result.data() + 8, timestamp_us);
    return result;
}

std::optional<PingMessage> PingMessage::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    PingMessage msg;
    msg.nonce = decode_u64(data.data());
    msg.timestamp_us = decode_u64(data.data() + 8);
    return msg;
}

// ============================================================================
// PongMessage Implementation
// ============================================================================

std::vector<std::uint8_t> PongMessage::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    encode_u64(result.data(), nonce);
    encode_u64(result.data() + 8, request_time_us);
    encode_u64(result.data() + 16, response_time_us);
    return result;
}

std::optional<PongMessage> PongMessage::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    PongMessage msg;
    msg.nonce = decode_u64(data.data());
    msg.request_time_us = decode_u64(data.data() + 8);
    msg.response_time_us = decode_u64(data.data() + 16);
    return msg;
}

// ============================================================================
// VDFCheckpointMessage Implementation
// ============================================================================

bool VDFCheckpointMessage::verify(const mldsa_public_key_t& pk) const {
    // Serialize message without signature for verification
    std::vector<std::uint8_t> msg_data;
    msg_data.resize(sizeof(slot_t) + HASH_SIZE + sizeof(std::uint64_t));

    std::uint8_t* ptr = msg_data.data();
    encode_u64(ptr, slot);
    ptr += sizeof(slot_t);
    std::copy(vdf_output.begin(), vdf_output.end(), ptr);
    ptr += HASH_SIZE;
    encode_u64(ptr, step_count);

    return mldsa_verify(pk, msg_data, signature);
}

std::vector<std::uint8_t> VDFCheckpointMessage::serialize() const {
    std::vector<std::uint8_t> result(SERIALIZED_SIZE);
    std::uint8_t* ptr = result.data();

    encode_u64(ptr, slot);
    ptr += sizeof(slot_t);

    std::copy(vdf_output.begin(), vdf_output.end(), ptr);
    ptr += HASH_SIZE;

    encode_u64(ptr, step_count);
    ptr += sizeof(std::uint64_t);

    std::copy(signature.begin(), signature.end(), ptr);

    return result;
}

std::optional<VDFCheckpointMessage> VDFCheckpointMessage::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < SERIALIZED_SIZE) {
        return std::nullopt;
    }

    VDFCheckpointMessage msg;
    const std::uint8_t* ptr = data.data();

    msg.slot = decode_u64(ptr);
    ptr += sizeof(slot_t);

    std::copy(ptr, ptr + HASH_SIZE, msg.vdf_output.begin());
    ptr += HASH_SIZE;

    msg.step_count = decode_u64(ptr);
    ptr += sizeof(std::uint64_t);

    std::copy(ptr, ptr + MLDSA65_SIGNATURE_SIZE, msg.signature.begin());

    return msg;
}

// ============================================================================
// PeerInfo Implementation
// ============================================================================

std::vector<std::uint8_t> PeerInfo::serialize() const {
    std::vector<std::uint8_t> result;

    result.insert(result.end(), node_id.begin(), node_id.end());

    std::array<std::uint8_t, 2> addr_len_bytes;
    encode_u16(addr_len_bytes.data(), static_cast<std::uint16_t>(address.size()));
    result.insert(result.end(), addr_len_bytes.begin(), addr_len_bytes.end());
    result.insert(result.end(), address.begin(), address.end());

    std::array<std::uint8_t, 4> age_bytes;
    encode_u32(age_bytes.data(), identity_age);
    result.insert(result.end(), age_bytes.begin(), age_bytes.end());

    std::array<std::uint8_t, 8> time_bytes;
    encode_u64(time_bytes.data(), last_seen_us);
    result.insert(result.end(), time_bytes.begin(), time_bytes.end());

    return result;
}

std::optional<PeerInfo> PeerInfo::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < HASH_SIZE + 2) {
        return std::nullopt;
    }

    PeerInfo info;
    const std::uint8_t* ptr = data.data();
    const std::uint8_t* end = data.data() + data.size();

    std::copy(ptr, ptr + HASH_SIZE, info.node_id.begin());
    ptr += HASH_SIZE;

    if (ptr + 2 > end) return std::nullopt;
    std::uint16_t addr_len = decode_u16(ptr);
    ptr += 2;

    if (ptr + addr_len > end) return std::nullopt;
    info.address.assign(reinterpret_cast<const char*>(ptr), addr_len);
    ptr += addr_len;

    if (ptr + 4 > end) return std::nullopt;
    info.identity_age = decode_u32(ptr);
    ptr += 4;

    if (ptr + 8 > end) return std::nullopt;
    info.last_seen_us = decode_u64(ptr);

    return info;
}

// ============================================================================
// PeerExchangeMessage Implementation
// ============================================================================

std::vector<std::uint8_t> PeerExchangeMessage::serialize() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 4> count_bytes;
    encode_u32(count_bytes.data(), static_cast<std::uint32_t>(peers.size()));
    result.insert(result.end(), count_bytes.begin(), count_bytes.end());

    for (const auto& peer : peers) {
        auto peer_data = peer.serialize();
        result.insert(result.end(), peer_data.begin(), peer_data.end());
    }

    return result;
}

std::optional<PeerExchangeMessage> PeerExchangeMessage::deserialize(
    std::span<const std::uint8_t> data) {
    if (data.size() < 4) {
        return std::nullopt;
    }

    PeerExchangeMessage msg;
    const std::uint8_t* ptr = data.data();
    const std::uint8_t* end = data.data() + data.size();

    std::uint32_t count = decode_u32(ptr);
    ptr += 4;

    for (std::uint32_t i = 0; i < count; ++i) {
        std::size_t remaining = static_cast<std::size_t>(end - ptr);
        auto peer_opt = PeerInfo::deserialize({ptr, remaining});
        if (!peer_opt) {
            return std::nullopt;
        }
        msg.peers.push_back(*peer_opt);

        // Calculate consumed bytes (variable due to address length)
        ptr += HASH_SIZE + 2 + peer_opt->address.size() + 4 + 8;
    }

    return msg;
}

// ============================================================================
// ErrorMessage Implementation
// ============================================================================

std::vector<std::uint8_t> ErrorMessage::serialize() const {
    std::vector<std::uint8_t> result;

    std::array<std::uint8_t, 2> code_bytes;
    encode_u16(code_bytes.data(), static_cast<std::uint16_t>(code));
    result.insert(result.end(), code_bytes.begin(), code_bytes.end());

    std::array<std::uint8_t, 2> msg_len_bytes;
    encode_u16(msg_len_bytes.data(), static_cast<std::uint16_t>(message.size()));
    result.insert(result.end(), msg_len_bytes.begin(), msg_len_bytes.end());
    result.insert(result.end(), message.begin(), message.end());

    result.push_back(related_hash.has_value() ? 1 : 0);
    if (related_hash) {
        result.insert(result.end(), related_hash->begin(), related_hash->end());
    }

    return result;
}

std::optional<ErrorMessage> ErrorMessage::deserialize(std::span<const std::uint8_t> data) {
    if (data.size() < 5) {
        return std::nullopt;
    }

    ErrorMessage msg;
    const std::uint8_t* ptr = data.data();
    const std::uint8_t* end = data.data() + data.size();

    msg.code = static_cast<ErrorCode>(decode_u16(ptr));
    ptr += 2;

    if (ptr + 2 > end) return std::nullopt;
    std::uint16_t msg_len = decode_u16(ptr);
    ptr += 2;

    if (ptr + msg_len > end) return std::nullopt;
    msg.message.assign(reinterpret_cast<const char*>(ptr), msg_len);
    ptr += msg_len;

    if (ptr + 1 > end) return std::nullopt;
    bool has_hash = (*ptr++ != 0);

    if (has_hash) {
        if (ptr + HASH_SIZE > end) return std::nullopt;
        hash_t h;
        std::copy(ptr, ptr + HASH_SIZE, h.begin());
        msg.related_hash = h;
    }

    return msg;
}

}  // namespace pop
