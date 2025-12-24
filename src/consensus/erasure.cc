#include "consensus/erasure.hh"
#include "crypto/hash.hh"
#include "core/logging.hh"
#include <algorithm>
#include <cstring>

namespace pop {

// ============================================================================
// GF256 Static Members
// ============================================================================

bool GF256::initialized_ = false;
std::array<std::uint8_t, 256> GF256::log_table_;
std::array<std::uint8_t, 512> GF256::exp_table_;

void GF256::initialize() {
    if (initialized_) return;

    // Generate exp and log tables for GF(2^8)
    // Using primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
    std::uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        exp_table_[i] = static_cast<std::uint8_t>(x);
        log_table_[x] = static_cast<std::uint8_t>(i);

        x <<= 1;
        if (x & 0x100) {
            x ^= PRIMITIVE_POLY;
        }
    }

    // Extend exp table for easier modular reduction
    for (int i = 255; i < 512; i++) {
        exp_table_[i] = exp_table_[i - 255];
    }

    log_table_[0] = 0;  // Convention (undefined mathematically)
    initialized_ = true;
}

std::uint8_t GF256::add(std::uint8_t a, std::uint8_t b) {
    return a ^ b;  // XOR in GF(2^8)
}

std::uint8_t GF256::sub(std::uint8_t a, std::uint8_t b) {
    return a ^ b;  // Same as addition in GF(2^8)
}

std::uint8_t GF256::mul(std::uint8_t a, std::uint8_t b) {
    if (a == 0 || b == 0) return 0;
    if (!initialized_) initialize();
    return exp_table_[log_table_[a] + log_table_[b]];
}

std::uint8_t GF256::div(std::uint8_t a, std::uint8_t b) {
    if (b == 0) return 0;  // Division by zero
    if (a == 0) return 0;
    if (!initialized_) initialize();
    return exp_table_[(log_table_[a] + 255 - log_table_[b]) % 255];
}

std::uint8_t GF256::pow(std::uint8_t a, std::uint8_t n) {
    if (n == 0) return 1;
    if (a == 0) return 0;
    if (!initialized_) initialize();
    return exp_table_[(static_cast<std::uint16_t>(log_table_[a]) * n) % 255];
}

std::uint8_t GF256::inv(std::uint8_t a) {
    if (a == 0) return 0;
    if (!initialized_) initialize();
    return exp_table_[255 - log_table_[a]];
}

// ============================================================================
// ErasureChunk Implementation
// ============================================================================

bool ErasureChunk::verify(const hash_t& reveal_root) const {
    if (chunk_index >= RS_TOTAL_CHUNKS) {
        return false;
    }

    // Compute hash of chunk data
    hash_t chunk_hash = sha3_256(data);

    // Verify Merkle proof
    hash_t current = chunk_hash;
    std::size_t index = chunk_index;

    for (const auto& sibling : merkle_proof) {
        SHA3Hasher hasher;
        if (index % 2 == 0) {
            hasher.update(current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize();
        index /= 2;
    }

    return current == reveal_root;
}

std::vector<std::uint8_t> ErasureChunk::serialize() const {
    std::vector<std::uint8_t> result;

    result.push_back(chunk_index);

    std::array<std::uint8_t, 4> data_len;
    encode_u32(data_len.data(), static_cast<std::uint32_t>(data.size()));
    result.insert(result.end(), data_len.begin(), data_len.end());
    result.insert(result.end(), data.begin(), data.end());

    std::array<std::uint8_t, 4> proof_len;
    encode_u32(proof_len.data(), static_cast<std::uint32_t>(merkle_proof.size()));
    result.insert(result.end(), proof_len.begin(), proof_len.end());

    for (const auto& node : merkle_proof) {
        result.insert(result.end(), node.begin(), node.end());
    }

    return result;
}

std::optional<ErasureChunk> ErasureChunk::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < 9) return std::nullopt;

    ErasureChunk result;
    std::size_t offset = 0;

    result.chunk_index = data[offset++];

    std::uint32_t data_len = decode_u32(data.data() + offset);
    offset += 4;

    if (data.size() < offset + data_len + 4) return std::nullopt;
    result.data.assign(data.begin() + offset, data.begin() + offset + data_len);
    offset += data_len;

    std::uint32_t proof_len = decode_u32(data.data() + offset);
    offset += 4;

    if (data.size() < offset + proof_len * HASH_SIZE) return std::nullopt;
    result.merkle_proof.resize(proof_len);
    for (std::uint32_t i = 0; i < proof_len; i++) {
        std::copy_n(data.begin() + offset, HASH_SIZE, result.merkle_proof[i].begin());
        offset += HASH_SIZE;
    }

    return result;
}

// ============================================================================
// ErasureCodedReveal Implementation
// ============================================================================

std::vector<std::uint8_t> ErasureCodedReveal::serialize() const {
    std::vector<std::uint8_t> result;
    result.reserve(SERIALIZED_SIZE);

    result.insert(result.end(), reveal_root.begin(), reveal_root.end());

    std::array<std::uint8_t, 8> size_bytes;
    encode_u64(size_bytes.data(), original_size);
    result.insert(result.end(), size_bytes.begin(), size_bytes.end());

    for (const auto& h : chunk_hashes) {
        result.insert(result.end(), h.begin(), h.end());
    }

    return result;
}

std::optional<ErasureCodedReveal> ErasureCodedReveal::deserialize(
    std::span<const std::uint8_t> data) {

    if (data.size() < SERIALIZED_SIZE) return std::nullopt;

    ErasureCodedReveal result;
    std::size_t offset = 0;

    std::copy_n(data.begin(), HASH_SIZE, result.reveal_root.begin());
    offset += HASH_SIZE;

    result.original_size = decode_u64(data.data() + offset);
    offset += sizeof(std::size_t);

    for (std::size_t i = 0; i < RS_TOTAL_CHUNKS; i++) {
        std::copy_n(data.begin() + offset, HASH_SIZE, result.chunk_hashes[i].begin());
        offset += HASH_SIZE;
    }

    return result;
}

// ============================================================================
// ReedSolomonEncoder Implementation
// ============================================================================

std::array<std::array<std::uint8_t, RS_DATA_CHUNKS>, RS_PARITY_CHUNKS>
ReedSolomonEncoder::compute_generator_matrix() {
    GF256::initialize();

    std::array<std::array<std::uint8_t, RS_DATA_CHUNKS>, RS_PARITY_CHUNKS> matrix;

    // Vandermonde matrix for systematic code
    // Row i, Col j: alpha^(i*j) where alpha = 2 (primitive element)
    for (std::size_t i = 0; i < RS_PARITY_CHUNKS; i++) {
        for (std::size_t j = 0; j < RS_DATA_CHUNKS; j++) {
            // Use evaluation points starting at RS_DATA_CHUNKS to avoid overlap
            std::uint8_t alpha_i = static_cast<std::uint8_t>(RS_DATA_CHUNKS + i);
            matrix[i][j] = GF256::pow(alpha_i, static_cast<std::uint8_t>(j));
        }
    }

    return matrix;
}

hash_t ReedSolomonEncoder::compute_chunk_merkle_root(
    const std::array<hash_t, RS_TOTAL_CHUNKS>& chunk_hashes) {

    // Build Merkle tree (32 leaves, height 5)
    std::vector<hash_t> level(chunk_hashes.begin(), chunk_hashes.end());

    while (level.size() > 1) {
        std::vector<hash_t> next_level;
        for (std::size_t i = 0; i < level.size(); i += 2) {
            SHA3Hasher hasher;
            hasher.update(level[i]);
            if (i + 1 < level.size()) {
                hasher.update(level[i + 1]);
            } else {
                hasher.update(level[i]);  // Duplicate if odd
            }
            next_level.push_back(hasher.finalize());
        }
        level = std::move(next_level);
    }

    return level.empty() ? hash_t{} : level[0];
}

std::vector<hash_t> ReedSolomonEncoder::generate_merkle_proof(
    const std::array<hash_t, RS_TOTAL_CHUNKS>& chunk_hashes,
    std::uint8_t chunk_index) {

    std::vector<hash_t> proof;

    // Build levels and collect siblings
    std::vector<hash_t> level(chunk_hashes.begin(), chunk_hashes.end());
    std::size_t index = chunk_index;

    while (level.size() > 1) {
        // Get sibling
        std::size_t sibling_idx = (index % 2 == 0) ? index + 1 : index - 1;
        if (sibling_idx < level.size()) {
            proof.push_back(level[sibling_idx]);
        } else {
            proof.push_back(level[index]);  // Duplicate if no sibling
        }

        // Build next level
        std::vector<hash_t> next_level;
        for (std::size_t i = 0; i < level.size(); i += 2) {
            SHA3Hasher hasher;
            hasher.update(level[i]);
            if (i + 1 < level.size()) {
                hasher.update(level[i + 1]);
            } else {
                hasher.update(level[i]);
            }
            next_level.push_back(hasher.finalize());
        }

        level = std::move(next_level);
        index /= 2;
    }

    return proof;
}

std::vector<std::uint8_t> ReedSolomonEncoder::pad_data(
    std::span<const std::uint8_t> data) {

    std::size_t chunk_size = (data.size() + RS_DATA_CHUNKS - 1) / RS_DATA_CHUNKS;
    if (chunk_size == 0) chunk_size = 1;

    std::size_t padded_size = chunk_size * RS_DATA_CHUNKS;
    std::vector<std::uint8_t> padded(padded_size, 0);
    std::copy(data.begin(), data.end(), padded.begin());

    return padded;
}

std::vector<ErasureChunk> ReedSolomonEncoder::encode(
    std::span<const std::uint8_t> reveal_data,
    hash_t& out_reveal_root) {

    GF256::initialize();

    std::vector<ErasureChunk> chunks;
    chunks.resize(RS_TOTAL_CHUNKS);

    // Pad data to multiple of RS_DATA_CHUNKS
    auto padded = pad_data(reveal_data);
    std::size_t chunk_size = padded.size() / RS_DATA_CHUNKS;

    // Create data chunks (systematic code - first 16 chunks are original data)
    for (std::size_t i = 0; i < RS_DATA_CHUNKS; i++) {
        chunks[i].chunk_index = static_cast<std::uint8_t>(i);
        chunks[i].data.assign(
            padded.begin() + i * chunk_size,
            padded.begin() + (i + 1) * chunk_size);
    }

    // Create parity chunks
    auto gen_matrix = compute_generator_matrix();

    for (std::size_t i = 0; i < RS_PARITY_CHUNKS; i++) {
        chunks[RS_DATA_CHUNKS + i].chunk_index = static_cast<std::uint8_t>(RS_DATA_CHUNKS + i);
        chunks[RS_DATA_CHUNKS + i].data.resize(chunk_size, 0);

        // Compute parity: P[i] = sum(G[i][j] * D[j]) for all data chunks
        for (std::size_t byte_idx = 0; byte_idx < chunk_size; byte_idx++) {
            std::uint8_t parity_byte = 0;
            for (std::size_t j = 0; j < RS_DATA_CHUNKS; j++) {
                parity_byte = GF256::add(parity_byte,
                    GF256::mul(gen_matrix[i][j], chunks[j].data[byte_idx]));
            }
            chunks[RS_DATA_CHUNKS + i].data[byte_idx] = parity_byte;
        }
    }

    // Compute chunk hashes
    std::array<hash_t, RS_TOTAL_CHUNKS> chunk_hashes;
    for (std::size_t i = 0; i < RS_TOTAL_CHUNKS; i++) {
        chunk_hashes[i] = sha3_256(chunks[i].data);
    }

    // Compute Merkle root
    out_reveal_root = compute_chunk_merkle_root(chunk_hashes);

    // Generate Merkle proofs for each chunk
    for (std::size_t i = 0; i < RS_TOTAL_CHUNKS; i++) {
        chunks[i].merkle_proof = generate_merkle_proof(
            chunk_hashes, static_cast<std::uint8_t>(i));
    }

    return chunks;
}

bool ReedSolomonEncoder::can_reconstruct(
    const std::bitset<RS_TOTAL_CHUNKS>& available_chunks) {
    return available_chunks.count() >= RS_DATA_CHUNKS;
}

std::vector<std::uint8_t> ReedSolomonEncoder::missing_chunks(
    const std::bitset<RS_TOTAL_CHUNKS>& available_chunks) {

    std::vector<std::uint8_t> missing;
    for (std::size_t i = 0; i < RS_TOTAL_CHUNKS; i++) {
        if (!available_chunks[i]) {
            missing.push_back(static_cast<std::uint8_t>(i));
        }
    }
    return missing;
}

std::optional<std::vector<std::vector<std::uint8_t>>>
ReedSolomonEncoder::solve_linear_system(
    const std::vector<ErasureChunk>& chunks,
    std::size_t chunk_size) {

    GF256::initialize();

    if (chunks.size() < RS_DATA_CHUNKS) {
        return std::nullopt;
    }

    // Build the decoding matrix based on which chunks we have
    // For systematic code: data chunks have identity rows, parity chunks use generator

    auto gen_matrix = compute_generator_matrix();

    // Collect chunk indices we have
    std::vector<std::size_t> available_indices;
    for (const auto& chunk : chunks) {
        available_indices.push_back(chunk.chunk_index);
        if (available_indices.size() == RS_DATA_CHUNKS) break;
    }

    // Build matrix for available chunks
    std::array<std::array<std::uint8_t, RS_DATA_CHUNKS>, RS_DATA_CHUNKS> matrix{};

    for (std::size_t row = 0; row < RS_DATA_CHUNKS; row++) {
        std::size_t idx = available_indices[row];
        if (idx < RS_DATA_CHUNKS) {
            // Data chunk - identity row
            matrix[row][idx] = 1;
        } else {
            // Parity chunk - generator row
            for (std::size_t col = 0; col < RS_DATA_CHUNKS; col++) {
                matrix[row][col] = gen_matrix[idx - RS_DATA_CHUNKS][col];
            }
        }
    }

    // Gaussian elimination to invert matrix
    std::array<std::array<std::uint8_t, RS_DATA_CHUNKS>, RS_DATA_CHUNKS> inverse{};
    for (std::size_t i = 0; i < RS_DATA_CHUNKS; i++) {
        inverse[i][i] = 1;  // Start with identity
    }

    for (std::size_t col = 0; col < RS_DATA_CHUNKS; col++) {
        // Find pivot
        std::size_t pivot_row = col;
        for (std::size_t row = col; row < RS_DATA_CHUNKS; row++) {
            if (matrix[row][col] != 0) {
                pivot_row = row;
                break;
            }
        }

        if (matrix[pivot_row][col] == 0) {
            return std::nullopt;  // Singular matrix
        }

        // Swap rows
        std::swap(matrix[col], matrix[pivot_row]);
        std::swap(inverse[col], inverse[pivot_row]);

        // Scale pivot row
        std::uint8_t scale = GF256::inv(matrix[col][col]);
        for (std::size_t j = 0; j < RS_DATA_CHUNKS; j++) {
            matrix[col][j] = GF256::mul(matrix[col][j], scale);
            inverse[col][j] = GF256::mul(inverse[col][j], scale);
        }

        // Eliminate column
        for (std::size_t row = 0; row < RS_DATA_CHUNKS; row++) {
            if (row != col && matrix[row][col] != 0) {
                std::uint8_t factor = matrix[row][col];
                for (std::size_t j = 0; j < RS_DATA_CHUNKS; j++) {
                    matrix[row][j] = GF256::sub(matrix[row][j],
                        GF256::mul(factor, matrix[col][j]));
                    inverse[row][j] = GF256::sub(inverse[row][j],
                        GF256::mul(factor, inverse[col][j]));
                }
            }
        }
    }

    // Multiply inverse by available chunk data to get original data chunks
    std::vector<std::vector<std::uint8_t>> result(RS_DATA_CHUNKS);
    for (std::size_t i = 0; i < RS_DATA_CHUNKS; i++) {
        result[i].resize(chunk_size, 0);
    }

    for (std::size_t byte_idx = 0; byte_idx < chunk_size; byte_idx++) {
        for (std::size_t out_chunk = 0; out_chunk < RS_DATA_CHUNKS; out_chunk++) {
            std::uint8_t val = 0;
            for (std::size_t in_chunk = 0; in_chunk < RS_DATA_CHUNKS; in_chunk++) {
                val = GF256::add(val,
                    GF256::mul(inverse[out_chunk][in_chunk],
                              chunks[in_chunk].data[byte_idx]));
            }
            result[out_chunk][byte_idx] = val;
        }
    }

    return result;
}

std::optional<std::vector<std::uint8_t>> ReedSolomonEncoder::decode(
    const std::vector<ErasureChunk>& chunks,
    std::size_t original_size) {

    if (chunks.size() < RS_DATA_CHUNKS) {
        POP_LOG_DEBUG(log::consensus) << "Not enough chunks for reconstruction: "
                                       << chunks.size() << " < " << RS_DATA_CHUNKS;
        return std::nullopt;
    }

    // Check if we have all data chunks (fast path)
    std::bitset<RS_DATA_CHUNKS> have_data;
    for (const auto& chunk : chunks) {
        if (chunk.chunk_index < RS_DATA_CHUNKS) {
            have_data.set(chunk.chunk_index);
        }
    }

    if (chunks.empty()) {
        return std::nullopt;
    }

    std::size_t chunk_size = chunks[0].data.size();

    if (have_data.all()) {
        // Fast path: just concatenate data chunks
        std::vector<std::uint8_t> result;
        result.reserve(original_size);

        std::vector<const ErasureChunk*> sorted_data(RS_DATA_CHUNKS, nullptr);
        for (const auto& chunk : chunks) {
            if (chunk.chunk_index < RS_DATA_CHUNKS) {
                sorted_data[chunk.chunk_index] = &chunk;
            }
        }

        for (const auto* chunk : sorted_data) {
            if (chunk) {
                result.insert(result.end(), chunk->data.begin(), chunk->data.end());
            }
        }

        result.resize(original_size);
        return result;
    }

    // Need to decode using linear algebra
    auto decoded_chunks = solve_linear_system(chunks, chunk_size);
    if (!decoded_chunks) {
        return std::nullopt;
    }

    // Concatenate decoded data chunks
    std::vector<std::uint8_t> result;
    result.reserve(original_size);
    for (const auto& chunk : *decoded_chunks) {
        result.insert(result.end(), chunk.begin(), chunk.end());
    }

    result.resize(original_size);
    return result;
}

// ============================================================================
// ChunkCollector Implementation
// ============================================================================

ChunkCollector::ChunkCollector(const ErasureCodedReveal& reveal_info)
    : reveal_info_(reveal_info) {}

bool ChunkCollector::add_chunk(const ErasureChunk& chunk) {
    if (chunk.chunk_index >= RS_TOTAL_CHUNKS) {
        return false;
    }

    if (available_[chunk.chunk_index]) {
        return can_reconstruct();  // Already have this chunk
    }

    // Verify chunk hash matches expected
    hash_t chunk_hash = sha3_256(chunk.data);
    if (chunk_hash != reveal_info_.chunk_hashes[chunk.chunk_index]) {
        POP_LOG_DEBUG(log::consensus) << "Chunk hash mismatch for index "
                                       << static_cast<int>(chunk.chunk_index);
        return false;
    }

    // Verify Merkle proof
    if (!chunk.verify(reveal_info_.reveal_root)) {
        POP_LOG_DEBUG(log::consensus) << "Chunk Merkle proof invalid for index "
                                       << static_cast<int>(chunk.chunk_index);
        return false;
    }

    chunks_.push_back(chunk);
    available_.set(chunk.chunk_index);

    return can_reconstruct();
}

bool ChunkCollector::can_reconstruct() const {
    return available_.count() >= RS_DATA_CHUNKS;
}

std::vector<std::uint8_t> ChunkCollector::missing_chunks() const {
    return ReedSolomonEncoder::missing_chunks(available_);
}

std::optional<std::vector<std::uint8_t>> ChunkCollector::reconstruct() const {
    if (!can_reconstruct()) {
        return std::nullopt;
    }

    return ReedSolomonEncoder::decode(chunks_, reveal_info_.original_size);
}

}  // namespace pop
