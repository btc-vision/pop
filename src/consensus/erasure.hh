#pragma once

#include "core/types.hh"
#include <array>
#include <span>
#include <vector>
#include <optional>
#include <bitset>

namespace pop {

// ============================================================================
// Erasure Coding Constants
// ============================================================================

// Reed-Solomon (32, 16) over GF(2^8)
// 16 data chunks, 16 parity chunks = 32 total
// Need any 16 of 32 chunks to reconstruct
inline constexpr std::size_t RS_DATA_CHUNKS = 16;
inline constexpr std::size_t RS_PARITY_CHUNKS = 16;
inline constexpr std::size_t RS_TOTAL_CHUNKS = RS_DATA_CHUNKS + RS_PARITY_CHUNKS;

// Each chunk has a Merkle proof to the reveal root
inline constexpr std::size_t MAX_CHUNK_SIZE = 4096;  // 4KB per chunk

// ============================================================================
// Erasure Coded Chunk
// ============================================================================

struct ErasureChunk {
    std::uint8_t chunk_index;          // 0-31
    std::vector<std::uint8_t> data;    // Chunk data
    std::vector<hash_t> merkle_proof;  // Proof to reveal root

    [[nodiscard]] bool verify(const hash_t& reveal_root) const;

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<ErasureChunk> deserialize(
        std::span<const std::uint8_t> data);
};

// ============================================================================
// Erasure Coded Reveal
// ============================================================================

struct ErasureCodedReveal {
    hash_t reveal_root;               // Merkle root of all chunks
    std::size_t original_size;        // Size of original reveal data
    std::array<hash_t, RS_TOTAL_CHUNKS> chunk_hashes;  // Hash of each chunk

    [[nodiscard]] std::vector<std::uint8_t> serialize() const;
    [[nodiscard]] static std::optional<ErasureCodedReveal> deserialize(
        std::span<const std::uint8_t> data);

    static constexpr std::size_t SERIALIZED_SIZE =
        HASH_SIZE +                         // reveal_root
        sizeof(std::size_t) +               // original_size
        RS_TOTAL_CHUNKS * HASH_SIZE;        // chunk_hashes
};

// ============================================================================
// Galois Field GF(2^8) Arithmetic
// ============================================================================

class GF256 {
public:
    // Initialize log/antilog tables
    static void initialize();

    // Field operations
    [[nodiscard]] static std::uint8_t add(std::uint8_t a, std::uint8_t b);
    [[nodiscard]] static std::uint8_t sub(std::uint8_t a, std::uint8_t b);
    [[nodiscard]] static std::uint8_t mul(std::uint8_t a, std::uint8_t b);
    [[nodiscard]] static std::uint8_t div(std::uint8_t a, std::uint8_t b);
    [[nodiscard]] static std::uint8_t pow(std::uint8_t a, std::uint8_t n);
    [[nodiscard]] static std::uint8_t inv(std::uint8_t a);

private:
    static bool initialized_;
    static std::array<std::uint8_t, 256> log_table_;
    static std::array<std::uint8_t, 512> exp_table_;

    // Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
    static constexpr std::uint16_t PRIMITIVE_POLY = 0x11d;
};

// ============================================================================
// Reed-Solomon Encoder
// ============================================================================

class ReedSolomonEncoder {
public:
    // Encode reveal data into 32 chunks (16 data + 16 parity)
    [[nodiscard]] static std::vector<ErasureChunk> encode(
        std::span<const std::uint8_t> reveal_data,
        hash_t& out_reveal_root);

    // Reconstruct reveal data from any 16+ chunks
    [[nodiscard]] static std::optional<std::vector<std::uint8_t>> decode(
        const std::vector<ErasureChunk>& chunks,
        std::size_t original_size);

    // Check if we have enough chunks to reconstruct
    [[nodiscard]] static bool can_reconstruct(
        const std::bitset<RS_TOTAL_CHUNKS>& available_chunks);

    // Get which chunks are still needed
    [[nodiscard]] static std::vector<std::uint8_t> missing_chunks(
        const std::bitset<RS_TOTAL_CHUNKS>& available_chunks);

private:
    // Generator matrix for systematic RS code
    [[nodiscard]] static std::array<std::array<std::uint8_t, RS_DATA_CHUNKS>, RS_PARITY_CHUNKS>
        compute_generator_matrix();

    // Compute Merkle tree of chunks
    [[nodiscard]] static hash_t compute_chunk_merkle_root(
        const std::array<hash_t, RS_TOTAL_CHUNKS>& chunk_hashes);

    // Generate Merkle proof for a chunk
    [[nodiscard]] static std::vector<hash_t> generate_merkle_proof(
        const std::array<hash_t, RS_TOTAL_CHUNKS>& chunk_hashes,
        std::uint8_t chunk_index);

    // Pad data to multiple of RS_DATA_CHUNKS
    [[nodiscard]] static std::vector<std::uint8_t> pad_data(
        std::span<const std::uint8_t> data);

    // Solve linear system for reconstruction
    [[nodiscard]] static std::optional<std::vector<std::vector<std::uint8_t>>>
        solve_linear_system(
            const std::vector<ErasureChunk>& chunks,
            std::size_t chunk_size);
};

// ============================================================================
// Chunk Collector
// ============================================================================

class ChunkCollector {
public:
    explicit ChunkCollector(const ErasureCodedReveal& reveal_info);

    // Add a chunk (returns true if we can now reconstruct)
    [[nodiscard]] bool add_chunk(const ErasureChunk& chunk);

    // Check if we have enough chunks
    [[nodiscard]] bool can_reconstruct() const;

    // Get collected chunks
    [[nodiscard]] const std::vector<ErasureChunk>& chunks() const { return chunks_; }

    // Get availability bitmap
    [[nodiscard]] const std::bitset<RS_TOTAL_CHUNKS>& availability() const {
        return available_;
    }

    // Get missing chunk indices
    [[nodiscard]] std::vector<std::uint8_t> missing_chunks() const;

    // Reconstruct the original reveal data
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> reconstruct() const;

private:
    ErasureCodedReveal reveal_info_;
    std::vector<ErasureChunk> chunks_;
    std::bitset<RS_TOTAL_CHUNKS> available_;
};

}  // namespace pop
