# Proof of Position: Complete Specification v1.0

A deterministic optimistic replicated state machine with receipt-attested availability, VDF-sequenced time, and convergence-bounded finalization.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Foundational Primitives](#2-foundational-primitives)
3. [Time Model](#3-time-model)
4. [Transaction Lifecycle](#4-transaction-lifecycle)
5. [State Model](#5-state-model)
6. [Receipt System](#6-receipt-system)
7. [Identity and Sybil Resistance](#7-identity-and-sybil-resistance)
8. [Finality Model](#8-finality-model)
9. [Network Protocol](#9-network-protocol)
10. [Economic Model](#10-economic-model)
11. [Light Clients](#11-light-clients)
12. [Adversary Model](#12-adversary-model)
13. [Constants and Parameters](#13-constants-and-parameters)

---

## 1. Overview

### 1.1 What This Is

Proof of Position is a distributed ledger protocol that achieves deterministic transaction ordering without consensus, leaders, validators, or synchronized clocks.

**Core insight**: If transactions determine their own position via cryptographic hash, and availability is proven via receipts containing data and work, then ordering becomes a mathematical fact rather than a social agreement.

### 1.2 Key Properties

- **No consensus**: Ordering derived from content, not voted upon
- **No leaders**: No block producers, no validators, no committees
- **No external time**: Time computed via VDF, not observed via NTP
- **No honest majority assumption**: One well-connected honest node sufficient
- **MEV impossible**: Content encrypted until position locked
- **Post-quantum**: ML-DSA, SHA3-256, STARKs throughout
- **50,000+ TPS**: Structural parallelism via declared access sets

### 1.3 Core Assumption

> At least one honest node exists with gossip connectivity to each distinct network neighborhood.

This is weaker than any threshold-based assumption. It is verifiable (fraud proofs propagate) and recoverable (new honest nodes can join).

---

## 2. Foundational Primitives

### 2.1 Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Hash | SHA3-256 | VDF, PoW, commitments, Merkle trees |
| Signature | ML-DSA (FIPS 204) | All persistent signatures |
| One-time signature | LM-OTS | Reveal binding to VDF range |
| Encryption | AES-256-GCM | Commit payload encryption |
| Erasure coding | Reed-Solomon (32,16) | Receipt chunk distribution |
| Proof system | STARKs | VDF verification for light clients |

All primitives are post-quantum secure.

### 2.2 Data Structures

#### 2.2.1 Commit Header
```
CommitHeader {
    payload_hash: Hash,           // SHA3-256 of encrypted payload
    fee_recipient: Address,       // Relayer address
    max_fee: u128,                // Maximum fee in native units
    fee_mode: FeeMode,            // PayOnInclude | PayOnExecute
    retry_nonce: u64,             // For position grinding on retry
    max_instructions: u64,        // Execution limit
    lmots_public_key: [u8; 32],   // One-time signature public key
}
```

#### 2.2.2 Commit
```
Commit {
    header: CommitHeader,
    encrypted_payload: Vec<u8>,   // AES-256-GCM encrypted transaction
    signature: Signature,         // ML-DSA signature over header
}
```

#### 2.2.3 Reveal
```
Reveal {
    commit_header: CommitHeader,  // Embedded, not referenced
    decryption_key: [u8; 32],     // AES-256-GCM key
    target_vdf_range: VdfRange,   // (start_step, end_step)
    declared_set: DeclaredSet,    // Access declarations
    expectations: Vec<Expectation>,
    receipt_reward_pool: u128,    // Reward for receipt signers
    lmots_signature: LmotsSignature, // One-time signature over reveal
}
```

#### 2.2.4 VdfRange
```
VdfRange {
    start_step: u64,              // Inclusive
    end_step: u64,                // Exclusive
}
```

---

## 3. Time Model

### 3.1 VDF Chain

Time is computed, not observed. Every node computes an identical sequential hash chain.

```
VDF_step(0) = SHA3-256(genesis_seed)
VDF_step(n) = SHA3-256(VDF_step(n-1))
```

**Properties**:
- Strictly sequential: Cannot parallelize
- Deterministic: Same input produces same output everywhere
- Post-quantum: No known quantum speedup beyond Grover's sqrt

### 3.2 Hardware Variance

SHA3-256 throughput varies ~2-3x across commodity hardware:

| Hardware | Relative Speed |
|----------|---------------|
| 2021 desktop (reference) | 1.0x |
| 2024 desktop | 1.25x |
| High-end server | 1.5-2.0x |
| Mobile high-end | 0.3x |
| Mobile low-end | 0.15x |

ASIC advantage bounded to ~2-5x (single-threaded efficiency only). Sequential iteration cannot be parallelized.

### 3.3 Time Units

| Unit | Definition | Approximate Duration |
|------|------------|---------------------|
| VDF step | One SHA3-256 iteration | ~1μs on reference hardware |
| Slot | S VDF steps | ~100ms |
| Transaction epoch | K slots | ~10 seconds |
| Identity epoch | ~30 days of VDF steps | ~30 days |

### 3.4 VDF Progress Caps

Nodes more than 1000 VDF steps ahead of median observed receipt timestamps should throttle VDF computation. This prevents stratification while allowing legitimate hardware variation.

### 3.5 VDF Checkpoints

At each epoch boundary, the VDF value is recorded as a checkpoint:

```
V_e = VDF_step(e * K * S)
```

Checkpoints enable:
- Receipt bucket binding verification
- STARK proof anchoring
- Fast sync for new nodes

---

## 4. Transaction Lifecycle

### 4.1 Position Derivation

Every transaction contains its own position, derived deterministically:

```
position = SHA3-256(commit_header) mod P
subposition = SHA3-256(commit_header || 0x01)  // Full 256-bit
```

Sort lexicographically by (position, subposition). Collisions in both dimensions are negligible (~2^-256).

**The order is the content. The content is the order.**

### 4.2 Lifecycle Phases

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TRANSACTION LIFECYCLE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐       │
│  │  CREATE  │───►│  COMMIT  │───►│  REVEAL  │───►│ EXECUTE  │       │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘       │
│       │               │               │               │              │
│       ▼               ▼               ▼               ▼              │
│  Generate         Broadcast       Broadcast       VM runs            │
│  keypair,         encrypted       decryption      transaction,       │
│  encrypt          commit          key + state     enforces           │
│  payload                          expectations    expectations       │
│                                                                      │
│  Position         Position        Epoch           Parallel           │
│  known            locked at       membership      execution          │
│  immediately      slot close      established     if no conflicts    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.3 Commit Phase

1. User generates LM-OTS keypair
2. User encrypts transaction payload with AES-256-GCM
3. User constructs commit header with public key
4. User sends commit + decryption key to relayer
5. Relayer broadcasts commit to network
6. Position is immediately known from hash(commit_header)
7. Position locks when slot closes (VDF advances past slot boundary)

### 4.4 Reveal Phase

1. Relayer constructs reveal with:
   - Commit header (embedded)
   - Decryption key
   - Target VDF range
   - Declared access set
   - State expectations
   - Receipt reward pool
2. Relayer signs reveal with LM-OTS key
3. Relayer broadcasts reveal
4. Epoch membership established by target VDF range

### 4.5 LM-OTS Replay Prevention

One key. One signature. One VDF range. Ever.

If someone signs a different VDF range with the same key, two signatures reveal the private key. Instant detection.

```
Timeout = K/2 slots of VDF steps
```

If reveal doesn't collect sufficient receipts within timeout, it expires. Commit dropped. Minimum fee burned. Nonce consumed. User must resubmit with new retry_nonce.

### 4.6 State Expectations

Expectations are conditions that must hold for execution to proceed:

```
Expectation =
    | BalanceRange { address: Address, min: u128, max: u128 }
    | StorageEquals { address: Address, key: Key, value: Value }
    | StorageRange { address: Address, key: Key, min: Value, max: Value }
    | OutputRange { output_id: u32, min: Value, max: Value }
```

Every node evaluates locally:
- State satisfies expectations? Execute
- Otherwise? Drop

**The transaction validates itself.**

---

## 5. State Model

### 5.1 Account Structure

```
Account {
    code_hash: Hash,              // SHA3-256 of WASM bytecode
    storage_root: Hash,           // Merkle root of storage trie
    balance: u128,                // Native token balance
    nonce: u64,                   // Replay protection
    rent_balance: u128,           // Prepaid storage rent
}
```

Global state is a map from Address to Account.

### 5.2 Declared Access Sets

Transactions declare a superset of possible state accesses. The VM enforces that actual accesses are a subset of declarations.

#### 5.2.1 Declaration Types

| Type | Syntax | Cost | Description |
|------|--------|------|-------------|
| Exact | `(addr, key)` | 1 unit | Specific storage slot |
| Prefix | `(addr, prefix)` | 10 + len(prefix) units | All keys starting with prefix |
| Namespace | `(addr, *)` | 100 units | Entire contract storage |
| BalanceOnly | `(addr, $balance)` | 1 unit | Only balance, not storage |

Maximum declared set size: 10,000 declarations.

#### 5.2.2 Conflict Detection

Two declarations conflict if they could access the same state:

**Exact vs Exact**:
```
conflict iff addr1 == addr2 AND key1 == key2
```

**Exact vs Prefix**:
```
conflict iff addr == prefix_addr AND key.starts_with(prefix_bytes)
```

**Prefix vs Prefix**:
```
conflict iff addr1 == addr2 AND (
    prefix1.starts_with(prefix2) OR
    prefix2.starts_with(prefix1)
)
```

**Namespace vs Any**:
```
conflict iff namespace_addr == other_addr
```

**BalanceOnly vs BalanceOnly**:
```
conflict iff addr1 == addr2
```

**BalanceOnly vs Storage**: No conflict (different state domains)

#### 5.2.3 Parallel Execution

Non-overlapping declared sets execute in parallel:

```
Transaction A: declares (X, key1), (X, key2)
Transaction B: declares (Y, key3), (Y, key4)
No overlap → Execute in parallel

Transaction C: declares (X, 0x12*)
Transaction D: declares (X, 0x1234)
Overlap (0x12* contains 0x1234) → Execute sequentially by position
```

### 5.3 Execution Limits

Transactions declare max_instructions in commit header. Fee scales with declared limit.

```
Default limit: 10,000,000 instructions
```

During execution, VM meters instructions. If count exceeds limit:
- Execution halts
- Transaction drops
- Expectations failed
- Fee burns (no refund)

### 5.4 State Rent

Each account has rent_balance. Per epoch, rent deducted proportional to storage size:

```
rent_per_epoch = R * (code_size + storage_slots * 32 + BASE_OVERHEAD)
```

**Lifecycle**:
- `rent_balance > 0`: Active, can be called
- `rent_balance == 0`: Dormant, skipped in execution
- Dormant for 1000 epochs: Pruned to cold storage
- Resurrection requires back-rent + buffer fee

---

## 6. Receipt System

### 6.1 What Is a Receipt?

A receipt is proof of:
1. **Data possession**: Contains assigned erasure-coded chunk
2. **Sequential work**: Contains PoW output
3. **Timing**: Contains verifiable VDF bucket binding

Receipts ARE the data availability layer.

### 6.2 Erasure Coding

Reveals are Reed-Solomon encoded into 32 chunks with threshold 16:

```
chunks = ReedSolomon::encode(reveal, 32, 16)
```

Any 16 chunks can reconstruct the full reveal.

### 6.3 Chunk Assignment

Chunk assignment is deterministic but unpredictable:

```
chunk_index = SHA3-256(
    reveal_root ||
    peer_id ||
    epoch_randomness
) mod 32
```

#### 6.3.1 Epoch Randomness Derivation

**Normal operation** (global finality current):
```
epoch_randomness = SHA3-256(
    "chunks_v2" ||
    global_state_root(epoch - 1) ||
    vdf_checkpoint(epoch_start) ||
    receipt_pow_accumulator(epoch - 1)
)
```

**Timeout mode** (global finality delayed > threshold):
```
epoch_randomness = SHA3-256(
    "chunks_timeout_v2" ||
    last_global_state_root ||
    vdf_checkpoint(timeout_trigger_step) ||
    receipt_pow_accumulator(last_5_epochs) ||
    timeout_epoch_number
)
```

Where `receipt_pow_accumulator(e)` = SHA3-256 of concatenated PoW final outputs from all valid receipts in epoch e, sorted by (reveal_root, peer_id).

**Why this works**: Attacker cannot predict:
- VDF checkpoints (deterministic from genesis)
- Honest nodes' PoW outputs (sequential work with unpredictable nonce)

### 6.4 Sequential Proof of Work

Each receipt requires 80,000 SHA3-256 iterations:

```
pow_input = SHA3-256(reveal_root || peer_id || nonce)
for i in 1..80000:
    pow_input = SHA3-256(pow_input)
pow_output = pow_input
```

Checkpoints at iterations 0, 20000, 40000, 60000, 80000 for efficient verification.

**Calibration**: ~10ms on 2021 desktop CPU (Intel i5-11400 / AMD Ryzen 5 5600X)

**Hardware scaling**:
| Hardware | Time |
|----------|------|
| 2021 desktop (reference) | 10ms |
| 2024 desktop | 8ms |
| Server | 5-7ms |
| High-end laptop | 12ms |
| Low-end laptop | 20ms |
| Mobile high-end | 33ms |
| Mobile low-end | 67ms |

**Why sequential PoW?**

Sybil with 1000 identities receipting one reveal:
- Must compute 1000 sequential PoWs
- Each takes 10ms
- Total: 10 seconds

No parallelization benefit. Cost scales linearly with identity count.

### 6.5 VDF Bucket Binding

Receipts must prove they were produced at the claimed VDF step:

```
ReceiptBucketProof {
    checkpoint_epoch: u64,
    checkpoint_value: Hash,       // V_e
    bucket_offset: u64,           // Steps from checkpoint
    bucket_proof: Vec<Hash>,      // Chain linking bucket to checkpoint
}
```

**Verification**:
1. Verify checkpoint_value matches known V_e for that epoch
2. Apply bucket_offset iterations to checkpoint_value
3. Verify result matches claimed bucket value
4. Verify receipt was produced within that bucket

**Optimization for distant buckets**: If bucket > 10,000 steps from checkpoint, use mini-checkpoints (published every 10,000 steps by any node).

### 6.6 Receipt Structure

```
ReceiptHeader {
    reveal_root: Hash,
    peer_id: PeerId,
    epoch_id: u64,
    vdf_bucket: u64,
    chunk_index: u8,
    pow_checkpoints_hash: Hash,
    bucket_proof_hash: Hash,
    signature: Signature,
}

Receipt {
    header: ReceiptHeader,
    chunk_data: Vec<u8>,
    chunk_merkle_proof: MerkleProof,
    pow_checkpoints: [Hash; 5],
    bucket_proof: ReceiptBucketProof,
    first_seen_vdf_step: u64,     // When node first saw reveal
}
```

### 6.7 Receipt Eligibility Window

Receipts valid only if produced within W VDF steps of first observation:

```
valid iff receipt_vdf_step - first_seen_vdf_step <= W
    AND first_seen_vdf_step >= reveal_target_epoch_start
    AND first_seen_vdf_step <= reveal_target_epoch_end
```

W calibrated to ~50ms of VDF progress.

**Anti-gaming**:
- Late first_seen_vdf_step delays receipt, reducing reward share
- Early first_seen_vdf_step (> 2W before any peer's first receipt) flagged as suspicious
- Sustained suspicious claims → eligibility revocation

### 6.8 Inclusion Threshold

A reveal is includable when:
1. Receipts from ≥16 unique chunk indices exist (reconstructable)
2. Combined PoW weight exceeds minimum threshold
3. Receipts originate from ≥3 distinct gossip neighborhoods

### 6.9 Receipt Propagation Protocol

1. Producer broadcasts receipt header to ALL connected peers within 1 VDF step
2. Each peer records (reveal_root, peer_id, first_header_received_step, received_from_peer)
3. Withholding detection via timing inconsistencies
4. Full receipt retrieved on demand

Path diversity requirement: Receipt headers must arrive via ≥3 distinct first-hop peers.

---

## 7. Identity and Sybil Resistance

### 7.1 Identity Structure

```
PeerIdentity {
    public_key: MlDsaPublicKey,
    nonce: u64,
    identity_epoch: u64,
}
```

Valid if:
```
SHA3-256(public_key || nonce || identity_salt(identity_epoch)) < difficulty_target
```

### 7.2 Identity PoW

One-time computation per identity epoch (~30 days):

```
Compute time: 10 seconds to 1 minute on normal hardware
```

### 7.3 Identity Salt Derivation

**Normal operation**:
```
identity_salt(T) = global_state_root(last_finalized_before_epoch_T)
```

**Timeout mode**:
```
identity_salt(T) = SHA3-256(
    "identity_timeout" ||
    last_global_state_root ||
    soft_state_root_at_timeout ||
    cumulative_vdf_steps_at_timeout ||
    merkle_root(receipt_roots_last_10_epochs) ||
    timeout_epoch_number
)
```

If partition recovery occurred, both partition soft roots are included.

### 7.4 Identity Epoch Transitions

```
Identity epoch T = floor(cumulative_vdf_steps / steps_per_identity_epoch)
```

**Ramp-in**: New identity eligible at epoch T+1 start + H hours of VDF steps
```
H = SHA3-256(public_key) mod 12
```

**Overlap**: Old identities from epoch T valid until T+1 start + 24 hours of VDF steps

### 7.5 Peer Eligibility

For transaction epoch e, eligible peers are those where:
1. Identity announcement seen in last 100 transaction epochs
2. Identity epoch is current or in overlap
3. Identity announcement has ≥10 relays from other eligible peers
4. Receipts from multiple distinct gossip neighborhoods

### 7.6 Bootstrap

Genesis specifies 5-10 bootstrap peer identities with:
- Automatic eligibility for epochs 0-10
- Can relay announcements for new peers
- Must meet normal eligibility after epoch 10
- Must self-destruct transaction in epoch 9

**Accelerated eligibility**:
- Epochs 0-5: 5 relays required
- Epochs 6-10: 7 relays required
- After epoch 10: 10 relays required

---

## 8. Finality Model

### 8.1 Two-Stage Finality

| Stage | Timing | Guarantee |
|-------|--------|-----------|
| Regional confirmation | ~12 seconds | Binding within connectivity neighborhood |
| Global finality | ~40 seconds (normal) | All honest nodes agree |

### 8.2 Regional Confirmation

Occurs at pool freeze when:
- VDF advances past epoch boundary
- Receipts meet inclusion threshold
- Reveals meet reconstruction threshold

Regional confirmation is local optimism. Can be reverted if:
- Sustained partition occurs
- Your region loses work-weighted tiebreak

### 8.3 Global Finality

Achieved when:
1. Reconciliation completes with all nodes agreeing on reveal set
2. No conflicting certificates with higher receipt weight
3. Challenge period expires without valid fraud proof

### 8.4 Reconciliation

IBLT-based set reconciliation:

1. Each node publishes state root + reveal set commitment
2. If roots differ, exchange IBLT sketch
3. IBLT identifies missing reveal hashes
4. Request only missing items
5. Receipts often contain enough chunks for reconstruction

### 8.5 Partition Handling

Under sustained partition:

1. Both regions regionally-confirm different states
2. IBLT identifies differences at reconciliation
3. Work-weighted attestation determines winner

```
weight = sum(valid_receipt_pow_count) for all receipts in epoch
```

Higher weight partition wins. Losing partition re-executes against winning base.

### 8.6 Global Finality Timeout

If global finality doesn't occur within 30 epochs (~5 minutes):

1. Network enters recovery mode
2. Use last known globally-finalized state + accumulated regional states
3. Identity salt uses timeout entropy sources
4. Epoch randomness uses timeout mode derivation
5. Identity PoW difficulty scales with time since last global finality

**Timeout escalation**:
| Timeouts in 100 epochs | Duration |
|------------------------|----------|
| 1st | 5 minutes |
| 2nd | 10 minutes |
| 3rd | 20 minutes |
| 4th+ | 40 minutes (cap) |

**Timeout attribution**: Timeout only triggers when partitions are roughly balanced (20-80% split). If one partition has >80% weight, it continues without delay.

**Economic cost**: Each timeout burns 10% of pending reveal fee escrows.

### 8.7 Epoch Certificate

The canonical ledger object:

```
EpochCertificate {
    epoch: u64,
    vdf_checkpoint: Hash,
    vdf_stark_proof: StarkProof,
    regional_state_root: Hash,
    reveal_set_root: Hash,
    receipt_set_root: Hash,
    execution_trace_root: Hash,
    previous_certificate_hash: Hash,
    global_finality_attestation: FinalityAttestation,
}

FinalityAttestation {
    reconciliation_complete: bool,
    winning_partition: Option<PartitionId>,
    total_receipt_weight: u64,
}
```

Epoch certificates form a hash chain. This is the ledger.

---

## 9. Network Protocol

### 9.1 Gossip Architecture

Full mesh within regions. Cross-region sync when possible.

**Neighborhood definition**:
```
neighborhood_id = SHA3-256(sorted_top_10_connections_by_uptime)
```

### 9.2 Message Types

| Type | Size | Priority |
|------|------|----------|
| Commit | ~500 bytes | High |
| Reveal | Variable | High |
| ReceiptHeader | ~500 bytes | Critical |
| ReceiptFull | Variable | On-demand |
| IdentityAnnouncement | ~200 bytes | Medium |
| FraudProof | Variable | Critical |
| IBLTSketch | ~10KB | High |

### 9.3 Peer Discovery

1. Bootstrap nodes hardcoded in genesis
2. New peers announce identity with PoW proof
3. Announcements propagate via gossip
4. Accept peer if:
   - Identity PoW valid for current/overlap epoch
   - Not already known
   - Connection rate limit not exceeded
   - Announcement has ≥10 relays

### 9.4 Rate Limits

- Max 10 new peers per existing peer per transaction epoch
- Max 10 receipts per peer per VDF bucket
- Prioritize by fee/instruction ratio

### 9.5 Eviction

- Not seen for 100 transaction epochs → pruned
- Sustained suspicious receipt timing → weight penalty
- No reputation beyond current epoch work

---

## 10. Economic Model

### 10.1 Fee Structure

| Fee | When Paid | To Whom |
|-----|-----------|---------|
| Minimum inclusion fee | On commit | Burned or receipt signers |
| Execution fee | On execution | Relayer (fee_recipient) |
| Receipt reward | On inclusion | Receipt signers proportionally |
| Declared set fee | On commit | Protocol |
| Instruction fee | On commit | Protocol |

### 10.2 Fee Modes

**PayOnInclude**: Fee paid if reveal becomes includable (receipts meet threshold). Relayers prefer this to avoid griefing.

**PayOnExecute**: Fee paid only if expectations pass and transaction executes. Higher risk for relayer.

### 10.3 Receipt Rewards

```
reward_per_receipt = receipt_reward_pool * (peer_pow_weight / total_pow_weight)
```

Weight = count of valid receipts with valid sequential PoW.

**Economic equilibrium**: Reward per receipt must exceed compute cost of sequential PoW. Self-regulating.

### 10.4 Relayer Competition

Competition is for latency:
- Better connected → see reveals first
- Lower ping → produce receipts first
- More receipts → more rewards

No staking. No token lockup. Pure infrastructure competition.

### 10.5 Congestion

When arrival exceeds capacity:
1. Drop rates increase
2. Backpressure signals propagate
3. Relayers see drop rates, adjust pricing
4. Sustained drops → network adapts (more positions/slot)

Drops are safe. Retry costs minimum fee only.

---

## 11. Light Clients

### 11.1 Optimistic Verification

Light clients accept state roots optimistically with fraud proof challenge period.

### 11.2 Fraud Proof Structure

```
FraudProof {
    transaction: Transaction,
    expectations: Vec<Expectation>,
    base_state: StateProof,
    execution_trace: ExecutionTrace,
}
```

Challenge period: 100 transaction epochs (~1000 seconds)

### 11.3 VDF Verification

STARK proofs verify VDF chain without computing it:

```
StarkProof {
    start_value: Hash,
    end_value: Hash,
    step_count: u64,
    proof: Vec<u8>,
}
```

Properties:
- Proof size: O(polylog N)
- Verification time: O(polylog N)
- No trusted setup (Fiat-Shamir)
- Post-quantum secure

### 11.4 Fast Sync

New node joins:
1. Download checkpoint: epoch E state root + VDF_step(E) + STARK proof chain
2. Verify STARK proofs (O(polylog N) per epoch)
3. Verify state commitments against roots
4. Start computing VDF from checkpoint
5. Catch up to network

No trust in checkpoint provider. Wrong checkpoint → invalid STARK.

### 11.5 Inclusion Verification

Light client verification:
1. Obtain receipt headers
2. Verify chunk coverage ≥ threshold
3. Retrieve full receipts, verify PoW and bucket binding
4. Reconstruct reveal if needed

Full verification without trusting anyone.

---

## 12. Adversary Model

### 12.1 Network Model

- Asynchronous with eventual delivery
- No synchrony assumption
- Honest nodes eventually gossip with each other (no timing bound)
- Partitions can occur (duration unbounded but economically costly)

### 12.2 Adversary Capabilities

- Control up to f fraction of identities (no threshold assumed, cost scales with f)
- Create partitions by controlling network routing
- Delay message delivery arbitrarily within partitions
- **Cannot**: Break cryptographic primitives (SHA3, ML-DSA, AES-GCM)
- **Cannot**: Forge VDF outputs (sequential work is sequential)
- **Cannot**: Predict future globally-finalized state roots

### 12.3 Adversary Limitations

| Attack | Why Impossible |
|--------|----------------|
| Fake receipts | Must possess data and do sequential work |
| Fast PoW | Sequential iteration cannot be parallelized |
| Grind chunk assignment | Epoch randomness unpredictable |
| Precompute identity PoW | Salt includes multiple entropy sources |
| Win tiebreak without work | Must dominate real-time receipt work |
| Fake VDF bucket claims | Bucket binding is verifiable |
| Front-run/MEV | Content encrypted until position locked |
| Replay | LM-OTS exhausted after one use |
| Forge transactions | Requires private key |
| Alter execution | VM enforces declared access |

### 12.4 Safety Guarantees

**Global finality safety**: Once globally final, state cannot be reverted without:
- Rewriting VDF history (cost: mass compute for months)
- Breaking hash functions

**Regional confirmation safety**: Can be reverted if:
- Partition occurs
- Your region loses work-weighted tiebreak

Probability of reversion depends on partition duration and relative work between partitions.

### 12.5 Liveness Guarantees

**Regional liveness**: Transactions confirm regionally within 12 seconds under normal gossip.

**Global liveness**:
- Normal conditions: ~40 seconds
- Under partition: Delayed until reconciliation
- Bounded by 5-minute timeout (escalating)

### 12.6 Explicit Tradeoff

The design chooses liveness over safety for regional confirmation. Users who need safety must wait for global finality.

**Partition duration guidance**:
| Duration | Recommendation |
|----------|---------------|
| < 1 minute | Regional confirmation safe for low-value |
| 1-5 minutes | Wait for global finality for medium-value |
| > 5 minutes | Timeout triggers, protocol recovery activates |

---

## 13. Constants and Parameters

### 13.1 Time Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| S (steps per slot) | ~100,000 | ~100ms on reference hardware |
| K (slots per epoch) | 100 | ~10 seconds per epoch |
| Identity epoch | ~2.6B steps | ~30 days |
| Receipt eligibility window W | ~50,000 steps | ~50ms |
| Global finality timeout | 30 epochs | ~5 minutes |
| Challenge period | 100 epochs | ~1000 seconds |

### 13.2 Threshold Parameters

| Parameter | Value |
|-----------|-------|
| Chunk count | 32 |
| Reconstruction threshold | 16 |
| Neighborhood diversity | 3 |
| Relay requirement (normal) | 10 |
| Relay requirement (bootstrap) | 5-7 |
| Max declared set size | 10,000 |
| Default instruction limit | 10,000,000 |

### 13.3 PoW Parameters

| Parameter | Value |
|-----------|-------|
| Receipt PoW iterations | 80,000 |
| Receipt PoW checkpoints | 5 (every 20,000) |
| Identity PoW time | 10-60 seconds |
| Max receipts per bucket | 10 |

### 13.4 Economic Parameters

| Parameter | Value |
|-----------|-------|
| Exact key declaration cost | 1 unit |
| Prefix declaration cost | 10 + prefix_length units |
| Namespace declaration cost | 100 units |
| Balance-only declaration cost | 1 unit |
| Timeout fee burn | 10% of escrows |

### 13.5 Eviction Parameters

| Parameter | Value |
|-----------|-------|
| Peer eviction threshold | 100 epochs unseen |
| Dormancy threshold | rent_balance = 0 |
| Pruning threshold | 1000 epochs dormant |
| Identity overlap | 24 hours of VDF steps |
| Identity ramp | 0-12 hours of VDF steps |

---

## Appendix A: Genesis Structure

```
Genesis {
    vdf_seed: Hash,
    network_id: u64,
    bootstrap_peers: Vec<PeerIdentity>,
    difficulty_target: Hash,
    vdf_calibration: VdfCalibration,
    initial_state_root: Hash,
}

VdfCalibration {
    reference_hardware: String,
    steps_per_slot: u64,
    slots_per_epoch: u64,
}
```

---

## Appendix B: Why Not...

**Why not PoW?** Mining for ordering is wasteful. Our PoW is purposeful (sybil resistance per action).

**Why not PoS?** Staking creates capital barriers and plutocracy. Our competition is infrastructure, not wealth.

**Why not BFT?** Voting rounds add latency and require ≥67% honesty. We need only one well-connected honest node.

**Why not DAG?** DAGs still need tips ordered. We have no tips. Position is deterministic.

**Why not sharding?** Shards need cross-shard coordination. Our parallelism is structural via declared sets.

---

## Appendix C: Security Properties Summary

| Property | Mechanism |
|----------|-----------|
| Ordering determinism | Hash-derived position |
| Privacy | Commit-reveal with encryption |
| Replay prevention | LM-OTS one-time signatures |
| Sybil resistance | Per-receipt sequential PoW + identity PoW |
| Data availability | Erasure-coded chunks in receipts |
| MEV prevention | Content hidden until position locked |
| Parallel execution | Declared access sets with conflict detection |
| State bounds | Rent + instruction limits + declared set costs |
| Light client security | Fraud proofs + STARK VDF verification |
| Quantum resistance | ML-DSA + SHA3 + STARKs throughout |

---

*Proof of Position v1.0*
*The first deterministic optimistic replicated state machine with receipt-attested availability, VDF-sequenced time, and convergence-bounded finalization.*
