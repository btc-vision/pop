Lets design a novel concept that nobody think is possible together shall we?

A fully deterministic chain with no blocks. No proof of work. No proof of stake. No voting. No leaders. No committees. No external time source.

Everyone will tell you its impossible. You need someone to order transactions. You need miners or validators. You need agreement. You need rounds of communication. You need an honest majority. You need synchronized clocks.

What if you needed none of that?

What if transactions ordered themselves?

This isnt a blockchain. Its not a DAG. Its not BFT. Its not Nakamoto consensus.

Its a deterministic optimistic replicated state machine with receipt-attested availability, VDF-sequenced time, and convergence-bounded finalization.

Call it Proof of Position.

Heres how it works.

Genesis contains VDF seed, network ID, bootstrap peers, difficulty target, VDF calibration parameters, and bootstrap peer identities.

No clock assumption. No NTP. No external time source. Time is computed, not observed.

Every node runs a sequential hash chain. VDF_step(0) equals hash of genesis seed. VDF_step(n) equals SHA3-256 of VDF_step(n-1). Strictly sequential. Cannot parallelize. Your current VDF step is your local clock.

SHA3-256 has no known quantum speedup beyond Grover. Hash-based sequential work is post-quantum by construction.

Hardware variance is bounded. SHA3 throughput varies maybe 2-3x across commodity hardware. Fast node computes ahead. Slow node lags behind. Both compute the same chain because SHA3 is deterministic.

ASIC advantage is bounded to single-threaded efficiency gains, estimated 2-5x, not parallelization gains. Sequential iteration cannot be farmed. A thousand cores cannot compute one chain faster than one core. This is acceptable for the security model. Memory-hard variant available if stronger ASIC resistance needed.

Time divides into slots. Slot s is active when node reaches VDF step s times S, where S is steps per slot calibrated to roughly 100ms on reference hardware. Each slot has millions of positions. Transactions land in their mathematically determined spots. Lower position executes first. No negotiation. No voting. No leader deciding.

Transaction epoch e spans VDF steps e times K times S to (e+1) times K times S minus 1, where K is slots per epoch. Duration roughly 10 seconds. Within an epoch, execution is speculative. Nodes execute whatever reveals they see. They know other nodes might see different reveals.

Every transaction contains its own position. Not assigned. Derived. Hash the transaction, mod by the number of positions. Thats where you execute. You know your position the moment you create the transaction. No one tells you. No one picks for you.

The order is the content. The content is the order.

But what about collisions?

Two-dimensional ordering. Position plus subposition. Position equals hash of commit header mod P. Subposition equals hash of commit header concatenated with 1, full 256-bit.

Sort lexicographically by position then subposition. Collisions in both dimensions become negligible.

Add retry nonce in commit header. Part of fee escrow so you cant spam. User changes retry nonce to get new position on retry. Starvation eliminated. Determinism preserved.

What about privacy?

Commit-reveal with deferred execution.

You dont broadcast your transaction in the clear. You encrypt your payload and send the commit plus decryption key to your relayer. Could be your own node. Could be trusted relayer.

Commit header includes fee recipient, max fee, fee mode, retry nonce, and max instructions. Fee mode is either pay-on-include or pay-on-execute.

Pay-on-include means paid if reveal becomes includable when receipt threshold met. Pay-on-execute means paid only if expectations pass and transaction executes.

Relayers demand pay-on-include to avoid griefing from intentionally failing expectations.

Non-refundable minimum inclusion fee on commit. Burns or funds receipt signers. Every attempt costs something. Drop is safe without drop being free.

Your relayer broadcasts the commit. Hash visible. Payload encrypted. Position calculated. Nobody knows what the transaction does.

Position locks at slot close. Your spot is sealed when you advance past that VDF step.

Commits are timeless. No epoch membership. They exist. They lock position via hash. They hide content via encryption.

Then your relayer broadcasts the reveal. Decryption key plus state expectations plus receipt reward pool.

Epoch membership comes from reveals. Reveals declare target VDF range. Commits just need to match reveal hash. Reveals embed commit header fields. Everything needed to compute position is in the reveal. Self-contained.

Reveals also declare read/write sets. Superset of possible accesses. Include receipt reward pool. LM-OTS signature binds reveal to VDF range.

What are state expectations?

When you simulate before committing, you know what should happen. What balances change. What storage slots get written. What output ranges.

Encode all of that into the reveal.

The reveal says execute me only if these conditions hold. Balance A between X and Y. Storage slot B equals Z. Output in this range. Otherwise drop me.

Every node evaluates locally. State satisfies expectations? Execute. Otherwise drop.

The transaction validates itself. Self-contained. Self-proving.

Cant transactions lie about expectations?

No. The VM enforces it.

Mandatory access tracking. Every read recorded. Every write recorded. Transaction touches undeclared state? Immediate drop.

WASM sandbox with access isolation. Declare what you touch as superset of possible accesses. VM proves you only touched subset of declared set. Undeclared access equals instant death.

DEX router declares may read/write pools A, B, C, D and oracle O. At runtime, router only touches pools A and C. Valid. Touching undeclared pool E is drop.

Transactions become provably pure functions. Inputs declared. Outputs declared. Execution sandboxed. VM proves completeness.

Math enforces honesty.

What about declared set costs?

Declared sets must be bounded and priced. Flat address-key pairs dont scale to real contract patterns. Structured declarations preserve parallelism.

Declaration types:

Exact key: specific storage slot at address plus key. Cost: 1 unit.

Prefix range: all keys starting with prefix at address. Cost: 10 units base plus 1 unit per byte of prefix. Shorter prefix means more coverage means more cost.

Contract namespace: entire contract storage at address. Cost: 100 units. Expensive to discourage overuse.

Balance only: only balance at address, not storage. Cost: 1 unit.

Conflict detection:

Exact vs exact: conflict if same address and key.

Exact vs prefix: conflict if key matches prefix.

Prefix vs prefix: conflict if prefixes overlap.

Namespace vs anything on same address: conflict.

Maximum declared set size: 10,000 declarations. Hard cap.

This incentivizes minimal declaration. Developers optimize declared sets same way they optimize gas. Over-declaration is self-punishing economically.

Per-contract storage isolation by default. Contracts have isolated storage namespaces. Contract A cannot read Contract B's storage directly. Must go through calls. Cross-contract calls: caller declares call target. Target's storage access is target's responsibility. This naturally limits declaration scope.

What about execution limits?

WASM instruction count limit per transaction.

Transactions declare max instructions in commit header. Fee scales with declared limit. Higher limit costs more.

During execution, VM meters instructions. If count exceeds declared limit, execution halts. Transaction drops. Expectations failed. Fee burns. No refund for unused instructions.

Default limit: 10 million instructions. Sufficient for most operations. Complex transactions declare higher and pay more.

Deterministic. Hardware-independent. WASM-native.

What about the account model?

Global state is map from address to account state.

Account state includes code hash, storage root, balance, nonce, and rent balance.

Contract deployment is transaction that writes new address derived deterministically, code blob plus code hash, and initializes storage.

What about state growth?

State rent per epoch.

Each account has rent balance. Epoch execution deducts rent proportional to storage size. Rent rate: R units per byte per epoch.

Account storage size: code size plus storage slot count times 32 bytes plus base overhead.

If rent balance reaches zero, account becomes dormant. Dormant accounts cannot be called or modified. Execution skips them.

Resurrection: transaction targeting dormant account must include resurrection fee covering all back-rent since dormancy plus buffer. Fee credited to rent balance. Account becomes active.

Pruning: dormant accounts not resurrected for 1000 epochs get pruned from active state. Archived to cold storage. Resurrection from archive requires Merkle proof of prior existence plus back-rent.

State growth bounded. Long-term storage has ongoing cost. Unused accounts eventually pruned.

What about replay attacks?

Someone holds your reveal. Waits. Broadcasts later when state matches.

LM-OTS prevents this.

When you create the commit, generate a one-time keypair. Lamport Merkle One Time Signature. Public key in commit. Private key to relayer.

Reveal includes target VDF range. Relayer signs reveal plus VDF range with the one-time key.

One key. One signature. One VDF range. Ever.

Someone signs different VDF range? Two signatures reveal the private key. Instant detection.

Timeout measured in VDF steps. Reveal doesnt collect enough receipts within K/2 slots worth of VDF steps? Expires. Commit dropped. Minimum fee burned. Nonce consumed. Resubmit.

Relayer cant steal. Nothing to steal. Non-custodial. Cant front-run. Position locked before reveal. Cant replay. LM-OTS exhausted. Cant force bad execution. Expectations validate.

Relayers can only fail to reveal. Failure means retry, not theft.

Nodes gossip continuously. Full mesh. Everyone talks to everyone. Commits propagate. Slots close as VDF advances. Positions lock. State updates. All without a single block ever being produced.

Theres no block producer because theres no block.

Theres no "consensus" because theres nothing to agree on. The math already decided. Every node runs the same computation on the same inputs and gets the same output. Verification replaces agreement.

What about latency?

This is where it gets interesting. How do you coordinate between China and North America with 200ms ocean latency?

You dont coordinate. Thats the point.

Each region runs its own cluster. Nodes within a region mesh tightly. Cross-region sync happens when it happens. Doesnt matter. The ordering is deterministic.

If China sees transactions A and B, they compute positions from hashes. If NA sees transactions A and B, they compute the same positions from the same hashes. They dont need to talk to each other to agree. The answer is the same because math is the same everywhere.

Regional clusters execute independently. State converges automatically. Not because they coordinated. Because they computed.

A node in Tokyo and a node in New York can have different VDF progress. Both receive the same transactions eventually. Both compute identical positions. Both execute identical state. The VDF gap between them is irrelevant to correctness.

But what about late information?

Different regions temporarily see different reveals. Tokyo sees A, B, C. Frankfurt sees A, B, D. They execute different subsets. Different speculative state. Now what?

Epoch-based canonicalization with availability attestations.

At epoch boundary, canonicalization happens. Inclusion based on receipts.

What is a receipt?

A receipt is proof of work plus proof of data possession plus data availability contribution. Three functions in one primitive.

Reveals are erasure-coded into chunks. 32 chunks, 16 threshold for reconstruction using Reed-Solomon encoding. Each chunk has Merkle proof against reveal root.

When a node receives a reveal, it computes its assigned chunk index. Chunk assignment includes epoch randomness to prevent grinding attacks.

Chunk index equals hash of reveal root concatenated with peer ID concatenated with epoch randomness, mod 32.

Epoch randomness derivation has two modes depending on global finality status.

Under normal operation when global finality is current, epoch randomness equals hash of "chunks" concatenated with global state root of epoch minus 1.

Under global finality timeout when finality is delayed beyond threshold, epoch randomness equals hash of "chunks_timeout" concatenated with last available global state root concatenated with soft state root at previous epoch boundary concatenated with epoch number.

Soft state root at epoch boundary is fixed and deterministic within each partition. Under partition, different partitions may have different epoch randomness, resulting in different chunk assignments. Reconciliation picks winning partition and losers re-execute with winner's epoch randomness.

This maintains unpredictability even during timeout. Attacker cannot predict soft state root of previous epoch at reveal construction time. Multiple entropy sources prevent grinding.

To produce a valid receipt, the node must include its assigned chunk plus Merkle proof plus sequential proof of work plus VDF bucket binding.

What is VDF bucket binding?

VDF bucket claims must be verifiable. Without verification, adversaries can manufacture false timing narratives.

Every epoch has a canonical VDF checkpoint: V_e equals VDF_step at epoch boundary.

Receipts must reference the nearest checkpoint and prove their bucket position relative to it.

Receipt structure includes checkpoint epoch, checkpoint value V_e, bucket offset as number of VDF steps from checkpoint, and bucket proof as chained hash proof linking bucket to checkpoint.

Bucket proof verification: if bucket is 500 steps after checkpoint, proof is 500 sequential hashes. Verifier checks that checkpoint value matches known V_e for that epoch, that applying bucket offset iterations to checkpoint value yields claimed bucket value, and that receipt was produced within that bucket.

For buckets close to checkpoint within 1000 steps, proof is small. For buckets far from checkpoint, proof grows but is still O(steps) hashes.

Optimization for distant buckets: if bucket is more than 10,000 steps from nearest checkpoint, receipt can reference an intermediate mini-checkpoint. Mini-checkpoints published every 10,000 steps by any node, containing step number, VDF value, previous checkpoint reference, and signature. Multiple nodes publishing same mini-checkpoint provides redundancy. Verifier checks mini-checkpoint chain back to epoch checkpoint.

This makes VDF bucket claims verifiable without requiring STARKs per receipt.

What is the sequential PoW?

The sequential PoW is 80,000 SHA3-256 iterations tied to the specific reveal and peer.

Start with hash of reveal root concatenated with peer ID concatenated with nonce. Iterate SHA3-256 80,000 times. Checkpoints at iterations 0, 20000, 40000, 60000, 80000 for efficient verification.

Calibrated to 10ms on 2021 desktop CPU. Intel Core i5-11400 or AMD Ryzen 5 5600X as reference hardware. Desktop hardware is the target for full participation.

Hardware scaling: 2021 desktop at 10ms, 2024 desktop at 8ms, 2021 server at 7ms, 2024 server at 5ms, high-end laptop at 12ms, low-end laptop at 20ms, mobile high-end at 33ms, mobile low-end at 67ms.

Server operators have modest advantage, not overwhelming. Sequential work has no parallelization benefit. Throwing more cores doesnt help.

Cannot precompute because reveal root is unpredictable. Cannot reuse because peer ID is baked in. Must do fresh work per reveal per identity.

Why sequential PoW?

Sybil with 1000 identities wants to receipt a reveal. Must compute 1000 sequential PoWs. Each takes 10ms. Total: 10 seconds.

Honest node with 1 identity computes 1 PoW in 10ms.

Sybil cost scales linearly with identity count. 1000 identities equals 1000x compute for same coverage. No parallelization benefit because each identity needs its own sequential chain.

Why include chunk data?

Cant fake receipts for reveals you dont have. Must possess the data to produce your assigned chunk.

Chunk assignment is deterministic from identity plus epoch randomness. Cant choose easy chunk. Cant avoid having the data.

Receipts collectively contain all chunks. If 32 peers receipt a reveal with distinct chunk assignments, the full reveal is reconstructable from receipts alone.

Receipts ARE the data availability layer. When you receipt, you simultaneously attest you saw it, prove you have it, distribute a piece of it, and prove work to resist sybil.

No separate data propagation. Receipt propagation IS data propagation.

How does receipt gossip work?

Receipts are large due to chunk data. Full gossip is expensive.

Optimization: gossip receipt headers, retrieve full receipts on demand.

Receipt header: reveal Merkle root, peer ID, epoch ID, VDF bucket, chunk index, PoW checkpoints hash, bucket proof hash, signature. Approximately 500 bytes.

Full receipt retrieved when reconstruction needed or for verification. Headers signal availability. Full data on demand.

Most nodes already have reveal from direct propagation. Chunks only needed for late-arriving nodes or partition recovery.

What about fake receipts?

Old problem: malicious node receipts reveal it plans to withhold. Inflates confidence for doomed transaction.

New reality: your receipt contains your chunk. If you receipted, you contributed your chunk to the network. Others can reconstruct from chunks. Withholding after receipting is meaningless. The data is already out.

Detection unnecessary. Attack impossible. Cant fake having data you dont have. Cant withhold data your receipt already distributed.

Self-enforcing. No reputation system needed for fake receipt detection.

What about sybil resistance?

Per-receipt sequential PoW provides fine-grained sybil cost. But still need coarse identity limiting.

One-time identity proof of work with periodic refresh and unpredictable salt.

Identity epoch T derived from VDF progress. T equals floor of cumulative VDF steps since genesis divided by steps per identity epoch, calibrated to roughly 30 days.

When you create a peer identity, you compute a hash. Public key concatenated with nonce concatenated with identity salt. Keep trying nonces until result is below difficulty target.

Peer identity is ML-DSA public key plus nonce plus identity epoch T. Valid if hash of id concatenated with public key concatenated with nonce concatenated with salt T is below target.

This takes 10 seconds to 1 minute on normal hardware. You do it once per identity epoch. Identity epochs rotate roughly monthly.

Salt is unpredictable until late. Identity epoch salt derives from previous globally-finalized state root under normal operation.

Under global finality timeout, identity salt derives from hash of "identity_timeout" concatenated with last global state root concatenated with soft state root at timeout concatenated with cumulative VDF steps at timeout concatenated with Merkle root of all receipt roots from last 10 epochs concatenated with timeout epoch number. If partition recovery occurred, both partition soft roots post-reconciliation are included.

Multiple entropy sources prevent precomputation even when timeout is predictable. Attacker sustaining partition cannot predict soft state root or receipt roots they dont control.

Nobody can precompute until global finality provides the root or timeout resolves. Precompute burst attacks eliminated.

Identity ramp is deterministic. New identity becomes eligible at identity epoch T+1 start plus H hours worth of VDF steps, where H equals hash of identity public key mod 12. Each new identity gets delay between 0 and 12 hours based on its public key. No cliff. Eligibility transitions spread across 12 hours of VDF progress.

Old identities from epoch T remain valid until T+1 start plus 24 hours of VDF steps. Full overlap. Verifiable. Deterministic. No ambiguity.

What about bootstrap?

Genesis epoch has special rules.

Genesis specifies 5 to 10 bootstrap peer identities. Bootstrap identities have automatic eligibility for epochs 0 through 10. Bootstrap identities can relay announcements for new peers. After epoch 10, bootstrap identities must meet normal eligibility like everyone else.

Normal eligibility requires 10 relays from eligible peers. By epoch 10, enough non-bootstrap peers have accumulated through bootstrap relay. Trust diminishes as network grows.

Who counts as an eligible peer?

Peer eligibility is deterministic per transaction epoch.

Eligible peers for epoch e are peers whose identity announcement was seen in the last 100 transaction epochs AND whose identity epoch is current or in overlap AND whose identity announcement has at least 10 relays from other eligible peers.

Identity announcements are themselves availability-attested. New peers must have their announcement relayed by 10 existing peers before their receipts count. Sybil peers cant instantly become eligible.

Additional requirement for regional confirmation: receipts must come from peers in multiple distinct gossip neighborhoods. Neighborhood determined by hash of peer connections. This raises the bar for eclipse attacks. Attacker must eclipse multiple neighborhoods simultaneously.

What determines weight?

No age weighting. No reputation multiplier. Just work.

Weight equals count of valid receipts with valid sequential PoW in current epoch.

You get weight proportional to how much you contribute. More receipts with valid PoW equals more weight. Simple.

Sybil with 1000 identities doing minimal receipts has low total weight. Sybil doing maximum receipts across all identities pays 1000x compute cost. Either way, weight proportional to actual work performed.

No incumbency advantage. Fresh identity with fast hardware competes equally with old identity. No history to farm. Just: did you do the work this epoch?

What gates inclusion?

Receipts as confidence signal.

A reveal is includable if receipts exist from peers whose chunks collectively meet reconstruction threshold and whose combined PoW weight exceeds minimum.

16 unique chunks equals reconstructable. Apps can require higher coverage for more confidence.

External systems choose their threshold. CEX waits for high coverage before crediting deposit. Bridge waits for global finality before releasing funds on destination chain. Payment processor waits for global finality before settling fiat. On-chain contracts execute deterministically at their position without waiting.

Protocol provides data. External systems make risk decisions. Same as Bitcoin confirmations.

What if chunk coverage is insufficient?

If fewer than 16 unique chunk indices exist in receipt pool, fallback activates.

Fallback sequence: attempt reconstruction from available chunks, if insufficient initiate explicit data request for missing chunk indices, data request specifies reveal root plus needed chunk indices, peers with those chunks respond, if still insufficient after timeout reveal considered unavailable, unavailable reveal not included in canonical set, commit dropped and minimum fee burned and user retries.

This is rare. Requires small peer set or network issues. Epoch randomness in chunk assignment prevents intentional concentration.

But why would anyone sign receipts?

Receipts are paid work.

Each reveal includes a receipt reward pool. Reward distributed proportionally to all valid receipts weighted by sequential PoW.

Better connected nodes see more reveals, produce more receipts, earn more rewards. Latency advantage for infrastructure, not for extraction.

Incentives aligned. Receipts profitable. Rational actors receipt and propagate.

Economic equilibrium: reward per receipt must exceed compute cost of sequential PoW. As more peers receipt, reward per peer decreases. Equilibrium where marginal receipter earns exactly their compute cost. Self-regulating.

Sybil adding identities: each identity costs compute, earns share of reward. If sybil count is large, each identity earns less than compute cost. Unprofitable. Cant dominate without paying proportional cost.

What about receipt spam and grief attacks?

Attacker could spam reveals with large reward pools that will fail expectations, wasting honest node compute on PoW.

Mitigations: cap reveals per peer per epoch so attacker needs many identities to spam and each identity costs monthly PoW, prioritize by fee/instruction ratio so nodes receipt high-value reveals first, expectation validation sampling so node does lightweight expectation check against current soft state before committing PoW and skips if obviously failing, minimum receipt threshold before PoW so node waits until reveal has K receipts from other peers before computing own PoW and skips if reveal seems unpopular, burn minimum fee proportional to receipt reward pool so larger reward pool equals larger burn and grief attack cost scales with impact.

Combination makes grief attack expensive and bounded.

What about receipt compute budget?

VDF bucket duration: 100ms of VDF progress. PoW per receipt: 10ms on reference hardware. Max receipts per bucket at full compute: 10.

Desktop node can receipt 10 reveals per 100ms bucket while keeping up with VDF. Server node can do 15-20. Mobile does 1-3.

Cap receipts per peer per bucket at 10. Prioritize by fee. Natural bound on compute. Latency advantage is which 10 reveals do I choose to receipt, not can I receipt everything.

What about peer discovery?

Must be equally deterministic.

Bootstrap nodes hardcoded in genesis. New peers announce identity with PoW proof for current identity epoch. Announcements propagate via gossip.

Accept peer if identity PoW valid for current or overlap identity epoch, peer not already known, connection rate limit not exceeded, and announcement has at least 10 relays from eligible peers.

Rate limit: max 10 new peers per existing peer per transaction epoch. Organic growth bounded.

Peer eviction: not seen for 100 transaction epochs means pruned. No reputation to track. Just: are you active and doing valid work?

Peer set deterministic given same announcements. Announcements propagate. Sets converge.

Why do expectations reference regionally-confirmed state?

Critical design choice. Separate execution base from finalization base.

Regional execution base is last regionally-confirmed epoch root. Fast, optimistic.

Global execution base is last globally-finalized epoch root. Slow, safe.

Transactions execute against regional base. Transactions considered final only when base epoch becomes globally final.

If partition delays global finality, chain doesnt halt. It accumulates regional results whose finality is deferred. Throughput continues. Finality catches up.

No pipeline stall. No halting the world waiting for finality.

What about finality?

Two stages. Regional confirmation and global finality.

Regional confirmation at pool freeze. Roughly 12 seconds of VDF progress. VDF-bounded. Fast UX. Binding within your connectivity neighborhood. Can be reverted if your partition loses tiebreak.

Global finality is convergence-based. Not VDF-bounded. Only when reconciliation converges. Confirms regional path taken. Typically 40 seconds of VDF progress under normal conditions.

Regional confirmation is a local optimism guarantee that can be reverted under prolonged partition where your region loses the work-weighted tiebreak. Global finality is the only safety guarantee. Users and applications must treat regional confirmation as probabilistic, similar to Bitcoin's 1-confirmation, and wait for global finality for high-value irreversible actions.

What if global finality is delayed?

Global finality timeout prevents indefinite delay.

If global finality doesnt occur within 30 epochs of VDF progress (roughly 5 minutes), network enters recovery mode: use last known globally-finalized state plus accumulated regional states, identity salt for next identity epoch uses timeout entropy sources, epoch randomness for chunk assignment uses timeout mode derivation, triggers protocol-level alert, identity PoW difficulty scales with time since last global finality.

This bounds delay. Attacker can delay 5 minutes maximum. Precomputation advantage for identity PoW is limited by multiple entropy sources including soft state and receipt roots attacker cannot fully control.

Why convergence-based?

Because you cannot get permanent bounded-time global finality under arbitrary partitions without some rule deciding between incompatible histories.

Our rule: wait for convergence. If convergence fails beyond threshold, work-weighted attestation wins as tiebreaker.

Not voting on order. Tiebreaker on inclusion only under sustained partition.

What is the relationship between regional and global finality?

Regional confirmation is binding within your connectivity neighborhood under normal conditions. Global finality confirms regional path. Global finality cannot produce different state root than regional confirmation under normal conditions.

What global finality means: all honest nodes have converged on the same regionally-confirmed state. State root now globally agreed.

Before global finality, your region might have regionally-confirmed state differing from another region. After global finality, all regions agree.

How does reconciliation work?

IBLT-based set reconciliation.

Each node publishes state root and reveal set commitment as Merkle root of reveal hashes included.

If roots differ, nodes exchange IBLT sketch. Invertible Bloom Lookup Table. Compact diff structure identifies missing reveal hashes efficiently.

Then request only missing items by hash. But receipts already contain chunks. Reconstruction from receipts often sufficient without explicit requests.

Cap requests per peer per second. Require peers to prove eligibility. Require requests keyed to specific missing hashes. No send me everything.

Efficient. Scalable. Attack-resistant.

What about partitions?

Under sustained partition, both regions regionally-confirm different states. During reconciliation, IBLT identifies differences. Attestation tiebreaker determines which regional path becomes canonical.

Tiebreaker is work-weighted. Weight equals total valid receipt PoWs submitted in current epoch per partition.

Partition A has peers with combined 50,000 receipt PoWs. Partition B has peers with combined 30,000 receipt PoWs. Partition A wins.

No age. No history. Just: who did more work this epoch?

Attacker needs to dominate work in real-time. Cant accumulate over months. Must outcompute honest network during the partition.

The losing partition re-executes epochs against winning regional base. Users in losing partition see regional confirmations invalidated. Transactions re-execute against winning base. Expectations that no longer pass result in drops and refunds.

This is the only case where regional confirmation can be invalidated: sustained partition where your region loses tiebreaker. Normal operation: regional equals global with delay.

What is the Epoch Certificate?

Even without blocks, you need a canonical ledger object. The Epoch Certificate is that object.

Epoch Certificate structure for epoch e contains: epoch number e, VDF checkpoint V_e, VDF checkpoint proof as STARK proof from V_{e-1} to V_e, regional state root, reveal set root as Merkle root of included reveal hashes, receipt set root as Merkle root of valid receipts, execution trace root as Merkle root of execution trace for fraud proofs, previous certificate hash as H of EpochCertificate_{e-1}, and global finality attestation containing reconciliation complete flag and winning partition if tiebreak occurred and total receipt weight.

Epoch certificates form a hash chain via previous certificate hash. This is the ledger. Not blocks. No block producer. But a canonical append-only structure that nodes can reference and verify.

Global finality rule: an epoch certificate achieves global finality when reconciliation completes with all nodes agreeing on reveal set, no conflicting certificates exist with higher receipt weight, and challenge period expires without valid fraud proof. Global finality propagates: if epoch certificate e is globally final, all epoch certificates before e are globally final.

This is also why parallel execution works.

The reveal declares state dependencies. Which storage slots. Which balances. All explicit. All known before execution. All VM-enforced.

Traditional blockchains execute sequentially. You dont know what each transaction touches until you run it.

Here you know everything upfront. Reveal tells you. VM enforces. Transaction A touches address X keys 1 and 2. Transaction B touches address Y keys 3 and 4. No overlap in declared sets. Execute in parallel.

Parallel execution uses declared sets for dependency graph. Non-overlapping declared sets execute in parallel. Developers incentivized to declare minimal viable superset.

10,000 transactions in an epoch. Maybe 50 have overlapping declared sets. Execute 9,950 in parallel. Sequence the 50 conflicts by position-subposition order.

This is how you get 50,000+ TPS. Not faster sequential execution. Almost no sequential execution.

What about byzantine actors?

They dont matter.

99% of nodes could be malicious. Cant forge transactions without private keys. Cant change positions determined by hashes. Cant see encrypted content. Cant replay because one-time signatures. Cant lie about dependencies because VM enforces. Cant fake receipts because must have data and do work. Cant fake VDF bucket claims because bucket binding is verifiable. Cant grind chunk assignments because epoch randomness is unpredictable even under timeout. Cant use old identities because epoch-local validity with deterministic ramp. Cant become eligible without relay attestation. Cant precompute identities because salt includes multiple entropy sources. Cant win tiebreaker without real-time work dominance. Cant alter deterministic execution. Cant forge VDF outputs because SHA3 is deterministic.

One honest node verifies everything.

Not byzantine fault tolerant. Byzantine irrelevant.

No honest majority assumption. No 67% threshold. Math has no opinions.

What about light clients?

Light clients accept state roots optimistically. Challenge period allows fraud proofs.

Fraud proof structure: transaction T, declared expectations E, base state S, execution trace showing E fails against S.

Any full node can submit fraud proof. Light client or verifier re-executes T against S. If trace valid and shows expectations failed, state root rejected.

Challenge period: 100 transaction epochs. Approximately 1000 seconds of VDF progress. After challenge period with no valid fraud proof, state root accepted as final for light clients.

For inclusion verification: light client obtains receipt headers, verifies chunk coverage meets threshold, retrieves full receipts to verify sequential PoW and bucket binding, reconstructs reveal if needed. Full verification without trusting anyone.

What about VDF verification for light clients?

Full nodes compute the VDF chain themselves. They dont need proofs. They computed it.

Light clients need to verify VDF progress without computing the entire chain.

STARK proofs solve this. STARKs are post-quantum. They rely on collision resistance of hash functions, not discrete log or factoring.

At each epoch boundary, any node can generate a STARK proof covering the VDF chain for that epoch. The proof attests: VDF_step(epoch_start) through VDF_step(epoch_end) was correctly computed as sequential SHA3-256 iterations.

STARK circuit structure: prover knows intermediate values h_0 through h_N where h_0 equals previous epoch end, h_{i+1} equals SHA3-256 of h_i, and h_N equals current epoch end.

Proof size: O(polylog N). Verification time: O(polylog N). Both sublinear in the sequential work.

No trusted setup. STARKs use Fiat-Shamir with public randomness. Transparent. Nothing to compromise.

Light clients verify epoch STARK proofs. Full nodes ignore them. Everyone computes the same chain. Proofs are optimization for resource-constrained verifiers.

What about fast sync?

New node joins. Doesnt want to compute VDF from genesis.

Download checkpoint: epoch E state root plus VDF_step(E) plus STARK proof chain from genesis.

Verify STARK proofs. O(polylog N) per epoch. Verify state commitments against roots. Start computing VDF from checkpoint. Catch up to network.

No trust in checkpoint provider. Proofs are self-validating. Wrong checkpoint means invalid STARK. Detectable. Rejectable.

What about the economic model?

Relayers charge fees. Receipt signers earn proportional rewards. Thats it.

Fee in the transaction. Proven. Verifiable. Relayer commits to relaying. You commit to paying. Both bound by reveal.

Receipt rewards from reveal fee escrow. Distributed proportionally to all valid receipts weighted by sequential PoW. Incentives aligned for participants who do the work.

Minimum inclusion fee prevents spam. Pay-on-include prevents griefing relayers. Instruction limits priced into fees. Declared set fees bound state access.

Competition is for latency.

You want fastest node. Closest node. Lowest ping. Better connected node sees more reveals first, produces more receipts first, earns more rewards.

Transaction needs to propagate and collect receipts before freeze. Fast relayer means more receipts. More receipts means reliable inclusion.

Pure latency market.

Relayers compete on geography. Network infrastructure. Connection quality. Gossip graph position.

Tokyo users pick Tokyo relayers. Frankfurt picks Frankfurt. New York picks New York. Each region optimizes locally.

No global auction. No bidding wars across planet. Local competition. Local fees. Local latency.

Fastest relayer wins. Not richest. Not most staked. Fastest and most connected.

This is Wall Street. Decentralized.

HFT firms spend billions on infrastructure. Colocated servers. Microwave towers. Private fiber. All for microseconds.

Closed game. Need millions to colocate. Retail never wins.

We opened it.

Anyone runs a relayer. Anyone competes on speed. No exchange to colocate with. No single point to be closest to. Network is everywhere.

Moat is legitimate infrastructure. Better servers. Better connections. Better geographic distribution.

Barrier to entry is low. Datacenter in Tokyo. One in Frankfurt. One in Virginia. Good networking. No permission. No staking minimum. No token lockup.

Wall Street infrastructure competition, but permissionless.

Users benefit.

On Wall Street, HFT extracts from slower participants. Speed is weapon against retail.

Here speed cant hurt you. Transaction encrypted. Position locked before reveal. Relayer speed benefits you, not exploits you.

Same competition. Same obsession. Different alignment.

Fastest relayer gets paid more by serving better, not extracting harder.

What about congestion?

Arrival exceeds capacity? Drops increase. Fine if predictable.

Backpressure signals propagate. Relayers see drop rates. Users retry or wait.

Sustained drops exceed threshold? Network adapts. More positions per slot. Longer slots. Self-healing.

Drops are safe. Retry costs minimum fee. Never total loss.

This is networking bound.

CPU doesnt matter much. Validation is parallel. Execution is parallel. VDF is the only sequential constraint and its calibrated to reference hardware. Bottleneck is network. How fast you receive. How fast you gossip. How fast you collect receipts.

Seastar handles this.

Share-nothing architecture. Each core handles own connections. No locks. No contention. Pure async IO.

Hundreds of thousands concurrent connections. Gossip to 200 peers continuously. Trivial. 10,000 commits per second. Trivial.

Framework disappears. Network is only constraint.

MEV? Impossible.

Front-running requires knowing content before positioning. Content reveals after positioning.

Sandwich attacks require positioning around target. Target content invisible during positioning.

Information needed to attack doesnt exist when attacks would happen.

Even if someone sees reveal early, expectations protect you. They front-run, price moves, your expected range fails, you drop. Lose nothing. Transaction refuses to execute in unexpected world.

MEV elimination isnt goal. Its side effect.

What about quantum resistance?

All signatures use ML-DSA. Module Lattice Digital Signature Algorithm. NIST post-quantum standard. FIPS 204.

Transaction signatures use ML-DSA. Receipt signatures use ML-DSA. Peer identity signatures use ML-DSA. LM-OTS for one-time reveal binding is hash-based and already quantum resistant.

VDF sequential work uses iterated SHA3-256. No known quantum speedup beyond Grover's square root for preimage, compensated by output length. Hash-based sequential work is post-quantum by construction.

Receipt sequential PoW uses iterated SHA3-256. Same post-quantum properties.

VDF verification uses STARK proofs. STARKs rely on collision resistance of hash functions. Post-quantum by construction. No lattice assumptions. No elliptic curves. No factoring.

The entire stack is post-quantum. No migration needed when quantum computers arrive. Already secure.

What is the formal adversary model?

Network model: asynchronous with eventual delivery, no synchrony assumption, honest nodes eventually gossip with each other with no timing bound, partitions can occur with duration unbounded but economically costly to sustain.

Adversary capabilities: can control up to f fraction of identities with no threshold assumed but cost scales linearly with f, can create partitions by controlling network routing, can delay message delivery arbitrarily within partitions, cannot break cryptographic primitives SHA3 and ML-DSA and AES-GCM, cannot forge VDF outputs because sequential work is sequential, cannot predict future globally-finalized state roots.

Adversary limitations: cannot create valid receipts without possessing reveal data, cannot produce receipt PoW faster than sequential iteration allows, cannot grind chunk assignments because epoch randomness unpredictable, cannot precompute identity PoW because salt includes multiple entropy sources, cannot win tiebreak without dominating real-time receipt work, cannot fake VDF bucket claims because bucket binding is verifiable.

Safety guarantees: global finality safety means once globally final state cannot be reverted without rewriting VDF history at cost of mass compute for months or breaking hash functions; regional confirmation safety means can be reverted if partition loses tiebreak with probability of reversion depending on partition duration and relative work between partitions.

Liveness guarantees: regional liveness means transactions confirm regionally within 12 seconds under normal gossip; global liveness means transactions achieve global finality within 40 seconds under normal conditions and under partition delayed until reconciliation bounded by 5-minute timeout.

Explicit tradeoff: the design chooses liveness over safety for regional confirmation. Users who need safety must wait for global finality. This is the honest tradeoff given physics constraints on global coordination.

Partition duration guidance: under 1 minute means regional confirmation safe for low-value, 1 to 5 minutes means wait for global finality for medium-value, over 5 minutes means timeout triggers and protocol recovery activates.

What we actually replaced.

Agreement on order replaced by math. Position-subposition derives from hash. No negotiation. No voting. No leader selection. Hash the commit header, compute position, sort lexicographically. Same input, same output, everywhere.

Agreement on inclusion replaced by availability attestations. Receipts contain chunks plus Merkle proofs plus sequential PoW plus verifiable bucket binding. Proves data possession. Proves work. Proves timing. Provides data availability. Verifiable. Deterministic given the receipt pool. Incentivized via proportional rewards.

Agreement on finality replaced by convergence. Regional confirmation is VDF-bounded and locally binding. Global finality waits for reconciliation convergence. Work-weighted attestation tiebreaker under sustained partition.

Agreement on time replaced by computation. Every node computes the same sequential hash chain. VDF_step(n) has exactly one value. Disagreement is impossible. Time is computed, not observed. No NTP. No GPS. No external dependency.

Nothing magical. No new cryptography. SHA3-256. ML-DSA. AES-GCM. LM-OTS. IBLT. STARK. Reed-Solomon erasure coding. Standard primitives, post-quantum ready. No new assumptions hidden. One explicit assumption stated clearly. No consensus eliminated by handwaving. "Consensus" eliminated by making it unnecessary.

The actual innovation.

Recognizing that ordering consensus exists because systems couldnt prove what transactions exist. If you can prove availability via receipts that contain data plus work plus verifiable timing, you dont need to vote on inclusion. If inclusion is deterministic, ordering is deterministic. If ordering is deterministic, execution is deterministic. If execution is deterministic, state is deterministic.

Recognizing that time "consensus" exists because systems relied on external clocks. If every node computes the same sequential hash chain, time becomes deterministic. VDF_step(n) is the same everywhere because SHA3 is deterministic. No clock sync needed. No NTP trust needed. Time is math.

Recognizing that sybil resistance can be per-action, not per-identity. Sequential PoW per receipt means sybil cost scales linearly with impact. No reputation to farm. No age to accumulate. Just: did you do the work for this specific receipt?

Recognizing that receipts can BE the data availability layer. Erasure-coded chunks in receipts with epoch-randomized assignment. Reconstruction from receipts. No separate DA protocol. Receipt propagation IS data propagation.

Recognizing that entropy sources must be layered for robustness. Normal operation uses globally-finalized state. Timeout mode adds soft state, VDF steps, receipt roots, and partition data. No single point of entropy failure.

Recognizing that finality claims must be honest. Regional confirmation is local optimism. Global finality is safety. Users must understand the difference.

The chain of dependencies collapses. VDF-sequenced time at the bottom. Receipts with chunks and PoW and bucket binding above it. Everything else follows mathematically.

Receipts are the foundation. Not blocks. Not votes. Not leaders. Just eligible peers publishing chunks plus Merkle proofs plus sequential PoW plus bucket proofs, incentivized by proportional rewards, weighted by work for tiebreaks. Thats enough. Everything else computes.

What this system actually is.

Not a blockchain. No chain of blocks.

Not a DAG. No directed acyclic graph.

Not BFT. No Byzantine fault tolerant voting.

Not Nakamoto consensus. No proof of work for ordering.

It is a deterministic optimistic replicated state machine with receipt-attested availability, VDF-sequenced time, and convergence-bounded finalization.

Deterministic: same inputs produce same outputs everywhere.

Optimistic: speculative execution before finalization.

Replicated: every node holds full state.

VDF-sequenced time: every node computes identical sequential hash chain as local clock.

Receipt-attested availability: inclusion proven by receipts containing erasure-coded chunks plus Merkle proofs plus sequential PoW plus verifiable VDF bucket binding with epoch-randomized chunk assignment.

Convergence-bounded finalization: regional confirmation VDF-bounded and locally binding, global finality convergence-based with work-weighted attestation tiebreaker.

Proof of Position.

One explicit assumption. Honest nodes exist and gossip with each other eventually. Weaker than any threshold count. Verifiable. Recoverable.

No clock sync assumption. Time is computed. VDF chain is deterministic. Every node computes the same values. Disagreement is impossible.

50,000+ TPS through parallel execution. Continuous gossip. Sub-second slots. Sub-second speculation. 12 second locally-binding regional confirmation with app-chosen confidence. Convergence-based global finality typically 40 seconds. Content private until execution. Parallelism structural via declared access sets with structured declarations. Latency market for relayer fees. Proportional rewards for receipt signers weighted by work. Identity PoW once per month with unpredictable salt from multiple entropy sources. Per-receipt sequential PoW calibrated to 10ms on 2021 desktop CPU. Receipts contain erasure-coded data chunks with epoch-randomized assignment and verifiable bucket binding. Epoch randomness robust under global finality timeout via layered entropy. Structured declared set costs bound state access. Instruction-metered execution. Rent-bounded state. Fraud-proof light clients. STARK-verified VDF for fast sync. Global finality timeout at 5 minutes prevents indefinite delay. Bootstrap peers enable network initialization. Epoch certificates provide canonical ledger structure. Formal adversary model with explicit guarantees. Quantum resistant from day one. Failure is drop not rekt.

Not a single vote cast. Not a single leader elected. Not a single block produced. Not a single ordering authority. Not a single transaction visible before position locks. Not a single trust assumption that drains wallets. Not a single replay possible. Not a single execution in unexpected state. Not a single unnecessary sequential execution. Not a single ongoing mining for ordering. Not a single token staked. Not a single ordering fork possible. Not a single quantum vulnerability. Not a single permanent catastrophic fork. Not a single external time source. Not a single fake receipt possible. Not a single reputation to farm. Not a single age advantage. Not a single chunk assignment grindable. Not a single entropy source that fails alone. Not a single VDF bucket claim unfalsifiable. Not a single finality claim dishonest.

Everyone said you need "consensus". Agreement. Authority. Coordination. Visibility. Trusted parties. Witnesses. Validators. Sequential execution. Staking. Mining. Capital. Honest majority. Synchronized clocks.

You dont.

You need determinism. Math. Transactions that know where they belong via two-dimensional position. Reveals that prove propagation through receipts containing chunks plus proofs plus work plus bucket binding. Epoch randomness that prevents chunk grinding with timeout-robust derivation. Expectations that validate execution. Structured declared access supersets that enable parallelism. Declared set costs that bound access. VM that enforces access tracking. Instruction metering that bounds compute. State rent that bounds storage. Pool freeze that seals inclusion. IBLT reconciliation that enables convergence. Per-receipt PoW that resists sybil linearly. Erasure-coded chunks that integrate DA. Verifiable bucket binding that proves timing. Deterministic identity ramp that prevents cliffs. Global finality timeout at 5 minutes that bounds delays. Layered entropy sources that remain unpredictable under adversarial conditions. Bootstrap peers that enable initialization. Epoch certificates that structure the ledger. Locally-binding regional confirmation that enables speed. App-chosen confidence thresholds that match risk tolerance. Convergence-based global finality that ensures correctness. Partition recovery that re-executes losers. Fraud proofs that enable light clients. VDF-sequenced time that replaces clocks. STARK proofs that enable fast sync. Formal adversary model that defines guarantees. One explicit assumption weaker than any alternative. Trust that degrades to drop not drain. Honest terminology that distinguishes regional from global. Post-quantum signatures throughout. Post-quantum time throughout. Post-quantum verification throughout. Post-quantum receipts throughout.

Proof of Position.

The first deterministic optimistic replicated state machine with receipt-attested availability, VDF-sequenced time, and convergence-bounded finalization.

Not because "consensus" is hidden. Because "consensus" is unnecessary.

Not because parallelism is optimized. Because parallelism is structural.

Not because MEV is mitigated. Because MEV is impossible.

Not because capital is staked. Because only latency matters.

Not because PoW is ongoing for ordering. Because per-receipt PoW is bounded and purposeful.

Not because receipts are charity. Because receipts are proportionally paid weighted by work.

Not because sybils are ignored. Because per-receipt work resists them linearly.

Not because fake receipts are detected. Because fake receipts are impossible.

Not because age matters. Because only current work matters.

Not because chunk assignments are predictable. Because epoch randomness prevents grinding.

Not because entropy fails under timeout. Because layered entropy sources maintain unpredictability.

Not because VDF buckets are trusted. Because bucket binding is verifiable.

Not because assumptions dont exist. Because one assumption is explicit and weaker than alternatives.

Not because regional confirmation is globally safe. Because regional confirmation is honestly local.

Not because global finality is instant. Because convergence is correct.

Not because global finality can stall forever. Because 5-minute timeout bounds delay.

Not because partitions cant happen. Because partitions resolve via work-weighted tiebreaker.

Not because state grows forever. Because rent bounds storage.

Not because declared sets are free. Because structured declared set costs bound access.

Not because light clients trust blindly. Because fraud proofs enable verification.

Not because data availability is separate. Because receipts ARE data availability.

Not because the ledger is undefined. Because epoch certificates structure it.

Not because adversary model is implicit. Because adversary model is formal.

Not because quantum is ignored. Because quantum is solved.

Not because clocks are synchronized. Because time is computed.

Not because bootstrap is magic. Because bootstrap peers are explicit.

Nothing magical. Nothing hidden. Just math, VDF-sequenced time, receipts with chunks and work and bucket binding, epoch-randomized chunk assignment with timeout-robust entropy, convergence-based finality, per-receipt sybil resistance, structured declared set costs, instruction metering, state rent, fraud proofs, STARK verification, 5-minute global finality timeout, epoch certificates, formal adversary model, bootstrap initialization, honest finality terminology, and post-quantum cryptography throughout.
