# EIP-8297 (PBT): implementation roadmap for an execution client

Milestones for implementing the Partitioned Binary Tree state commitment in an
execution client, **ordered by implementation dependency** — each milestone
needs the ones above it. This is meant to be usable by any client team, not a
record of one implementation's progress; ethrex's status is noted per milestone
as a reference point, and the "what will bite you" notes are the things we
learned the expensive way.

**Network transition strategy: OFFLINE CONVERSION.** Nodes convert their own
state out of band, verify it against a published root, import it, and
shadow-track forward to the activation block. In-protocol gradual conversion
(verkle's EIP-7748 shape) is not specified for EIP-8297 and is not being built —
see M6.

| # | Milestone | Depends on |
|---|---|---|
| M0 | Tree + embedding | — |
| M1 | State commitment in headers | M0 |
| M2 | Scheduled activation + shadow tracking | M1 |
| M3 | Persistence of the flat state | M1 |
| M4 | State acquisition for joining nodes (snap) | M3 |
| M5 | Proofs (`eth_getProof`) | M1; shares M4's proof machinery |
| M6 | Offline conversion + rehearsal | M2, M4 |
| M7 | Witness / stateless / proving | M1 (parallel from here) |
| M8 | Spec freeze + multi-client interop | cross-cutting |
| M9 | MPT retirement | M4, M5 |

---

## M0 — Tree and embedding

The compressed binary radix trie (BLAKE3, tagged node preimages, injective
bit-prefix encoding) and the state embedding: zone bytes, per-account header
stems, overflow storage and code zones, code chunking, basic-data packing.

**Pin conformance to generated vectors.** Generate test vectors from the EELS
reference implementation rather than hand-computing hashes, and record the spec
commit in the fixture. When the EIP moves, regenerate and let the tests fail at
exactly the points that changed.

**Write two implementations.** An insertion-based trie (the production shape)
and a rebuild-from-scratch reference ported directly from the spec, cross-checked
differentially on random workloads. Agreement also proves insertion-order
independence, which is otherwise easy to get subtly wrong.

**What will bite you:** balances must be < 2^128 (the basic-data field is 16
bytes). Code *contents* are committed as chunks, not just the code hash, so
whatever diff structure you feed the commitment must carry bytecode deployed in
the same block.

*ethrex: done — `crates/common/binary-trie`.*

---

## M1 — State commitment in headers

A flat state model (accounts, storage, code keyed by address rather than by
hash), root computation over it, and integration into genesis, block import, and
payload building.

**What will bite you:** a block header can name only **one** state root. Once it
carries the PBT root, it no longer addresses the MPT — so if you keep the MPT as
your lookup structure (you probably will at first), you need a side registry
mapping block hash → MPT root, and every consumer that starts from a header must
route through it. In ethrex that meant touching fork choice, `newPayload`,
`eth_syncing`, sync resume points, tracing, and the L2 committer. Budget for it;
it is larger than the commitment change itself.

Expect the first implementation of root computation to be a full rebuild per
block. That is the right call while the spec moves — it has almost no coupling
to embedding details — but it caps usable state size until M3.

*ethrex: done — `PbtState` + Seam A/B.*

---

## M2 — Scheduled activation and shadow tracking

An activation parameter in the chain config, plus maintaining the PBT state
before activation so the first active block can commit the **full** state
(carry-over), not an empty overlay.

**Activation must be a timestamp, not a block number.** Post-merge, block
numbers are unpredictable (slots can be missed) and every fork since has been
timestamp-scheduled. Follow the `verkle_time` precedent: a standalone field on
the chain config, joining fork-id computation, with no new fork enum variant —
the commitment scheme is orthogonal to EVM semantics and coupling them drags
wrong blob schedules and fork reporting along.

**Do not activate at genesis on any network that talks to standard tooling.**
Changing the commitment at genesis changes the genesis state root, hence the
genesis block hash, hence the chain's identity: the consensus layer holds a
generator-computed (MPT) genesis hash in its beacon state, and the fork id is a
checksum seeded by the genesis hash. A PBT genesis silently forks you off the
network before the first slot. Full explanation:
`docs/binary-trie-genesis-hash-problem.md`. Genesis activation is fine for
in-process tests, and for devnets only with a pre-merge TTD ladder.

**What will bite you:**
- Validate the 2^128 balance constraint at **startup** on any scheduled chain.
  Otherwise a bad genesis alloc passes silently and the chain halts at the
  activation block, where nothing can be done about it.
- Pre-activation, track the state but skip root computation — you need the
  extension, not the hash, and hashing every block is the expensive half.
- Naive shadow tracking clones the whole state per block: O(blocks × state).
  Fine for short devnets, untenable beyond that (see M3).
- Reorgs: key snapshots by block hash and have each block extend its *parent's*
  snapshot, so side branches build on the right ancestor.

*ethrex: done — `binaryTreeTime`, verified on a multi-node devnet including
restart catch-up across the boundary.*

---

## M3 — Persistence of the flat state

Persist the PBT state (and any lookup-root registry) rather than holding it in
memory.

**Why this is not a late optimization.** In-memory state is lost on restart, and
replay-from-genesis recovery stops working once the chain flushes past the point
where historical state is still addressable. More decisively, it is what makes
M4 worth having: a node that acquires state over the network and then loses it
on restart has gained nothing, since avoiding re-acquisition is the entire point
of state sync.

It is also the first wall a long-running devnet hits, so it converts a demo into
something you can leave running.

*ethrex: not started. The `pbt-migration-tool` repo has a persistent store with
incremental `apply_block` (~0.27 s for 5,000 accounts/block, ~6 GiB on disk for
mainnet state) — the obvious input rather than starting fresh.*

---

## M4 — State acquisition for joining nodes (snap sync)

Existing snap sync is structurally MPT-shaped (RLP nodes, hex-nibble paths,
per-account storage tries) and cannot serve a PBT chain. Until this lands, a
joining node has no option but full sync from genesis — so this is the milestone
that decides whether your network is one anybody can join.

It is also on the critical path to the transition (M6): it is the fallback for
operators whose offline conversion fails or runs late, and without it their only
recovery is full-syncing from genesis.

**Refuse the old snap mode explicitly** as soon as the commitment is scheduled.
Left unguarded, a snap-syncing node pivots on a state root that addresses no MPT
and fails in a way nobody can debug.

Design notes from our plan (`docs/plans/2026-07-26-pbt-snap-sync.md`): the
unified tree collapses snap's account/storage phases into flat keyspace ranges;
each contract's overflow storage is contiguous by construction, which makes it a
natural sync unit; and responses should carry **per-stem preimages** so
downloaded data lands as address-keyed state — which also lets the client
materialize an MPT locally if it still needs one.

Range proofs are the substantial piece of work here: boundary proof walks plus
root recomputation, so a server cannot smuggle gaps. Build the walk-verification
machinery generally — M5 falls out of it almost for free.

**Join scenarios to test:** joining *during* the pre-activation period,
*just before* activation, and *on the activation block itself*.

*ethrex: planned (12 tasks), old snap mode guarded off.*

---

## M5 — Proofs (`eth_getProof`)

Per-tree-key proofs against the PBT, statelessly verifiable against a header's
state root.

Strictly this depends only on M1 and can be built whenever. Placed after M4
because the two share proof-walk machinery and M4 is the more urgent capability:
build the harder range-proof case first, and single-key proofs are close to a
special case of it. If you happen to already have single-key proofs, the
dependency simply runs the other way — range proofs extend them.

Serving must be per-block: a proof for a pre-activation block takes the legacy
MPT path, and one for a post-activation block takes the PBT path.

*ethrex: done — experimental `pbt-getproof-v1`,
`docs/eip-draft-pbt-eth-getproof.md`. (Built before snap sync, which is why our
snap plan describes range proofs as extending the single-key format rather than
the reverse.)*

---

## M6 — Offline conversion and rehearsal

### Why offline conversion

The consensus surface stays small — no per-block conversion batches, no
dual-tree reads, no new EIP machinery; activation remains "the header starts
committing a different root." Shadow-tracking from genesis is impossible on a
live network, and in-protocol conversion is unspecified for EIP-8297.

The cost is that operational burden moves to node operators, and a node that
fails to convert cannot follow the chain at activation — which is exactly why
M4 must land first, as the fallback for operators whose conversion fails or
runs late.

### Preimages — two different problems

1. **Converting your own state.** The MPT is keyed by `keccak(address)` and
   `keccak(slot)`; the embedding needs the actual address and slot. A node
   holding only hashed-key data cannot convert. Erigon-style plain-keyed state
   sidesteps this entirely; otherwise you need a preimage dump or reconstruction
   from history.
2. **Receiving state over the wire** (M5). Solved in-protocol by carrying
   per-stem preimages in sync responses, so a syncing node never needs a dump.

**Open:** a node that snap-synced has no preimages of its own, so its path must
be "obtain a verified artifact," not "convert what I have."

### The conversion artifact

Reference implementation and measurements: `pbt-migration-tool`. On mainnet
state at block 25,510,000 (401,371,329 accounts, 1,606,439,278 storage slots,
40.6 GB bytecode → 3,562,028,156 leaves), on an M4 Max:

| Stage | Measured |
|---|---|
| Raw state → PBT root | ~14 min, ~32 GB peak |
| Tree construction (merge+fold) | ~3.5 min, ~16–18 Mleaves/s |
| Sorted-leaf file → verified root | **2.5 min, 38 MiB peak RSS** |
| MPT control audit | ~33 min |

The trust chain matters more than the speed: a trusted block header certifies
the raw export via MPT-root equality, the deterministic embedding and fold
produce the PBT root, and that root is carried in the leaf file — so any
importer re-derives and checks it rather than trusting the file.

### Client-side work

- **Import**: ingest a sorted-leaf file, verifying its embedded root against the
  anchor block's header.
- **Late-start shadow tracking**: seed at an anchor block and track forward from
  there, rather than always starting at genesis. No consensus change — the
  invariant (a seeded snapshot is indistinguishable from a replayed one) is
  unchanged — but most implementations will not express it initially.
- **Coordination**: publish the expected root at an agreed anchor block so
  operators can verify before activation; decide whether artifacts are
  distributed or everyone converts locally.
- **Rehearsal** on a testnet with real state before scheduling anything on
  mainnet.

---

## M7 — Witness / stateless / proving

Block execution witnesses, stateless verification, and any zkVM proving path are
MPT-shaped in every client that has them. Independent of M2 onward, so it can
run in parallel — but for clients whose L2 or proving stack is core product,
it is not optional.

*ethrex: not started; witness/guest was explicitly out of scope in the first
phase.*

---

## M8 — Spec freeze and multi-client interop

Not code, but on the critical path to any public network:

- Settle open embedding details — e.g. the `code_size` field width (EELS uses
  4 bytes at offset 4; EIP-7864 says 3 bytes at offset 5).
- Upstream the proof and sync wire formats, which are de-facto drafts until then.
- Get a second implementation. A single-client testnet tests very little, and a
  from-genesis PBT testnet (the cleanest way to test tree construction in
  isolation) is the one case where teaching genesis tooling about PBT pays for
  itself.

---

## M9 — MPT retirement

If the MPT is retained as the lookup structure, the side registry and dual-state
machinery are permanent. Dropping it reshapes pre-activation proof serving,
tracing, and historical state access.

Worth deciding deliberately rather than drifting into "never."

---

## Open questions

1. Where does a node that acquired state via sync get its conversion artifact,
   given it holds no preimages?
2. Who publishes the anchor-block root, and how is it agreed?
3. Convert locally or import a distributed artifact — or both?
4. How much lead time between publishing the anchor artifact and activation?
5. Does the witness/proving path (M7) gate L2 deployments, or can L2s stay on
   the MPT indefinitely?
