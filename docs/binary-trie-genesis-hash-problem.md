# Why the binary-tree commitment cannot activate at genesis (and what we do instead)

Changing the state commitment changes the genesis state root, which changes
the genesis block hash, which changes the identity of the chain — as seen by
the consensus layer, by every peer's fork id, and by every tool that computes
a genesis hash. This document records the failure mode, why patching the
tooling is the wrong first move, and the scheduled-activation design that
sidesteps it.

Applies to the experimental EIP-8297 Partitioned Binary Tree (PBT) commitment
on `kw/bin-trie-integration`.

---

## The problem

### 1. The genesis state root is an input to the chain's identity

`Genesis::compute_state_root` (`crates/common/types/genesis.rs`) returns a PBT
root instead of an MPT root when the commitment is active at the genesis
timestamp:

```rust
if self.config.is_binary_tree_active(self.timestamp) {
    return PbtState::from_genesis_alloc(&self.alloc).compute_root()...;
}
self.compute_mpt_state_root()
```

That root lands in the header built by `Genesis::get_block_header`, and the
hash of that header *is* the genesis hash. So the choice of commitment scheme
propagates: **commitment → state root → genesis header → genesis hash →
everything downstream that names the chain.**

This is not a quirk of our implementation. It is true of any client that
changes the commitment at genesis, in any language.

### 2. Background: why there is a "genesis generator" on the CL side

Mainnet never had this problem, because nobody *creates* mainnet's genesis. It
was created once, in 2015, and every client ships the resulting file; its hash
is a historical constant you inherit rather than compute.

A brand-new network has no such inheritance — someone has to manufacture
genesis. After the merge, that means manufacturing **two** artifacts that must
agree with each other:

- **The execution-layer genesis** — chain config (the fork schedule), the alloc
  (prefunded accounts), gas limit, timestamp. Computing the state root over the
  alloc and hashing the resulting header gives the EL genesis block hash.
- **The consensus-layer genesis** — the beacon state at slot 0: the validator
  registry (on a devnet, derived from a mnemonic), genesis time, fork versions.

These are not independent. After the merge the beacon chain is the authority on
which chain is canonical, and every beacon block carries an execution payload
that must chain back to a parent. The chain therefore needs a parent to start
from, and that parent is EL **block 0** — which no slot produces; the generator
manufactures it directly from the alloc. The beacon *state* at slot 0 records
it, in the `latest_execution_payload_header` field, including EL block 0's
**hash**. (The beacon *block* at slot 0 is a placeholder with an empty body; the
pointer lives in the state, not the block. This is also why
`is_merge_transition_complete` — defined as "that field is not the default
value" — reports true from slot 0 on a merged-from-genesis network.) In other
words, the CL is *born already holding a specific opinion* about what the EL's
genesis hash is.

The first execution block consensus actually produces is EL block 1, in the
first proposed beacon block, and its `parent_hash` must equal the block hash
recorded in that field.

Someone has to compute that opinion, and it must come out byte-identical for
every participant: if one CL's beacon state named one EL genesis hash and
another CL's named a different one, the network would be split before the first
slot was ever produced. Hence a single shared tool — `ethereum-genesis-generator`
in the kurtosis stack — that takes one set of inputs and emits both artifacts
consistently for every client in the enclave. It also saves each client team
from reimplementing a cross-domain computation that needs EL rules (RLP,
keccak, state root) *and* CL rules (SSZ, hash tree root) to agree exactly.

If you know git, the analogy is tight: genesis is the initial commit. A commit's
hash is derived from the tree it points at, so two people who each "create the
same initial commit" but compute the tree differently end up with different
commit hashes — and their repositories can never share history, no matter how
identical the files look to a human. The generator is what guarantees everyone
runs the equivalent of `git init` over byte-identical content, so they all land
on the same first hash.

**The load-bearing detail for this document:** when the generator computes that
EL genesis block hash, it computes the state root using **Merkle-Patricia-Trie
rules** — because that is the only state commitment Ethereum has ever had, in
every client and every genesis tool ever written. The MPT assumption is not
merely *present* in the tooling; the tooling *freezes it into the CL's beacon
state* before ethrex has executed a single line of code.

### 3. What the consensus layer does with it at runtime

The CL therefore starts life holding an MPT-derived genesis hash as fact. It
then drives the EL over the engine API, referencing that hash as the head of
the chain.

If the EL computed a different genesis hash — which it does the moment its
genesis header carries a PBT root — the EL does not recognise the block the CL
is asking about. It cannot answer affirmatively for a block it has never seen,
so the handshake never completes and the chain never produces a block. Nor
could the first payload ever be accepted: its `parent_hash` would have to name
a block 0 that the EL does not have. The two layers are, correctly, describing
different chains: identical accounts, identical balances, identical everything
a human would look at, but a different chain identity.

### 4. What the peer-to-peer layer does with it

The genesis hash is also the seed of the fork id. In
`crates/common/types/fork_id.rs`:

```rust
let genesis_hash = genesis_header.hash();
...
hasher.update(genesis_hash.as_bytes());
```

`ForkId` is a CRC32 checksum seeded by the genesis hash and then advanced by
each scheduled fork. A divergent genesis hash therefore yields a divergent
fork id, and peers reject each other before exchanging any blocks.

Note the corollary for genesis activation specifically: an at-or-before-genesis
`binary_tree_time` deliberately does **not** join `gather_forks`, because it
cannot — it is already baked into the genesis hash that seeds the checksum.
Nodes that disagree about genesis activation have already diverged at the
genesis hash itself. (A *scheduled* future time is different: it does join the
fork id, mirroring `verkle_time`, so nodes with mismatched schedules split at
the flip by design.)

### 5. The observed failure mode

Before scheduled activation existed, the only way to run a genesis-activated
devnet was `fixtures/networks/binary-tree-devnet.yaml`, which carries a
pre-merge TTD ladder. The ladder is not there for fork-coverage reasons: it
exists precisely because the chain must start pre-merge, so that the EL genesis
hash is not the artifact the CL validates at startup, with the merge reached
later via terminal total difficulty. The cost is roughly eight minutes of fork
ladder before the first useful block.

---

## Why fixing the tooling is not the first move

The instinct is to teach the genesis generator about the binary tree. It is a
reasonable long-term step, but not now:

- **It rescues only the degenerate mode.** Mainnet's genesis hash is frozen
  forever, so a commitment change on a real chain *must* be a timestamp
  transition on an existing chain. Genesis activation can never be the
  deployment path; investment there is investment in a mode that will never
  ship.
- **It is a second implementation of the embedding.** The generator would need
  BLAKE3 plus the full EIP-8297 embedding in another codebase, with its own
  conformance pinning — while the embedding is still a draft (our crate README
  still flags the `code_size` field width disagreeing with EIP-7864).
- **We already have what it would buy us.** Scheduled activation gives a
  merged-from-genesis devnet on completely stock tooling, in under a minute.

**When it *would* make sense:** multi-client interop. A from-genesis network is
the cleanest way to test tree construction in isolation from all transition
machinery, and verkle's testnets took exactly this route once several clients
were implementing. That is the trigger to upstream genesis support — ideally
after the embedding is frozen.

---

## The solution: scheduled activation

Keep genesis MPT-committed, and flip the commitment at a timestamp on a chain
that is already running.

**Mechanism.** Two predicates on `ChainConfig` carry the whole rule:

- `binary_tree_scheduled()` — `binary_tree_time` is set. Scheduled nodes
  *shadow-track* `PbtState` from genesis: snapshot seeding at genesis, then the
  per-block clone/apply/store loop, without committing or validating anything
  in headers.
- `is_binary_tree_active(ts)` — `binary_tree_time <= ts`. From the first block
  at or after that time, `header.state_root` commits the shadow state's PBT
  root, and `eth_getProof` serves the `pbt-getproof-v1` shape.

Because the shadow state has been accumulating since genesis, the first active
block commits the **full** state. Carry-over is the consensus rule; there is no
conversion event and no empty-start overlay.

**Why this dissolves the problem.** Genesis genuinely is MPT-committed, so the
generator's computed genesis hash is *correct*, the CL's embedded execution
payload header matches what the EL derives, and the fork id agrees. Nothing
outside ethrex needs to know the binary tree exists until the flip, which
happens over the engine API like any other block.

**Configuring it.** In genesis JSON, `binaryTreeTime: <unix timestamp>`
(camelCase). For devnets, `--experimental.binary-tree-delay <seconds>` sets
`binary_tree_time = genesis.timestamp + delay` after genesis load. The flag is
a *relative delay* rather than an absolute time because a kurtosis yaml is
written before genesis exists; every node given the same genesis and the same
delay derives the identical schedule.

`fixtures/networks/binary-tree-devnet-fast.yaml` is the reference config:
merged-from-genesis (all forks at epoch 0, stock generator, stock lighthouse),
with `--experimental.binary-tree-delay=30` as the only activation input and
`--syncmode=full` (see limits below).

**Verified.** On the 3× ethrex + lighthouse run recorded in
`docs/plans/2026-07-25-binary-trie-state-commitment.md`: first block under a
minute after launch (versus ~8 minutes of fork ladder on the genesis-activated
config), flip at block 10 with timestamp exactly `genesis + 30`, state roots
identical across all three nodes at every sampled height through and past the
boundary, `eth_getProof` changing shape at the boundary, a post-flip transfer
mined with agreement across nodes, and a stopped node rejoining and catching up
across the boundary in 12 seconds.

---

## What genesis activation is still for

It remains supported as the degenerate case, spelled `binaryTreeTime: 0` (or
the CLI sugar `--experimental.binary-tree`, which sets it to the genesis
timestamp). It is the right tool where nothing external needs to agree with us
about the genesis hash:

- the in-process test suites (`test/tests/blockchain/binary_tree_tests.rs`),
  which construct chains directly;
- `fixtures/networks/binary-tree-devnet.yaml`, retained with its TTD ladder
  specifically to exercise this mode.

`Genesis::compute_mpt_state_root` exists for the same reason: under genesis
activation the header carries the PBT root, so the MPT lookup structure needs a
root of its own, recorded per block in the `mpt_lookup_roots` registry.

---

## Current limits

Not consequences of the genesis design, but the boundaries within which the
above is true:

- **Full sync only.** Snap sync is refused at startup on any scheduled chain
  (`validate_sync_mode`, `cmd/ethrex/initializers.rs`); it is MPT-shaped and
  would pivot on a PBT root that addresses no MPT. Scheduled devnet configs
  therefore pin `--syncmode=full`. PBT snap sync is planned separately in
  `docs/plans/2026-07-26-pbt-snap-sync.md`.
- **In-memory registries.** `pbt_states` and `mpt_lookup_roots` do not survive
  restart. Recovery replays from genesis, which only works while the chain is
  short enough that the pre-flip MPT state is still addressable; past the DB
  commit threshold, only offline seeding remains. Persistence is the first
  Phase-2 upgrade.
- **The delay flag is not persisted.** Every boot must re-supply the identical
  value (kurtosis `el_extra_params` does this naturally), or the node reopens
  unscheduled and fails loudly at the first post-flip block.
- **In-protocol conversion is not designed.** Nodes must have processed the
  chain from genesis. The mainnet-credible mechanism (bounded per-block
  conversion batches, cf. verkle's EIP-7748) is unspecified by EIP-7864/8297
  and deliberately not built ahead of the EIP.

---

## References

- `crates/common/types/genesis.rs` — `compute_state_root`,
  `compute_mpt_state_root`, `get_block_header`, `binary_tree_scheduled`,
  `is_binary_tree_active`, `gather_forks`
- `crates/common/types/fork_id.rs` — genesis-hash-seeded checksum
- `cmd/ethrex/initializers.rs` — `apply_binary_tree_overrides`,
  `validate_sync_mode`
- `docs/plans/2026-07-26-binary-tree-transition.md` — the plan that introduced
  scheduled activation
- `docs/plans/2026-07-25-binary-trie-state-commitment.md` — as-built notes and
  devnet verification records
