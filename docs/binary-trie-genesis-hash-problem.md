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

### 2. What the consensus layer does with it

For a merged-from-genesis network (all forks at epoch 0, the modern devnet
default), the genesis generator produces two coupled artifacts from one input:

- the execution-layer `genesis.json` (the alloc and chain config), and
- the beacon genesis state, whose embedded execution payload header is derived
  from the EL genesis block the generator just computed — including its block
  hash.

The generator computes that EL genesis block hash using **MPT rules**, because
that is the only state commitment Ethereum has. The CL therefore starts life
holding an MPT-derived genesis hash as fact.

At startup the CL drives the EL over the engine API, referencing that hash as
the head of the chain. If the EL computed a different genesis hash — which it
does the moment its genesis header carries a PBT root — the EL does not
recognise the hash the CL is asking about. The EL cannot answer affirmatively
for a block it has never seen, so the handshake never completes and the chain
never produces a block. The two layers are, correctly, describing different
chains.

### 3. What the peer-to-peer layer does with it

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

### 4. The observed failure mode

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
