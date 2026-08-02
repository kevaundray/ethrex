"""
Dump EIP-8297 binary trie + embedding test vectors from the EELS
reference implementation (execution-specs, projects/binary-trie) as
JSON, for use as fixtures in ethrex's Rust implementation.

Run from the root of the execution-specs checkout:
    uv run python dump_vectors.py > binary_trie_vectors.json

The script records the checkout's HEAD commit in the fixture's
`source_commit` field (via `git rev-parse HEAD` in the CWD), pinning
the exact spec revision the vectors were generated from.
"""

import json
import random
import subprocess
import sys

from ethereum_types.bytes import Bytes, Bytes20, Bytes32
from ethereum_types.numeric import U32, U64, U256, Uint

from ethereum.binary_trie.trie import BinaryTrie, root, trie_set
from ethereum.binary_trie.embedding import (
    address20_to_address32,
    chunkify_code,
    encode_basic_data,
    get_tree_key_for_basic_data,
    get_tree_key_for_code_chunk,
    get_tree_key_for_code_hash,
    get_tree_key_for_header,
    get_tree_key_for_storage_slot,
)
from ethereum.crypto.hash import keccak256
from ethereum.state import Account, BlockDiff
from ethereum.state_pbt import (
    State as PbtSpecState,
    apply_changes_to_state,
    set_account,
    set_storage,
    state_root,
    store_code,
)


def hx(b: bytes) -> str:
    return "0x" + bytes(b).hex()


def trie_root_case(name: str, entries: list) -> dict:
    """`entries` is an ordered list of (key, value) pairs, applied in
    order with trie_set; duplicates are preserved in the serialized
    output so consumers can replay overwrites."""
    t = BinaryTrie()
    for k, v in entries:
        trie_set(t, Bytes(k), Bytes32(v))
    return {
        "name": name,
        "entries": [{"key": hx(k), "value": hx(v)} for k, v in entries],
        "root": hx(root(t)),
    }


V1 = bytes.fromhex("01" * 32)
V2 = bytes.fromhex("02" * 32)
V3 = bytes.fromhex("03" * 32)

trie_cases = [
    trie_root_case("empty", []),
    trie_root_case("single_leaf", [(b"\x00" * 34, V1)]),
    trie_root_case("single_leaf_one_byte_key", [(b"\xab", V1)]),
    trie_root_case(
        "two_leaves_diverge_first_bit",
        [(b"\x00" + b"\x11" * 33, V1), (b"\x80" + b"\x11" * 33, V2)],
    ),
    trie_root_case(
        "two_leaves_diverge_last_bit",
        [(b"\x22" * 33 + b"\x00", V1), (b"\x22" * 33 + b"\x01", V2)],
    ),
    trie_root_case(
        "three_leaves_shared_prefix",
        [
            (b"\xf0" + b"\x00" * 33, V1),
            (b"\xf1" + b"\x00" * 33, V2),
            (b"\x0f" + b"\x00" * 33, V3),
        ],
    ),
    trie_root_case(
        "mixed_key_lengths_34_and_66",
        [
            (b"\x00" + b"\xaa" * 32 + b"\x05", V1),
            (b"\xff" + b"\xbb" * 64 + b"\x07", V2),
        ],
    ),
    trie_root_case(
        "overwrite_takes_last_value",
        # same key written twice: the second trie_set overwrites
        [(b"\x42" * 34, V1), (b"\x42" * 34, V2)],
    ),
]

# Deterministic pseudo-random case: 50 distinct 34-byte keys, listed in
# generation (insertion) order.
rng = random.Random(8297)
rand_entries = {}
while len(rand_entries) < 50:
    k = bytes(rng.randrange(256) for _ in range(34))
    v = bytes(rng.randrange(256) for _ in range(32))
    rand_entries[k] = v
trie_cases.append(
    trie_root_case("random_50_keys_seed_8297", list(rand_entries.items()))
)

ADDRESS20 = bytes.fromhex("00112233445566778899aabbccddeeff00112233")
ADDR32 = address20_to_address32(Bytes20(ADDRESS20))
CODE_HASH = keccak256(b"\xfe")  # hash of some 1-byte code

embedding_cases = {
    "address20": hx(ADDRESS20),
    "address32": hx(ADDR32),
    "basic_data_key": hx(get_tree_key_for_basic_data(ADDR32)),
    "code_hash_key": hx(get_tree_key_for_code_hash(ADDR32)),
    "header_sub_index_255_key": hx(get_tree_key_for_header(ADDR32, Uint(255))),
    "storage_slot_keys": {
        str(slot): hx(get_tree_key_for_storage_slot(ADDR32, U256(slot)))
        for slot in [0, 1, 63, 64, 255, 256, 511, 512, 2**200]
    },
    "code_chunk_keys": {
        str(cid): hx(
            get_tree_key_for_code_chunk(ADDR32, Bytes32(CODE_HASH), Uint(cid))
        )
        for cid in [0, 1, 127, 128, 129, 383, 384]
    },
    "code_chunk_content_hash": hx(CODE_HASH),
}

# chunkify vectors
PUSH4 = bytes([0x63])
PUSH32 = bytes([0x7F])
chunkify_cases = [
    {"name": "empty", "code": hx(b""), "chunks": []},
    {
        "name": "stop_padded",
        "code": hx(b"\x00"),
        "chunks": [hx(c) for c in chunkify_code(Bytes(b"\x00"))],
    },
    {
        "name": "eip_example_push4_boundary",
        # PUSH4 at position 29: its 4 data bytes spill 2 into chunk 1
        "code": hx(b"\x01" * 29 + PUSH4 + b"\xaa\xbb\xcc\xdd" + b"\x01" * 10),
        "chunks": [
            hx(c)
            for c in chunkify_code(
                Bytes(b"\x01" * 29 + PUSH4 + b"\xaa\xbb\xcc\xdd" + b"\x01" * 10)
            )
        ],
    },
    {
        "name": "push32_at_chunk_end_spills_31",
        "code": hx(b"\x01" * 30 + PUSH32 + bytes(range(32)) + b"\x01" * 5),
        "chunks": [
            hx(c)
            for c in chunkify_code(
                Bytes(b"\x01" * 30 + PUSH32 + bytes(range(32)) + b"\x01" * 5)
            )
        ],
    },
]

basic_data_cases = [
    {
        "code_size": 0,
        "nonce": 0,
        "balance": "0x0",
        "encoded": hx(encode_basic_data(U32(0), U64(0), U256(0))),
    },
    {
        "code_size": 1234,
        "nonce": 42,
        "balance": hex(10**18),
        "encoded": hx(encode_basic_data(U32(1234), U64(42), U256(10**18))),
    },
    {
        "code_size": 2**32 - 1,
        "nonce": 2**64 - 1,
        "balance": hex(2**128 - 1),
        "encoded": hx(
            encode_basic_data(U32(2**32 - 1), U64(2**64 - 1), U256(2**128 - 1))
        ),
    },
]

# --- Flat-state embedding vectors (state_pbt.py) ---
# Shared constants: the spec state/diffs AND the serialized fixture
# are both derived from these, so the declared pre-state and diff
# descriptions can never drift from the committed roots.
ADDR_EOA = Bytes20(bytes.fromhex("1000000000000000000000000000000000000001"))
ADDR_CONTRACT = Bytes20(
    bytes.fromhex("2000000000000000000000000000000000000002")
)
# >127 chunks so content-addressed overflow chunks are exercised:
# 4030 bytes = 130 chunks of 31 bytes; PUSH data crosses chunk boundaries.
CONTRACT_CODE = Bytes(bytes([0x60, 0xAA, 0x01] * 1343 + [0x00]))

EOA_NONCE = 7
EOA_BALANCE = 10**18
CONTRACT_NONCE = 1
CONTRACT_BALANCE = 2**127 - 1
STORAGE_SLOTS = [(0, 0xDEAD), (63, 1), (64, 2), (300, 3)]

DIFF1_EOA_NONCE = 8
DIFF1_EOA_BALANCE = 2 * 10**18
DIFF1_STORAGE = [(0, 0), (64, 9)]  # slot 0 -> 0 deletes the leaf


def slot_key(slot: int) -> Bytes32:
    return Bytes32(slot.to_bytes(32, "big"))


spec_state = PbtSpecState()
code_hash = store_code(spec_state, CONTRACT_CODE)
set_account(
    spec_state,
    ADDR_EOA,
    Account(
        nonce=Uint(EOA_NONCE),
        balance=U256(EOA_BALANCE),
        code_hash=keccak256(b""),
    ),
)
set_account(
    spec_state,
    ADDR_CONTRACT,
    Account(
        nonce=Uint(CONTRACT_NONCE),
        balance=U256(CONTRACT_BALANCE),
        code_hash=code_hash,
    ),
)
for slot, val in STORAGE_SLOTS:
    set_storage(spec_state, ADDR_CONTRACT, slot_key(slot), U256(val))

pre_root = state_root(spec_state)

diff1 = BlockDiff(
    account_changes={
        ADDR_EOA: Account(
            nonce=Uint(DIFF1_EOA_NONCE),
            balance=U256(DIFF1_EOA_BALANCE),
            code_hash=keccak256(b""),
        )
    },
    storage_changes={
        ADDR_CONTRACT: {
            slot_key(slot): U256(val) for slot, val in DIFF1_STORAGE
        }
    },
    code_changes={},
)
apply_changes_to_state(spec_state, diff1)
post_diff1_root = state_root(spec_state)

diff2 = BlockDiff(account_changes={ADDR_CONTRACT: None})
apply_changes_to_state(spec_state, diff2)
post_delete_root = state_root(spec_state)

pbt_state_cases = {
    "eoa_address": hx(ADDR_EOA),
    "contract_address": hx(ADDR_CONTRACT),
    "contract_code": hx(CONTRACT_CODE),
    "pre": {
        "eoa": {"nonce": EOA_NONCE, "balance": hex(EOA_BALANCE)},
        "contract": {
            "nonce": CONTRACT_NONCE,
            "balance": hex(CONTRACT_BALANCE),
            "storage": {str(s): hex(v) for s, v in STORAGE_SLOTS},
        },
        "root": hx(pre_root),
    },
    # Informational description of the mutations, derived from the same
    # constants used to build the actual BlockDiffs; the roots below
    # remain the authority.
    "diff1": {
        "eoa": {
            "nonce": DIFF1_EOA_NONCE,
            "balance": hex(DIFF1_EOA_BALANCE),
        },
        "contract_storage": {str(s): hex(v) for s, v in DIFF1_STORAGE},
    },
    "diff2": "delete contract account",
    "post_diff1_root": hx(post_diff1_root),
    "post_delete_contract_root": hx(post_delete_root),
}

json.dump(
    {
        "source": "ethereum/execution-specs projects/binary-trie",
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "trie_roots": trie_cases,
        "embedding": embedding_cases,
        "chunkify_code": chunkify_cases,
        "encode_basic_data": basic_data_cases,
        "pbt_state": pbt_state_cases,
    },
    sys.stdout,
    indent=2,
)
print()
