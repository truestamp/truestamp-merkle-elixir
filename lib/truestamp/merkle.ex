# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle do
  @moduledoc """
  Pure Elixir Merkle tree implementation.

  Secure, deterministic Merkle tree for cryptographic applications. Handles millions of
  leaves with strong security properties and a simple API. Standalone module with zero
  external dependencies beyond `:crypto` and `Base`. Requires OTP 25 or newer, which is
  where `:crypto.hash_equals/2` arrived.

  You supply entries: a key, plus a 32-byte digest you have already computed over
  whatever that key names. The tree sorts, pads and hashes those into leaves. What a key
  identifies, and what the digest was taken over, are entirely yours to decide.

  Size a large workload by memory before you size it by time. A finished tree retains
  roughly 300 MB of heap per million leaves, and construction costs a good deal more
  than that while the input list, the intermediate levels and the finished tree are all
  alive at once: building a million leaves from a million-element list peaked around
  1.4 GB of total BEAM heap when measured. Budget on that order, around 1.5 GB per
  million leaves, rather than on the retained size. A few million leaves is comfortable
  on an ordinary server. Ten million is a different proposition and worth a trial run
  on the real hardware before you commit to it.

  What a proof does and does not attest, and the reasoning behind each check here, are in
  `SECURITY.md` at the root of this repository. The tree contract a port must reproduce,
  with its known answers, is in `README.md`.

  ## How the Tree Is Built

  Read this before porting the algorithm or comparing roots against another
  implementation.

  Leaves are sorted byte-wise by key, padded up to the next power of two with a constant
  synthetic leaf, and hashed into a perfect binary tree. A leaf is
  `SHA256(0x00 || leaf_hash)`, an interior node is `SHA256(0x01 || left || right)`, and
  the root of an empty tree is `SHA256("")`. Every hash going in is 64 lowercase hex
  characters. The padded shape is frozen: Truestamp has committed roots computed this
  way to public blockchains, so it cannot change.

  The leaf and node hashing follows RFC 6962; the padded shape does not, so a verifier
  written strictly to that standard reproduces a root from this library only at leaf
  counts of 0, 1, and exact powers of two.

  The synthetic leaf carries a single reserved value,
  `96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7`, and padding
  slots are placed by the tree, never by a caller. That value is therefore refused
  in both directions: `new/2` and the builder raise `ArgumentError` if you hand it
  in as an entry hash, and `verify/3` returns `false` if you present it as the value
  being proved, because such a proof proves a padding slot rather than an entry.
  The reservation covers the leaf value only. The padding leaf's *hash* appears as
  an ordinary sibling in most proofs from a padded tree and keeps verifying.

  Two more limits are worth stating plainly. The proof encoding is specific to this
  library, both the direction-prefixed hex list that `proof/2` returns and its compact
  binary form. And only inclusion proofs exist here: no consistency proofs, no Signed
  Tree Heads, no log monitoring.

  ## Security Properties

  - **Domain separation**: Leaf `SHA256(0x00 || hash)`, internal `SHA256(0x01 || left || right)`
  - **32-byte input enforcement**: All hashes must be exactly 64 lowercase hex chars (defense-in-depth)
  - **Constant-time root comparison**: `:crypto.hash_equals/2`, kept as a habit rather
    than as a defense, since every value it compares is public
  - **Bounded verification**: a proof carries at most 64 steps
  - **Empty tree**: Root is `HASH("")`

  Hex is canonical lowercase throughout, on the way in and on the way out. Uppercase is
  not a synonym for it: `new/2` raises `ArgumentError` on an uppercase hash, and
  `verify/3` returns `false` for an uppercase root, leaf value, or proof sibling, which
  looks exactly like a proof that does not check out. Hexdump tools commonly emit
  uppercase, so downcase before handing anything over.

  ## Limits and Where They Apply

  The 64-step proof cap is a real bound on work: it is what keeps `verify/3`,
  `decode_proof/1`, and `decode_proof_base64/1` cheap on bytes from a stranger. Those
  three are the entry points safe to put in front of untrusted callers.

  The tree depth cap of 40 is not that. It keeps the depth arithmetic in range, and a
  tree big enough to reach it holds about a trillion leaves, so memory is gone long
  before the cap has anything to say. Construction has no entry-count limit of its own,
  and `new/2` will try to build whatever list it is handed, so build trees from input
  you control.

  ## Quick Start

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-2", "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> root_hash = Truestamp.Merkle.root(tree)
      "27fdfb0ec5b8a6cd13283e2c192d32ee5baee7aa4807e96287008f42598c51d1"
      iex> proof = Truestamp.Merkle.proof(tree, "entry-1")
      ["r:97de9286ff6aec3c2f718237f34f6062d515daf8ea863ed52b503ee4ad98444c"]
      iex> Truestamp.Merkle.verify(proof, root_hash, "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
      true
      iex> single = [%{"key" => "single-entry", "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"}]
      iex> single_tree = Truestamp.Merkle.new(single)
      iex> Truestamp.Merkle.proof(single_tree, "single-entry")
      []

  ## Test Vectors

  Cross-implementation verification vectors covering empty trees, single leaves,
  even/odd leaf counts, and padding behavior. These are this library's vectors: reproduce
  them with the rules above, not with another library's tree. The keys below are input
  data, so a port has to feed in exactly the keys shown to get the roots shown.

  ### Test Vector 0: Empty Tree

      iex> tree = Truestamp.Merkle.new([])
      iex> Truestamp.Merkle.root(tree)
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      iex> tree.tree_depth
      0
      iex> Truestamp.Merkle.proof(tree, "any-key")
      nil

  ### Test Vector 1: Single Leaf

      iex> data = [
      ...>   %{"key" => "entry1", "hash" => "1111111111111111111111111111111111111111111111111111111111111111"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.root(tree)
      "4635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e"
      iex> tree.tree_depth
      0
      iex> Truestamp.Merkle.proof(tree, "entry1")
      []

  ### Test Vector 2: Two Leaves

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "2222222222222222222222222222222222222222222222222222222222222222"},
      ...>   %{"key" => "entry-2", "hash" => "3333333333333333333333333333333333333333333333333333333333333333"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.root(tree)
      "96cfe136315282442cd0133b934dd99622a510c075930239725ced808ce7dfa0"
      iex> tree.tree_depth
      1
      iex> Truestamp.Merkle.proof(tree, "entry-1")
      ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]
      iex> Truestamp.Merkle.proof(tree, "entry-2")
      ["l:bc6f27de60abf5319d16ff4c98fe3c42022c84f6a7a2b207c8df19b0ec3d8d58"]

  ### Test Vector 3: Three Leaves (Padding to 4)

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "4444444444444444444444444444444444444444444444444444444444444444"},
      ...>   %{"key" => "entry-2", "hash" => "5555555555555555555555555555555555555555555555555555555555555555"},
      ...>   %{"key" => "entry-3", "hash" => "6666666666666666666666666666666666666666666666666666666666666666"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.root(tree)
      "d8c7e05bf72cf133500667297ffa73ba97900e6f2adcee472bfb8a5f0db9f6d3"
      iex> tree.tree_depth
      2
      iex> Truestamp.Merkle.proof(tree, "entry-1")
      ["r:a23e5f60b577afd1d5d31a3efa2c95b1586648dbb4f0aa254d3de36cf3966d85", "r:b8f04324df5a0d8b64f89465f58da9c385de8e0b27c86783093988ef86f1bc25"]
      iex> Truestamp.Merkle.proof(tree, "entry-3")
      ["r:d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319", "l:ad87655bd0d907088388cf532d6495ab11ce7b2db53e3247783a6a8108046f5a"]

  ### Test Vector 4: Four Leaves

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "7777777777777777777777777777777777777777777777777777777777777777"},
      ...>   %{"key" => "entry-2", "hash" => "8888888888888888888888888888888888888888888888888888888888888888"},
      ...>   %{"key" => "entry-3", "hash" => "9999999999999999999999999999999999999999999999999999999999999999"},
      ...>   %{"key" => "entry-4", "hash" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.root(tree)
      "28a9f015a225b68dc7ada02ad7474e0e42fd2bcc262802bda2cac48626e14cba"
      iex> tree.tree_depth
      2
      iex> Truestamp.Merkle.proof(tree, "entry-1")
      ["r:048d913ab15694f3b6675c7889ee4f5588eaa484fd25c9646289ed601aeb2c28", "r:df3e04295fa98f06cfebf6b09eb04852d517f8c5385ce8019e5e50f978b8c7ed"]
      iex> Truestamp.Merkle.proof(tree, "entry-4")
      ["l:8fb240aea60b45db01c7a243e82d36c5695cab53142a64996ef946eb8788326a", "l:d764cc06dcdfe5b7f902f0605de2ff64fb1966ef182f991dc4738d7b1bb2584a"]

  ### Test Vector 5: Five Leaves (Padding to 8)

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
      ...>   %{"key" => "entry-2", "hash" => "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
      ...>   %{"key" => "entry-3", "hash" => "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
      ...>   %{"key" => "entry-4", "hash" => "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
      ...>   %{"key" => "entry-5", "hash" => "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.root(tree)
      "797eb8e773660265c45bf3c2a538f7e223def7191324599d61426b2d625b77bc"
      iex> tree.tree_depth
      3
      iex> Truestamp.Merkle.proof(tree, "entry-1")
      ["r:2e3aa189e1f666b2c3e864e21d978388020b89a6725e31ff2657bad5840a7f02", "r:13f9584406a6feceda026bdb8f5ae4016ff806592c78288d18202ae78abe7379", "r:df312295efe541715fe1698fc92374e8653dd41cd953926f95c77dab4ad25e23"]
      iex> Truestamp.Merkle.proof(tree, "entry-5")
      ["r:d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319", "r:3af5290a630909c56594370a5d53f1fad8231179978bedb08410b348475c0176", "l:1bee6619e5c929fab37bf20d256e46727c005c5779a7576ee07869d084bbb6c0"]

  ### Test Vector 6: Seven Leaves (Padding to 8)

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
      ...>   %{"key" => "entry-2", "hash" => "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"},
      ...>   %{"key" => "entry-3", "hash" => "23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"},
      ...>   %{"key" => "entry-4", "hash" => "3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012"},
      ...>   %{"key" => "entry-5", "hash" => "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"},
      ...>   %{"key" => "entry-6", "hash" => "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234"},
      ...>   %{"key" => "entry-7", "hash" => "6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.root(tree)
      "ee732f21e935db7f21e285436d8f100220d6dd10cda89d9f280d5a12459532d0"
      iex> tree.tree_depth
      3
      iex> Truestamp.Merkle.proof(tree, "entry-1")
      ["r:2a973eab8f2f8e75a78cb2f2091eed699ae989ad9df4d3f43aa73bfeb835ef2c", "r:3a28889d826c485dec4abbd2926c2584d52e143e3bd441f65d8d62baa76ee636", "r:442c8c67a33da213e5901d0e16950622466d1656a838d7f78769ff41dbebb87b"]
      iex> Truestamp.Merkle.proof(tree, "entry-7")
      ["r:d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319", "l:1c756beb6256bde51c213814e963a2b7138ead5e915b4f2ca78ed9bc3aedacbf", "l:4d19e260baa0c2af21481e05bcd9ae74089db64244ac3f50569c0a8300a088c8"]

  ### Verification Example

      iex> proof = ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]
      iex> root = "96cfe136315282442cd0133b934dd99622a510c075930239725ced808ce7dfa0"
      iex> Truestamp.Merkle.verify(proof, root, "2222222222222222222222222222222222222222222222222222222222222222")
      true

  ## API Summary

  - `new/2` - Create tree from a list of `%{"key" => ..., "hash" => ...}` entries
  - `root/1` - Get root hash as hex string
  - `proof/2` - Generate inclusion proof for key (returns `nil` if not found)
  - `verify/3` - Verify proof against root hash (returns boolean)
  - `builder/0`, `add_entry/2`, `add_entries/2`, `finalize/2` - Streaming builder pattern
  - `from_stream/2`, `from_maps/2`, `from_tuples/2` - Convenience constructors

  ## Error Handling

  - `new/2` raises `ArgumentError` for invalid keys, hashes, duplicate keys, excessive
    depth, or input that is not a list of entry maps
  - `proof/2` returns `nil` for non-existent keys
  - `verify/3` never raises; it returns `false` for any invalid input or failed verification
  - `encode_proof/1` and `encode_proof_base64/1` return the encoded value directly and raise
    `ArgumentError` for a proof that would not survive the round trip
  - `decode_proof/1` and `decode_proof_base64/1` take untrusted bytes, so they return
    `{:ok, proof}` or `{:error, reason}` rather than raising
  """

  # Longest proof verify/3 and decode_proof/1 will process, and so the ceiling on
  # the hashing an untrusted proof can ask for. 64 steps spans a tree of
  # 2^64 = 18,446,744,073,709,551,616 leaves, past anything that could be built.
  @max_proof_depth 64

  # Ceiling on the depth arithmetic, which keeps the leaf-count math in range. Not a
  # resource limit: 2^40 = 1,099,511,627,776 (~1 trillion) leaves exhausts memory long
  # before the cap is reached.
  @max_tree_depth 40

  # Hash size constants for SHA-256 (defense-in-depth against second preimage attacks)
  # Input hashes must be exactly 32 bytes, preventing internal node forgery (which would be 64 bytes)
  @expected_hash_bytes 32
  @expected_hash_hex_chars @expected_hash_bytes * 2

  # Stored hash carried by every padding leaf when a tree is filled out to the
  # next power of two. Computed at compile time: SHA256(0x00 || 0x00).
  #
  # This constant is public and identical in every tree, so it conceals nothing.
  # A padding leaf is recognizable on sight: from one proof an observer can
  # compute SHA256(0x00 || @empty_leaf_hash), then SHA256(0x01 || x || x)
  # repeatedly to get the hash of an all-padding subtree at any level, and match
  # those against the proof's siblings. That yields the tree depth, the proved
  # leaf's index, and a range for the real leaf count, which narrows to the exact
  # count for a leaf near the end of the tree.
  #
  # That is accepted, not overlooked. Roots must be reproducible by any third
  # party from published data alone, so the padding has to be deterministic;
  # random padding would make a root unreproducible. If an approximate leaf count
  # is sensitive in your setting, that is a property to design around. In
  # Truestamp's own deployment it is published alongside every root anyway.
  @empty_leaf_hash :crypto.hash(:sha256, <<0x00, 0x00>>)

  # The leaf hash every padding slot holds, in every construction path.
  # Equal to hash_leaf(encode_hex(@empty_leaf_hash)) = SHA256(0x00 || @empty_leaf_hash),
  # so a padded tree hashes identically whether it came from new/1 or the builder.
  @padding_leaf_hash :crypto.hash(:sha256, <<0x00>> <> @empty_leaf_hash)

  # Hex spelling of the padding leaf's input hash. Reserved in both directions:
  # refused as a caller-supplied leaf value, and refused as a verification
  # subject. Only the padding slots may carry it, and they are placed by the
  # tree itself, never by a caller.
  @empty_leaf_hash_hex Base.encode16(@empty_leaf_hash, case: :lower)

  alias __MODULE__.Builder

  defstruct [:root_hash, :leaves, :tree_depth, :tree_levels, :leaf_index]

  @type t :: %__MODULE__{
          root_hash: binary(),
          leaves: [{binary(), binary()}],
          tree_depth: non_neg_integer(),
          tree_levels: [tuple()],
          leaf_index: %{binary() => non_neg_integer()}
        }

  # Format: "direction:hash" where direction is "l" or "r"
  @type proof_step :: binary()
  @type proof :: [proof_step()]

  # ============================================================================
  # Builder API Functions
  # ============================================================================

  @doc """
  Creates a new empty builder for incrementally constructing a Merkle tree.

  ## Example

      builder = Merkle.builder()
      builder = Merkle.add_entry(builder, %{"key" => "entry1", "hash" => "abc..."})
      tree = Merkle.finalize(builder)

  """
  @spec builder() :: Builder.t()
  def builder do
    %Builder{}
  end

  @doc """
  Adds a single entry to the builder.

  Validates the entry and pre-computes its leaf hash. Entries are accumulated
  for later finalization.

  ## Duplicate Handling

  - If both key AND hash match an entry already added → silently ignored (idempotent)
  - If key exists with a different hash → raises `ArgumentError`

  ## Example

      builder = Merkle.builder()
                |> Merkle.add_entry(%{"key" => "entry1", "hash" => "a1b2..."})
                |> Merkle.add_entry(%{"key" => "entry2", "hash" => "c3d4..."})

  """
  @spec add_entry(Builder.t(), %{binary() => binary()}) :: Builder.t()
  def add_entry(%Builder{} = builder, %{"key" => key, "hash" => hash}) do
    # Validate input
    validate_key!(key)
    validate_hash!(hash)

    # Check for duplicates
    case Map.get(builder.seen, key) do
      nil ->
        # New key - compute leaf hash and add
        leaf_hash = hash_leaf(hash)

        %Builder{
          leaves: [{key, leaf_hash} | builder.leaves],
          seen: Map.put(builder.seen, key, hash),
          count: builder.count + 1
        }

      ^hash ->
        # Same key AND same hash - silently ignore (idempotent)
        builder

      existing_hash ->
        # Same key but different hash - error!
        raise ArgumentError, """
        Duplicate key with different hash detected.
        Key: #{inspect(key)}
        Existing hash: #{existing_hash}
        New hash: #{hash}
        """
    end
  end

  @doc """
  Adds multiple entries from an enumerable to the builder.

  This is a convenience wrapper that reduces over the enumerable,
  calling `add_entry/2` for each element.

  ## Example

      entries = [
        %{"key" => "entry1", "hash" => "a1b2..."},
        %{"key" => "entry2", "hash" => "c3d4..."}
      ]

      builder = Merkle.builder() |> Merkle.add_entries(entries)
      tree = Merkle.finalize(builder)

  """
  @spec add_entries(Builder.t(), Enumerable.t()) :: Builder.t()
  def add_entries(%Builder{} = builder, enumerable) do
    Enum.reduce(enumerable, builder, &add_entry(&2, &1))
  end

  @doc """
  Finalizes the builder into a complete Merkle tree.

  Sorts leaves by key (unless `sort: false`), pads to next power of 2,
  and builds the full tree structure.

  ## Options

    * `:sort` (default: `true`) - When `true`, sorts leaves by key for
      deterministic ordering. When `false`, preserves insertion order.

  ## Example

      tree = builder |> Merkle.finalize()
      tree = builder |> Merkle.finalize(sort: false)

      # The returned tree supports all standard operations
      root = Merkle.root(tree)
      proof = Merkle.proof(tree, "some-key")

  """
  @spec finalize(Builder.t(), keyword()) :: t()
  def finalize(builder, opts \\ [])

  def finalize(%Builder{leaves: [], count: 0}, _opts) do
    # Empty builder - return empty tree
    new([])
  end

  def finalize(%Builder{leaves: leaves, seen: seen, count: _count}, opts) do
    sort? = Keyword.get(opts, :sort, true)

    # Reverse to get original insertion order (we prepended during add)
    reversed_leaves = Enum.reverse(leaves)

    # Optionally sort by key
    sorted_leaves =
      if sort? do
        Enum.sort_by(reversed_leaves, &elem(&1, 0))
      else
        reversed_leaves
      end

    # Pad to next power of 2 (leaves are {key, leaf_hash_binary})
    padded_leaves = pad_builder_leaves_to_power_of_two(sorted_leaves)

    # Build the tree with all levels stored for fast proof generation
    {root_hash, tree_levels} = build_tree_from_leaf_hashes(padded_leaves)
    tree_depth = calculate_depth(length(padded_leaves))

    # Reconstruct leaves in original format {key, hash_hex} for consistency.
    # `seen` holds {key => hash_hex}, keyed on the key exactly as the caller wrote
    # it, byte for byte, so "Key" and "key" are two separate leaves.
    # Only include non-padding leaves
    final_leaves =
      sorted_leaves
      |> Enum.map(fn {key, _leaf_hash_binary} ->
        {key, Map.get(seen, key)}
      end)

    # Build leaf index map for O(1) key lookup in proof/2
    leaf_index = build_leaf_index(final_leaves)

    # Convert each level from list to tuple so proof generation can use elem/2
    # for O(1) sibling access instead of Enum.at/2 which is O(n) on lists
    tuple_levels = Enum.map(tree_levels, &List.to_tuple/1)

    %__MODULE__{
      root_hash: root_hash,
      leaves: final_leaves,
      tree_depth: tree_depth,
      tree_levels: tuple_levels,
      leaf_index: leaf_index
    }
  end

  # Helper to pad builder leaves (which are {key, leaf_hash_binary} tuples)
  defp pad_builder_leaves_to_power_of_two(leaves) do
    count = length(leaves)
    next_power = next_power_of_two(count)

    if count == next_power do
      leaves
    else
      # Padding keys begin with __PAD__, a prefix validate_key! refuses in any
      # case, so they cannot collide with a caller's key.
      padding =
        for i <- 1..(next_power - count) do
          {"__PAD__#{String.pad_leading(Integer.to_string(i), 16, "0")}", @padding_leaf_hash}
        end

      leaves ++ padding
    end
  end

  # Build tree from pre-computed leaf hashes
  defp build_tree_from_leaf_hashes(leaves) do
    leaves
    |> Enum.map(fn {_key, leaf_hash} -> leaf_hash end)
    |> build_levels_from_leaf_hashes()
  end

  # ============================================================================
  # Convenience Wrappers for Streaming
  # ============================================================================

  @doc """
  Creates a Merkle tree from an enumerable using extractor functions.

  This is the most flexible convenience wrapper - it works with any data type
  by using the provided functions to extract keys and hashes.

  **Performance note**: slower than `new/1`, by roughly a quarter at 100k entries and
  by more than that as the count grows, because of the per-entry extractor calls and
  the builder's duplicate detection. Use `new/1` when all entries are available upfront
  and performance is critical. See `Merkle.Builder` docs for measured figures and how
  much to trust them.

  ## Options

    * `:key_fn` (required) - Function to extract key from each element
    * `:hash_fn` (required) - Function to extract hash from each element
    * `:sort` (default: `true`) - Whether to sort by key

  ## Examples

      # From a list of structs
      tree = records |> Merkle.from_stream(key_fn: & &1.id, hash_fn: & &1.digest)

      # From a database stream
      tree = Repo.stream(query)
             |> Merkle.from_stream(key_fn: & &1.id, hash_fn: & &1.hash)

      # Disable sorting for pre-sorted data
      tree = sorted_records
             |> Merkle.from_stream(key_fn: & &1.id, hash_fn: & &1.hash, sort: false)

  """
  @spec from_stream(Enumerable.t(), keyword()) :: t()
  def from_stream(enumerable, opts) do
    key_fn = Keyword.fetch!(opts, :key_fn)
    hash_fn = Keyword.fetch!(opts, :hash_fn)

    enumerable
    |> Enum.reduce(builder(), fn entry, b ->
      add_entry(b, %{"key" => key_fn.(entry), "hash" => hash_fn.(entry)})
    end)
    |> finalize(Keyword.take(opts, [:sort]))
  end

  @doc """
  Creates a Merkle tree from an enumerable of maps with "key" and "hash" fields.

  This is the stream-equivalent of `new/1` - use it when your data is already
  in the standard `%{"key" => ..., "hash" => ...}` format.

  **Performance note**: this is the builder path with no conversion on top, so it
  measures within a few percent of `builder + finalize`: close to `new/1` at 100k
  entries and around 2.5x slower at a million, where the duplicate-detection map
  starts to cost real time. Use `new/1` when all entries are available upfront and
  performance is critical. See `Merkle.Builder` docs for measured figures and how
  much to trust them.

  ## Options

    * `:sort` (default: `true`) - Whether to sort by key

  ## Examples

      tree = map_stream |> Merkle.from_maps()
      tree = map_stream |> Merkle.from_maps(sort: false)

  """
  @spec from_maps(Enumerable.t(), keyword()) :: t()
  def from_maps(enumerable, opts \\ []) do
    enumerable
    |> Enum.reduce(builder(), &add_entry(&2, &1))
    |> finalize(opts)
  end

  @doc """
  Creates a Merkle tree from an enumerable of `{key, hash}` tuples.

  **Performance note**: the slowest of the three wrappers, around 1.5x `new/1` at
  100k entries, because every tuple is turned into a map before the builder sees it.
  Use `new/1` when all entries are available upfront and performance is critical. See
  `Merkle.Builder` docs for measured figures and how much to trust them.

  ## Options

    * `:sort` (default: `true`) - Whether to sort by key

  ## Examples

      tree = [{id1, hash1}, {id2, hash2}] |> Merkle.from_tuples()
      tree = tuple_stream |> Merkle.from_tuples(sort: false)

  """
  @spec from_tuples(Enumerable.t(), keyword()) :: t()
  def from_tuples(enumerable, opts \\ []) do
    enumerable
    |> Enum.reduce(builder(), fn {key, hash}, b ->
      add_entry(b, %{"key" => key, "hash" => hash})
    end)
    |> finalize(opts)
  end

  # ============================================================================
  # Original API Functions
  # ============================================================================

  @doc """
  Creates a new Merkle tree from a list of key-hash maps.

  **This is the fastest tree construction method**, and it is also the one whose cost
  stays closest to linear as the entry count grows: roughly 160k entries/sec at both
  100k and 1M entries on an Apple M-series laptop. Treat that as indicative, since the
  same build varies by more than a factor of two with the calling process's heap state.
  Use this when all entries are available upfront. For streaming or incremental input,
  use the Builder pattern or convenience wrappers
  (`from_stream/2`, `from_maps/2`, `from_tuples/2`). `Merkle.Builder` carries the
  full comparison.

  Input data should be a list of maps with "key" and "hash" keys:
  - "key": Alphanumeric string with optional .-_ separators (max 36 chars)
  - "hash": Pre-computed SHA-256 digest as 64-character lowercase hex string (^[a-f0-9]{64}$)

  ## Duplicate Keys

  Every key must appear exactly once. A key that appears twice raises
  `ArgumentError`, whether or not the two hashes agree. The Builder is looser:
  `add_entry/2` ignores a repeat whose hash matches the one it already holds for
  that key, and only raises when the hashes differ. So the builder path accepts
  everything `new/2` accepts, plus repeats of identical entries, and for any input
  both accept the two produce the same root.

  ## Empty Input

  `new([])` builds the empty tree, whose root is `SHA256("")`.
  `finalize/2` on a builder that was never fed returns the same tree. That root is not
  the leaf hash of anything, so no inclusion proof can verify against it: a `false`
  from `verify/3` against an empty tree's root is the right answer rather than a fault.

  **Important**: The "hash" value must be a pre-computed SHA-256 digest of your source data,
  not the raw data itself. This allows the Merkle tree to operate on existing cryptographic
  hashes without needing to process arbitrary-sized source documents.

  ## Options

    * `:sort` (default: `true`) - When `true`, sorts input by key for deterministic
      ordering. When `false`, preserves the exact order of input data. Different
      orderings produce different Merkle roots.

  The tree is constructed by:
  1. Validating input format
  2. Optionally sorting input by key (default: true)
  3. Rejecting duplicate keys
  4. Padding to next power of 2 if needed
  5. Building a complete binary tree
  6. Using domain separation (0x00/0x01 prefixes) on every leaf and node

  ## Examples

      iex> # Default behavior: sorts by key
      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-2", "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> is_binary(tree.root_hash)
      true
      iex> tree.tree_depth
      1
      iex> Truestamp.Merkle.root(tree)
      "27fdfb0ec5b8a6cd13283e2c192d32ee5baee7aa4807e96287008f42598c51d1"

      iex> # Preserving input order: sort: false
      iex> data = [
      ...>   %{"key" => "z-last", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "a-first", "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"}
      ...> ]
      iex> # With sorting (default), keys would be reordered to [a-first, z-last]
      iex> sorted_tree = Truestamp.Merkle.new(data)
      iex> # Without sorting, order is preserved as [z-last, a-first]
      iex> unsorted_tree = Truestamp.Merkle.new(data, sort: false)
      iex> # Different orders produce different roots
      iex> Truestamp.Merkle.root(sorted_tree) != Truestamp.Merkle.root(unsorted_tree)
      true

  """
  @spec new([%{binary() => binary()}], keyword()) :: t()
  def new(data, opts \\ [])

  def new([], _opts) do
    # Empty tree: root hash is HASH("") - hash of empty string
    # This provides a deterministic, cryptographically sound value
    empty_tree_hash = :crypto.hash(:sha256, <<>>)

    %__MODULE__{
      root_hash: empty_tree_hash,
      leaves: [],
      tree_depth: 0,
      tree_levels: [{empty_tree_hash}],
      leaf_index: %{}
    }
  end

  def new(data, opts) when is_list(data) do
    # Validate input data format
    validate_input_data!(data)

    # Sort by default, so the same set of entries always yields the same root
    sort? = Keyword.get(opts, :sort, true)

    # Optionally sort for deterministic ordering
    leaves =
      data
      |> Enum.map(fn %{"key" => key, "hash" => hash} -> {key, hash} end)
      |> then(fn normalized_data ->
        if sort? do
          Enum.sort_by(normalized_data, &elem(&1, 0))
        else
          normalized_data
        end
      end)

    # Build leaf index map for O(1) key lookup
    leaf_index = build_leaf_index(leaves)

    leaf_count = length(leaves)

    # The index keys on the leaf key, so a key that repeats collapses two leaves
    # into one entry. Comparing sizes catches that without a second pass; only the
    # failing path pays to find out which key it was.
    if map_size(leaf_index) != leaf_count do
      raise_duplicate_key!(leaves)
    end

    # Hash the real leaves, then fill the bottom level out to a power of two with
    # the padding leaf hash. Every padding slot holds the same value, so it is a
    # constant the module works out at compile time rather than something to
    # re-derive per slot. Padding slots need no key: the leaf index above is
    # built from the real leaves and nothing looks a padding slot up by name.
    padded_count = next_power_of_two(leaf_count)

    leaf_hashes =
      Enum.map(leaves, fn {_key, hash} -> hash_leaf(hash) end) ++
        List.duplicate(@padding_leaf_hash, padded_count - leaf_count)

    # Build the tree with all levels stored for fast proof generation
    {root_hash, tree_levels} = build_levels_from_leaf_hashes(leaf_hashes)
    tree_depth = calculate_depth(padded_count)

    # Convert each level from list to tuple so proof generation can use elem/2
    # for O(1) sibling access instead of Enum.at/2 which is O(n) on lists.
    # One-time O(n) cost at construction; pays for itself on the first proof.
    tuple_levels = Enum.map(tree_levels, &List.to_tuple/1)

    %__MODULE__{
      root_hash: root_hash,
      leaves: leaves,
      tree_depth: tree_depth,
      tree_levels: tuple_levels,
      leaf_index: leaf_index
    }
  end

  def new(data, _opts) do
    raise ArgumentError,
          "Invalid input data. Expected a list of maps with \"key\" and \"hash\" keys, got: #{inspect(data, limit: 10)}"
  end

  @doc """
  Returns the root hash of the Merkle tree as a lowercase hex string.

  ## Examples

      iex> data = [%{"key" => "entry", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}]
      iex> tree = Truestamp.Merkle.new(data)
      iex> root = Truestamp.Merkle.root(tree)
      iex> is_binary(root) and String.length(root) == 64
      true

  """
  @spec root(t()) :: binary()
  def root(%__MODULE__{root_hash: root_hash}) do
    # Encode binary root hash to hex string for external API
    encode_hex(root_hash)
  end

  @doc """
  Generates a Merkle proof for the given key.

  Returns a list of proof steps, where each step is a string in the format "direction:hash".
  The direction is "l" for left or "r" for right, indicating where the hash should be
  placed when reconstructing the path to the root.

  Returns `nil` if the key is not found in the tree.

  **Note**: Single-element trees return empty proofs `[]` since there are no sibling
  nodes required to prove inclusion.

  ## Examples

      iex> data = [
      ...>   %{"key" => "entry-a", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-b", "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> proof = Truestamp.Merkle.proof(tree, "entry-a")
      iex> is_list(proof)
      true
      iex> proof
      ["r:ace7a3c346f28a627f857ad504ddb16935e754ed64d641729dad35fb63e1138e"]
      iex> Truestamp.Merkle.proof(tree, "entry-b")
      ["l:642fab7c2f9470c67cff3bd9bdddb9e4fdf55141571f5e544ebe8b135f78303f"]

  """
  @spec proof(t(), binary()) :: proof() | nil
  def proof(%__MODULE__{leaf_index: leaf_index, tree_depth: depth, tree_levels: tree_levels}, key) do
    # Hot path: an O(1) map lookup rather than a linear scan of the leaves.
    # For a 50K-leaf tree that is one lookup per proof, not ~25K comparisons on average.
    case Map.get(leaf_index, key) do
      nil -> nil
      index -> generate_proof_optimized(tree_levels, index, depth)
    end
  end

  @doc """
  Verifies a Merkle proof against a root hash.

  Takes a proof, the expected root hash, and the hash value (pre-computed SHA-256 digest).
  Returns true if the proof is valid, false otherwise.

  **Parameters**:
  - `proof`: List of proof steps in "direction:hash" format
  - `root_hash`: Expected root hash as a 64-character lowercase hex string
  - `hash`: Pre-computed SHA-256 digest as a 64-character lowercase hex string
    (same value used in tree creation)

  Every hash here is lowercase hex only, proof siblings included. Uppercase input is
  rejected as malformed, which surfaces as `false` and is indistinguishable from a
  proof that genuinely fails. If a hash reaches you in uppercase, downcase it before
  calling rather than reading the `false` as a cryptographic result.

  **Security Features**:
  - Validates all inputs before processing (prevents crashes from malformed data)
  - Caps the proof at #{@max_proof_depth} steps, so the work an untrusted proof can
    ask for is bounded
  - Compares the root in constant time
  - Refuses the reserved padding constant `#{@empty_leaf_hash_hex}` as a leaf value.
    Padding slots are placed by the tree, never by a caller, so a proof presented for
    that value proves a padding slot rather than one of your entries. Only the value
    being proved is refused; the padding leaf's hash remains a valid proof sibling.

  ## Examples

      iex> # Verify proof for single-element tree (empty proof)
      iex> data = [%{"key" => "entry", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}]
      iex> tree = Truestamp.Merkle.new(data)
      iex> proof = Truestamp.Merkle.proof(tree, "entry")
      iex> proof
      []
      iex> root = Truestamp.Merkle.root(tree)
      iex> Truestamp.Merkle.verify(proof, root, "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
      true
      iex>
      iex> # Verify proof for two-element tree
      iex> data2 = [
      ...>   %{"key" => "entry-a", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-b", "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
      ...> ]
      iex> tree2 = Truestamp.Merkle.new(data2)
      iex> proof2 = Truestamp.Merkle.proof(tree2, "entry-a")
      iex> root2 = Truestamp.Merkle.root(tree2)
      iex> Truestamp.Merkle.verify(proof2, root2, "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
      true

  """
  @spec verify(proof(), binary(), binary()) :: boolean()
  def verify(proof, root_hash, hash) when is_list(proof) do
    # Comprehensive input validation - returns false for any invalid input
    with :ok <- validate_proof_size(proof),
         :ok <- validate_hex_hash(root_hash),
         :ok <- validate_hex_hash(hash),
         :ok <- reject_reserved_leaf(hash),
         :ok <- validate_proof_format(proof) do
      # All inputs valid - proceed with verification
      perform_verification(proof, root_hash, hash)
    else
      {:error, _reason} -> false
    end
  end

  # Catch-all for non-list proof inputs
  def verify(_proof, _root_hash, _hash), do: false

  # ── Compact Proof Encoding ──────────────────────────────────────────

  @doc """
  Encode a proof list into a compact binary format.

  The binary format packs direction flags into a bitfield and stores sibling
  hashes as raw 32-byte values, eliminating the overhead of hex encoding and
  "l:"/"r:" string prefixes.

  ## Binary Layout

      byte 0:      depth (uint8, number of proof steps)
      bytes 1..D:  direction bitfield, ceil(depth/8) bytes
                   bit N: 0 = left sibling ("l:"), 1 = right sibling ("r:")
      bytes D+1..: depth * 32 bytes of sibling hashes (raw binary, bottom to top)

  ## Input Requirements

  The proof list must hold at most #{@max_proof_depth} steps, and every step must be
  `"l:"` or `"r:"` followed by a #{@expected_hash_hex_chars}-character lowercase hex
  SHA-256 hash. These are the same invariants `decode_proof/1` enforces, so anything
  this function accepts decodes back to exactly what was passed in.

  ## Return Value and Errors

  Returns the binary directly rather than an `{:ok, binary}` tuple, because encoding
  validated input cannot fail. Anything that would not survive the round trip raises
  `ArgumentError` instead: a list longer than #{@max_proof_depth}, or an element that
  is not a well formed `"l:"` / `"r:"` step. Decoding takes untrusted bytes, so
  `decode_proof/1` returns `{:ok, proof}` or `{:error, reason}`.

  ## Examples

      iex> proof = ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]
      iex> binary = Truestamp.Merkle.encode_proof(proof)
      iex> byte_size(binary)
      34
      iex> {:ok, decoded} = Truestamp.Merkle.decode_proof(binary)
      iex> decoded == proof
      true

      iex> Truestamp.Merkle.encode_proof([])
      <<0>>

  """
  @spec encode_proof(proof()) :: binary()
  def encode_proof([]), do: <<0::8>>

  def encode_proof(proof_list) when is_list(proof_list) do
    depth = length(proof_list)

    if depth > @max_proof_depth do
      raise ArgumentError,
            "Invalid proof length. Expected at most #{@max_proof_depth} steps, got: #{depth}"
    end

    {direction_bits, hashes} =
      proof_list
      |> Enum.with_index()
      |> Enum.reduce({0, <<>>}, fn {item, index}, {bits, hash_acc} ->
        {bit, hex_hash} = encodable_proof_element!(item)
        new_bits = Bitwise.bor(bits, Bitwise.bsl(bit, index))
        hash_binary = Base.decode16!(hex_hash, case: :lower)
        {new_bits, hash_acc <> hash_binary}
      end)

    bitfield_bytes = div(depth + 7, 8)
    <<depth::8, direction_bits::little-size(bitfield_bytes * 8), hashes::binary>>
  end

  # Accept exactly what decode_proof/1 can produce: an "l:" or "r:" prefix followed by
  # @expected_hash_hex_chars lowercase hex characters. Returns the direction bit and the
  # hex hash, or raises for anything that would not survive the round trip.
  defp encodable_proof_element!(
         <<prefix::binary-size(2), hex_hash::binary-size(@expected_hash_hex_chars)>> = item
       )
       when prefix in ["l:", "r:"] do
    unless lowercase_hex_binary?(hex_hash) do
      raise ArgumentError,
            "Invalid proof element hash. Expected #{@expected_hash_hex_chars} lowercase hex characters, got: #{inspect(item)}"
    end

    bit = if prefix == "r:", do: 1, else: 0
    {bit, hex_hash}
  end

  defp encodable_proof_element!(invalid) do
    raise ArgumentError,
          ~s(Invalid proof element format. Expected "l:" or "r:" followed by #{@expected_hash_hex_chars} lowercase hex characters, got: #{inspect(invalid)})
  end

  defp lowercase_hex_binary?(<<>>), do: true

  defp lowercase_hex_binary?(<<char, rest::binary>>)
       when char in ?0..?9 or char in ?a..?f,
       do: lowercase_hex_binary?(rest)

  defp lowercase_hex_binary?(_), do: false

  @doc """
  Decode a compact binary proof back to the standard proof list format.

  ## Examples

      iex> binary = <<1, 1, 94, 92, 174, 175, 194, 113, 85, 195, 104, 182, 242, 1, 16, 125,
      ...>   111, 139, 39, 7, 71, 206, 99, 106, 197, 23, 74, 86, 198, 225, 46, 248, 154, 209>>
      iex> {:ok, proof} = Truestamp.Merkle.decode_proof(binary)
      iex> proof
      ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]

      iex> {:ok, proof} = Truestamp.Merkle.decode_proof(<<0>>)
      iex> proof
      []

  """
  @spec decode_proof(binary()) :: {:ok, proof()} | {:error, term()}
  def decode_proof(<<0::8>>), do: {:ok, []}

  def decode_proof(<<depth::8, rest::binary>>) when depth > 0 and depth <= @max_proof_depth do
    bitfield_bytes = div(depth + 7, 8)
    expected_hash_bytes = depth * 32

    case rest do
      <<direction_bits::little-size(^bitfield_bytes * 8),
        hashes::binary-size(^expected_hash_bytes)>> ->
        {:ok, decode_proof_entries(depth, direction_bits, hashes)}

      _ ->
        {:error,
         "Invalid proof binary: expected #{bitfield_bytes + expected_hash_bytes} bytes after depth, got #{byte_size(rest)}"}
    end
  end

  def decode_proof(<<depth::8, _rest::binary>>) when depth > @max_proof_depth do
    {:error, "Proof depth #{depth} exceeds maximum #{@max_proof_depth}"}
  end

  def decode_proof(_), do: {:error, "Invalid proof binary format"}

  defp decode_proof_entries(depth, direction_bits, hashes) do
    for i <- 0..(depth - 1) do
      bit = Bitwise.band(Bitwise.bsr(direction_bits, i), 1)
      direction = if bit == 1, do: "r", else: "l"
      hash_binary = binary_part(hashes, i * 32, 32)
      hex_hash = Base.encode16(hash_binary, case: :lower)
      "#{direction}:#{hex_hash}"
    end
  end

  @doc """
  Encode a proof list to a base64url string (no padding).

  Delegates to `encode_proof/1`, so it applies the same input requirements and raises
  the same `ArgumentError` for a list longer than #{@max_proof_depth} steps or an
  element that is not a well formed `"l:"` / `"r:"` step. Returns the string directly;
  `decode_proof_base64/1` returns `{:ok, proof}` or `{:error, reason}`.

  ## Examples

      iex> proof = ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]
      iex> encoded = Truestamp.Merkle.encode_proof_base64(proof)
      iex> {:ok, decoded} = Truestamp.Merkle.decode_proof_base64(encoded)
      iex> decoded == proof
      true

      iex> Truestamp.Merkle.encode_proof_base64([])
      "AA"

  """
  @spec encode_proof_base64(proof()) :: String.t()
  def encode_proof_base64(proof_list) do
    proof_list
    |> encode_proof()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Decode a base64url-encoded compact proof back to the standard proof list format.

  ## Examples

      iex> {:ok, proof} = Truestamp.Merkle.decode_proof_base64("AA")
      iex> proof
      []

  """
  @spec decode_proof_base64(String.t()) :: {:ok, proof()} | {:error, term()}
  def decode_proof_base64(base64_string) when is_binary(base64_string) do
    case Base.url_decode64(base64_string, padding: false) do
      {:ok, binary} -> decode_proof(binary)
      :error -> {:error, "Invalid base64url encoding"}
    end
  end

  # Private helper functions

  defp perform_verification(proof, root_hash, hash) do
    # Start with the leaf hash (returns binary)
    leaf_hash = hash_leaf(hash)

    # Follow the proof path to reconstruct the root
    computed_root =
      Enum.reduce(proof, leaf_hash, fn proof_step, current_hash ->
        [direction, sibling_hash] = String.split(proof_step, ":", parts: 2)
        # Decode hex sibling_hash to binary for hash_internal
        sibling_binary = decode_hex(sibling_hash)

        case direction do
          "l" -> hash_internal(sibling_binary, current_hash)
          "r" -> hash_internal(current_hash, sibling_binary)
        end
      end)

    # Constant-time comparison, kept as a matter of habit rather than because
    # anything depends on it. The computed root, the expected root, the proof and
    # the leaf value are all public, so there is no secret for the comparison to
    # leak and no timing channel to close. It costs nothing and keeps the door shut
    # if a caller ever compares something that is not public.
    constant_time_compare(computed_root, decode_hex(root_hash))
  end

  # :crypto.hash_equals/2 requires OTP 25 or newer.
  defp constant_time_compare(a, b) when byte_size(a) == byte_size(b) do
    :crypto.hash_equals(a, b)
  end

  defp constant_time_compare(_a, _b), do: false

  # Bound the hashing a proof from an untrusted source can ask verify/3 to do.
  defp validate_proof_size(proof) when is_list(proof) do
    if length(proof) > @max_proof_depth do
      {:error, "Proof exceeds maximum depth of #{@max_proof_depth}"}
    else
      :ok
    end
  end

  # Validate hex hash format - must be exactly @expected_hash_hex_chars (64) lowercase hex chars
  # This enforces 32-byte hashes at verification time as defense-in-depth against second preimage attacks
  defp validate_hex_hash(hash) when is_binary(hash) do
    if hex_hash?(hash) do
      :ok
    else
      {:error, "Invalid hash format"}
    end
  end

  defp validate_hex_hash(_), do: {:error, "Hash must be a string"}

  # Exactly @expected_hash_hex_chars bytes, every one of them lowercase hex.
  #
  # Matching the head width first is what makes this exact. A regex ending in
  # `$` would also accept a hash followed by a single newline, because that
  # is what `$` means in PCRE, and the trailing byte then blows up in
  # Base.decode16!/2 well past the point where the caller was promised a clean
  # rejection. Walking the bytes is also several times faster than a sigil in a
  # function body, which the compiler rebuilds on every call.
  defp hex_hash?(<<hash::binary-size(@expected_hash_hex_chars)>>), do: hex_chars?(hash)
  defp hex_hash?(_), do: false

  defp hex_chars?(<<>>), do: true
  defp hex_chars?(<<c, rest::binary>>) when c in ?0..?9 or c in ?a..?f, do: hex_chars?(rest)
  defp hex_chars?(_), do: false

  # A proof presented FOR the padding constant is a proof of a padding slot, not
  # of a real entry. validate_hash!/1 refuses the constant on every construction
  # surface, so no honest tree carries it as a real leaf and there is nothing
  # legitimate to reject here. Applies to the leaf value only: the padding leaf
  # hash (SHA-256(0x00 || this)) is a normal sibling in most padded proofs and
  # must keep verifying, so validate_proof_element/1 is deliberately untouched.
  defp reject_reserved_leaf(@empty_leaf_hash_hex), do: {:error, "Reserved padding constant"}
  defp reject_reserved_leaf(_), do: :ok

  # Validate proof format - each element must be "direction:hash"
  defp validate_proof_format(proof) when is_list(proof) do
    Enum.reduce_while(proof, :ok, fn item, _acc ->
      case validate_proof_element(item) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  # Validate individual proof element format
  defp validate_proof_element(item) when is_binary(item) do
    case String.split(item, ":", parts: 2) do
      [direction, hash] when direction in ["l", "r"] ->
        validate_hex_hash(hash)

      _ ->
        {:error, "Invalid proof element format"}
    end
  end

  defp validate_proof_element(_), do: {:error, "Proof element must be a string"}

  defp next_power_of_two(n) when n <= 1, do: 1

  defp next_power_of_two(n) do
    # Use integer bit operations to avoid floating-point precision issues
    Bitwise.bsl(1, integer_log2_ceil(n))
  end

  defp calculate_depth(leaf_count) do
    next_power = next_power_of_two(leaf_count)
    # For powers of 2, trailing zeros count gives exact log2
    depth = integer_log2(next_power)

    # Validate depth doesn't exceed maximum
    if depth > @max_tree_depth do
      raise ArgumentError,
            "Tree depth #{depth} exceeds maximum #{@max_tree_depth} (#{leaf_count} leaves)"
    end

    depth
  end

  # Exact integer log2 for powers of 2 (counts trailing zeros)
  defp integer_log2(1), do: 0
  defp integer_log2(n) when n > 0, do: integer_log2(Bitwise.bsr(n, 1)) + 1

  # Ceiling of log2(n) using bit operations
  defp integer_log2_ceil(n) when n <= 1, do: 0

  defp integer_log2_ceil(n) do
    # log2_ceil(n) = log2_floor(n-1) + 1
    integer_log2_floor(n - 1) + 1
  end

  defp integer_log2_floor(1), do: 0
  defp integer_log2_floor(n) when n > 1, do: integer_log2_floor(Bitwise.bsr(n, 1)) + 1

  # Build every level bottom up from a full power-of-two row of leaf hashes,
  # keeping each level for fast proof generation.
  defp build_levels_from_leaf_hashes(leaf_hashes) do
    levels = build_tree_levels(leaf_hashes, [leaf_hashes])
    root_hash = levels |> List.last() |> List.first()
    {root_hash, levels}
  end

  defp build_tree_levels([_root_hash], levels), do: Enum.reverse(levels)

  defp build_tree_levels(hashes, levels) do
    next_level =
      hashes
      |> Enum.chunk_every(2)
      |> Enum.map(fn
        [left, right] -> hash_internal(left, right)
        # This should never happen due to power-of-2 padding - assert invariant
        [_single] -> raise "Invalid tree level: odd number of nodes after padding"
      end)

    build_tree_levels(next_level, [next_level | levels])
  end

  # Build a map of {key => index} for O(1) leaf lookups during proof generation.
  # The map is stored in the struct, which is what keeps proof/2 off a linear scan
  # of the leaves list.
  defp build_leaf_index(leaves) do
    leaves
    |> Enum.with_index()
    |> Map.new(fn {{key, _hash}, index} -> {key, index} end)
  end

  # Called only once a size mismatch has proven a repeat exists, so the scan
  # always halts on a key.
  defp raise_duplicate_key!(leaves) do
    key =
      Enum.reduce_while(leaves, MapSet.new(), fn {key, _hash}, seen ->
        if MapSet.member?(seen, key) do
          {:halt, key}
        else
          {:cont, MapSet.put(seen, key)}
        end
      end)

    raise ArgumentError,
          "Duplicate key in input data: #{inspect(key)}. Every key must be unique."
  end

  defp generate_proof_optimized(tree_levels, target_index, depth) do
    # Use pre-computed tree levels for O(log n) proof generation
    generate_proof_path_optimized(tree_levels, target_index, depth, 0, [])
  end

  defp generate_proof_path_optimized(_tree_levels, _index, depth, current_level, proof)
       when current_level >= depth do
    Enum.reverse(proof)
  end

  defp generate_proof_path_optimized(tree_levels, index, depth, current_level, proof) do
    # Enum.at/2 is O(depth) on the levels list, but depth is at most @max_tree_depth (40),
    # so this is bounded and small. The element access below is the cost that matters.
    level_hashes = Enum.at(tree_levels, current_level)

    {sibling_index, direction} =
      if rem(index, 2) == 0 do
        {index + 1, "r"}
      else
        {index - 1, "l"}
      end

    # Hot path: levels are tuples, so elem/2 reaches a sibling in O(1). The bottom
    # level can hold 65K+ elements (the next power of two above the leaf count),
    # where walking a list would dominate the time spent generating a proof.
    sibling_hash = elem(level_hashes, sibling_index)

    # Move to next level
    next_index = div(index, 2)
    # Encode binary sibling_hash to hex for external proof string format
    new_proof = ["#{direction}:#{encode_hex(sibling_hash)}" | proof]

    generate_proof_path_optimized(tree_levels, next_index, depth, current_level + 1, new_proof)
  end

  # The 0x00 prefix keeps a leaf hash out of the interior-node domain, so an interior
  # node can never be presented as a leaf
  defp hash_leaf(hash) do
    # Decode hex hash to binary before hashing for correct cryptographic operation
    # Return binary for efficient internal operations
    decoded_hash = decode_hex(hash)
    :crypto.hash(:sha256, <<0x00>> <> decoded_hash)
  end

  # The 0x01 prefix keeps an interior hash out of the leaf domain, so a leaf can never
  # be presented as an interior node
  defp hash_internal(left_hash, right_hash) do
    # Both inputs are binary from hash_leaf or previous hash_internal calls
    # Return binary for efficient internal operations
    :crypto.hash(:sha256, <<0x01>> <> left_hash <> right_hash)
  end

  # Standalone hex encoding helper (no external dependencies)
  defp encode_hex(binary) do
    Base.encode16(binary, case: :lower)
  end

  # Standalone hex decoding helper (no external dependencies)
  defp decode_hex(hex_string) do
    Base.decode16!(hex_string, case: :lower)
  end

  # Input validation helpers
  defp validate_input_data!(data) do
    Enum.each(data, &validate_input_entry!/1)
  end

  defp validate_input_entry!(%{"key" => key, "hash" => hash}) do
    validate_key!(key)
    validate_hash!(hash)
  end

  defp validate_input_entry!(invalid) do
    raise ArgumentError,
          "Invalid input entry format. Expected map with \"key\" and \"hash\" keys, got: #{inspect(invalid, limit: 10)}"
  end

  defp validate_key!(key) when is_binary(key) do
    # Check length (max 36 characters)
    if String.length(key) > 36 do
      raise ArgumentError,
            "Invalid key length. Expected maximum 36 characters, got: #{String.length(key)}"
    end

    # Check for leading/trailing spaces
    trimmed = String.trim(key)

    if trimmed != key do
      raise ArgumentError,
            "Invalid key format. Keys must not have leading or trailing spaces, got: #{inspect(key, limit: 10)}"
    end

    # Check character set: alphanumeric, hyphen, underscore, period only
    if key == "" or not key_chars?(key) do
      raise ArgumentError,
            "Invalid key format. Expected alphanumeric characters with optional .-_ separators, got: #{inspect(key, limit: 10)}"
    end

    # Reject keys that could collide with internal padding prefix
    if String.starts_with?(String.downcase(key), "__pad__") do
      raise ArgumentError,
            "Invalid key format. Keys must not use reserved padding prefix, got: #{inspect(key, limit: 10)}"
    end
  end

  defp validate_key!(invalid) do
    raise ArgumentError, "Invalid key type. Expected string, got: #{inspect(invalid, limit: 10)}"
  end

  # ASCII letters, digits, and the three separators. Byte-wise, so any
  # multi-byte character fails on its lead byte.
  defp key_chars?(<<>>), do: true

  defp key_chars?(<<c, rest::binary>>)
       when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?., ?_, ?-],
       do: key_chars?(rest)

  defp key_chars?(_), do: false

  defp validate_hash!(hash) when is_binary(hash) do
    # Validate exactly @expected_hash_hex_chars (64) hex characters
    # This enforces 32-byte hashes as defense-in-depth against second preimage attacks
    unless hex_hash?(hash) do
      raise ArgumentError,
            "Invalid hash format. Expected #{@expected_hash_hex_chars}-character lowercase hex SHA-256 hash (#{@expected_hash_bytes} bytes), got: #{inspect(hash, limit: 10)}"
    end

    # Reject the reserved padding constant. A padded slot stands for this value,
    # but construction splices the slot's leaf hash straight in and never routes
    # the constant through here, so no honest tree can carry it as a real leaf.
    # That invariant is what lets verify/3 refuse it outright.
    if hash == @empty_leaf_hash_hex do
      raise ArgumentError,
            "Invalid hash. #{@empty_leaf_hash_hex} is the reserved Merkle padding constant and must not be used as an entry hash."
    end
  end

  defp validate_hash!(invalid) do
    raise ArgumentError, "Invalid hash type. Expected string, got: #{inspect(invalid, limit: 10)}"
  end
end
