# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle do
  @moduledoc """
  Pure Elixir Merkle tree implementation.

  Secure, deterministic Merkle tree for cryptographic applications. Handles millions of
  leaves with strong security properties and a simple API. Standalone module with zero
  external dependencies beyond `:crypto` and `Base`. Requires Elixir 1.20, and so OTP 27
  or newer.

  You supply entries: a key, plus a 32-byte digest you have already computed over
  whatever that key names. The tree sorts, pads and hashes those into leaves. What a key
  identifies, and what the digest was taken over, are entirely yours to decide.

  Size a large workload by memory before you size it by time. A finished tree holds about
  300 bytes of heap per entry, and building one needs a good deal more while the input
  list, the tree's levels and the finished tree are all alive at once: budget around
  1.5 GB per million entries rather than the retained size. The README's Performance
  section has measured build, proof and verification times, and `bench/performance.exs`
  reproduces them on your hardware.

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
  in both directions: `new/2` raises `ArgumentError` if you hand it
  in as an entry hash, `walk/3` refuses it with `{:error, :reserved_leaf}`, and
  `verify/4` returns `false` if you present it as the value being proved, because such
  a proof proves a padding slot rather than an entry.
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
  not a synonym for it: `new/2` raises `ArgumentError` on an uppercase hash, `walk/3`
  refuses an uppercase leaf value or proof sibling, and `verify/4` returns `false` for
  an uppercase root, leaf value, or proof sibling, which looks exactly like a proof that
  does not check out. Hexdump tools commonly emit uppercase, so downcase before handing
  anything over.

  ## Limits and Where They Apply

  The 64-step proof cap is a real bound on work: it is what keeps `walk/3`, `verify/4`,
  `steps_from_binary/1`, and `decode_proof_base64/1` cheap on bytes from a stranger. Those
  four are the entry points safe to put in front of untrusted callers, and `walk/3` and
  `verify/4` take a lower cap through `:max_steps`.

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
      iex> Truestamp.Merkle.verify("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", proof, root_hash)
      true
      iex> single = [%{"key" => "single-entry", "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"}]
      iex> single_tree = Truestamp.Merkle.new(single)
      iex> Truestamp.Merkle.proof(single_tree, "single-entry")
      []

  ## Known Answers

  `vectors/merkle.json` in this repository holds the known answers a port of the tree
  must reproduce: roots, paths and their encodings for trees of 0 to 7 entries, 300
  entries and a set of mixed keys, plus the inputs that construction, `walk/3` and the
  decoders must refuse. `vectors/generate.exs` writes it from the tree contract in
  `README.md` without using this module, and the tests hold this module to every value.

  ## API Summary

  - `new/2` - Create tree from a list of `%{"key" => ..., "hash" => ...}` entries
  - `root/1` - Get root hash as hex string
  - `proof/2` - Generate inclusion proof for key (returns `nil` if not found)
  - `walk/3` - Recompute the root an inclusion path implies (returns `{:ok, root}` or an error)
  - `verify/4` - Check an inclusion path against a root hash (returns boolean)
  - `steps_to_binary/1`, `steps_from_binary/1` - The compact binary form of a path, for storage

  ## Error Handling

  - `new/2` raises `ArgumentError` for invalid keys, hashes, duplicate keys, excessive
    depth, or input that is not a list of entry maps
  - `proof/2` returns `nil` for non-existent keys
  - `walk/3` returns `{:ok, root}` or `{:error, reason}` for any input, and raises only for
    invalid options
  - `verify/4` returns `false` for any invalid input or failed verification, and raises
    only for invalid options
  - `steps_to_binary/1` and `encode_proof_base64/1` return the encoded value directly and raise
    `ArgumentError` for a proof that would not survive the round trip
  - `steps_from_binary/1` and `decode_proof_base64/1` take untrusted bytes, so they return
    `{:ok, proof}` or `{:error, reason}` rather than raising, where the reason is one of
    the atoms `binary_error()` and `decode_error()` list
  """

  # The public API. Each function delegates to the internal module that owns it:
  # Tree builds, Paths produces and walks paths, Codec encodes paths for storage,
  # Input holds the entry rules, and Hash the hashing and hex rules they all share.

  alias __MODULE__.{Codec, Hash, Paths, Tree}

  # Interpolated into the docs below.
  @max_proof_depth Paths.max_steps()
  @expected_hash_hex_chars Hash.digest_hex_chars()
  @empty_leaf_hash_hex Hash.reserved_digest_hex()

  defstruct [:root_hash, :leaves, :tree_depth, :tree_levels, :leaf_index]

  @type t :: %__MODULE__{
          root_hash: binary(),
          leaves: [{binary(), binary()}],
          tree_depth: non_neg_integer(),
          tree_levels: [tuple()],
          leaf_index: %{binary() => non_neg_integer()}
        }

  # A step is "l:" or "r:" followed by the sibling's 64 lowercase hex characters.
  @type proof_step :: binary()
  @type proof :: [proof_step()]

  @type walk_error :: :invalid_leaf | :reserved_leaf | :too_many_steps | :invalid_step

  @type binary_error :: :invalid_binary | :too_many_steps | :wrong_length | :unused_direction_bits

  @type decode_error :: binary_error() | :invalid_base64url

  # ── Building a tree from a list ───────────────────────────────────────────

  @doc """
  Creates a new Merkle tree from a list of key-hash maps.

  The README's Performance section has measured figures.

  Input data should be a list of maps with "key" and "hash" keys:
  - "key": Alphanumeric string with optional .-_ separators (max 36 chars)
  - "hash": Pre-computed SHA-256 digest as exactly 64 lowercase hex characters

  ## Duplicate Keys

  Every key must appear exactly once. A key that appears twice raises
  `ArgumentError`, whether or not the two hashes agree.

  ## Empty Input

  `new([])` builds the empty tree, whose root is `SHA256("")`. That root is not
  the leaf hash of anything, so no inclusion proof can verify against it: a `false`
  from `verify/4` against an empty tree's root is the right answer rather than a fault.

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
  defdelegate new(entries, opts \\ []), to: Tree

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
  def root(%__MODULE__{root_hash: root_hash}), do: Hash.to_hex(root_hash)

  # ── Proving an entry ──────────────────────────────────────────────────────

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
  def proof(%__MODULE__{leaf_index: index, tree_depth: depth, tree_levels: levels}, key) do
    # One map lookup finds the leaf, however large the tree.
    case Map.fetch(index, key) do
      {:ok, position} -> Paths.steps(levels, position, depth)
      :error -> nil
    end
  end

  @doc """
  Walks an inclusion path from a leaf value up to the root it implies.

  `leaf_hex` is the value being proved: the 64-character lowercase hex digest the
  entry carried when the tree was built. `steps` is the path `proof/2` returns, bottom
  to top. Each step is `l:` or `r:` followed by the sibling's 64 lowercase hex
  characters, where `l` puts the sibling on the left of the running hash and `r` on
  the right. The walk hashes the leaf as `SHA-256(0x00 || leaf)`, combines it with
  each sibling as `SHA-256(0x01 || left || right)`, and returns the hash it ends on.

  It is never given a root. Compare the result with a root you already trust, or call
  `verify/4`, which does that in constant time.

  ## Options

    * `:max_steps` - the longest path accepted, an integer from 0 to #{@max_proof_depth}.
      Defaults to #{@max_proof_depth}.

  An unknown option, or a `:max_steps` outside that range, raises `ArgumentError`.
  Everything else may come from a stranger, so it is refused with an error instead of
  raising. The checks run in this order:

    * `{:error, :invalid_leaf}` - `leaf_hex` is not exactly 64 lowercase hex characters.
    * `{:error, :reserved_leaf}` - `leaf_hex` is the reserved padding value
      `#{@empty_leaf_hash_hex}`. A path from it proves a padding slot, not an entry.
    * `{:error, :too_many_steps}` - `steps` holds more than `:max_steps` steps. The path
      is refused before any step is read, so the work a path can ask for is bounded.
    * `{:error, :invalid_step}` - `steps` is not a proper list, or a step is anything
      other than `l:` or `r:` and exactly 64 lowercase hex characters. Uppercase hex, a
      trailing newline and a bare hash without its direction are all refused.

  ## Examples

      iex> leaf = "2222222222222222222222222222222222222222222222222222222222222222"
      iex> steps = ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]
      iex> Truestamp.Merkle.walk(leaf, steps)
      {:ok, "96cfe136315282442cd0133b934dd99622a510c075930239725ced808ce7dfa0"}
      iex> Truestamp.Merkle.walk(leaf, steps, max_steps: 0)
      {:error, :too_many_steps}
      iex> Truestamp.Merkle.walk(leaf, ["R:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"])
      {:error, :invalid_step}
      iex> Truestamp.Merkle.walk(String.duplicate("A", 64), steps)
      {:error, :invalid_leaf}

  """
  @spec walk(term(), term(), keyword()) :: {:ok, binary()} | {:error, walk_error()}
  defdelegate walk(leaf_hex, steps, opts \\ []), to: Paths

  @doc """
  Verifies that `leaf_hex` is in the tree whose root is `root_hex`.

  Walks `steps` from `leaf_hex` exactly as `walk/3` does, with the same options, and
  compares the hash it ends on with `root_hex` in constant time. Returns `true` only
  when the walk succeeds and the two roots are equal.

  Every refusal `walk/3` reports, and a `root_hex` that is not 64 lowercase hex
  characters, returns `false`. That is indistinguishable from a path that genuinely
  fails, so call `walk/3` to learn which check refused it. If a hash reaches you in
  uppercase, downcase it first rather than reading the `false` as a cryptographic
  result. Only invalid options raise.

  The reserved padding value is refused as `leaf_hex` because padding slots are placed
  by the tree, never by a caller, so a path from it proves a padding slot rather than
  one of your entries. The padding leaf's hash remains a valid sibling in a path.

  ## Examples

      iex> data = [%{"key" => "entry", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}]
      iex> tree = Truestamp.Merkle.new(data)
      iex> steps = Truestamp.Merkle.proof(tree, "entry")
      iex> steps
      []
      iex> Truestamp.Merkle.verify("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", steps, Truestamp.Merkle.root(tree))
      true
      iex>
      iex> data2 = [
      ...>   %{"key" => "entry-a", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-b", "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
      ...> ]
      iex> tree2 = Truestamp.Merkle.new(data2)
      iex> steps2 = Truestamp.Merkle.proof(tree2, "entry-a")
      iex> Truestamp.Merkle.verify("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", steps2, Truestamp.Merkle.root(tree2))
      true
      iex> Truestamp.Merkle.verify("b1b2c3d4e5f67890123456789012345678901234567890123456789012345678", steps2, Truestamp.Merkle.root(tree2))
      false

  """
  @spec verify(term(), term(), term(), keyword()) :: boolean()
  defdelegate verify(leaf_hex, steps, root_hex, opts \\ []), to: Paths

  # ── Storing a path ────────────────────────────────────────────────────────

  @doc """
  Encodes a path as the compact binary form used for storage.

  The binary form packs the directions into a bitfield and stores each sibling as its
  raw 32 bytes, without the hex spelling or the `l:` / `r:` prefixes. It is the one
  canonical binary for a path: `steps_from_binary/1` accepts exactly what this function
  produces and nothing else.

  ## Binary Layout

      byte 0:      depth (uint8, number of proof steps)
      bytes 1..D:  direction bitfield, ceil(depth/8) bytes, little-endian
                   bit N: 0 = left sibling ("l:"), 1 = right sibling ("r:")
                   bits from depth up are always 0
      bytes D+1..: depth * 32 bytes of sibling hashes (raw binary, bottom to top)

  ## Input Requirements

  The proof list must hold at most #{@max_proof_depth} steps, and every step must be
  `"l:"` or `"r:"` followed by a #{@expected_hash_hex_chars}-character lowercase hex
  SHA-256 hash. These are the same invariants `steps_from_binary/1` enforces, so
  anything this function accepts decodes back to exactly what was passed in.

  ## Return Value and Errors

  Returns the binary directly rather than an `{:ok, binary}` tuple, because encoding
  validated input cannot fail. Anything that would not survive the round trip raises
  `ArgumentError` instead: a list longer than #{@max_proof_depth}, or an element that
  is not a well formed `"l:"` / `"r:"` step. Decoding takes untrusted bytes, so
  `steps_from_binary/1` returns `{:ok, steps}` or `{:error, reason}`.

  ## Examples

      iex> proof = ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]
      iex> binary = Truestamp.Merkle.steps_to_binary(proof)
      iex> byte_size(binary)
      34
      iex> {:ok, decoded} = Truestamp.Merkle.steps_from_binary(binary)
      iex> decoded == proof
      true

      iex> Truestamp.Merkle.steps_to_binary([])
      <<0>>

  """
  @spec steps_to_binary(proof()) :: binary()
  defdelegate steps_to_binary(steps), to: Codec

  @doc """
  Decodes the compact binary form back to a path of `l:` / `r:` steps.

  It takes untrusted bytes, so it returns `{:ok, steps}` or `{:error, reason}` and never
  raises. It accepts only the canonical encoding `steps_to_binary/1` produces: a depth of
  0 to #{@max_proof_depth}, exactly `ceil(depth / 8)` direction bytes with every bit from
  `depth` up clear, and exactly `depth` 32-byte siblings, with nothing after them. A set
  unused direction bit would give one path several encodings, so it is refused.

  An argument that is not a binary is refused with `:invalid_binary`. For a binary, the
  checks run in this order, and the first that fails names the refusal:

    * `:too_many_steps` - the depth byte is over #{@max_proof_depth}.
    * `:wrong_length` - the bytes after the depth are not exactly the direction bytes and
      siblings it implies, or there are no bytes at all.
    * `:unused_direction_bits` - a direction bit past the depth is set.

  ## Examples

      iex> binary = <<1, 1, 94, 92, 174, 175, 194, 113, 85, 195, 104, 182, 242, 1, 16, 125,
      ...>   111, 139, 39, 7, 71, 206, 99, 106, 197, 23, 74, 86, 198, 225, 46, 248, 154, 209>>
      iex> {:ok, steps} = Truestamp.Merkle.steps_from_binary(binary)
      iex> steps
      ["r:5e5caeafc27155c368b6f201107d6f8b270747ce636ac5174a56c6e12ef89ad1"]

      iex> Truestamp.Merkle.steps_from_binary(<<0>>)
      {:ok, []}

      iex> Truestamp.Merkle.steps_from_binary(<<1, 3>> <> :binary.copy(<<0>>, 32))
      {:error, :unused_direction_bits}

  """
  @spec steps_from_binary(term()) :: {:ok, proof()} | {:error, binary_error()}
  defdelegate steps_from_binary(binary), to: Codec

  @doc """
  Encode a proof list to a base64url string (no padding).

  Delegates to `steps_to_binary/1`, so it applies the same input requirements and raises
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
  defdelegate encode_proof_base64(steps), to: Codec

  @doc """
  Decodes a base64url-encoded compact path back to its steps.

  Accepts only the canonical text: unpadded base64url exactly as `encode_proof_base64/1`
  writes it, so a padded string, or one whose last character carries stray low bits, is
  refused with `:invalid_base64url`. The bytes then go to `steps_from_binary/1`, which
  accepts only the canonical binary form and names its own refusals. Returns
  `{:ok, steps}` or `{:error, reason}`, whatever it is given.

  ## Examples

      iex> Truestamp.Merkle.decode_proof_base64("AA")
      {:ok, []}
      iex> Truestamp.Merkle.decode_proof_base64("AB")
      {:error, :invalid_base64url}

  """
  @spec decode_proof_base64(term()) :: {:ok, proof()} | {:error, decode_error()}
  defdelegate decode_proof_base64(text), to: Codec
end
