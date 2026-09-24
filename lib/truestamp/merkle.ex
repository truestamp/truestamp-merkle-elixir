# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle do
  @moduledoc """
  SHA-256 Merkle trees with inclusion proofs, following RFC 9162 section 2.1.

  You supply entries: a key, plus a 32-byte digest you have already computed over
  whatever that key names. The tree sorts the entries by key and hashes them into RFC
  9162's Merkle Tree Hash; `proof/2` gives an entry's inclusion proof, and `walk/3` and
  `verify/4` check one. What a key identifies, and what the digest was taken over, are
  yours to decide. Pure Elixir with no dependencies beyond `:crypto` and `Base`; it
  requires Elixir 1.20, and so OTP 27 or newer.

  ## The tree

  A leaf is `SHA-256(0x00 || digest)` over the digest's 32 raw bytes, a node is
  `SHA-256(0x01 || left || right)`, and the root of a tree with no entries is
  `SHA-256("")`. A tree of `n > 1` entries splits at the largest power of two below `n`
  (RFC 9162, section 2.1.1): no padding, no filler leaves. Entries are sorted byte-wise by
  key first, so the same set of entries always gives the same root, whatever order they
  arrive in. The README states the contract a port must reproduce, and
  `vectors/merkle.json` holds its known answers.

  An inclusion proof is RFC 9162's: the entry's `leaf_index`, the `tree_size`, and the
  `path` of sibling hashes from the leaf up. A proof carries no left or right markers:
  the verifier derives each step's side from the index and size (section 2.1.3.2), and a
  path of the wrong length is refused. Any RFC 6962 or RFC 9162 verifier accepts these
  proofs.

  **Take the tree size from where you take the root, not from the proof.** A root does
  not fix the size of its tree, and the size decides which index a path proves. In trees
  of 1 to 300 entries, 43,730 of the 45,150 proofs (97%) still reach their root with
  `tree_size` raised by one, and the index can move with the size: the last of three
  entries also verifies as index 1 of a two-entry tree. Given the true size, no other
  index verifies. Certificate Transparency gets the size from the signed tree head,
  beside the root; do the same, and check that a proof's `tree_size` equals it. A proof
  checked without that still shows the digest is in the tree, but not where.

  ## Security Properties

  - **Domain separation**: leaves hash with `0x00` and nodes with `0x01`, so a node can
    never be presented as a leaf or the reverse.
  - **Fixed-size inputs**: every digest, root and path node is exactly 64 lowercase hex
    characters. Uppercase is refused, never normalized.
  - **Bounded work**: a proof's index and size fix its path length, which is checked
    before any node is read or hashed; `:max_steps` lowers the ceiling (Truestamp passes
    32).
  - **One encoding per proof**: the binary form has fixed-width fields and a path length
    the index and size determine.

  What a proof does and does not attest is in `SECURITY.md`. Keys are not bound into a
  proof: bind an identifier into the digest itself if you need that.

  Size a large workload by memory before time: a finished tree holds a few hundred bytes
  of heap per entry, and building one needs more while the input and the tree are both
  alive. The README's Performance section has measured figures, and
  `bench/performance.exs` reproduces them on your hardware.

  ## Quick Start

      iex> data = [
      ...>   %{"key" => "entry-1", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-2", "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> root = Truestamp.Merkle.root(tree)
      "27fdfb0ec5b8a6cd13283e2c192d32ee5baee7aa4807e96287008f42598c51d1"
      iex> proof = Truestamp.Merkle.proof(tree, "entry-1")
      %{leaf_index: 0, tree_size: 2, path: ["97de9286ff6aec3c2f718237f34f6062d515daf8ea863ed52b503ee4ad98444c"]}
      iex> Truestamp.Merkle.verify("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", proof, root)
      true

  ## API Summary

  - `new/2` - build a tree from a list of `%{"key" => ..., "hash" => ...}` entries
  - `root/1` - the root as 64 lowercase hex characters
  - `proof/2` - an entry's inclusion proof, or `nil` for a key the tree does not hold
  - `walk/3` - the root an inclusion proof implies, or the check that refused it
  - `verify/4` - whether an inclusion proof reaches a given root
  - `proof_to_binary/1`, `proof_from_binary/1` - the binary form of a proof, for storage

  ## Error Handling

  - `new/2` raises `ArgumentError` for an invalid key or digest, a repeated key, invalid
    options, or input that is not a list of entry maps.
  - `walk/3`, `verify/4` and `proof_from_binary/1` take untrusted input: they return
    errors (or `false`) for anything they are given, and raise only for invalid options.
  - `proof_to_binary/1` raises `ArgumentError` for a proof that is not well formed; it is
    for proofs you produced.
  """

  # The public API. Each function delegates to the internal module that owns it:
  # Tree builds, Paths produces and checks inclusion proofs, Codec encodes them for
  # storage, Input holds the entry rules, and Hash the hashing and hex rules they share.

  alias __MODULE__.{Codec, Hash, Paths, Tree}

  # Interpolated into the docs below.
  @max_steps Paths.max_steps()

  defstruct [:root_hash, :leaves, :tree_depth, :tree_levels, :leaf_index]

  @type t :: %__MODULE__{
          root_hash: binary(),
          leaves: [{binary(), binary()}],
          tree_depth: non_neg_integer(),
          tree_levels: [tuple()],
          leaf_index: %{binary() => non_neg_integer()}
        }

  @typedoc "An RFC 9162 inclusion proof: the path holds 64-hex sibling hashes, bottom to top."
  @type proof :: %{
          leaf_index: non_neg_integer(),
          tree_size: pos_integer(),
          path: [String.t()]
        }

  @type walk_error ::
          :invalid_leaf
          | :invalid_proof
          | :index_out_of_range
          | :too_many_steps
          | :wrong_path_length
          | :invalid_node

  @type decode_error :: :invalid_binary | :wrong_length | :index_out_of_range

  # ── Building a tree ───────────────────────────────────────────────────────

  @doc """
  Builds a tree from a list of `%{"key" => key, "hash" => digest}` entries.

  - `"key"`: 1 to 36 characters, each an ASCII letter, a digit, `.`, `_` or `-`. Every
    key appears once; a repeated key raises, whether or not the digests agree.
  - `"hash"`: the entry's pre-computed SHA-256 digest, exactly 64 lowercase hex
    characters. The tree hashes digests, never documents.

  `new([])` builds the empty tree, whose root is `SHA-256("")`.

  ## Options

    * `:sort` - `true` (the default) sorts entries byte-wise by key, which is what the
      tree contract specifies. `false` keeps the list's order, which gives a different
      root for a different order and is outside the contract.

  An unknown option, a `:sort` that is not a boolean, an invalid key or digest, a
  repeated key, or input that is not a list of entry maps raises `ArgumentError`.

  ## Examples

      iex> data = [
      ...>   %{"key" => "b", "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"},
      ...>   %{"key" => "a", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Enum.map(tree.leaves, &elem(&1, 0))
      ["a", "b"]
      iex> Truestamp.Merkle.root(Truestamp.Merkle.new([]))
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  """
  @spec new([%{binary() => binary()}], keyword()) :: t()
  defdelegate new(entries, opts \\ []), to: Tree

  @doc """
  Returns the root as 64 lowercase hex characters.
  """
  @spec root(t()) :: String.t()
  def root(%__MODULE__{root_hash: root_hash}), do: Hash.to_hex(root_hash)

  # ── Proving an entry ──────────────────────────────────────────────────────

  @doc """
  Returns the inclusion proof for `key` (RFC 9162, section 2.1.3.1), or `nil` if the
  tree holds no such key.

  The proof is `%{leaf_index: index, tree_size: size, path: [sibling, ...]}`, with the
  path's sibling hashes as 64 lowercase hex characters, from the leaf up. A tree of one
  entry has an empty path.

  ## Examples

      iex> data = [
      ...>   %{"key" => "a", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "b", "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"},
      ...>   %{"key" => "c", "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> Truestamp.Merkle.proof(tree, "c")
      %{leaf_index: 2, tree_size: 3, path: ["27fdfb0ec5b8a6cd13283e2c192d32ee5baee7aa4807e96287008f42598c51d1"]}
      iex> Truestamp.Merkle.proof(tree, "missing")
      nil

  """
  @spec proof(t(), binary()) :: proof() | nil
  def proof(%__MODULE__{leaf_index: index, tree_levels: levels}, key) do
    # One map lookup finds the leaf, however large the tree.
    case Map.fetch(index, key) do
      {:ok, position} ->
        %{
          leaf_index: position,
          tree_size: tuple_size(hd(levels)),
          path: Paths.audit_path(levels, position)
        }

      :error ->
        nil
    end
  end

  @doc """
  Recomputes the root an inclusion proof implies for a digest (RFC 9162, section
  2.1.3.2), without being given a root.

  `leaf_hex` is the digest being proved, 64 lowercase hex characters: the value the entry
  carried when the tree was built. `proof` is the map `proof/2` returns. Compare the
  result with a root you already trust, or call `verify/4`, which does that in constant
  time. Take `tree_size` from the same place as that root: the module documentation
  explains why a size taken from the proof alone proves less.

  ## Options

    * `:max_steps` - the longest path accepted, an integer from 0 to #{@max_steps}.
      Defaults to #{@max_steps}. Truestamp passes 32, which admits trees of up to 2^32
      entries.

  An unknown option, or a `:max_steps` outside that range, raises `ArgumentError`.
  Everything else may come from a stranger, so it is refused with an error instead of
  raising. The checks run in this order:

    * `{:error, :invalid_leaf}` - `leaf_hex` is not exactly 64 lowercase hex characters.
    * `{:error, :invalid_proof}` - `proof` is not a map with an integer `:leaf_index` of
      at least 0, an integer `:tree_size` from 1 to 2^64 - 1, and a list as its `:path`.
    * `{:error, :index_out_of_range}` - `leaf_index` is not below `tree_size`.
    * `{:error, :too_many_steps}` - the path this index and size require is longer than
      `:max_steps`.
    * `{:error, :wrong_path_length}` - the path is not a proper list of exactly the nodes
      the index and size require. It is counted without reading more than one node past
      that length.
    * `{:error, :invalid_node}` - a path node is not exactly 64 lowercase hex characters.

  ## Examples

      iex> proof = %{leaf_index: 0, tree_size: 2, path: ["97de9286ff6aec3c2f718237f34f6062d515daf8ea863ed52b503ee4ad98444c"]}
      iex> Truestamp.Merkle.walk("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", proof)
      {:ok, "27fdfb0ec5b8a6cd13283e2c192d32ee5baee7aa4807e96287008f42598c51d1"}
      iex> Truestamp.Merkle.walk("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", %{proof | tree_size: 3})
      {:error, :wrong_path_length}
      iex> Truestamp.Merkle.walk("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", %{proof | leaf_index: 2})
      {:error, :index_out_of_range}

  """
  @spec walk(term(), term(), keyword()) :: {:ok, String.t()} | {:error, walk_error()}
  defdelegate walk(leaf_hex, proof, opts \\ []), to: Paths

  @doc """
  Verifies that `leaf_hex` is included in the tree whose root is `root_hex`.

  Walks `proof` from `leaf_hex` exactly as `walk/3` does, with the same options, and
  compares the result with `root_hex` in constant time. Returns `true` only when the walk
  succeeds and the roots are equal.

  Every refusal `walk/3` reports, and a `root_hex` that is not 64 lowercase hex
  characters, returns `false`, indistinguishable from a proof that genuinely fails: call
  `walk/3` to learn which check refused it. Only invalid options raise. As with `walk/3`,
  `true` places the digest at `leaf_index` only when `tree_size` came from the same
  place as `root_hex`.

  ## Examples

      iex> data = [
      ...>   %{"key" => "entry-a", "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
      ...>   %{"key" => "entry-b", "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
      ...> ]
      iex> tree = Truestamp.Merkle.new(data)
      iex> proof = Truestamp.Merkle.proof(tree, "entry-a")
      iex> Truestamp.Merkle.verify("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", proof, Truestamp.Merkle.root(tree))
      true
      iex> Truestamp.Merkle.verify("b1b2c3d4e5f67890123456789012345678901234567890123456789012345678", proof, Truestamp.Merkle.root(tree))
      false

  """
  @spec verify(term(), term(), term(), keyword()) :: boolean()
  defdelegate verify(leaf_hex, proof, root_hex, opts \\ []), to: Paths

  # ── Storing a proof ───────────────────────────────────────────────────────

  @doc """
  Encodes an inclusion proof as its binary form, for storage.

      bytes 0-7    leaf_index, unsigned 64-bit big-endian
      bytes 8-15   tree_size, unsigned 64-bit big-endian
      the rest     each path node's 32 raw bytes, bottom to top

  Each proof has exactly one binary form, and `proof_from_binary/1` accepts only that
  form. A proof that would fail `walk/3`'s proof checks raises `ArgumentError`.

  ## Examples

      iex> proof = %{leaf_index: 0, tree_size: 1, path: []}
      iex> Truestamp.Merkle.proof_to_binary(proof)
      <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>

  """
  @spec proof_to_binary(proof()) :: binary()
  defdelegate proof_to_binary(proof), to: Codec

  @doc """
  Decodes the binary form of an inclusion proof.

  It takes untrusted bytes, so it returns `{:ok, proof}` or `{:error, reason}` and never
  raises. The checks run in this order, and the first that fails names the refusal:

    * `:invalid_binary` - the argument is not a binary.
    * `:wrong_length` - fewer than the 16 bytes of the two fields.
    * `:index_out_of_range` - `leaf_index` is not below `tree_size` (a size of 0 always
      fails here).
    * `:wrong_length` - the bytes after the two fields are not exactly the 32-byte nodes
      the index and size require.

  ## Examples

      iex> Truestamp.Merkle.proof_from_binary(<<0::64, 1::64>>)
      {:ok, %{leaf_index: 0, tree_size: 1, path: []}}
      iex> Truestamp.Merkle.proof_from_binary(<<1::64, 1::64>>)
      {:error, :index_out_of_range}

  """
  @spec proof_from_binary(term()) :: {:ok, proof()} | {:error, decode_error()}
  defdelegate proof_from_binary(binary), to: Codec
end
