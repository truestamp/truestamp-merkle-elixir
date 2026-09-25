# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Paths do
  @moduledoc false

  # Inclusion proofs, as RFC 9162 section 2.1.3 defines them: the leaf's index, the
  # tree's size, and the audit path of sibling hashes from the leaf up. There are no
  # direction markers; the verifier derives each step's side from the index and size.
  # The root does not fix the tree size, so the size must come from the same trusted
  # source as the root. The RFC names the two counters fn and sn; they are fnum and snum
  # here, since fn is reserved.

  alias Truestamp.Merkle.Hash

  # The longest path a walk will read, and so the ceiling on the hashing an untrusted
  # proof can ask for. A path is at most the ceiling of log2(tree_size) steps, and a
  # tree size fits 64 bits, so 64 steps covers every tree there could be.
  @max_steps 64

  # The codec writes a tree size as an unsigned 64-bit integer.
  @max_tree_size 0xFFFF_FFFF_FFFF_FFFF

  @doc "The default, and largest, `:max_steps`: 64, enough for any 64-bit tree size."
  @spec max_steps() :: pos_integer()
  def max_steps, do: @max_steps

  @doc "The largest `tree_size` a proof may state: 2^64 - 1, what the binary form holds."
  @spec max_tree_size() :: pos_integer()
  def max_tree_size, do: @max_tree_size

  @doc """
  The audit path of the leaf at `index` (RFC 9162 section 2.1.3.1), bottom to top, as
  64-character lowercase hex.

  `levels` are the tree's levels as `Truestamp.Merkle.Tree.levels/1` builds them. Each
  level is a tuple, so each sibling is one `elem/2` away. A node with no right-hand
  sibling at some level is carried up unchanged and contributes no node there.
  """
  @spec audit_path([tuple()], non_neg_integer()) :: [String.t()]
  def audit_path(levels, index) do
    {path, _index} =
      levels
      |> Enum.drop(-1)
      |> Enum.reduce({[], index}, fn level, {path, i} ->
        sibling = Bitwise.bxor(i, 1)

        path =
          if sibling < tuple_size(level),
            do: [Hash.to_hex(elem(level, sibling)) | path],
            else: path

        {path, div(i, 2)}
      end)

    Enum.reverse(path)
  end

  @doc """
  The root an inclusion proof implies for a digest, or the check that refused it.
  `Truestamp.Merkle.walk/3` documents the contract and the order of the checks.
  """
  @spec walk(term(), term(), keyword()) ::
          {:ok, String.t()} | {:error, Truestamp.Merkle.walk_error()}
  def walk(leaf_hex, proof, opts) do
    max_steps = max_steps!(opts)

    with {:ok, root} <- root_from_proof(leaf_hex, proof, max_steps) do
      {:ok, Hash.to_hex(root)}
    end
  end

  @doc """
  Whether an inclusion proof reaches `root_hex` from a digest, compared in constant time.
  `Truestamp.Merkle.verify/4` documents the contract.
  """
  @spec verify(term(), term(), term(), keyword()) :: boolean()
  def verify(leaf_hex, proof, root_hex, opts) do
    max_steps = max_steps!(opts)

    with {:ok, expected} <- Hash.parse_digest(root_hex),
         {:ok, root} <- root_from_proof(leaf_hex, proof, max_steps) do
      # Constant-time comparison, kept as a matter of habit rather than because
      # anything depends on it. Every value here is public, so there is no secret for
      # the comparison to leak. Both sides are 32 bytes.
      :crypto.hash_equals(root, expected)
    else
      _refused -> false
    end
  end

  @doc """
  Checks a proof's shape, index, size and path length, in `Truestamp.Merkle.walk/3`'s
  order, without reading a single path element, so the codec applies the same rules.
  Returns `{:ok, length}`, the number of nodes the index and size require, or the first
  refusal.
  """
  @spec check_proof(term(), non_neg_integer()) ::
          {:ok, non_neg_integer()}
          | {:error, :invalid_proof | :index_out_of_range | :too_many_steps | :wrong_path_length}
  def check_proof(%{leaf_index: index, tree_size: size, path: path}, max_steps)
      when is_integer(index) and is_integer(size) and is_list(path) do
    cond do
      index < 0 or size < 1 or size > @max_tree_size ->
        {:error, :invalid_proof}

      index >= size ->
        {:error, :index_out_of_range}

      true ->
        expected = path_length(index, size)
        if expected > max_steps, do: {:error, :too_many_steps}, else: count_path(path, expected)
    end
  end

  def check_proof(_not_a_proof, _max_steps), do: {:error, :invalid_proof}

  @doc """
  A path node's raw 32 bytes, if it is exactly 64 lowercase hex characters, or `:error`.
  """
  @spec parse_node(term()) :: {:ok, <<_::256>>} | :error
  def parse_node(node), do: Hash.parse_digest(node)

  @doc """
  The number of path nodes RFC 9162 section 2.1.3.2's loop consumes for this index and
  size: one per iteration, until `sn` reaches 0. The size must be at least 1.
  """
  @spec path_length(non_neg_integer(), pos_integer()) :: non_neg_integer()
  def path_length(index, size) when is_integer(size) and size >= 1,
    do: path_length(index, size - 1, 0)

  defp path_length(_fnum, 0, count), do: count

  defp path_length(fnum, snum, count) do
    {fnum, snum} = if odd?(fnum) or fnum == snum, do: to_odd(fnum, snum), else: {fnum, snum}
    path_length(Bitwise.bsr(fnum, 1), Bitwise.bsr(snum, 1), count + 1)
  end

  defp root_from_proof(leaf_hex, proof, max_steps) do
    case Hash.parse_digest(leaf_hex) do
      {:ok, digest} -> walk_leaf_hash(Hash.leaf(digest), proof, max_steps)
      :error -> {:error, :invalid_leaf}
    end
  end

  @doc """
  RFC 9162 section 2.1.3.2 from a 32-byte leaf hash, whatever data it was taken over,
  returning the root's raw bytes or the first refusal.

  `walk/3` and `verify/4` come through here once the digest is checked, and the interop
  tests call it with other implementations' leaf hashes. `max_steps` is taken as given.
  """
  @spec walk_leaf_hash(<<_::256>>, term(), non_neg_integer()) ::
          {:ok, <<_::256>>} | {:error, Truestamp.Merkle.walk_error()}
  def walk_leaf_hash(<<_::binary-size(32)>> = leaf_hash, proof, max_steps) do
    with {:ok, _length} <- check_proof(proof, max_steps),
         {:ok, siblings} <- parse_path(proof.path, []) do
      root(proof.leaf_index, proof.tree_size - 1, leaf_hash, siblings)
    end
  end

  # RFC 9162 section 2.1.3.2 with hash = the leaf hash, fnum = leaf_index and
  # snum = tree_size - 1. check_proof/2 has already established that the path has
  # exactly the length this loop consumes; the loop still makes the RFC's own checks.
  defp root(_fnum, snum, running, []) do
    if snum == 0, do: {:ok, running}, else: {:error, :wrong_path_length}
  end

  defp root(_fnum, 0, _running, [_ | _]), do: {:error, :wrong_path_length}

  defp root(fnum, snum, running, [sibling | rest]) do
    {fnum, snum, running} =
      if odd?(fnum) or fnum == snum do
        {fnum, snum} = to_odd(fnum, snum)
        {fnum, snum, Hash.node(sibling, running)}
      else
        {fnum, snum, Hash.node(running, sibling)}
      end

    root(Bitwise.bsr(fnum, 1), Bitwise.bsr(snum, 1), running, rest)
  end

  # If LSB(fnum) is not set, right-shift fnum and snum equally until it is. When fnum
  # is even here it equals snum, which is not 0, so the loop always ends on an odd
  # fnum (RFC 9162 erratum 8670 notes the RFC's "or fn is 0" cannot happen).
  defp to_odd(fnum, snum) do
    if odd?(fnum) or fnum == 0,
      do: {fnum, snum},
      else: to_odd(Bitwise.bsr(fnum, 1), Bitwise.bsr(snum, 1))
  end

  defp odd?(n), do: Bitwise.band(n, 1) == 1

  # Counts no further than one step past the expected length, so an oversized path is
  # refused without reading it, whatever its length. An improper list is not a path of
  # any length.
  defp count_path(path, expected), do: count_path(path, expected, 0)

  defp count_path([], expected, expected), do: {:ok, expected}
  defp count_path([_ | _], expected, expected), do: {:error, :wrong_path_length}
  defp count_path([_ | rest], expected, count), do: count_path(rest, expected, count + 1)
  defp count_path(_short_or_improper, _expected, _count), do: {:error, :wrong_path_length}

  defp parse_path([], parsed), do: {:ok, Enum.reverse(parsed)}

  defp parse_path([node | rest], parsed) do
    case parse_node(node) do
      {:ok, sibling} -> parse_path(rest, [sibling | parsed])
      :error -> {:error, :invalid_node}
    end
  end

  defp max_steps!(opts) do
    if not is_list(opts) or List.improper?(opts) do
      raise ArgumentError, "options must be a keyword list, got: #{inspect(opts)}"
    end

    case Keyword.validate!(opts, max_steps: @max_steps)[:max_steps] do
      steps when is_integer(steps) and steps >= 0 and steps <= @max_steps ->
        steps

      other ->
        raise ArgumentError,
              ":max_steps must be an integer from 0 to #{@max_steps}, got: #{inspect(other)}"
    end
  end
end
