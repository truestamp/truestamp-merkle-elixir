# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Tree do
  @moduledoc false

  # Building a tree from a list of entries: RFC 9162 section 2.1.1's Merkle Tree Hash over
  # the entries sorted byte-wise by key. There is no padding: a level with an
  # odd number of nodes carries its last node up unchanged, which builds exactly the tree
  # the RFC's recursive split at the largest power of two defines.

  alias Truestamp.Merkle
  alias Truestamp.Merkle.{Hash, Input}

  # A ceiling that turns an impossible input into a clear error. Not a resource limit:
  # a tree 40 levels deep holds over 2^39 (about 550 billion) leaves, and memory runs out
  # long before that.
  @max_depth 40

  @doc """
  Builds a tree from a list of entries. `Truestamp.Merkle.new/1` documents the entry rules
  and what raises.
  """
  @spec new(term()) :: Merkle.t()
  def new([]), do: empty()

  def new(entries) when is_list(entries) do
    if List.improper?(entries), do: raise_not_entries!(entries)

    # Keys are unique once the duplicate check below passes, so sorting the tuples orders
    # them by key alone; a repeated key raises whatever order its entries take.
    triples = entries |> Input.parse_entries!() |> Enum.sort()
    pairs = Enum.map(triples, fn {key, digest, _bytes} -> {key, digest} end)

    # The index keys on the entry's key, so a key that repeats collapses two entries
    # into one. Comparing sizes catches that without a second pass; only the failing
    # path pays to find out which key it was.
    index = leaf_index(pairs)
    if map_size(index) != length(pairs), do: raise_duplicate_key!(pairs)

    assemble(pairs, Enum.map(triples, fn {_key, _digest, bytes} -> Hash.leaf(bytes) end), index)
  end

  def new(entries), do: raise_not_entries!(entries)

  defp raise_not_entries!(entries) do
    raise ArgumentError,
          "Invalid input data. Expected a list of maps with \"key\" and \"hash\" keys, got: #{inspect(entries, limit: 10)}"
  end

  defp empty do
    [{root}] = levels = levels([])
    %Merkle{root_hash: root, leaves: [], tree_depth: 0, tree_levels: levels, leaf_index: %{}}
  end

  # `pairs` are the entries in leaf order as {key, digest_hex}, and `leaf_hashes` their
  # leaf hashes in the same order. Every level is kept as a tuple, bottom first, so proof
  # generation reaches any sibling with elem/2.
  defp assemble(pairs, leaf_hashes, index) do
    depth = depth!(length(leaf_hashes))
    levels = levels(leaf_hashes)

    %Merkle{
      root_hash: levels |> List.last() |> elem(0),
      leaves: pairs,
      tree_depth: depth,
      tree_levels: levels,
      leaf_index: index
    }
  end

  @doc """
  The levels of the RFC 9162 tree over leaf hashes already in leaf order, bottom first,
  each a tuple; the last holds the root alone. No leaves give one level holding the empty
  root.

  Every tree is built here, and the interop tests call it with other implementations'
  leaf hashes, which need not be hashes of 32-byte digests.
  """
  @spec levels([binary()]) :: [tuple(), ...]
  def levels([]), do: [{Hash.empty_root()}]
  def levels([_ | _] = leaf_hashes), do: build_levels(leaf_hashes, [])

  defp build_levels([_root] = level, built), do: Enum.reverse([List.to_tuple(level) | built])

  defp build_levels(level, built),
    do: build_levels(pair_up(level), [List.to_tuple(level) | built])

  # Pairs adjacent nodes left to right; an unpaired last node moves up unchanged.
  defp pair_up([left, right | rest]), do: [Hash.node(left, right) | pair_up(rest)]
  defp pair_up(unpaired), do: unpaired

  @doc """
  The number of levels above the leaves of a tree of `count` entries: the ceiling of
  log2(count), or 0 for none or one. It is also the longest path in the tree. Raises
  `ArgumentError` above the 40-level ceiling, that is, for more than 2^40 entries.
  """
  @spec depth!(non_neg_integer()) :: non_neg_integer()
  def depth!(count) do
    depth = if count <= 1, do: 0, else: bit_length(count - 1)

    if depth > @max_depth do
      raise ArgumentError, "Tree depth #{depth} exceeds maximum #{@max_depth} (#{count} leaves)"
    end

    depth
  end

  defp bit_length(0), do: 0
  defp bit_length(n), do: 1 + bit_length(Bitwise.bsr(n, 1))

  # {key => position}, which is what keeps proof generation off a linear scan.
  defp leaf_index(pairs) do
    pairs
    |> Enum.with_index()
    |> Map.new(fn {{key, _digest}, position} -> {key, position} end)
  end

  # Called only once a size mismatch has proven a repeat exists, so the scan always
  # halts on a key.
  defp raise_duplicate_key!(pairs) do
    key =
      Enum.reduce_while(pairs, MapSet.new(), fn {key, _digest}, seen ->
        if MapSet.member?(seen, key), do: {:halt, key}, else: {:cont, MapSet.put(seen, key)}
      end)

    raise ArgumentError, "Duplicate key in input data: #{inspect(key)}. Every key must be unique."
  end
end
