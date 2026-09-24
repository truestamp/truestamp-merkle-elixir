# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Tree do
  @moduledoc false

  # Building a tree, from a whole list or through the builder. Both paths end in
  # assemble/3, so a tree hashes identically whichever built it.

  alias Truestamp.Merkle
  alias Truestamp.Merkle.{Builder, Hash, Input}

  # Ceiling on the depth arithmetic, which keeps the leaf-count math in range. Not a
  # resource limit: 2^40 = 1,099,511,627,776 (~1 trillion) leaves exhausts memory long
  # before the cap is reached.
  @max_depth 40

  def new([], _opts), do: empty()

  def new(entries, opts) when is_list(entries) do
    Input.validate_entries!(entries)

    pairs =
      entries
      |> Enum.map(fn %{"key" => key, "hash" => digest} -> {key, digest} end)
      |> maybe_sort(opts)

    # The index keys on the entry's key, so a key that repeats collapses two entries
    # into one. Comparing sizes catches that without a second pass; only the failing
    # path pays to find out which key it was.
    index = leaf_index(pairs)
    if map_size(index) != length(pairs), do: raise_duplicate_key!(pairs)

    assemble(pairs, Enum.map(pairs, fn {_key, digest} -> Hash.leaf(digest) end), index)
  end

  def new(entries, _opts) do
    raise ArgumentError,
          "Invalid input data. Expected a list of maps with \"key\" and \"hash\" keys, got: #{inspect(entries, limit: 10)}"
  end

  def builder, do: %Builder{}

  # The builder hashes each leaf as it arrives and remembers every key's digest, so a
  # repeat is caught at once: an identical repeat is ignored, a conflicting one raises.
  def add_entry(%Builder{} = builder, %{"key" => key, "hash" => digest}) do
    Input.validate_key!(key)
    Input.validate_digest!(digest)

    case Map.get(builder.seen, key) do
      nil ->
        %Builder{
          leaves: [{key, Hash.leaf(digest)} | builder.leaves],
          seen: Map.put(builder.seen, key, digest),
          count: builder.count + 1
        }

      ^digest ->
        builder

      existing ->
        raise ArgumentError, """
        Duplicate key with different hash detected.
        Key: #{inspect(key)}
        Existing hash: #{existing}
        New hash: #{digest}
        """
    end
  end

  def add_entries(%Builder{} = builder, enumerable) do
    Enum.reduce(enumerable, builder, &add_entry(&2, &1))
  end

  def finalize(%Builder{leaves: [], count: 0}, _opts), do: empty()

  def finalize(%Builder{leaves: leaves, seen: seen}, opts) do
    # add_entry/2 prepends, so reverse to insertion order before any sort.
    leaves = leaves |> Enum.reverse() |> maybe_sort(opts)
    pairs = Enum.map(leaves, fn {key, _leaf} -> {key, Map.fetch!(seen, key)} end)
    assemble(pairs, Enum.map(leaves, &elem(&1, 1)), leaf_index(pairs))
  end

  def from_stream(enumerable, opts) do
    key_fn = Keyword.fetch!(opts, :key_fn)
    hash_fn = Keyword.fetch!(opts, :hash_fn)

    enumerable
    |> Enum.reduce(builder(), fn item, acc ->
      add_entry(acc, %{"key" => key_fn.(item), "hash" => hash_fn.(item)})
    end)
    |> finalize(Keyword.take(opts, [:sort]))
  end

  def from_maps(enumerable, opts), do: builder() |> add_entries(enumerable) |> finalize(opts)

  def from_tuples(enumerable, opts) do
    enumerable
    |> Enum.reduce(builder(), fn {key, digest}, acc ->
      add_entry(acc, %{"key" => key, "hash" => digest})
    end)
    |> finalize(opts)
  end

  defp empty do
    root = Hash.empty_root()
    %Merkle{root_hash: root, leaves: [], tree_depth: 0, tree_levels: [{root}], leaf_index: %{}}
  end

  # The one construction path. `pairs` are the entries in leaf order as
  # {key, digest_hex}, and `leaf_hashes` their leaf hashes in the same order. Pads the
  # bottom level to a power of two with the padding leaf, then keeps every level as a
  # tuple, so proof generation reaches any sibling with elem/2.
  defp assemble(pairs, leaf_hashes, index) do
    count = length(leaf_hashes)
    depth = depth!(count)
    padding = List.duplicate(Hash.padding_leaf(), Bitwise.bsl(1, depth) - count)
    levels = build_levels(leaf_hashes ++ padding, [])

    %Merkle{
      root_hash: levels |> List.last() |> elem(0),
      leaves: pairs,
      tree_depth: depth,
      tree_levels: levels,
      leaf_index: index
    }
  end

  defp build_levels([_root] = level, built), do: Enum.reverse([List.to_tuple(level) | built])

  defp build_levels(level, built) do
    above =
      level |> Enum.chunk_every(2) |> Enum.map(fn [left, right] -> Hash.node(left, right) end)

    build_levels(above, [List.to_tuple(level) | built])
  end

  # Levels above the leaves once `count` leaves are padded to a power of two: the
  # ceiling of log2(count), or 0 for one leaf.
  defp depth!(count) do
    depth = if count <= 1, do: 0, else: bit_length(count - 1)

    if depth > @max_depth do
      raise ArgumentError,
            "Tree depth #{depth} exceeds maximum #{@max_depth} (#{Bitwise.bsl(1, depth)} leaves)"
    end

    depth
  end

  defp bit_length(0), do: 0
  defp bit_length(n), do: 1 + bit_length(Bitwise.bsr(n, 1))

  defp maybe_sort(pairs, opts) do
    if Keyword.get(opts, :sort, true), do: Enum.sort_by(pairs, &elem(&1, 0)), else: pairs
  end

  # {key => position} for the real leaves, which is what keeps proof generation off a
  # linear scan. Padding slots have no key and are never looked up.
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
