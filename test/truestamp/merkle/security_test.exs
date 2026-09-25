# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.SecurityTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Truestamp.Merkle
  alias Truestamp.Merkle.{Generators, RFC9162}

  # Trees of 2 to 40 entries with distinct keys and, almost surely, distinct digests.
  defp tree_gen(min \\ 2) do
    gen all(
          entries <- list_of(Generators.entry(), min_length: min, max_length: 40),
          unique = Enum.uniq_by(entries, & &1["key"]),
          length(unique) >= min
        ) do
      unique
    end
  end

  defp flip_last_char(hex) do
    String.slice(hex, 0..-2//1) <> if(String.last(hex) == "0", do: "1", else: "0")
  end

  property "every entry's proof verifies against its tree's root" do
    check all(entries <- tree_gen(1)) do
      tree = Merkle.new(entries)
      root = Merkle.root(tree)

      for %{"key" => key, "hash" => digest} <- entries do
        assert Merkle.verify(digest, Merkle.proof(tree, key), root)
      end
    end
  end

  property "changing any one node of a path makes it fail" do
    check all(entries <- tree_gen(), position <- integer(0..63)) do
      tree = Merkle.new(entries)
      %{"key" => key, "hash" => digest} = hd(entries)
      proof = Merkle.proof(tree, key)

      # Two or more entries always give a path of at least one node.
      assert [_ | _] = proof.path
      i = rem(position, length(proof.path))
      altered = List.update_at(proof.path, i, &flip_last_char/1)

      refute Merkle.verify(digest, %{proof | path: altered}, Merkle.root(tree))
    end
  end

  property "dropping, adding or reordering nodes makes a path fail" do
    check all(entries <- tree_gen(4)) do
      tree = Merkle.new(entries)
      root = Merkle.root(tree)

      # The first leaf's path is the full depth, at least two nodes for four or more
      # entries, and nodes at different heights differ, so reversing it changes it.
      {key, digest} = hd(tree.leaves)
      proof = Merkle.proof(tree, key)
      assert length(proof.path) == tree.tree_depth
      assert length(proof.path) >= 2
      refute Merkle.verify(digest, %{proof | path: Enum.drop(proof.path, -1)}, root)
      refute Merkle.verify(digest, %{proof | path: proof.path ++ [root]}, root)
      refute Merkle.verify(digest, %{proof | path: Enum.reverse(proof.path)}, root)
    end
  end

  property "a proof moved to another index of the same tree fails" do
    check all(entries <- tree_gen(), shift <- integer(1..39)) do
      tree = Merkle.new(entries)
      %{"key" => key, "hash" => digest} = hd(entries)
      proof = Merkle.proof(tree, key)
      other = rem(proof.leaf_index + shift, proof.tree_size)

      if other != proof.leaf_index do
        refute Merkle.verify(digest, %{proof | leaf_index: other}, Merkle.root(tree))
      end

      # The unmoved proof verifies, so a refusal above is about the index.
      assert Merkle.verify(digest, proof, Merkle.root(tree))
    end
  end

  # A tree's leaves are its digests in key order; keys are not hashed.
  defp leaf_digests(entries), do: entries |> Enum.sort_by(& &1["key"]) |> Enum.map(& &1["hash"])

  property "a proof from one tree fails against a tree whose digests, in key order, differ" do
    check all(a <- tree_gen(1), b <- tree_gen(1), leaf_digests(a) != leaf_digests(b)) do
      %{"key" => key, "hash" => digest} = hd(a)
      proof = Merkle.proof(Merkle.new(a), key)

      refute Merkle.verify(digest, proof, Merkle.root(Merkle.new(b)))
    end
  end

  test "trees with other keys but the same digests in the same order share a root" do
    [d1, d2] = for label <- ["x", "y"], do: RFC9162.hex(RFC9162.sha256(label))
    a = [%{"key" => "a1", "hash" => d1}, %{"key" => "a2", "hash" => d2}]
    b = [%{"key" => "b1", "hash" => d1}, %{"key" => "b2", "hash" => d2}]

    # Keys only order the leaves, so the proofs are interchangeable.
    assert Merkle.root(Merkle.new(a)) == Merkle.root(Merkle.new(b))
    assert Merkle.verify(d1, Merkle.proof(Merkle.new(a), "a1"), Merkle.root(Merkle.new(b)))
  end

  property "an interior node presented as a leaf, with the path above it, fails" do
    check all(entries <- tree_gen()) do
      tree = Merkle.new(entries)
      root = Merkle.root(tree)

      # The first leaf always has a sibling at the bottom level, so dropping the path's
      # first node leaves exactly the path above the node they make.
      {key, _digest} = hd(tree.leaves)
      proof = Merkle.proof(tree, key)
      [_first | above] = proof.path

      # The node one level up from this leaf, its index and the size of its level.
      level1 = Enum.at(tree.tree_levels, 1)
      index = div(proof.leaf_index, 2)
      node = elem(level1, index)
      size = tuple_size(level1)

      # Walked up from the node as it stands, the path above reaches the root...
      above_bytes = Enum.map(above, &RFC9162.unhex/1)
      assert RFC9162.hex(RFC9162.walk_from(node, index, size, above_bytes)) == root

      # ...but presented as a leaf it is hashed with 0x00 first, so it does not.
      refute Merkle.verify(
               RFC9162.hex(node),
               %{leaf_index: index, tree_size: size, path: above},
               root
             )
    end
  end

  property "proofs are deterministic, and every node is 64 lowercase hex characters" do
    check all(entries <- tree_gen(1)) do
      tree = Merkle.new(entries)

      for %{"key" => key} <- entries do
        proof = Merkle.proof(tree, key)
        assert proof == Merkle.proof(Merkle.new(Enum.shuffle(entries)), key)
        assert Enum.all?(proof.path, &(&1 =~ ~r/\A[0-9a-f]{64}\z/))
        assert length(proof.path) <= tree.tree_depth
      end
    end
  end
end
