# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.TreeTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Truestamp.Merkle
  alias Truestamp.Merkle.{Generators, RFC9162}

  @digest "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"

  defp entry(key, digest \\ @digest), do: %{"key" => key, "hash" => digest}

  describe "the RFC 9162 tree" do
    test "every size from 0 to 300 has the root, depth and levels the RFC defines" do
      for n <- 0..300 do
        entries = RFC9162.entries(n)
        tree = Merkle.new(entries)

        assert Merkle.root(tree) == RFC9162.hex(RFC9162.mth(RFC9162.digests(entries))), "n=#{n}"

        depth = if n <= 1, do: 0, else: Enum.find(1..10, &(Bitwise.bsl(1, &1) >= n))
        assert tree.tree_depth == depth, "n=#{n}"

        if n > 0 do
          # No padding: the bottom level holds exactly the entries' leaves.
          assert tuple_size(hd(tree.tree_levels)) == n
          assert length(tree.tree_levels) == depth + 1
        end
      end
    end

    test "the empty tree's root is SHA-256 of no bytes" do
      tree = Merkle.new([])
      assert Merkle.root(tree) == RFC9162.hex(:crypto.hash(:sha256, <<>>))
      assert tree.tree_depth == 0
      assert Merkle.proof(tree, "any") == nil
    end

    test "a one-entry tree's root is its leaf hash, SHA-256(0x00 || digest)" do
      tree = Merkle.new([entry("only")])
      expected = RFC9162.sha256(<<0x00>> <> RFC9162.unhex(@digest))
      assert Merkle.root(tree) == RFC9162.hex(expected)
    end

    test "three entries: the third leaf is carried up and pairs with the first two's node" do
      [a, b, c] = entries = RFC9162.entries(3)
      [la, lb, lc] = Enum.map([a, b, c], &RFC9162.sha256(<<0x00>> <> RFC9162.unhex(&1["hash"])))
      node = RFC9162.sha256(<<0x01>> <> la <> lb)
      expected = RFC9162.sha256(<<0x01>> <> node <> lc)

      assert Merkle.root(Merkle.new(entries)) == RFC9162.hex(expected)
    end

    test "leaves and the index hold the entries in leaf order" do
      tree = Merkle.new([entry("b", String.duplicate("b", 64)), entry("a")])

      assert tree.leaves == [{"a", @digest}, {"b", String.duplicate("b", 64)}]
      assert tree.leaf_index == %{"a" => 0, "b" => 1}
    end

    test "root/1 is 64 lowercase hex characters" do
      assert Merkle.root(Merkle.new(RFC9162.entries(5))) =~ ~r/\A[0-9a-f]{64}\z/
    end
  end

  describe "sorting" do
    test "entries are sorted byte-wise by key: case, punctuation and digits as bytes" do
      keys = ["b", "B", "A", "_x", "-x", ".x", "a", "a0", "10", "9"]
      tree = Merkle.new(Enum.map(keys, &entry/1))

      assert Enum.map(tree.leaves, &elem(&1, 0)) ==
               ["-x", ".x", "10", "9", "A", "B", "_x", "a", "a0", "b"]
    end

    test "entries are always sorted: a reversed list gives the sorted list's root" do
      entries = RFC9162.entries(5)
      reversed = Enum.reverse(entries)

      assert Merkle.root(Merkle.new(reversed)) ==
               RFC9162.hex(RFC9162.mth(RFC9162.digests(entries)))

      # The reversed order would give another root if it were kept.
      refute Merkle.root(Merkle.new(reversed)) ==
               RFC9162.hex(RFC9162.mth(RFC9162.digests(reversed)))
    end

    property "the root does not depend on the input order" do
      check all(
              entries <- list_of(Generators.entry(), min_length: 1, max_length: 40),
              unique = Enum.uniq_by(entries, & &1["key"])
            ) do
        assert Merkle.root(Merkle.new(unique)) == Merkle.root(Merkle.new(Enum.shuffle(unique)))
      end
    end
  end

  describe "size/1" do
    test "is the entry count, every proof's tree_size, and 0 for the empty tree" do
      for n <- [0, 1, 2, 3, 7, 8, 9, 300] do
        entries = RFC9162.entries(n)
        tree = Merkle.new(entries)
        assert Merkle.size(tree) == n

        for entry <- entries do
          assert Merkle.proof(tree, entry["key"]).tree_size == n
        end
      end
    end
  end

  describe "entry rules" do
    test "keys: 1 to 36 characters from letters, digits, . _ and -" do
      assert %Merkle{} = Merkle.new([entry(String.duplicate("k", 36))])
      assert %Merkle{} = Merkle.new([entry("A-z_0.9")])

      assert_raise ArgumentError, ~r/Invalid key length/, fn ->
        Merkle.new([entry(String.duplicate("k", 37))])
      end

      # One grapheme of a million bytes is refused by its size, without walking it.
      huge = "a" <> String.duplicate("\u0301", 500_000)
      {:reductions, before} = Process.info(self(), :reductions)
      assert_raise ArgumentError, ~r/Invalid key length/, fn -> Merkle.new([entry(huge)]) end
      {:reductions, later} = Process.info(self(), :reductions)
      assert later - before < 100_000

      for bad <- ["", "a b", "a/b", "é", "a\n"] do
        assert_raise ArgumentError, ~r/Invalid key format/, fn -> Merkle.new([entry(bad)]) end
      end

      assert_raise ArgumentError, ~r/leading or trailing spaces/, fn ->
        Merkle.new([entry(" a")])
      end

      assert_raise ArgumentError, ~r/Invalid key type/, fn -> Merkle.new([entry(:a)]) end
    end

    test "digests: exactly 64 lowercase hex characters" do
      for bad <- [
            String.upcase(@digest),
            @digest <> "\n",
            binary_part(@digest, 0, 63),
            @digest <> "0",
            "zz" <> binary_part(@digest, 2, 62)
          ] do
        assert_raise ArgumentError, ~r/Invalid hash format/, fn ->
          Merkle.new([entry("a", bad)])
        end
      end

      assert_raise ArgumentError, ~r/Invalid hash type/, fn -> Merkle.new([entry("a", 7)]) end
    end

    test "each key once: a repeated key raises, naming it, whether or not the digests agree" do
      # The repeated key is neither first in the list nor first in key order, so the
      # message has to name the key that actually repeats.
      for second <- [@digest, String.duplicate("b", 64)] do
        assert_raise ArgumentError, ~r/Duplicate key in input data: "zz"/, fn ->
          Merkle.new([entry("b"), entry("zz"), entry("a"), entry("zz", second)])
        end
      end
    end

    test "no key prefix or digest is reserved" do
      zero_zero = RFC9162.hex(RFC9162.sha256(<<0, 0>>))
      entries = [entry("__pad__0", zero_zero), entry("__PAD__1"), entry("b")]
      tree = Merkle.new(entries)
      root = Merkle.root(tree)

      assert root == RFC9162.hex(RFC9162.mth(RFC9162.digests(Enum.sort_by(entries, & &1["key"]))))

      for %{"key" => key, "hash" => digest} <- entries do
        assert Merkle.verify(digest, Merkle.proof(tree, key), root)
      end
    end

    test "two keys may share a digest, and each is provable" do
      tree = Merkle.new([entry("a"), entry("b")])
      root = Merkle.root(tree)

      for key <- ["a", "b"] do
        assert Merkle.verify(@digest, Merkle.proof(tree, key), root)
      end
    end

    test "input that is not a list of entry maps" do
      for bad <- [%{}, "entries", nil, [entry("a") | :tail]] do
        assert_raise ArgumentError, ~r/Invalid input data/, fn -> Merkle.new(bad) end
      end

      # The message shows the input, improper tail included.
      assert_raise ArgumentError, ~r/\| :tail\]/, fn -> Merkle.new([entry("a") | :tail]) end

      for bad <- [
            [:not_a_map],
            [%{"key" => "a"}],
            [%{"hash" => @digest}],
            [%{key: "a", hash: @digest}]
          ] do
        assert_raise ArgumentError, ~r/Invalid input entry format/, fn -> Merkle.new(bad) end
      end
    end

    test "every entry is checked, not just the first" do
      assert_raise ArgumentError, ~r/Invalid hash format/, fn ->
        Merkle.new([entry("a"), entry("b"), entry("c", "bad")])
      end
    end
  end
end
