# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.PathTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle
  alias Truestamp.Merkle.RFC9162

  # A three-entry tree and the last entry's proof, for the refusal tests.
  setup_all do
    entries = RFC9162.entries(3)
    tree = Merkle.new(entries)
    last = List.last(entries)

    %{
      tree: tree,
      root: Merkle.root(tree),
      digest: last["hash"],
      proof: Merkle.proof(tree, last["key"])
    }
  end

  defp hash_hex(label), do: RFC9162.hex(RFC9162.sha256(label))

  # 64-character values whose last one or two characters are not lowercase hex: the four
  # characters just outside 0-9 and a-f, whitespace, and a NUL. The bad character comes
  # last, so a check that stops early cannot pass them.
  defp non_hex(hex) do
    for tail <- ["g", "/", ":", "`", "  ", "zz", <<0>>] do
      binary_part(hex, 0, 64 - byte_size(tail)) <> tail
    end
  end

  # Lowercase hex of an even length other than 64, which a decoder alone would accept.
  defp wrong_length(hex), do: ["", binary_part(hex, 0, 62), hex <> "ab", hex <> hex]

  describe "proof/2" do
    test "every proof in trees of 1 to 130 entries is the RFC's audit path" do
      for n <- 1..130 do
        entries = RFC9162.entries(n)
        tree = Merkle.new(entries)
        digests = RFC9162.digests(entries)

        for {entry, m} <- Enum.with_index(entries) do
          expected = Enum.map(RFC9162.path(m, digests), &RFC9162.hex/1)

          assert Merkle.proof(tree, entry["key"]) ==
                   %{leaf_index: m, tree_size: n, path: expected},
                 "n=#{n} m=#{m}"
        end
      end
    end

    test "a one-entry tree's proof has an empty path; a missing key has no proof" do
      tree = Merkle.new(RFC9162.entries(1))
      assert Merkle.proof(tree, "k00001") == %{leaf_index: 0, tree_size: 1, path: []}
      assert Merkle.proof(tree, "k00002") == nil
    end
  end

  describe "walk/3 and verify/4 accept" do
    test "every proof in trees of 1 to 130 entries, reaching the RFC's root" do
      for n <- 1..130 do
        entries = RFC9162.entries(n)
        tree = Merkle.new(entries)
        root = Merkle.root(tree)

        for entry <- entries do
          proof = Merkle.proof(tree, entry["key"])
          assert Merkle.walk(entry["hash"], proof) == {:ok, root}
          assert Merkle.verify(entry["hash"], proof, root)
          assert Merkle.verify(entry["hash"], proof, root, max_steps: tree.tree_depth)
        end
      end
    end

    test "the path length the RFC's loop accepts, and only that, for arbitrary nodes" do
      digest = RFC9162.sha256("d")
      nodes = for i <- 1..12, do: RFC9162.sha256("n#{i}")

      for size <- 1..70, index <- 0..(size - 1) do
        accepted =
          for len <- 0..12,
              RFC9162.walk(digest, index, size, Enum.take(nodes, len)) != :fail,
              do: len

        # The RFC's loop accepts exactly one length for each index and size, and it is
        # the length of the RFC's recursive PATH definition.
        assert [len] = accepted
        assert len == RFC9162.path_length(index, size)

        for try <- 0..12 do
          path = nodes |> Enum.take(try) |> Enum.map(&RFC9162.hex/1)

          result =
            Merkle.walk(RFC9162.hex(digest), %{leaf_index: index, tree_size: size, path: path})

          if try == len do
            expected = RFC9162.walk(digest, index, size, Enum.take(nodes, len))
            assert result == {:ok, RFC9162.hex(expected)}, "size=#{size} index=#{index}"
          else
            assert result == {:error, :wrong_path_length},
                   "size=#{size} index=#{index} len=#{try}"
          end
        end
      end
    end

    test "the RFC's path length at the edges of the size range" do
      digest = RFC9162.hex(RFC9162.sha256("d"))
      nodes = for i <- 1..65, do: RFC9162.hex(RFC9162.sha256("n#{i}"))

      sizes =
        for(k <- 0..63, delta <- [-1, 0, 1], do: Bitwise.bsl(1, k) + delta)
        |> Enum.concat([0xFFFF_FFFF_FFFF_FFFF])
        |> Enum.filter(&(&1 >= 1 and &1 <= 0xFFFF_FFFF_FFFF_FFFF))
        |> Enum.uniq()

      for size <- sizes,
          index <- Enum.uniq([0, 1, div(size, 2), size - 2, size - 1]),
          index >= 0 and index < size do
        len = RFC9162.path_length(index, size)
        proof = %{leaf_index: index, tree_size: size, path: Enum.take(nodes, len)}

        assert {:ok, _root} = Merkle.walk(digest, proof), "size=#{size} index=#{index}"

        assert Merkle.walk(digest, %{proof | path: Enum.take(nodes, len + 1)}) ==
                 {:error, :wrong_path_length}

        if len > 0 do
          assert Merkle.walk(digest, %{proof | path: Enum.take(nodes, len - 1)}) ==
                   {:error, :wrong_path_length}
        end
      end
    end
  end

  describe "walk/3 and verify/4 refuse" do
    test "any altered proof, including changes that keep the path's length" do
      entries = RFC9162.entries(7)
      tree = Merkle.new(entries)
      root = Merkle.root(tree)
      [first_entry | _] = entries
      digest = first_entry["hash"]
      proof = Merkle.proof(tree, first_entry["key"])
      [first | rest] = proof.path
      changed = String.slice(first, 0..-2//1) <> if(String.last(first) == "0", do: "1", else: "0")

      # Indexes 1 to 3 have paths as long as index 0's, so these get as far as hashing
      # and reach some other root.
      same_length = [
        %{proof | leaf_index: 1},
        %{proof | leaf_index: 2},
        %{proof | leaf_index: 3},
        %{proof | path: [changed | rest]},
        %{proof | path: Enum.reverse(proof.path)}
      ]

      for altered <- same_length do
        assert {:ok, other} = Merkle.walk(digest, altered), inspect(altered)
        refute other == root
        refute Merkle.verify(digest, altered, root)
      end

      for altered <- [%{proof | path: rest}, %{proof | path: proof.path ++ [root]}] do
        assert Merkle.walk(digest, altered) == {:error, :wrong_path_length}
        refute Merkle.verify(digest, altered, root)
      end

      assert Merkle.verify(digest, proof, root)
    end

    test "a digest that is not 64 lowercase hex characters", %{proof: proof} do
      for bad <-
            [
              String.duplicate("A", 64),
              String.duplicate("a", 63),
              String.duplicate("a", 64) <> "\n",
              nil,
              7
            ] ++ non_hex(String.duplicate("a", 64)) ++ wrong_length(String.duplicate("a", 64)) do
        assert Merkle.walk(bad, proof) == {:error, :invalid_leaf}, inspect(bad)
      end
    end

    test "a proof that is not a proof", %{digest: digest} do
      for bad <- [
            nil,
            [],
            "proof",
            %{},
            %{leaf_index: 0, tree_size: 1},
            %{"leaf_index" => 0, "tree_size" => 1, "path" => []},
            %{leaf_index: -1, tree_size: 1, path: []},
            %{leaf_index: 0, tree_size: 0, path: []},
            %{leaf_index: 0, tree_size: 18_446_744_073_709_551_616, path: []},
            # A size past 2^64 - 1 is refused before the index is compared with it.
            %{
              leaf_index: 18_446_744_073_709_551_617,
              tree_size: 18_446_744_073_709_551_616,
              path: []
            },
            %{
              leaf_index: 18_446_744_073_709_551_616,
              tree_size: 18_446_744_073_709_551_616,
              path: []
            },
            %{leaf_index: 0.0, tree_size: 1, path: []},
            %{leaf_index: 0, tree_size: 3, path: "not a list"},
            %{leaf_index: 0, tree_size: 3, path: nil}
          ] do
        assert Merkle.walk(digest, bad) == {:error, :invalid_proof}, inspect(bad)
      end
    end

    test "an index not below the size", %{digest: digest} do
      for {index, size} <- [{3, 3}, {4, 3}, {1, 1}] do
        proof = %{leaf_index: index, tree_size: size, path: []}
        assert Merkle.walk(digest, proof) == {:error, :index_out_of_range}
      end
    end

    test "a path longer than :max_steps, before the path is read", %{digest: digest} do
      proof = %{leaf_index: 0, tree_size: Bitwise.bsl(1, 33), path: [:not_read]}
      assert Merkle.walk(digest, proof, max_steps: 32) == {:error, :too_many_steps}

      assert Merkle.walk(digest, %{proof | tree_size: 2}, max_steps: 0) ==
               {:error, :too_many_steps}
    end

    test "a path of the wrong length, counted without reading its nodes", %{digest: digest} do
      # Two nodes are needed; a million junk elements are refused on length alone.
      long = List.duplicate(:junk, 1_000_000)

      assert Merkle.walk(digest, %{leaf_index: 0, tree_size: 3, path: long}) ==
               {:error, :wrong_path_length}

      assert Merkle.walk(digest, %{leaf_index: 0, tree_size: 3, path: [:junk]}) ==
               {:error, :wrong_path_length}
    end

    test "an improper list, whatever its length", %{digest: digest} do
      [a, b, c, d] = for label <- ~w(a b c d), do: hash_hex(label)

      for path <- [[a | b], [a, b | :tail], [a, b, c, d | :tail]] do
        assert Merkle.walk(digest, %{leaf_index: 0, tree_size: 3, path: path}) ==
                 {:error, :wrong_path_length}
      end
    end

    test "counting stops one node past the length, however long the path is", ctx do
      %{digest: digest} = ctx
      long = List.duplicate(:junk, 1_000_000)
      proof = %{leaf_index: 0, tree_size: 3, path: long}

      {:reductions, before} = Process.info(self(), :reductions)
      assert Merkle.walk(digest, proof) == {:error, :wrong_path_length}
      {:reductions, later} = Process.info(self(), :reductions)

      # Counting the whole list would take about a million reductions.
      assert later - before < 10_000
    end

    test "a node that is not 64 lowercase hex characters", %{digest: digest, proof: proof} do
      [first] = proof.path

      for bad <-
            [
              String.upcase(first),
              first <> "\n",
              binary_part(first, 0, 63),
              "r:" <> first,
              :atom,
              7,
              nil
            ] ++ non_hex(first) ++ wrong_length(first) do
        assert Merkle.walk(digest, %{proof | path: [bad]}) == {:error, :invalid_node},
               inspect(bad)
      end
    end

    test "the checks run in order: digest, proof, index, cap, length, nodes", %{digest: digest} do
      # The path's nodes come last: a wrong node in a path of the right length.
      assert Merkle.walk(digest, %{leaf_index: 2, tree_size: 3, path: [:x]}) ==
               {:error, :invalid_node}

      assert Merkle.walk("bad", %{leaf_index: 9, tree_size: 3, path: []}) ==
               {:error, :invalid_leaf}

      assert Merkle.walk("bad", %{leaf_index: 0, tree_size: 0, path: :x}) ==
               {:error, :invalid_leaf}

      assert Merkle.walk(digest, %{leaf_index: 9, tree_size: 0, path: []}) ==
               {:error, :invalid_proof}

      assert Merkle.walk(digest, %{leaf_index: 9, tree_size: 3, path: :x}) ==
               {:error, :invalid_proof}

      assert Merkle.walk(digest, %{leaf_index: 9, tree_size: 3, path: [:x]}) ==
               {:error, :index_out_of_range}

      # Any path for this index, at this size or the next, is about 40 nodes: over the cap.
      huge = Bitwise.bsl(1, 40) - 1

      assert Merkle.walk(digest, %{leaf_index: huge, tree_size: huge, path: []}, max_steps: 32) ==
               {:error, :index_out_of_range}

      big = %{leaf_index: 0, tree_size: huge, path: [:x]}
      assert Merkle.walk(digest, big, max_steps: 32) == {:error, :too_many_steps}

      assert Merkle.walk(digest, %{leaf_index: 0, tree_size: 3, path: [:x]}) ==
               {:error, :wrong_path_length}
    end

    test "verify/4 is false for a root that is not 64 lowercase hex characters", ctx do
      %{digest: digest, proof: proof, root: root} = ctx

      for bad <-
            [String.upcase(root), root <> "\n", binary_part(root, 0, 63), nil] ++
              non_hex(root) ++ wrong_length(root) do
        refute Merkle.verify(digest, proof, bad), inspect(bad)
      end
    end
  end

  describe "the tree size" do
    # RFC 9162's design, not a defect: the size must come from the same trusted source
    # as the root, which is why the docs say to check it there.

    test "is not checked by the walk: a size-3 proof claiming size 4 still reaches the size-3 root" do
      entries = RFC9162.entries(3)
      tree = Merkle.new(entries)
      [first | _] = entries
      proof = Merkle.proof(tree, first["key"])

      assert Merkle.verify(first["hash"], %{proof | tree_size: 4}, Merkle.root(tree))
      refute Merkle.verify(first["hash"], %{proof | tree_size: 5}, Merkle.root(tree))
    end

    test "and the index moves with it: the last of three also verifies as index 1 of two" do
      entries = RFC9162.entries(3)
      tree = Merkle.new(entries)
      last = List.last(entries)
      proof = Merkle.proof(tree, last["key"])

      assert proof.leaf_index == 2 and proof.tree_size == 3

      assert Merkle.verify(
               last["hash"],
               %{proof | leaf_index: 1, tree_size: 2},
               Merkle.root(tree)
             )
    end

    test "in trees of 1 to 300 entries, 43,730 of 45,150 proofs verify with the size raised by one" do
      counts =
        for n <- 1..300, reduce: {0, 0} do
          {total, raised} ->
            entries = RFC9162.entries(n)
            tree = Merkle.new(entries)
            root = Merkle.root(tree)

            still =
              Enum.count(entries, fn entry ->
                proof = Merkle.proof(tree, entry["key"])
                Merkle.verify(entry["hash"], %{proof | tree_size: n + 1}, root)
              end)

            {total + n, raised + still}
        end

      # The figure the module documentation quotes.
      assert counts == {45_150, 43_730}
    end

    test "given the true size, no other index verifies, in trees of 1 to 64 entries" do
      for n <- 1..64 do
        entries = RFC9162.entries(n)
        tree = Merkle.new(entries)
        root = Merkle.root(tree)

        for entry <- entries do
          proof = Merkle.proof(tree, entry["key"])

          for other <- 0..(n - 1), other != proof.leaf_index do
            refute Merkle.verify(entry["hash"], %{proof | leaf_index: other}, root),
                   "n=#{n} index=#{proof.leaf_index} other=#{other}"
          end
        end
      end
    end
  end

  describe "options" do
    test ":max_steps is an integer from 0 to 64, and nothing else is accepted", ctx do
      %{digest: digest, proof: proof, root: root} = ctx

      for bad <- [
            [max_steps: 65],
            [max_steps: -1],
            [max_steps: nil],
            [max_steps: "32"],
            [max_steps: 32.0],
            [cap: 1]
          ] do
        assert_raise ArgumentError, fn -> Merkle.walk(digest, proof, bad) end
        assert_raise ArgumentError, fn -> Merkle.verify(digest, proof, root, bad) end
      end

      for bad <- [%{max_steps: 3}, nil, "opts", [{:max_steps, 3} | :tail]] do
        assert_raise ArgumentError, ~r/options must be a keyword list/, fn ->
          Merkle.walk(digest, proof, bad)
        end
      end
    end
  end
end
