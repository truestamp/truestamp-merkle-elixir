# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.CodecTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Truestamp.Merkle
  alias Truestamp.Merkle.RFC9162

  describe "proof_to_binary/1" do
    test "writes leaf_index and tree_size as unsigned 64-bit big-endian, then the nodes" do
      [a, b] = for label <- ["a", "b"], do: RFC9162.sha256(label)
      proof = %{leaf_index: 1, tree_size: 3, path: [RFC9162.hex(a), RFC9162.hex(b)]}

      assert Merkle.proof_to_binary(proof) ==
               <<0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3>> <> a <> b
    end

    test "round-trips every proof in trees of 1 to 130 entries" do
      for n <- 1..130 do
        entries = RFC9162.entries(n)
        tree = Merkle.new(entries)

        for entry <- entries do
          proof = Merkle.proof(tree, entry["key"])
          binary = Merkle.proof_to_binary(proof)

          assert byte_size(binary) == 16 + 32 * length(proof.path)
          assert Merkle.proof_from_binary(binary) == {:ok, proof}
        end
      end
    end

    test "raises for a proof walk/3 would refuse" do
      node = RFC9162.hex(RFC9162.sha256("a"))

      for bad <- [
            %{leaf_index: 3, tree_size: 3, path: []},
            %{leaf_index: 0, tree_size: 3, path: [node]},
            %{leaf_index: 0, tree_size: 2, path: [String.upcase(node)]},
            %{leaf_index: 0, tree_size: 0, path: []},
            nil
          ] do
        assert_raise ArgumentError, ~r/Invalid proof/, fn -> Merkle.proof_to_binary(bad) end
      end
    end
  end

  describe "proof_from_binary/1 refuses" do
    test "anything but a binary" do
      for bad <- [nil, 7, [], %{}, <<1::3>>] do
        assert Merkle.proof_from_binary(bad) == {:error, :invalid_binary}, inspect(bad)
      end
    end

    test "fewer than the 16 bytes of the two fields" do
      for bad <- [<<>>, :binary.copy(<<0>>, 15)] do
        assert Merkle.proof_from_binary(bad) == {:error, :wrong_length}
      end
    end

    test "an index not below the size, before the path's length" do
      assert Merkle.proof_from_binary(<<0::64, 0::64>>) == {:error, :index_out_of_range}
      assert Merkle.proof_from_binary(<<3::64, 3::64>>) == {:error, :index_out_of_range}
      assert Merkle.proof_from_binary(<<9::64, 3::64, 1, 2>>) == {:error, :index_out_of_range}
    end

    test "path bytes that are not exactly the nodes the index and size require" do
      two = <<0::64, 3::64>> <> RFC9162.sha256("a") <> RFC9162.sha256("b")

      for bad <- [
            binary_part(two, 0, byte_size(two) - 32),
            two <> RFC9162.sha256("c"),
            two <> <<0>>,
            binary_part(two, 0, byte_size(two) - 1)
          ] do
        assert Merkle.proof_from_binary(bad) == {:error, :wrong_length}
      end

      assert {:ok, %{path: [_, _]}} = Merkle.proof_from_binary(two)
    end
  end

  # Small values, and values anywhere in the 64-bit range.
  defp u64, do: one_of([integer(0..300), integer(0..0xFFFF_FFFF_FFFF_FFFF)])

  property "arbitrary bytes decode only when canonical, and then re-encode exactly" do
    check all(
            index <- u64(),
            size <- u64(),
            extra <- integer(-2..2),
            path_bytes <-
              binary(
                length: max(0, 32 * RFC9162.path_length(index, max(size, index + 1)) + extra)
              )
          ) do
      input = <<index::64, size::64>> <> path_bytes

      # The length comes from the RFC's recursive PATH definition, not from the library.
      canonical? =
        index < size and byte_size(path_bytes) == 32 * RFC9162.path_length(index, size)

      case Merkle.proof_from_binary(input) do
        {:ok, proof} ->
          assert canonical?
          assert Merkle.proof_to_binary(proof) == input

        {:error, reason} ->
          refute canonical?
          assert reason == if(index >= size, do: :index_out_of_range, else: :wrong_length)
      end
    end
  end
end
