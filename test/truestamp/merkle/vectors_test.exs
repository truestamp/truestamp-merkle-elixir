# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.VectorsTest do
  # The library must reproduce every value in vectors/merkle.json, which
  # vectors/generate.exs writes from RFC 9162 without using the library.
  use ExUnit.Case, async: true

  alias Truestamp.Merkle
  alias Truestamp.Merkle.RFC9162

  @vectors_path Path.expand("../../../vectors/merkle.json", __DIR__)
  @external_resource @vectors_path
  @vectors @vectors_path |> File.read!() |> JSON.decode!()

  @fields %{"leaf_index" => :leaf_index, "tree_size" => :tree_size, "path" => :path}

  defp entries(tree),
    do: Enum.map(tree["entries"], &%{"key" => &1["key"], "hash" => &1["digest"]})

  # A JSON proof object as the library takes it. Anything else is passed as it stands.
  defp to_proof(%{} = json), do: Map.new(json, fn {key, value} -> {@fields[key], value} end)
  defp to_proof(other), do: other

  test "every section the tests loop over has cases, so no loop can pass empty" do
    for section <- ~w(trees entry_refusals walk_accepts walk_refusals binary_refusals) do
      assert [_ | _] = @vectors[section], section
    end

    for tree <- @vectors["trees"], tree["entries"] != [] do
      assert [_ | _] = tree["paths"], tree["name"]
    end
  end

  describe "constants" do
    test "the empty root, the default step cap and the largest tree size" do
      %{"empty_root" => empty_root, "max_steps" => cap, "max_tree_size" => max_size} =
        @vectors["constants"]

      assert Merkle.root(Merkle.new([])) == empty_root

      digest = RFC9162.hex(RFC9162.sha256("d"))
      path = for i <- 1..cap, do: RFC9162.hex(RFC9162.sha256("n#{i}"))
      largest = %{leaf_index: 0, tree_size: max_size, path: path}

      # The largest size takes exactly the default cap of steps, so the default never
      # refuses a proof the size field can express.
      assert {:ok, _root} = Merkle.walk(digest, largest)
      assert {:ok, _root} = Merkle.walk(digest, largest, max_steps: cap)
      assert Merkle.walk(digest, %{largest | tree_size: max_size + 1}) == {:error, :invalid_proof}
      assert_raise ArgumentError, fn -> Merkle.walk(digest, largest, max_steps: cap + 1) end
    end
  end

  describe "trees" do
    for tree <- @vectors["trees"] do
      @tree tree

      test "#{tree["name"]}: root, depth, size, and every path in both forms" do
        built = Merkle.new(entries(@tree))
        root = @tree["root"]

        assert Merkle.root(built) == root
        assert built.tree_depth == @tree["depth"]
        assert length(built.leaves) == @tree["tree_size"]

        for path <- @tree["paths"] do
          proof = to_proof(Map.take(path, Map.keys(@fields)))
          bytes = Base.decode16!(path["binary_hex"], case: :lower)

          assert proof.tree_size == @tree["tree_size"]
          assert Merkle.proof(built, path["key"]) == proof
          assert Merkle.walk(path["digest"], proof) == {:ok, root}
          assert Merkle.verify(path["digest"], proof, root)
          assert Merkle.proof_to_binary(proof) == bytes
          assert Merkle.proof_from_binary(bytes) == {:ok, proof}
        end
      end
    end
  end

  describe "walks" do
    for accept <- @vectors["walk_accepts"] do
      @accept accept

      test "walk accepts: #{accept["name"]}" do
        %{"digest" => digest, "proof" => json, "max_steps" => cap, "root" => root} = @accept
        proof = to_proof(json)

        assert Merkle.walk(digest, proof, max_steps: cap) == {:ok, root}
        assert Merkle.verify(digest, proof, root, max_steps: cap)

        bytes = Base.decode16!(@accept["binary_hex"], case: :lower)
        assert Merkle.proof_to_binary(proof) == bytes
        assert Merkle.proof_from_binary(bytes) == {:ok, proof}
      end
    end

    test "the size-3 path claimed at size 4 reaches the leaf-3 tree's root" do
      accept = Enum.find(@vectors["walk_accepts"], &String.starts_with?(&1["name"], "a size-3"))
      tree = Enum.find(@vectors["trees"], &(&1["name"] == "leaf-3"))

      # The root does not fix the tree size; a verifier takes the size from where it
      # takes the root.
      assert accept["root"] == tree["root"]
      assert accept["proof"]["tree_size"] != tree["tree_size"]
    end
  end

  describe "refusals" do
    for refusal <- @vectors["entry_refusals"] do
      @refusal refusal

      test "construction refuses: #{refusal["name"]}" do
        assert_raise ArgumentError, fn -> Merkle.new(entries(@refusal)) end
      end
    end

    for refusal <- @vectors["walk_refusals"] do
      @refusal refusal

      test "walk refuses: #{refusal["name"]}" do
        %{"digest" => digest, "proof" => json, "max_steps" => cap} = @refusal

        assert {:error, reason} = Merkle.walk(digest, to_proof(json), max_steps: cap)
        assert Atom.to_string(reason) == @refusal["error"]
      end
    end

    test "verify refuses what walk refuses, even against the root the proof would reach" do
      reachable =
        for %{"name" => name, "digest" => digest, "proof" => json, "max_steps" => cap} <-
              @vectors["walk_refusals"],
            {:ok, root} <- [unchecked_root(digest, json)] do
          refute Merkle.verify(digest, to_proof(json), root, max_steps: cap), name
          name
        end

      # The uppercase digest, the uppercase node and the whole path under a small cap.
      assert length(reachable) >= 3, inspect(reachable)
    end

    test "the binary decoder refuses every non-canonical binary, naming why" do
      for %{"name" => name, "binary_hex" => hex, "error" => error} <-
            @vectors["binary_refusals"] do
        bytes = Base.decode16!(hex, case: :lower)
        assert {:error, reason} = Merkle.proof_from_binary(bytes), name
        assert Atom.to_string(reason) == error, name
      end
    end
  end

  # Where a refused proof would lead if nothing but the RFC's loop checked it: hex in
  # any case, no step cap. :error when the loop fails or the proof cannot be read.
  defp unchecked_root(digest, %{"leaf_index" => index, "tree_size" => size, "path" => path})
       when is_integer(index) and index >= 0 and is_integer(size) and is_list(path) do
    with {:ok, leaf} <- Base.decode16(digest, case: :mixed),
         {:ok, nodes} <- decode_nodes(path, []),
         root when is_binary(root) <- RFC9162.walk(leaf, index, size, nodes) do
      {:ok, RFC9162.hex(root)}
    else
      _ -> :error
    end
  end

  defp unchecked_root(_digest, _json), do: :error

  defp decode_nodes([], nodes), do: {:ok, Enum.reverse(nodes)}

  defp decode_nodes([node | rest], nodes) when is_binary(node) do
    case Base.decode16(node, case: :mixed) do
      {:ok, bytes} -> decode_nodes(rest, [bytes | nodes])
      :error -> :error
    end
  end

  defp decode_nodes(_path, _nodes), do: :error
end
