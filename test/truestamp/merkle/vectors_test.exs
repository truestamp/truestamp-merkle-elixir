# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.VectorsTest do
  # The library must reproduce every value in vectors/merkle.json, which
  # vectors/generate.exs writes from the README's contract without using the
  # library.
  use ExUnit.Case, async: true

  alias Truestamp.Merkle

  @vectors_path Path.expand("../../../vectors/merkle.json", __DIR__)
  @readme_path Path.expand("../../../README.md", __DIR__)
  @external_resource @vectors_path
  @external_resource @readme_path
  @vectors @vectors_path |> File.read!() |> JSON.decode!()

  defp entries(tree),
    do: Enum.map(tree["entries"], &%{"key" => &1["key"], "hash" => &1["digest"]})

  test "every section the tests loop over has cases, so no loop can pass empty" do
    for section <-
          ~w(trees entry_refusals walk_accepts walk_refusals binary_refusals base64url_refusals) do
      assert [_ | _] = @vectors[section], section
    end

    for tree <- @vectors["trees"], tree["entries"] != [] do
      assert [_ | _] = tree["paths"], tree["name"]
    end
  end

  describe "constants" do
    test "the empty root, the reserved digest and the padding leaf" do
      constants = @vectors["constants"]

      assert Merkle.root(Merkle.new([])) == constants["empty_root"]
      assert Merkle.walk(constants["reserved_digest"], []) == {:error, :reserved_leaf}

      assert_raise ArgumentError, fn ->
        Merkle.new([%{"key" => "k", "hash" => constants["reserved_digest"]}])
      end

      padding_step = "r:" <> constants["padding_leaf"]
      paths = Enum.flat_map(@vectors["trees"], & &1["paths"])
      assert Enum.any?(paths, &(padding_step in &1["steps"]))
    end
  end

  describe "trees" do
    for tree <- @vectors["trees"] do
      @tree tree

      test "#{tree["name"]}: root, depth, and every path in every form" do
        built = Merkle.new(entries(@tree))
        root = @tree["root"]

        assert Merkle.root(built) == root
        assert built.tree_depth == @tree["depth"]

        if @tree["padded_size"] > 0 do
          assert @tree["padded_size"] == Integer.pow(2, @tree["depth"])
        end

        # Strict RFC 6962 agrees exactly when no padding was needed.
        assert @tree["rfc6962_root"] == root ==
                 (@tree["padded_size"] == length(@tree["entries"]))

        for path <- @tree["paths"] do
          steps = path["steps"]
          bytes = Base.decode16!(path["binary_hex"], case: :lower)

          assert Merkle.proof(built, path["key"]) == steps
          assert Merkle.walk(path["digest"], steps) == {:ok, root}
          assert Merkle.verify(path["digest"], steps, root)
          assert Merkle.steps_to_binary(steps) == bytes
          assert Merkle.steps_from_binary(bytes) == {:ok, steps}
          assert Merkle.encode_proof_base64(steps) == path["base64url"]
          assert Merkle.decode_proof_base64(path["base64url"]) == {:ok, steps}
        end
      end
    end
  end

  describe "walks" do
    for accept <- @vectors["walk_accepts"] do
      @accept accept

      test "walk accepts: #{accept["name"]}" do
        %{"digest" => digest, "steps" => steps, "max_steps" => cap, "root" => root} = @accept

        assert Merkle.walk(digest, steps, max_steps: cap) == {:ok, root}
        assert Merkle.verify(digest, steps, root, max_steps: cap)
      end
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
        %{"digest" => digest, "steps" => steps, "max_steps" => cap} = @refusal

        assert {:error, reason} = Merkle.walk(digest, steps, max_steps: cap)
        assert Atom.to_string(reason) == @refusal["error"]
        refute Merkle.verify(digest, steps, @vectors["constants"]["empty_root"], max_steps: cap)
      end
    end

    test "the binary decoder refuses every non-canonical binary, naming why" do
      for %{"name" => name, "binary_hex" => hex, "error" => error} <-
            @vectors["binary_refusals"] do
        bytes = Base.decode16!(hex, case: :lower)
        assert {:error, reason} = Merkle.steps_from_binary(bytes), name
        assert Atom.to_string(reason) == error, name

        assert {:error, _} = Merkle.decode_proof_base64(Base.url_encode64(bytes, padding: false)),
               name
      end
    end

    test "the base64url decoder refuses every non-canonical spelling" do
      for %{"name" => name, "base64url" => text, "error" => error} <-
            @vectors["base64url_refusals"] do
        assert {:error, reason} = Merkle.decode_proof_base64(text), name
        assert Atom.to_string(reason) == error, name
      end
    end
  end

  test "every hash and path the README prints is in the vectors file" do
    vectors = File.read!(@vectors_path)
    readme = File.read!(@readme_path)
    known = Regex.scan(~r/\b[0-9a-f]{64}\b/, readme) |> List.flatten() |> Enum.uniq()

    assert known != []
    assert Enum.reject(known, &String.contains?(vectors, &1)) == []
    assert String.contains?(vectors, "AQHXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wnw")
  end
end
