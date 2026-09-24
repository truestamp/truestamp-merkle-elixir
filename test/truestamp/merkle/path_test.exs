# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.PathTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle

  # Walk fixtures come from vectors/merkle.json, which vectors_test.exs holds the
  # library to in full. These tests cover behavior the file cannot express.
  @vectors_path Path.expand("../../../vectors/merkle.json", __DIR__)
  @external_resource @vectors_path
  @vectors @vectors_path |> File.read!() |> JSON.decode!()
  @trees Map.new(@vectors["trees"], &{&1["name"], &1})
  @reserved @vectors["constants"]["reserved_digest"]

  # key01's path and the root, for the tree of the given name.
  defp fixture(name) do
    tree = Map.fetch!(@trees, name)
    [path | _] = tree["paths"]
    %{leaf: path["digest"], root: tree["root"], steps: path["steps"]}
  end

  defp digest(text), do: Base.encode16(:crypto.hash(:sha256, text), case: :lower)

  # A syntactically valid path of `count` steps, for the step-count checks.
  defp steps(count), do: for(n <- 1..count//1, do: "r:" <> digest("sibling#{n}"))

  describe "proof/2" do
    test "generates proof for single element tree" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")

      assert is_list(proof)
      # No siblings for single element
      assert proof == []
    end

    test "generates proof for two element tree" do
      data = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)

      proof_a = Merkle.proof(tree, "test-key-a")
      proof_b = Merkle.proof(tree, "test-key-b")

      assert is_list(proof_a)
      assert is_list(proof_b)
      assert length(proof_a) == 1
      assert length(proof_b) == 1

      # Proof should contain sibling information as strings
      [proof_element_a] = proof_a
      [proof_element_b] = proof_b

      assert is_binary(proof_element_a)
      assert is_binary(proof_element_b)
      assert String.contains?(proof_element_a, ":")
      assert String.contains?(proof_element_b, ":")

      # Extract directions and verify they're opposite
      [direction_a, _hash_a] = String.split(proof_element_a, ":", parts: 2)
      [direction_b, _hash_b] = String.split(proof_element_b, ":", parts: 2)
      assert direction_a in ["l", "r"]
      assert direction_b in ["l", "r"]
      assert direction_a != direction_b
    end

    test "generates proof for larger tree" do
      data = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-c",
          "hash" => "c1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-d",
          "hash" => "d1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)

      proof = Merkle.proof(tree, "test-key-a")

      assert is_list(proof)
      # Depth 2 tree should have 2 proof elements
      assert length(proof) == 2

      # Each proof element should be a "direction:hash" string
      Enum.each(proof, fn proof_element ->
        assert is_binary(proof_element)
        assert String.contains?(proof_element, ":")
        [direction, hash] = String.split(proof_element, ":", parts: 2)
        assert direction in ["l", "r"]
        assert is_binary(hash)
        assert String.length(hash) == 64
      end)
    end

    test "returns nil for non-existent key" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "nonexistent-key-not-found-12345")

      assert proof == nil
    end

    test "handles keys with different ordering" do
      data = [
        %{
          "key" => "test-key-z",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-a",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "c1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      # Listed z, a, b; sorted a, b, z. Every key proves its own digest.
      assert Enum.map(tree.leaves, &elem(&1, 0)) == ["test-key-a", "test-key-b", "test-key-z"]

      for %{"key" => key, "hash" => hash} <- data do
        assert Merkle.verify(hash, Merkle.proof(tree, key), root), key
      end
    end
  end

  describe "verify/4" do
    test "verifies proof for single element tree" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               root
             ) == true
    end

    test "returns false for a leaf hash with a trailing newline" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
      tree = Merkle.new([%{"key" => "test-key-1", "hash" => hash}])
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      # verify/4 answers every invalid input with false, so a stray newline has
      # to be rejected rather than carried into the hashing path.
      assert Merkle.verify(hash <> "\n", proof, root) == false
    end

    test "verifies proof for two element tree" do
      data = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      proof_a = Merkle.proof(tree, "test-key-a")
      proof_b = Merkle.proof(tree, "test-key-b")

      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof_a,
               root
             ) == true

      assert Merkle.verify(
               "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof_b,
               root
             ) == true
    end

    test "verifies proof for larger tree" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-12345",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-23456",
          "hash" => "c1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-34567",
          "hash" => "d1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      # Verify every entry
      Enum.each(data, fn %{"key" => key, "hash" => hash} ->
        proof = Merkle.proof(tree, key)
        assert Merkle.verify(hash, proof, root) == true
      end)
    end

    test "rejects invalid proof with wrong root" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")

      wrong_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               wrong_root
             ) == false
    end

    test "rejects invalid proof with wrong hash" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      assert Merkle.verify(
               "aaa0012345678901234567890123456789012345678901234567890123456789",
               proof,
               root
             ) == false
    end

    test "rejects invalid proof with different hash" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      assert Merkle.verify(
               "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               root
             ) == false
    end

    test "rejects tampered proof" do
      data = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-a")
      root = Merkle.root(tree)

      # Tamper with proof
      tampered_proof =
        case proof do
          [proof_element] ->
            [direction, _hash] = String.split(proof_element, ":", parts: 2)
            ["#{direction}:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]

          _ ->
            proof
        end

      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               tampered_proof,
               root
             ) == false
    end
  end

  describe "JSON serialization compatibility" do
    test "proof structure is JSON-serializable" do
      data = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-a")

      # Should be able to encode/decode proof as JSON
      json_proof = JSON.encode!(proof)
      decoded_proof = JSON.decode!(json_proof)

      # No conversion needed - strings are preserved in JSON
      normalized_proof = decoded_proof

      assert proof == normalized_proof
    end

    test "proof verification works with JSON roundtrip" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-xyz",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      # JSON roundtrip
      json_proof = JSON.encode!(proof)
      decoded_proof = JSON.decode!(json_proof)

      # No conversion needed - strings are preserved in JSON
      normalized_proof = decoded_proof

      # Verification should still work
      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               normalized_proof,
               root
             ) == true
    end
  end

  describe "walk/3" do
    test "walks every entry of a padded tree to its root" do
      entries = for i <- 1..13, do: %{"key" => "k#{i}", "hash" => digest("e#{i}")}
      tree = Merkle.new(entries)

      for %{"key" => key, "hash" => hash} <- entries do
        assert Merkle.walk(hash, Merkle.proof(tree, key)) == {:ok, Merkle.root(tree)}
      end
    end
  end

  describe "walk/3 refusals" do
    setup do
      fixture("leaf-3")
    end

    test "a leaf that is not 64 lowercase hex characters", %{steps: steps, leaf: leaf} do
      for bad <- [String.upcase(leaf), leaf <> "\n", binary_part(leaf, 0, 63), "", nil, 42] do
        assert Merkle.walk(bad, steps) == {:error, :invalid_leaf}, inspect(bad)
      end
    end

    test "the reserved padding value as the leaf", %{steps: steps} do
      assert Merkle.walk(@reserved, steps) == {:error, :reserved_leaf}
      assert Merkle.walk(@reserved, []) == {:error, :reserved_leaf}
    end

    test "33 steps under a cap of 32, and 65 under the default of 64", %{leaf: leaf} do
      assert {:ok, _} = Merkle.walk(leaf, steps(32), max_steps: 32)
      assert Merkle.walk(leaf, steps(33), max_steps: 32) == {:error, :too_many_steps}
      assert {:ok, _} = Merkle.walk(leaf, steps(64))
      assert Merkle.walk(leaf, steps(65)) == {:error, :too_many_steps}
    end

    test "an oversized path is refused before any step is read", %{leaf: leaf} do
      junk = List.duplicate(:not_a_step, 33)
      assert Merkle.walk(leaf, junk, max_steps: 32) == {:error, :too_many_steps}
    end

    test "uppercase hex or direction in a step", %{leaf: leaf, steps: [first | rest]} do
      "r:" <> sibling = first
      assert Merkle.walk(leaf, ["r:" <> String.upcase(sibling) | rest]) == {:error, :invalid_step}
      assert Merkle.walk(leaf, ["R:" <> sibling | rest]) == {:error, :invalid_step}
    end

    test "a step with a trailing newline", %{leaf: leaf, steps: [first | rest]} do
      assert Merkle.walk(leaf, [first <> "\n" | rest]) == {:error, :invalid_step}
    end

    test "a bare hash with no direction", %{leaf: leaf, steps: [first | rest]} do
      "r:" <> sibling = first
      assert Merkle.walk(leaf, [sibling | rest]) == {:error, :invalid_step}
    end

    test "other malformed steps", %{leaf: leaf} do
      sibling = digest("s")

      for bad <- [
            "x:" <> sibling,
            "r" <> sibling,
            "r::" <> sibling,
            "r:" <> binary_part(sibling, 0, 63),
            :atom,
            7,
            nil
          ] do
        assert Merkle.walk(leaf, [bad]) == {:error, :invalid_step}, inspect(bad)
      end
    end

    test "steps that are not a proper list", %{leaf: leaf, steps: [first | _]} do
      for bad <- ["not a list", %{}, nil, [first | :tail]] do
        assert Merkle.walk(leaf, bad) == {:error, :invalid_step}, inspect(bad)
      end
    end

    test "the leaf is checked before the steps", %{leaf: leaf} do
      assert Merkle.walk("bad", steps(65)) == {:error, :invalid_leaf}
      assert Merkle.walk(@reserved, [:not_a_step]) == {:error, :reserved_leaf}
      assert Merkle.walk(leaf, [:not_a_step]) == {:error, :invalid_step}
    end
  end

  describe "options" do
    test ":max_steps must be an integer from 0 to 64" do
      leaf = digest("leaf1")
      assert {:ok, _} = Merkle.walk(leaf, [], max_steps: 0)
      assert Merkle.walk(leaf, steps(1), max_steps: 0) == {:error, :too_many_steps}

      for bad <- [65, -1, 1.5, nil, "32"] do
        assert_raise ArgumentError, fn -> Merkle.walk(leaf, [], max_steps: bad) end
        assert_raise ArgumentError, fn -> Merkle.verify(leaf, [], leaf, max_steps: bad) end
      end
    end

    test "an unknown option, or options that are not a keyword list, raise" do
      leaf = digest("leaf1")
      assert_raise ArgumentError, fn -> Merkle.walk(leaf, [], cap: 3) end

      for bad <- [%{max_steps: 3}, nil, "opts"] do
        assert_raise ArgumentError, fn -> Merkle.walk(leaf, [], bad) end
        assert_raise ArgumentError, fn -> Merkle.verify(leaf, [], leaf, bad) end
      end
    end
  end

  describe "verify/4 refusals" do
    setup do
      fixture("leaf-5")
    end

    test "true for a path that reaches the root", %{leaf: leaf, root: root, steps: steps} do
      assert Merkle.verify(leaf, steps, root)
      big = fixture("bigleaf-300")
      assert Merkle.verify(big.leaf, big.steps, big.root)
    end

    test "false for a different root or leaf", %{leaf: leaf, root: root, steps: steps} do
      refute Merkle.verify(leaf, steps, fixture("bigleaf-300").root)
      refute Merkle.verify(digest("leaf2"), steps, root)
    end

    test "false for every walk refusal", %{leaf: leaf, root: root, steps: steps} do
      refute Merkle.verify(String.upcase(leaf), steps, root)
      refute Merkle.verify(@reserved, steps, root)
      refute Merkle.verify(leaf, ["R" <> tl_string(hd(steps)) | tl(steps)], root)
      refute Merkle.verify(leaf, steps, root, max_steps: length(steps) - 1)
    end

    test "false for a root that is not 64 lowercase hex characters",
         %{leaf: leaf, root: root, steps: steps} do
      for bad <- [String.upcase(root), root <> "\n", binary_part(root, 0, 63), nil] do
        refute Merkle.verify(leaf, steps, bad), inspect(bad)
      end
    end
  end

  defp tl_string(<<_, rest::binary>>), do: rest
end
