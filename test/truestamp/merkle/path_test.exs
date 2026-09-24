# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.PathTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle

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
end
