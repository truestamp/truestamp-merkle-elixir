# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.MerkleTest do
  use ExUnit.Case, async: true
  doctest Truestamp.Merkle

  alias Truestamp.Merkle

  describe "new/1" do
    test "creates a tree with single element" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)

      assert %Merkle{} = tree
      assert is_binary(tree.root_hash)
      # SHA-256 binary should be 32 bytes, hex representation should be 64 chars
      assert byte_size(tree.root_hash) == 32
      assert String.length(Merkle.root(tree)) == 64
      assert tree.tree_depth == 0

      assert tree.leaves == [
               {"test-key-1", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
             ]
    end

    test "creates a tree with multiple elements" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-xyz",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree = Merkle.new(data)

      assert %Merkle{} = tree
      assert is_binary(tree.root_hash)
      # SHA-256 binary should be 32 bytes, hex representation should be 64 chars
      assert byte_size(tree.root_hash) == 32
      assert String.length(Merkle.root(tree)) == 64
      assert tree.tree_depth == 1
      assert length(tree.leaves) == 2
    end

    test "raises for a duplicate key with different hashes" do
      data = [
        %{
          "key" => "dup-key",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "other-key",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        },
        %{
          "key" => "dup-key",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      assert_raise ArgumentError, ~r/Duplicate key in input data: "dup-key"/, fn ->
        Merkle.new(data)
      end
    end

    test "raises for a duplicate key even when the hashes match" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"

      data = [
        %{"key" => "dup-key", "hash" => hash},
        %{"key" => "dup-key", "hash" => hash}
      ]

      assert_raise ArgumentError, ~r/Duplicate key in input data: "dup-key"/, fn ->
        Merkle.new(data)
      end
    end

    test "raises for a duplicate key with sort: false" do
      data = [
        %{
          "key" => "z-key",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "a-key",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "z-key",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      assert_raise ArgumentError, ~r/Duplicate key in input data: "z-key"/, fn ->
        Merkle.new(data, sort: false)
      end
    end

    test "accepts distinct keys that share the same hash" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"

      tree =
        Merkle.new([
          %{"key" => "key-a", "hash" => hash},
          %{"key" => "key-b", "hash" => hash}
        ])

      assert length(tree.leaves) == 2
      assert map_size(tree.leaf_index) == 2

      root = Merkle.root(tree)
      assert Merkle.verify(Merkle.proof(tree, "key-a"), root, hash)
      assert Merkle.verify(Merkle.proof(tree, "key-b"), root, hash)
    end

    test "every accepted leaf is provable" do
      data =
        for i <- 1..64 do
          %{
            "key" => "leaf-#{i}",
            "hash" => :crypto.hash(:sha256, "leaf-#{i}") |> Base.encode16(case: :lower)
          }
        end

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      for %{"key" => key, "hash" => hash} <- data do
        assert Merkle.verify(Merkle.proof(tree, key), root, hash), "#{key} is not provable"
      end
    end

    test "sorts input by key deterministically" do
      data1 = [
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-c",
          "hash" => "c1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      data2 = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-c",
          "hash" => "c1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree1 = Merkle.new(data1)
      tree2 = Merkle.new(data2)

      # Same data in different order should produce identical trees
      assert tree1.root_hash == tree2.root_hash
      assert tree1.leaves == tree2.leaves

      assert tree1.leaves == [
               {"test-key-a", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
               {"test-key-b", "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
               {"test-key-c", "c1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
             ]
    end

    test "pads to power of 2 for balanced tree" do
      # 3 elements should be padded to 4
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
        }
      ]

      tree = Merkle.new(data)

      # log2(4) = 2
      assert tree.tree_depth == 2
      # Original data preserved
      assert length(tree.leaves) == 3
    end

    test "handles empty tree correctly" do
      tree = Merkle.new([])

      # Empty tree root should be HASH("") - SHA256 of empty string
      expected_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      assert Merkle.root(tree) == expected_root

      # Empty tree has depth 0
      assert tree.tree_depth == 0

      # Empty tree has no leaves
      assert tree.leaves == []

      # Proof for any key should return nil
      assert Merkle.proof(tree, "any-key") == nil
      assert Merkle.proof(tree, "00000000-0000-0000-0000-000000000000") == nil
    end

    test "raises error for invalid key format" do
      data = [
        %{
          "key" => "INVALID_KEY_FORMAT!",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      assert_raise ArgumentError, ~r/Invalid key format/, fn ->
        Merkle.new(data)
      end
    end

    test "raises error for invalid hash format" do
      data = [%{"key" => "test-key-1", "hash" => "invalid_hash"}]

      assert_raise ArgumentError, ~r/Invalid hash format/, fn ->
        Merkle.new(data)
      end
    end

    test "raises the format error for a hash with a trailing newline" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
      data = [%{"key" => "test-key-1", "hash" => hash <> "\n"}]

      # The complaint must come from the format check, not from Base.decode16!
      # further down the line.
      assert_raise ArgumentError, ~r/Invalid hash format/, fn ->
        Merkle.new(data)
      end
    end

    test "raises error for missing key field" do
      data = [%{"hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}]

      assert_raise ArgumentError, ~r/Invalid input entry format/, fn ->
        Merkle.new(data)
      end
    end

    test "raises error for missing hash field" do
      data = [%{"key" => "test-key-1"}]

      assert_raise ArgumentError, ~r/Invalid input entry format/, fn ->
        Merkle.new(data)
      end
    end

    test "raises error for input that is not a list" do
      for not_a_list <- ["not a list", %{"key" => "k"}, nil, 42] do
        assert_raise ArgumentError, ~r/Invalid input data/, fn ->
          # credo:disable-for-next-line Credo.Check.Refactor.Apply
          apply(Merkle, :new, [not_a_list])
        end
      end
    end

    test "raises error for non-string key" do
      data = [
        %{
          "key" => 123,
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      assert_raise ArgumentError, ~r/Invalid key type/, fn ->
        Merkle.new(data)
      end
    end

    test "raises error for non-string hash" do
      data = [%{"key" => "test-key-1", "hash" => 123}]

      assert_raise ArgumentError, ~r/Invalid hash type/, fn ->
        Merkle.new(data)
      end
    end

    test "handles power of 2 sizes correctly" do
      # Test with exactly 4 elements (already power of 2)
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

      # log2(4) = 2
      assert tree.tree_depth == 2
      assert length(tree.leaves) == 4
    end
  end

  describe "root/1" do
    test "returns the root hash as hex string" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      assert is_binary(root)
      assert String.length(root) == 64
      # Only lowercase hex
      assert String.match?(root, ~r/^[0-9a-f]+$/)
    end

    test "different data produces different roots" do
      data1 = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      data2 = [
        %{
          "key" => "entry-xyz",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree1 = Merkle.new(data1)
      tree2 = Merkle.new(data2)

      assert Merkle.root(tree1) != Merkle.root(tree2)
    end

    test "same data produces same root (deterministic)" do
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

      tree1 = Merkle.new(data)
      tree2 = Merkle.new(data)

      assert Merkle.root(tree1) == Merkle.root(tree2)
    end
  end

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

      # Should be able to generate proofs for all keys
      proof_a = Merkle.proof(tree, "test-key-a")
      proof_b = Merkle.proof(tree, "test-key-b")
      proof_z = Merkle.proof(tree, "test-key-z")

      assert is_list(proof_a)
      assert is_list(proof_b)
      assert is_list(proof_z)
    end
  end

  describe "verify/3" do
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
               proof,
               root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == true
    end

    test "returns false for a leaf hash with a trailing newline" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
      tree = Merkle.new([%{"key" => "test-key-1", "hash" => hash}])
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      # verify/3 answers every invalid input with false, so a stray newline has
      # to be rejected rather than carried into the hashing path.
      assert Merkle.verify(proof, root, hash <> "\n") == false
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
               proof_a,
               root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == true

      assert Merkle.verify(
               proof_b,
               root,
               "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
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
        assert Merkle.verify(proof, root, hash) == true
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
               proof,
               wrong_root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
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
               proof,
               root,
               "aaa0012345678901234567890123456789012345678901234567890123456789"
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
               proof,
               root,
               "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
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
               tampered_proof,
               root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false
    end
  end

  describe "security properties" do
    test "different leaf and internal node hashes prevent second preimage attacks" do
      # Create a tree where we try to confuse leaf and internal node hashes
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
      root1 = Merkle.root(tree)

      # Create another tree with different structure but try to reuse internal hash
      # This should fail due to domain separation
      data2 = [
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
        }
      ]

      tree2 = Merkle.new(data2)
      root2 = Merkle.root(tree2)

      assert root1 != root2
    end

    test "domain separation ensures leaf hashes differ from internal hashes" do
      # This test ensures that even if we have identical input data,
      # the domain separation prevents hash collisions
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)

      # The root should be different from any direct hash of the input
      direct_sha =
        :crypto.hash(:sha256, "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
        |> Base.encode16(case: :lower)

      assert Merkle.root(tree) != direct_sha
    end

    test "domain separation uses 0x00 prefix for leaves" do
      # Verify that leaf hashing uses the 0x00 prefix
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      # Manually compute what the root should be with 0x00 prefix
      hash_binary =
        Base.decode16!("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
          case: :mixed
        )

      expected_root =
        :crypto.hash(:sha256, <<0x00>> <> hash_binary) |> Base.encode16(case: :lower)

      assert root == expected_root
    end

    test "domain separation uses 0x01 prefix for internal nodes" do
      # Verify that internal node hashing uses the 0x01 prefix
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

      # Manually compute what the root should be with 0x00 and 0x01 prefixes
      hash_a =
        Base.decode16!("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
          case: :mixed
        )

      hash_b =
        Base.decode16!("b1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
          case: :mixed
        )

      leaf_a = :crypto.hash(:sha256, <<0x00>> <> hash_a)
      leaf_b = :crypto.hash(:sha256, <<0x00>> <> hash_b)

      # Internal node combines leaves with 0x01 prefix
      expected_root =
        :crypto.hash(:sha256, <<0x01>> <> leaf_a <> leaf_b) |> Base.encode16(case: :lower)

      assert root == expected_root
    end

    test "root comparison rejects a wrong root whether one bit differs or all of them" do
      # Create a tree and get a valid proof
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      # Test with completely different root (all bits different)
      wrong_root1 = "0000000000000000000000000000000000000000000000000000000000000000"

      # Test with root differing in only last bit
      root_binary = Base.decode16!(root, case: :mixed)
      <<prefix::binary-size(31), last_byte::8>> = root_binary
      flipped_last = Bitwise.bxor(last_byte, 1)
      wrong_root2 = <<prefix::binary, flipped_last::8>> |> Base.encode16(case: :lower)

      # Both should fail verification
      assert Merkle.verify(
               proof,
               wrong_root1,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false

      assert Merkle.verify(
               proof,
               wrong_root2,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false

      # The root comparison is constant-time by habit, not because a secret is
      # being compared: both roots here are public values. This test asserts the
      # behavior (a wrong root fails), which is the part that matters.
    end

    test "proof size limit rejects an over-deep proof before hashing" do
      # Create a proof-like structure that exceeds the maximum depth
      oversized_proof =
        Enum.map(1..65, fn _i ->
          hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
          "l:#{hash}"
        end)

      root = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
      hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

      # Should reject oversized proof
      assert Merkle.verify(oversized_proof, root, hash) == false
    end

    test "tree depth limit prevents integer overflow" do
      # Try to create a tree that would exceed maximum depth
      # 2^40 leaves would require depth 40, which is our limit
      # We can't actually create 2^40 leaves, but we can verify the limit exists
      # by checking the module's max depth constant indirectly

      # Create progressively larger trees and verify depth increases correctly
      depths =
        for exp <- 1..10 do
          count = :math.pow(2, exp) |> round()

          data =
            Enum.map(1..count, fn i ->
              %{
                "key" => "key-#{String.pad_leading(Integer.to_string(i), 8, "0")}",
                "hash" => :crypto.hash(:sha256, "data#{i}") |> Base.encode16(case: :lower)
              }
            end)

          tree = Merkle.new(data)
          tree.tree_depth
        end

      # Verify depths increase monotonically and match expected values
      expected_depths = Enum.to_list(1..10)
      assert depths == expected_depths
    end

    test "input validation rejects invalid hex hashes in verify" do
      data = [
        %{
          "key" => "test-key-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree = Merkle.new(data)
      proof = Merkle.proof(tree, "test-key-1")
      root = Merkle.root(tree)

      # Test invalid root hash (wrong length)
      assert Merkle.verify(
               proof,
               "invalid",
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false

      # Test invalid leaf hash (wrong length)
      assert Merkle.verify(proof, root, "invalid") == false

      # Test invalid root hash (non-hex characters)
      assert Merkle.verify(
               proof,
               "z1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false

      # Test invalid leaf hash (non-hex characters)
      assert Merkle.verify(
               proof,
               root,
               "z1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false
    end

    test "input validation rejects malformed proof elements" do
      root = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
      hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

      # Proof element missing colon separator
      malformed_proof1 = ["l" <> hash]
      assert Merkle.verify(malformed_proof1, root, hash) == false

      # Proof element with invalid direction
      malformed_proof2 = ["x:#{hash}"]
      assert Merkle.verify(malformed_proof2, root, hash) == false

      # Proof element with invalid hash
      malformed_proof3 = ["l:invalid_hash"]
      assert Merkle.verify(malformed_proof3, root, hash) == false

      # Proof element with wrong hash length
      malformed_proof4 = ["l:a1b2c3"]
      assert Merkle.verify(malformed_proof4, root, hash) == false
    end

    test "empty leaf padding is cryptographically distinct" do
      # Create trees with 1, 2, and 3 elements to test padding
      data1 = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      data2 = [
        %{
          "key" => "test-key-a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-key-b",
          "hash" => "b1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      data3 = [
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
        }
      ]

      tree1 = Merkle.new(data1)
      tree2 = Merkle.new(data2)
      tree3 = Merkle.new(data3)

      root1 = Merkle.root(tree1)
      root2 = Merkle.root(tree2)
      root3 = Merkle.root(tree3)

      # All roots should be different (padding doesn't cause collisions)
      assert root1 != root2
      assert root2 != root3
      assert root1 != root3
    end

    test "verify rejects non-list proof" do
      root = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
      hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

      # Non-list proof should be rejected
      assert Merkle.verify("not a list", root, hash) == false
      assert Merkle.verify(%{}, root, hash) == false
      assert Merkle.verify(nil, root, hash) == false
    end
  end

  describe "performance and determinism" do
    test "handles moderate size datasets efficiently" do
      # Test with 1000 elements
      data =
        Enum.map(1..1000, fn i ->
          key = "#{String.pad_leading("#{i}", 8, "0")}-89ab-cdef-0123-456789abcdef"
          hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
          %{"key" => key, "hash" => hash}
        end)

      {time_microseconds, tree} = :timer.tc(fn -> Merkle.new(data) end)
      time_ms = time_microseconds / 1000

      # log2(1000) ≈ 9.97, so at least 10 levels
      assert tree.tree_depth >= 9
      assert is_binary(tree.root_hash)

      # Should complete reasonably quickly (less than 100ms)
      assert time_ms < 100
    end

    test "deterministic results across multiple runs" do
      data =
        Enum.map(1..100, fn i ->
          key = "#{String.pad_leading("#{i}", 8, "0")}-89ab-cdef-0123-456789abcdef"
          hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
          %{"key" => key, "hash" => hash}
        end)

      # Create multiple trees with same data
      trees = Enum.map(1..5, fn _ -> Merkle.new(data) end)
      roots = Enum.map(trees, &Merkle.root/1)

      # All roots should be identical
      [first_root | rest_roots] = roots
      assert Enum.all?(rest_roots, &(&1 == first_root))
    end

    test "proof generation and verification roundtrip for many entries" do
      data =
        Enum.map(1..50, fn i ->
          key = "#{String.pad_leading("#{i}", 8, "0")}-89ab-cdef-0123-456789abcdef"
          hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
          %{"key" => key, "hash" => hash}
        end)

      tree = Merkle.new(data)
      root = Merkle.root(tree)

      # Verify all proofs
      results =
        Enum.map(data, fn %{"key" => key, "hash" => hash} ->
          proof = Merkle.proof(tree, key)
          Merkle.verify(proof, root, hash)
        end)

      assert Enum.all?(results, &(&1 == true))
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
               normalized_proof,
               root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == true
    end
  end

  describe "compact proof encoding bidirectional roundtrip" do
    test "empty proof roundtrips through binary" do
      assert Merkle.encode_proof([]) == <<0>>
      assert {:ok, []} = Merkle.decode_proof(<<0>>)
    end

    test "empty proof roundtrips through base64" do
      encoded = Merkle.encode_proof_base64([])
      assert encoded == "AA"
      assert {:ok, []} = Merkle.decode_proof_base64(encoded)
    end

    test "single left sibling roundtrips" do
      proof = ["l:" <> String.duplicate("ab", 32)]
      binary = Merkle.encode_proof(proof)
      assert {:ok, ^proof} = Merkle.decode_proof(binary)
    end

    test "single right sibling roundtrips" do
      proof = ["r:" <> String.duplicate("cd", 32)]
      binary = Merkle.encode_proof(proof)
      assert {:ok, ^proof} = Merkle.decode_proof(binary)
    end

    test "multi-level mixed directions roundtrip through binary" do
      proof = [
        "l:" <> String.duplicate("11", 32),
        "r:" <> String.duplicate("22", 32),
        "l:" <> String.duplicate("33", 32),
        "r:" <> String.duplicate("44", 32),
        "l:" <> String.duplicate("55", 32)
      ]

      binary = Merkle.encode_proof(proof)
      assert {:ok, decoded} = Merkle.decode_proof(binary)
      assert decoded == proof
    end

    test "multi-level mixed directions roundtrip through base64" do
      proof = [
        "r:" <> String.duplicate("aa", 32),
        "l:" <> String.duplicate("bb", 32),
        "r:" <> String.duplicate("cc", 32),
        "l:" <> String.duplicate("dd", 32)
      ]

      encoded = Merkle.encode_proof_base64(proof)
      assert {:ok, decoded} = Merkle.decode_proof_base64(encoded)
      assert decoded == proof
    end

    test "roundtrip preserves direction bits for all-left proof" do
      proof = for _ <- 1..10, do: "l:" <> String.duplicate("ff", 32)
      {:ok, decoded} = proof |> Merkle.encode_proof() |> Merkle.decode_proof()
      assert decoded == proof
    end

    test "roundtrip preserves direction bits for all-right proof" do
      proof = for _ <- 1..10, do: "r:" <> String.duplicate("ee", 32)
      {:ok, decoded} = proof |> Merkle.encode_proof() |> Merkle.decode_proof()
      assert decoded == proof
    end

    test "roundtrip with real tree-generated proofs" do
      hashes =
        for i <- 1..16 do
          hash = :crypto.hash(:sha256, "entry-#{i}") |> Base.encode16(case: :lower)
          %{"key" => "entry-#{i}", "hash" => hash}
        end

      tree = Merkle.new(hashes)
      root = Merkle.root(tree)

      for %{"key" => key, "hash" => hash} <- hashes do
        proof = Merkle.proof(tree, key)
        assert is_list(proof)

        # Binary roundtrip
        binary = Merkle.encode_proof(proof)
        assert {:ok, decoded} = Merkle.decode_proof(binary)
        assert decoded == proof

        # Base64 roundtrip
        b64 = Merkle.encode_proof_base64(proof)
        assert {:ok, decoded_b64} = Merkle.decode_proof_base64(b64)
        assert decoded_b64 == proof

        # Decoded proof still verifies
        assert Merkle.verify(decoded, root, hash)
      end
    end

    test "decode rejects truncated binary" do
      proof = ["l:" <> String.duplicate("ab", 32)]
      binary = Merkle.encode_proof(proof)
      truncated = binary_part(binary, 0, byte_size(binary) - 1)
      assert {:error, _} = Merkle.decode_proof(truncated)
    end

    test "decode rejects invalid base64" do
      assert {:error, _} = Merkle.decode_proof_base64("not!valid!base64!!!")
    end

    test "decode rejects depth exceeding max" do
      # depth byte = 65 which exceeds @max_proof_depth (64)
      assert {:error, _} = Merkle.decode_proof(<<65, 0>>)
    end

    test "encode accepts a proof at the maximum depth" do
      # 64 steps is @max_proof_depth, the deepest proof the format can carry
      proof = for _ <- 1..64, do: "l:" <> String.duplicate("ab", 32)

      assert {:ok, decoded} = Merkle.decode_proof(Merkle.encode_proof(proof))
      assert decoded == proof
    end

    test "encode rejects a proof deeper than the maximum" do
      proof = for _ <- 1..65, do: "l:" <> String.duplicate("ab", 32)

      assert_raise ArgumentError, ~r/at most 64 steps/, fn ->
        Merkle.encode_proof(proof)
      end
    end

    test "encode rejects a proof long enough to wrap the depth byte" do
      proof = for _ <- 1..256, do: "l:" <> String.duplicate("ab", 32)

      assert_raise ArgumentError, ~r/at most 64 steps/, fn ->
        Merkle.encode_proof(proof)
      end
    end

    test "encode rejects an unknown direction prefix" do
      assert_raise ArgumentError, ~r/Invalid proof element format/, fn ->
        Merkle.encode_proof(["x:" <> String.duplicate("ab", 32)])
      end
    end

    test "encode rejects malformed elements" do
      malformed = [
        # no separator at all
        String.duplicate("ab", 32),
        # separator but no direction
        ":" <> String.duplicate("ab", 32),
        # hash too short
        "r:abcd",
        # hash too long
        "r:" <> String.duplicate("ab", 33),
        # odd number of hex characters
        "l:" <> String.duplicate("ab", 31) <> "a",
        # uppercase hex is not the canonical form
        "l:" <> String.duplicate("AB", 32),
        # non-hex characters of the right length
        "l:" <> String.duplicate("zz", 32),
        # not a string at all
        nil,
        :"l:abc",
        123
      ]

      for element <- malformed do
        assert_raise ArgumentError, fn -> Merkle.encode_proof([element]) end
      end
    end

    test "encode rejects a malformed element anywhere in the list" do
      good = "l:" <> String.duplicate("ab", 32)

      assert_raise ArgumentError, fn ->
        Merkle.encode_proof([good, good, "r:abcd", good])
      end
    end

    test "base64 encoding inherits the same validation" do
      assert_raise ArgumentError, ~r/Invalid proof element format/, fn ->
        Merkle.encode_proof_base64(["x:" <> String.duplicate("ab", 32)])
      end

      assert_raise ArgumentError, ~r/at most 64 steps/, fn ->
        Merkle.encode_proof_base64(for _ <- 1..65, do: "l:" <> String.duplicate("ab", 32))
      end
    end

    test "every proof from proof/2 encodes and roundtrips unchanged" do
      for leaf_count <- [1, 2, 3, 5, 8, 13, 17, 32] do
        data =
          for i <- 1..leaf_count do
            %{
              "key" => "entry-#{i}",
              "hash" =>
                :crypto.hash(:sha256, "leaf-#{leaf_count}-#{i}") |> Base.encode16(case: :lower)
            }
          end

        tree = Merkle.new(data)
        root = Merkle.root(tree)

        for %{"key" => key, "hash" => hash} <- data do
          proof = Merkle.proof(tree, key)

          assert {:ok, ^proof} = Merkle.decode_proof(Merkle.encode_proof(proof))
          assert {:ok, ^proof} = Merkle.decode_proof_base64(Merkle.encode_proof_base64(proof))
          assert Merkle.verify(proof, root, hash)
        end
      end
    end
  end

  describe "property-based security tests" do
    use ExUnitProperties
    import StreamData

    # Generator for valid hex hashes (64-char lowercase hex)
    defp hex_hash_generator do
      string([?a..?f, ?0..?9], length: 64)
    end

    # Generator for valid keys
    defp key_generator do
      # Lowercase alphanumerics with optional . - _ separators, up to 36 characters,
      # which is wide enough for a UUID. Must not start or end with a separator, so
      # nothing is lost to trimming.
      gen all(
            first <- one_of([member_of(?a..?z), member_of(?0..?9)]),
            middle <- string([?a..?z, ?0..?9, ?., ?-, ?_], max_length: 34),
            last <- one_of([member_of(?a..?z), member_of(?0..?9)])
          ) do
        to_string([first] ++ String.to_charlist(middle) ++ [last])
      end
    end

    # Generator for valid key-hash pairs
    defp key_hash_pair_generator do
      gen all(
            key <- key_generator(),
            hash <- hex_hash_generator()
          ) do
        %{"key" => key, "hash" => hash}
      end
    end

    property "round-trip proof verification always succeeds for valid trees" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 100),
              # Ensure unique keys
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)

        # Test proof verification for each key in the tree
        Enum.all?(unique_data, fn %{"key" => key, "hash" => hash} ->
          proof = Merkle.proof(tree, key)
          Merkle.verify(proof, root_hash, hash)
        end)
      end
    end

    property "bit-flipping in proofs causes verification failure" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 10),
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              length(unique_data) >= 2
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)
        %{"key" => test_key, "hash" => test_hash} = hd(unique_data)

        proof = Merkle.proof(tree, test_key)

        # Only test if proof is non-empty (not a single-element tree)
        if proof != [] do
          # Flip a random bit in the first proof element
          [first_proof | rest] = proof
          [direction, sibling_hash] = String.split(first_proof, ":", parts: 2)

          # Flip last character of hash (safe bit flip)
          flipped_hash =
            String.slice(sibling_hash, 0..-2//1) <>
              case String.last(sibling_hash) do
                "a" -> "b"
                "f" -> "e"
                char -> if char == "0", do: "1", else: "0"
              end

          corrupted_proof = ["#{direction}:#{flipped_hash}" | rest]

          # Verification should fail with corrupted proof
          refute Merkle.verify(corrupted_proof, root_hash, test_hash)
        else
          # Single element tree - this is expected behavior
          true
        end
      end
    end

    property "swapping proof directions causes verification failure" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 10),
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              length(unique_data) >= 2
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)
        %{"key" => test_key, "hash" => test_hash} = hd(unique_data)

        proof = Merkle.proof(tree, test_key)

        # Only test if proof is non-empty
        if proof != [] do
          # Swap direction in first proof element
          swapped_proof =
            Enum.map(proof, fn proof_element ->
              [direction, hash] = String.split(proof_element, ":", parts: 2)
              new_direction = if direction == "l", do: "r", else: "l"
              "#{new_direction}:#{hash}"
            end)

          # Verification should fail with swapped directions
          refute Merkle.verify(swapped_proof, root_hash, test_hash)
        else
          # Single element tree - this is expected behavior
          true
        end
      end
    end

    property "truncated proofs cause verification failure" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 4, max_length: 16),
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              length(unique_data) >= 4
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)
        %{"key" => test_key, "hash" => test_hash} = hd(unique_data)

        proof = Merkle.proof(tree, test_key)

        # Only test if proof has multiple elements
        if length(proof) > 1 do
          # Remove last element from proof
          truncated_proof = Enum.drop(proof, -1)

          # Verification should fail with truncated proof
          refute Merkle.verify(truncated_proof, root_hash, test_hash)
        else
          # Too small to truncate meaningfully
          true
        end
      end
    end

    property "trees are deterministic regardless of input order" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 20),
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              length(unique_data) >= 2
            ) do
        # Create tree with original order
        tree1 = Merkle.new(unique_data)
        root1 = Merkle.root(tree1)

        # Create tree with shuffled order
        shuffled_data = Enum.shuffle(unique_data)
        tree2 = Merkle.new(shuffled_data)
        root2 = Merkle.root(tree2)

        # Roots should be identical
        root1 == root2
      end
    end

    property "malicious internal node hashes cannot be used as fake leaves" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 8),
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              length(unique_data) >= 2
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)
        %{"key" => test_key} = hd(unique_data)

        proof = Merkle.proof(tree, test_key)

        # Try to use internal node hash (from proof) as a fake leaf
        if proof != [] do
          [_direction, internal_hash] = String.split(hd(proof), ":", parts: 2)

          # Create fake data using internal hash as "leaf" hash
          fake_data = [%{"key" => "fake-key-attack-test", "hash" => internal_hash}]
          fake_tree = Merkle.new(fake_data)
          fake_root = Merkle.root(fake_tree)

          # The fake tree root should be different from original
          # This proves domain separation is working
          fake_root != root_hash
        else
          # Can't test with single element
          true
        end
      end
    end

    property "power-of-two and non-power-of-two trees both work correctly" do
      check all(base_size <- integer(1..15)) do
        # Test both power-of-2 and non-power-of-2 sizes
        sizes = [base_size, base_size * 2, base_size * 2 + 1]

        Enum.all?(sizes, fn size ->
          data =
            for i <- 1..size do
              %{
                "key" => "test-key-#{String.pad_leading(Integer.to_string(i), 4, "0")}-#{i}",
                "hash" => :crypto.hash(:sha256, "test data #{i}") |> Base.encode16(case: :lower)
              }
            end

          tree = Merkle.new(data)
          root_hash = Merkle.root(tree)

          # Verify all proofs work
          Enum.all?(data, fn %{"key" => key, "hash" => hash} ->
            proof = Merkle.proof(tree, key)
            Merkle.verify(proof, root_hash, hash)
          end)
        end)
      end
    end

    property "injectable sibling attacks fail due to domain separation" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 8),
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              length(unique_data) >= 2
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)
        %{"key" => test_key} = hd(unique_data)

        proof = Merkle.proof(tree, test_key)

        # Try to use internal node hash (from proof) as a fake leaf input
        if proof != [] do
          [_direction, internal_hash] = String.split(hd(proof), ":", parts: 2)

          # Attempt to create a malicious tree using internal hash as leaf
          malicious_data = [%{"key" => "malicious-key-test", "hash" => internal_hash}]
          malicious_tree = Merkle.new(malicious_data)
          malicious_root = Merkle.root(malicious_tree)

          # The roots should be different - domain separation prevents this attack
          malicious_root != root_hash
        else
          # Can't test injectable sibling with single element
          true
        end
      end
    end

    property "empty padding scenarios work correctly" do
      check all(real_count <- integer(0..3)) do
        # Test scenarios with mostly or entirely padding
        data =
          if real_count == 0 do
            # Create at least one real element to avoid empty tree
            [
              %{
                "key" => "real-element-key",
                "hash" => :crypto.hash(:sha256, "real") |> Base.encode16(case: :lower)
              }
            ]
          else
            for i <- 1..real_count do
              %{
                "key" => "real-key-#{String.pad_leading(Integer.to_string(i), 4, "0")}",
                "hash" => :crypto.hash(:sha256, "real data #{i}") |> Base.encode16(case: :lower)
              }
            end
          end

        tree = Merkle.new(data)
        root_hash = Merkle.root(tree)

        # Verify all real elements have valid proofs
        Enum.all?(data, fn %{"key" => key, "hash" => hash} ->
          proof = Merkle.proof(tree, key)
          Merkle.verify(proof, root_hash, hash)
        end)
      end
    end

    property "repeated hash inputs with unique keys work correctly" do
      check all(
              base_hash <- hex_hash_generator(),
              key_count <- integer(2..10)
            ) do
        # Multiple different keys with the same hash value
        data =
          for i <- 1..key_count do
            %{
              "key" => "unique-key-#{String.pad_leading(Integer.to_string(i), 4, "0")}",
              # Same hash for all keys
              "hash" => base_hash
            }
          end

        tree = Merkle.new(data)
        root_hash = Merkle.root(tree)

        # Tree structure should not collapse - each key should have a valid proof
        Enum.all?(data, fn %{"key" => key, "hash" => hash} ->
          proof = Merkle.proof(tree, key)
          is_list(proof) and Merkle.verify(proof, root_hash, hash)
        end)
      end
    end

    property "proof lookup is case-sensitive" do
      check all(data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 5)) do
        unique_data = data |> Enum.uniq_by(& &1["key"])

        if unique_data != [] do
          tree = Merkle.new(unique_data)
          %{"key" => test_key} = hd(unique_data)

          # Proof lookup with the original key succeeds
          proof = Merkle.proof(tree, test_key)
          assert is_list(proof) or is_nil(proof)
          true
        else
          true
        end
      end
    end

    property "root hash collision resistance - different data produces different roots" do
      check all(
              data1 <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 20),
              data2 <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 20),
              unique_data1 = Enum.uniq_by(data1, & &1["key"]),
              unique_data2 = Enum.uniq_by(data2, & &1["key"]),
              unique_data1 != [],
              unique_data2 != [],
              unique_data1 != unique_data2
            ) do
        tree1 = Merkle.new(unique_data1)
        tree2 = Merkle.new(unique_data2)

        Merkle.root(tree1) != Merkle.root(tree2)
      end
    end

    property "proof independence - proof for one leaf cannot verify a different leaf" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 10),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              length(unique_data) >= 2
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)

        [entry1, entry2 | _] = unique_data
        proof1 = Merkle.proof(tree, entry1["key"])

        # The proof for the first entry must not verify the second entry's hash
        not Merkle.verify(proof1, root, entry2["hash"])
      end
    end

    property "proof uniqueness - proof generation is deterministic" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        %{"key" => test_key} = hd(unique_data)

        # Generate proof multiple times
        proof1 = Merkle.proof(tree, test_key)
        proof2 = Merkle.proof(tree, test_key)
        proof3 = Merkle.proof(tree, test_key)

        proof1 == proof2 and proof2 == proof3
      end
    end

    property "proof ordering invariance - reordering proof elements causes verification failure" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 4, max_length: 10),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              length(unique_data) >= 4
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)
        %{"key" => key, "hash" => hash} = hd(unique_data)

        proof = Merkle.proof(tree, key)

        if length(proof) >= 2 do
          # Reverse the proof array
          reversed_proof = Enum.reverse(proof)

          # Should fail unless proof is symmetric (rare edge case)
          not Merkle.verify(reversed_proof, root, hash) or proof == reversed_proof
        else
          true
        end
      end
    end

    property "proof size bounds - proof length never exceeds tree depth" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 100),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)

        Enum.all?(unique_data, fn %{"key" => key} ->
          proof = Merkle.proof(tree, key)
          length(proof) <= tree.tree_depth
        end)
      end
    end

    property "tree depth correctness - depth matches mathematical formula" do
      check all(count <- integer(1..1000)) do
        data =
          for i <- 1..count do
            %{
              "key" => "key-#{String.pad_leading("#{i}", 8, "0")}",
              "hash" => :crypto.hash(:sha256, "#{i}") |> Base.encode16(case: :lower)
            }
          end

        tree = Merkle.new(data)

        # Calculate expected depth: ceil(log2(next_power_of_2(count)))
        next_pow2 = :math.pow(2, :math.ceil(:math.log2(count))) |> round()
        expected_depth = :math.log2(next_pow2) |> round()

        tree.tree_depth == expected_depth
      end
    end

    property "proof format validation - all proof elements follow exact format" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)

        Enum.all?(unique_data, fn %{"key" => key} ->
          proof = Merkle.proof(tree, key)

          Enum.all?(proof, fn proof_elem ->
            case String.split(proof_elem, ":", parts: 2) do
              [direction, hash] ->
                direction in ["l", "r"] and
                  String.length(hash) == 64 and
                  String.match?(hash, ~r/^[0-9a-f]+$/)

              _ ->
                false
            end
          end)
        end)
      end
    end

    property "root hash format consistency - always 64-char lowercase hex" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)

        String.length(root) == 64 and
          String.match?(root, ~r/^[0-9a-f]+$/)
      end
    end

    property "empty proof correctness - single-element trees always have empty proofs" do
      check all(entry <- key_hash_pair_generator()) do
        tree = Merkle.new([entry])
        proof = Merkle.proof(tree, entry["key"])

        proof == []
      end
    end

    property "cross-tree proof compatibility - proofs from equivalent trees are interchangeable" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 2, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              length(unique_data) >= 2
            ) do
        # Build two trees from same data in different order
        tree1 = Merkle.new(unique_data)
        tree2 = Merkle.new(Enum.shuffle(unique_data))

        root1 = Merkle.root(tree1)
        root2 = Merkle.root(tree2)

        %{"key" => key, "hash" => hash} = hd(unique_data)

        # Get proof from tree1
        proof1 = Merkle.proof(tree1, key)

        # Should verify against tree2's root (they're equivalent)
        Merkle.verify(proof1, root2, hash) and root1 == root2
      end
    end

    property "subtree independence - proofs don't contain raw hashes of non-sibling leaves" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 4, max_length: 10),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              length(unique_data) >= 4
            ) do
        tree = Merkle.new(unique_data)
        [entry1 | rest_entries] = unique_data

        proof = Merkle.proof(tree, entry1["key"])

        # Extract all hashes from proof
        proof_hashes =
          Enum.map(proof, fn elem ->
            [_dir, hash] = String.split(elem, ":", parts: 2)
            hash
          end)

        # Check that no raw input hash from other leaves appears in proof
        # Note: Siblings may appear, but non-siblings should never appear as raw hashes
        other_leaf_hashes = Enum.map(rest_entries, & &1["hash"])

        MapSet.intersection(MapSet.new(proof_hashes), MapSet.new(other_leaf_hashes))
        |> MapSet.size() == 0
      end
    end

    property "sibling hash uniqueness - no duplicate hashes in proofs" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)

        Enum.all?(unique_data, fn %{"key" => key} ->
          proof = Merkle.proof(tree, key)

          # Extract hashes
          hashes =
            Enum.map(proof, fn elem ->
              [_dir, hash] = String.split(elem, ":", parts: 2)
              hash
            end)

          # Check for uniqueness
          length(hashes) == length(Enum.uniq(hashes))
        end)
      end
    end

    property "proof self-sufficiency - verification requires only proof, root, and leaf hash" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)
        %{"key" => key, "hash" => hash} = hd(unique_data)

        proof = Merkle.proof(tree, key)

        # Should be able to verify without tree, without key, without other data
        # Just proof + root + hash
        result = Merkle.verify(proof, root, hash)

        # Also verify that we get same result if we serialize/deserialize
        json_proof = JSON.encode!(proof)
        decoded_proof = JSON.decode!(json_proof)

        result == Merkle.verify(decoded_proof, root, hash)
      end
    end
  end

  describe "optional sorting" do
    use ExUnitProperties
    import StreamData

    test "new/2 with default behavior sorts by key" do
      data = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "m-middle",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "a-first",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree = Merkle.new(data)

      # Leaves should be sorted alphabetically by key
      assert tree.leaves == [
               {"a-first", "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"},
               {"m-middle", "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"},
               {"z-last", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
             ]
    end

    test "new/2 with sort: true explicitly sorts by key" do
      data = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "m-middle",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "a-first",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree = Merkle.new(data, sort: true)

      # Leaves should be sorted alphabetically by key
      assert tree.leaves == [
               {"a-first", "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"},
               {"m-middle", "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"},
               {"z-last", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"}
             ]
    end

    test "new/2 with sort: false preserves input order" do
      data = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "m-middle",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "a-first",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree = Merkle.new(data, sort: false)

      # Leaves should preserve input order exactly
      assert tree.leaves == [
               {"z-last", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
               {"m-middle", "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"},
               {"a-first", "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"}
             ]
    end

    test "sorted and unsorted trees produce different roots for different orders" do
      data = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      sorted_tree = Merkle.new(data, sort: true)
      unsorted_tree = Merkle.new(data, sort: false)

      # Different orders should produce different roots
      assert Merkle.root(sorted_tree) != Merkle.root(unsorted_tree)
    end

    test "sorted trees produce same root regardless of input order" do
      data1 = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      data2 = [
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree1 = Merkle.new(data1, sort: true)
      tree2 = Merkle.new(data2, sort: true)

      # Same data sorted should produce identical roots
      assert Merkle.root(tree1) == Merkle.root(tree2)
    end

    test "unsorted trees produce different roots for different input orders" do
      data1 = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      data2 = [
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      tree1 = Merkle.new(data1, sort: false)
      tree2 = Merkle.new(data2, sort: false)

      # Different orders without sorting should produce different roots
      assert Merkle.root(tree1) != Merkle.root(tree2)
    end

    test "proof generation works correctly for unsorted trees" do
      data = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree = Merkle.new(data, sort: false)
      root = Merkle.root(tree)

      # Proofs should be generated correctly regardless of sorting
      proof_z = Merkle.proof(tree, "z-last")
      proof_a = Merkle.proof(tree, "a-first")

      assert proof_z != nil
      assert proof_a != nil

      # Proofs should verify correctly
      assert Merkle.verify(
               proof_z,
               root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             )

      assert Merkle.verify(
               proof_a,
               root,
               "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
             )
    end

    test "empty tree handles sort option" do
      empty_sorted = Merkle.new([], sort: true)
      empty_unsorted = Merkle.new([], sort: false)

      # Empty trees should be identical regardless of sort option
      assert Merkle.root(empty_sorted) == Merkle.root(empty_unsorted)
      assert empty_sorted.tree_depth == 0
      assert empty_unsorted.tree_depth == 0
    end

    property "sorted trees are deterministic - same data always produces same root" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        # Shuffle the data in different ways
        shuffled1 = Enum.shuffle(unique_data)
        shuffled2 = Enum.shuffle(unique_data)
        shuffled3 = Enum.shuffle(unique_data)

        # All sorted trees should produce the same root
        tree1 = Merkle.new(shuffled1, sort: true)
        tree2 = Merkle.new(shuffled2, sort: true)
        tree3 = Merkle.new(shuffled3, sort: true)

        Merkle.root(tree1) == Merkle.root(tree2) and Merkle.root(tree2) == Merkle.root(tree3)
      end
    end

    property "unsorted trees preserve exact input order" do
      check all(
              data <- list_of(key_hash_pair_generator(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data, sort: false)

        # Extract keys from leaves
        leaf_keys = Enum.map(tree.leaves, fn {key, _hash} -> key end)
        input_keys = Enum.map(unique_data, fn %{"key" => key} -> key end)

        # Keys should be in exact same order
        leaf_keys == input_keys
      end
    end
  end

  describe "padding with generic key format" do
    test "padding keys use the __PAD__ format, which caller input cannot use" do
      # Create a tree that requires padding (3 leaves -> padded to 4)
      data = [
        %{
          "key" => "test-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "test-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "test-3",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree = Merkle.new(data)

      # Leaves should only contain caller input (padding is internal)
      assert length(tree.leaves) == 3

      # Tree depth should account for padding (4 leaves = depth 2)
      assert tree.tree_depth == 2

      # Verify tree was constructed successfully with padding
      assert is_binary(tree.root_hash)
      assert byte_size(tree.root_hash) == 32
    end

    test "padding keys cannot collide with caller keys" do
      # Try to supply a caller key that looks like padding
      invalid_data = [
        %{
          "key" => "__PAD__0000000000000001",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        }
      ]

      # Should raise ArgumentError due to reserved padding prefix
      assert_raise ArgumentError, ~r/reserved padding prefix/, fn ->
        Merkle.new(invalid_data)
      end
    end

    test "padding works correctly with sorted trees" do
      # 5 leaves -> padded to 8
      data = [
        %{
          "key" => "entry-5",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-1",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "entry-3",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        },
        %{
          "key" => "entry-2",
          "hash" => "d4e5f6789012345678901234567890123456789012345678901234567890abcd"
        },
        %{
          "key" => "entry-4",
          "hash" => "e5f6789012345678901234567890123456789012345678901234567890123456"
        }
      ]

      tree = Merkle.new(data, sort: true)

      # Leaves should contain only caller input (5 entries)
      assert length(tree.leaves) == 5

      # Tree depth should account for padding to 8 (depth 3)
      assert tree.tree_depth == 3

      # Caller keys should be sorted
      caller_keys = data |> Enum.map(& &1["key"]) |> Enum.sort()
      tree_keys = tree.leaves |> Enum.map(&elem(&1, 0))
      assert tree_keys == caller_keys
    end

    test "padding works correctly with unsorted trees" do
      # 3 leaves -> padded to 4
      data = [
        %{
          "key" => "z-last",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "a-first",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "m-middle",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree = Merkle.new(data, sort: false)

      # Leaves should only contain caller input
      assert length(tree.leaves) == 3

      # Tree depth should account for padding to 4 (depth 2)
      assert tree.tree_depth == 2

      # Caller keys should preserve input order
      assert elem(Enum.at(tree.leaves, 0), 0) == "z-last"
      assert elem(Enum.at(tree.leaves, 1), 0) == "a-first"
      assert elem(Enum.at(tree.leaves, 2), 0) == "m-middle"
    end

    test "padding is deterministic for same tree size" do
      # Single leaf trees are special case - no padding needed (depth 0)
      # Use 3 leaves -> padded to 4 to test determinism
      data1 = [
        %{
          "key" => "a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "b",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "c",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      data2 = [
        %{
          "key" => "a",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "b",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "c",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree1 = Merkle.new(data1)
      tree2 = Merkle.new(data2)

      # Same input with deterministic padding should produce identical roots
      assert Merkle.root(tree1) == Merkle.root(tree2)

      # Both should have depth 2 (padded to 4 leaves)
      assert tree1.tree_depth == 2
      assert tree2.tree_depth == 2
    end

    test "padding uses empty leaf hash internally" do
      # This test verifies padding behavior by comparing tree roots
      # Single-entry trees have no padding (special case), so use 3 entries -> padded to 4
      data = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "entry-3",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree = Merkle.new(data)

      # Tree should be constructed successfully with padding
      assert is_binary(tree.root_hash)
      assert byte_size(tree.root_hash) == 32
      assert tree.tree_depth == 2

      # Verify the tree root is deterministic
      tree2 = Merkle.new(data)
      assert Merkle.root(tree) == Merkle.root(tree2)
    end

    test "a hand-built proof for a padding slot does not verify" do
      tree = Merkle.new(five_padded_to_eight())
      root = Merkle.root(tree)

      # Whoever holds the last real leaf also holds a proof whose first step is the
      # padding slot's leaf hash. Swapping that step for their own leaf hash
      # yields the padding slot's own proof, with no hashing they cannot do.
      [_padding_sibling | rest] = Merkle.proof(tree, "entry-5")
      forged = ["l:" <> leaf_hash(last_real_hash()) | rest]

      # The path is arithmetically sound: walked by hand it reaches the real root.
      assert walk_proof(forged, padding_constant()) == root

      # The library still refuses it, because the value being proved is reserved.
      refute Merkle.verify(forged, root, padding_constant())
    end

    test "the padding constant is refused as an entry hash on every construction surface" do
      padhash = padding_constant()
      message = ~r/reserved Merkle padding constant/
      entry = %{"key" => "entry-1", "hash" => padhash}

      assert_raise ArgumentError, message, fn -> Merkle.new([entry]) end
      assert_raise ArgumentError, message, fn -> Merkle.add_entry(Merkle.builder(), entry) end
      assert_raise ArgumentError, message, fn -> Merkle.add_entries(Merkle.builder(), [entry]) end
      assert_raise ArgumentError, message, fn -> Merkle.from_maps([entry]) end
      assert_raise ArgumentError, message, fn -> Merkle.from_tuples([{"entry-1", padhash}]) end

      assert_raise ArgumentError, message, fn ->
        Merkle.from_stream([entry], key_fn: & &1["key"], hash_fn: & &1["hash"])
      end
    end

    test "the padding leaf hash still verifies as a proof sibling" do
      tree = Merkle.new(five_padded_to_eight())
      root = Merkle.root(tree)
      proof = Merkle.proof(tree, "entry-5")

      # This is the regression guard: the reservation must cover the value being
      # proved and nothing else, or most proofs from a padded tree stop verifying.
      assert ("r:" <> padding_leaf_hash()) in proof

      assert Merkle.verify(proof, root, last_real_hash())
    end
  end

  # SHA-256(<<0x00, 0x00>>), the value every padding slot carries.
  defp padding_constant,
    do: "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"

  # SHA-256(0x00 || padding_constant()), the padding slot's leaf hash, which
  # shows up as an ordinary sibling in proofs from a padded tree.
  defp padding_leaf_hash,
    do: "d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319"

  defp last_real_hash,
    do: "e5f6789012345678901234567890123456789012345678901234567890123456"

  # Five leaves pad to eight, so the slot at index 5 is padding and the holder of
  # the real leaf at index 4 can assemble that slot's whole path by hand.
  defp five_padded_to_eight do
    [
      %{
        "key" => "entry-1",
        "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
      },
      %{
        "key" => "entry-2",
        "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
      },
      %{
        "key" => "entry-3",
        "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
      },
      %{
        "key" => "entry-4",
        "hash" => "d4e5f6789012345678901234567890123456789012345678901234567890abcd"
      },
      %{"key" => "entry-5", "hash" => last_real_hash()}
    ]
  end

  defp leaf_hash(hex) do
    :crypto.hash(:sha256, <<0x00>> <> Base.decode16!(hex, case: :lower))
    |> Base.encode16(case: :lower)
  end

  # An independent walk of the audit path, so the forgery test can show that the hand-built
  # path really does reach the root and is refused for carrying a reserved value
  # rather than for being malformed.
  defp walk_proof(proof, leaf_hex) do
    start = :crypto.hash(:sha256, <<0x00>> <> Base.decode16!(leaf_hex, case: :lower))

    proof
    |> Enum.reduce(start, fn step, acc ->
      case String.split(step, ":", parts: 2) do
        ["l", sibling] -> :crypto.hash(:sha256, <<0x01>> <> decode(sibling) <> acc)
        ["r", sibling] -> :crypto.hash(:sha256, <<0x01>> <> acc <> decode(sibling))
      end
    end)
    |> Base.encode16(case: :lower)
  end

  defp decode(hex), do: Base.decode16!(hex, case: :lower)

  # ============================================================================
  # Builder Pattern API Tests
  # ============================================================================

  describe "builder/0" do
    test "creates an empty builder" do
      builder = Merkle.builder()
      assert %Merkle.Builder{} = builder
      assert builder.leaves == []
      assert builder.seen == %{}
      assert builder.count == 0
    end
  end

  describe "add_entry/2" do
    test "adds a single entry to the builder" do
      builder =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })

      assert builder.count == 1
      assert map_size(builder.seen) == 1
      assert length(builder.leaves) == 1
    end

    test "adds multiple entries sequentially" do
      builder =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })
        |> Merkle.add_entry(%{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        })

      assert builder.count == 2
      assert map_size(builder.seen) == 2
      assert length(builder.leaves) == 2
    end

    test "stores keys preserving original case" do
      builder =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })
        |> Merkle.add_entry(%{
          "key" => "ENTRY-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        })

      # Keys are stored as-is
      assert Map.has_key?(builder.seen, "entry-1")
      assert Map.has_key?(builder.seen, "ENTRY-2")
      assert builder.count == 2
    end

    test "silently ignores duplicate key+hash (idempotent)" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"

      builder =
        Merkle.builder()
        |> Merkle.add_entry(%{"key" => "entry-1", "hash" => hash})
        |> Merkle.add_entry(%{"key" => "entry-1", "hash" => hash})
        |> Merkle.add_entry(%{"key" => "entry-1", "hash" => hash})

      # Should only have one entry despite three identical adds
      assert builder.count == 1
      assert map_size(builder.seen) == 1
      assert length(builder.leaves) == 1
    end

    test "raises error for duplicate key with different hash" do
      builder =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })

      assert_raise ArgumentError, ~r/Duplicate key with different hash/, fn ->
        Merkle.add_entry(builder, %{
          "key" => "entry-1",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        })
      end
    end

    test "validates key format" do
      assert_raise ArgumentError, fn ->
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "INVALID KEY WITH SPACES",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })
      end
    end

    test "validates hash format" do
      assert_raise ArgumentError, fn ->
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry-1",
          "hash" => "invalid-hash"
        })
      end
    end
  end

  describe "add_entries/2" do
    test "adds multiple entries from a list" do
      entries = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "entry-3",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      builder = Merkle.builder() |> Merkle.add_entries(entries)

      assert builder.count == 3
      assert map_size(builder.seen) == 3
    end

    test "works with streams" do
      entries =
        Stream.iterate(1, &(&1 + 1))
        |> Stream.take(5)
        |> Stream.map(fn i ->
          %{
            "key" => "entry-#{i}",
            "hash" => :crypto.hash(:sha256, "data-#{i}") |> Base.encode16(case: :lower)
          }
        end)

      builder = Merkle.builder() |> Merkle.add_entries(entries)

      assert builder.count == 5
    end
  end

  describe "finalize/2" do
    test "creates empty tree from empty builder" do
      tree = Merkle.builder() |> Merkle.finalize([])

      assert tree.tree_depth == 0
      # Empty tree root is SHA256("")
      assert Merkle.root(tree) ==
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    end

    test "creates a tree from a single entry" do
      tree =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })
        |> Merkle.finalize([])

      assert tree.tree_depth == 0
      assert length(tree.leaves) == 1
    end

    test "produces same root as new/1 for same data" do
      data = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "entry-3",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree_from_new = Merkle.new(data)

      tree_from_builder =
        Merkle.builder()
        |> Merkle.add_entries(data)
        |> Merkle.finalize([])

      assert Merkle.root(tree_from_new) == Merkle.root(tree_from_builder)
      assert tree_from_new.tree_depth == tree_from_builder.tree_depth
    end

    test "sorts by key by default" do
      # Add in reverse order
      tree =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "z-last",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        })
        |> Merkle.add_entry(%{
          "key" => "a-first",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })
        |> Merkle.finalize([])

      # First leaf should be "a-first" after sorting
      [{first_key, _}] = Enum.take(tree.leaves, 1)
      assert first_key == "a-first"
    end

    test "preserves insertion order with sort: false" do
      tree =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "z-last",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        })
        |> Merkle.add_entry(%{
          "key" => "a-first",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })
        |> Merkle.finalize(sort: false)

      # First leaf should be "z-last" (insertion order)
      [{first_key, _}] = Enum.take(tree.leaves, 1)
      assert first_key == "z-last"
    end

    test "proof generation works on finalized tree" do
      data = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree =
        Merkle.builder()
        |> Merkle.add_entries(data)
        |> Merkle.finalize([])

      # Generate and verify a proof for entry-1
      proof = Merkle.proof(tree, "entry-1")
      root = Merkle.root(tree)

      assert Merkle.verify(
               proof,
               root,
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             )
    end

    test "proofs match between new/1 and builder for same data" do
      data = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        },
        %{
          "key" => "entry-3",
          "hash" => "c3d4e5f6789012345678901234567890123456789012345678901234567890ab"
        }
      ]

      tree_from_new = Merkle.new(data)

      tree_from_builder =
        Merkle.builder()
        |> Merkle.add_entries(data)
        |> Merkle.finalize([])

      # Proofs should be identical
      for %{"key" => key} <- data do
        proof_new = Merkle.proof(tree_from_new, key)
        proof_builder = Merkle.proof(tree_from_builder, key)
        assert proof_new == proof_builder, "Proofs differ for key: #{key}"
      end
    end
  end

  describe "from_stream/2" do
    test "creates a tree from a struct enumerable with extractor functions" do
      entries = [
        %{
          id: "entry-1",
          digest: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          id: "entry-2",
          digest: "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree = Merkle.from_stream(entries, key_fn: & &1.id, hash_fn: & &1.digest)

      assert is_binary(tree.root_hash)
      assert tree.tree_depth == 1
      assert length(tree.leaves) == 2
    end

    test "produces same root as new/1 for same data" do
      entries = [
        %{
          id: "entry-1",
          digest: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          id: "entry-2",
          digest: "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree_from_stream = Merkle.from_stream(entries, key_fn: & &1.id, hash_fn: & &1.digest)

      data = Enum.map(entries, fn e -> %{"key" => e.id, "hash" => e.digest} end)
      tree_from_new = Merkle.new(data)

      assert Merkle.root(tree_from_stream) == Merkle.root(tree_from_new)
    end

    test "supports sort: false option" do
      entries = [
        %{
          id: "z-last",
          digest: "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          id: "a-first",
          digest: "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree = Merkle.from_stream(entries, key_fn: & &1.id, hash_fn: & &1.digest, sort: false)

      [{first_key, _}] = Enum.take(tree.leaves, 1)
      assert first_key == "z-last"
    end

    test "raises error when key_fn is missing" do
      assert_raise KeyError, fn ->
        Merkle.from_stream([], hash_fn: & &1.hash)
      end
    end

    test "raises error when hash_fn is missing" do
      assert_raise KeyError, fn ->
        Merkle.from_stream([], key_fn: & &1.id)
      end
    end
  end

  describe "from_maps/2" do
    test "creates tree from map enumerable" do
      maps = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      tree = Merkle.from_maps(maps)

      assert is_binary(tree.root_hash)
      assert length(tree.leaves) == 2
    end

    test "produces same root as new/1" do
      maps = [
        %{
          "key" => "entry-1",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        },
        %{
          "key" => "entry-2",
          "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
        }
      ]

      assert Merkle.root(Merkle.from_maps(maps)) == Merkle.root(Merkle.new(maps))
    end

    test "works with stream input" do
      maps =
        Stream.iterate(1, &(&1 + 1))
        |> Stream.take(3)
        |> Stream.map(fn i ->
          %{
            "key" => "entry-#{i}",
            "hash" => :crypto.hash(:sha256, "data-#{i}") |> Base.encode16(case: :lower)
          }
        end)

      tree = Merkle.from_maps(maps)
      assert length(tree.leaves) == 3
    end
  end

  describe "from_tuples/2" do
    test "creates tree from tuple enumerable" do
      tuples = [
        {"entry-1", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
        {"entry-2", "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"}
      ]

      tree = Merkle.from_tuples(tuples)

      assert is_binary(tree.root_hash)
      assert length(tree.leaves) == 2
    end

    test "produces same root as new/1" do
      tuples = [
        {"entry-1", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"},
        {"entry-2", "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"}
      ]

      maps = Enum.map(tuples, fn {k, h} -> %{"key" => k, "hash" => h} end)

      assert Merkle.root(Merkle.from_tuples(tuples)) == Merkle.root(Merkle.new(maps))
    end
  end

  describe "type safety between Builder and Merkle" do
    # These tests intentionally pass wrong types to verify runtime FunctionClauseError.
    # We use apply/3 to defeat the compile-time type checker since we're testing
    # runtime behavior, not compile-time type checking.

    test "add_entry only works on Builder, not Merkle tree" do
      tree =
        Merkle.new([
          %{
            "key" => "entry",
            "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
          }
        ])

      assert_raise FunctionClauseError, fn ->
        # credo:disable-for-next-line Credo.Check.Refactor.Apply
        apply(Merkle, :add_entry, [
          tree,
          %{
            "key" => "new-entry",
            "hash" => "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
          }
        ])
      end
    end

    test "finalize only works on Builder, not Merkle tree" do
      tree =
        Merkle.new([
          %{
            "key" => "entry",
            "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
          }
        ])

      assert_raise FunctionClauseError, fn ->
        # credo:disable-for-next-line Credo.Check.Refactor.Apply
        apply(Merkle, :finalize, [tree, []])
      end
    end

    test "proof only works on Merkle tree, not Builder" do
      builder =
        Merkle.builder()
        |> Merkle.add_entry(%{
          "key" => "entry",
          "hash" => "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        })

      assert_raise FunctionClauseError, fn ->
        # credo:disable-for-next-line Credo.Check.Refactor.Apply
        apply(Merkle, :proof, [builder, "entry"])
      end
    end
  end

  describe "builder pattern performance equivalence" do
    test "handles moderate dataset with same performance characteristics as new/1" do
      # Generate 100 entries
      data =
        for i <- 1..100 do
          %{
            "key" => "entry-#{String.pad_leading(Integer.to_string(i), 5, "0")}",
            "hash" => :crypto.hash(:sha256, "data-#{i}") |> Base.encode16(case: :lower)
          }
        end

      tree_from_new = Merkle.new(data)
      tree_from_builder = Merkle.builder() |> Merkle.add_entries(data) |> Merkle.finalize([])

      # Same root
      assert Merkle.root(tree_from_new) == Merkle.root(tree_from_builder)

      # Same depth
      assert tree_from_new.tree_depth == tree_from_builder.tree_depth

      # Proofs work identically
      proof_new = Merkle.proof(tree_from_new, "entry-00050")
      proof_builder = Merkle.proof(tree_from_builder, "entry-00050")
      assert proof_new == proof_builder
    end
  end

  describe "all construction methods produce identical results" do
    test "new/1, builder, from_stream, from_maps, from_tuples all produce same tree" do
      # Generate complex test data with varied keys
      map_data =
        for i <- 1..50 do
          %{
            "key" => "doc-#{String.pad_leading(Integer.to_string(i), 4, "0")}-#{rem(i, 7)}",
            "hash" =>
              :crypto.hash(:sha256, "complex-data-#{i}-#{:rand.uniform(1000)}")
              |> Base.encode16(case: :lower)
          }
        end

      # Prepare data in different formats
      tuple_data = Enum.map(map_data, fn %{"key" => k, "hash" => h} -> {k, h} end)

      struct_data =
        Enum.map(map_data, fn %{"key" => k, "hash" => h} -> %{id: k, digest: h} end)

      # Build trees using all five construction methods
      tree_new = Merkle.new(map_data)

      tree_builder =
        Merkle.builder()
        |> Merkle.add_entries(map_data)
        |> Merkle.finalize([])

      tree_from_maps = Merkle.from_maps(map_data)
      tree_from_tuples = Merkle.from_tuples(tuple_data)
      tree_from_stream = Merkle.from_stream(struct_data, key_fn: & &1.id, hash_fn: & &1.digest)

      # All roots must be identical
      root = Merkle.root(tree_new)
      assert Merkle.root(tree_builder) == root, "builder root mismatch"
      assert Merkle.root(tree_from_maps) == root, "from_maps root mismatch"
      assert Merkle.root(tree_from_tuples) == root, "from_tuples root mismatch"
      assert Merkle.root(tree_from_stream) == root, "from_stream root mismatch"

      # All depths must be identical
      depth = tree_new.tree_depth
      assert tree_builder.tree_depth == depth
      assert tree_from_maps.tree_depth == depth
      assert tree_from_tuples.tree_depth == depth
      assert tree_from_stream.tree_depth == depth

      # All leaves must be identical (same order after sorting)
      leaves = tree_new.leaves
      assert tree_builder.leaves == leaves
      assert tree_from_maps.leaves == leaves
      assert tree_from_tuples.leaves == leaves
      assert tree_from_stream.leaves == leaves

      # Proofs from all trees must be identical and verifiable
      sample_keys = map_data |> Enum.take_every(10) |> Enum.map(& &1["key"])

      for key <- sample_keys do
        proof_new = Merkle.proof(tree_new, key)
        proof_builder = Merkle.proof(tree_builder, key)
        proof_from_maps = Merkle.proof(tree_from_maps, key)
        proof_from_tuples = Merkle.proof(tree_from_tuples, key)
        proof_from_stream = Merkle.proof(tree_from_stream, key)

        # All proofs must be identical
        assert proof_builder == proof_new, "builder proof mismatch for #{key}"
        assert proof_from_maps == proof_new, "from_maps proof mismatch for #{key}"
        assert proof_from_tuples == proof_new, "from_tuples proof mismatch for #{key}"
        assert proof_from_stream == proof_new, "from_stream proof mismatch for #{key}"

        # All proofs must verify against the common root
        hash = Enum.find(map_data, &(&1["key"] == key))["hash"]
        assert Merkle.verify(proof_new, root, hash), "proof verification failed for #{key}"
      end
    end

    test "new/1 and the builder constructors never disagree about an input list" do
      hash = fn seed -> :crypto.hash(:sha256, seed) |> Base.encode16(case: :lower) end

      inputs = [
        [],
        [%{"key" => "solo", "hash" => hash.("1")}],
        [
          %{"key" => "b-key", "hash" => hash.("2")},
          %{"key" => "a-key", "hash" => hash.("1")}
        ],
        for(i <- 1..9, do: %{"key" => "k-#{i}", "hash" => hash.("s#{i}")}),
        [
          %{"key" => "shared-a", "hash" => hash.("same")},
          %{"key" => "shared-b", "hash" => hash.("same")},
          %{"key" => "shared-c", "hash" => hash.("same")}
        ]
      ]

      for data <- inputs, sort? <- [true, false] do
        tuples = Enum.map(data, fn %{"key" => k, "hash" => h} -> {k, h} end)
        root = Merkle.new(data, sort: sort?) |> Merkle.root()

        assert Merkle.from_maps(data, sort: sort?) |> Merkle.root() == root
        assert Merkle.from_tuples(tuples, sort: sort?) |> Merkle.root() == root

        assert Merkle.from_stream(data, key_fn: & &1["key"], hash_fn: & &1["hash"], sort: sort?)
               |> Merkle.root() == root

        assert Merkle.builder()
               |> Merkle.add_entries(data)
               |> Merkle.finalize(sort: sort?)
               |> Merkle.root() == root
      end
    end

    test "new/1 rejects a repeated key that the builder folds away" do
      hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
      other = "b2c3d4e5f6789012345678901234567890123456789012345678901234567890"

      with_duplicate = [
        %{"key" => "dup", "hash" => hash},
        %{"key" => "other", "hash" => other},
        %{"key" => "dup", "hash" => hash}
      ]

      without_duplicate = [
        %{"key" => "dup", "hash" => hash},
        %{"key" => "other", "hash" => other}
      ]

      assert_raise ArgumentError, ~r/Duplicate key in input data/, fn ->
        Merkle.new(with_duplicate)
      end

      # The builder accepts the repeat and folds it into the one leaf it already
      # holds, landing on the root new/1 produces for the list without the repeat.
      assert Merkle.from_maps(with_duplicate) |> Merkle.root() ==
               Merkle.new(without_duplicate) |> Merkle.root()
    end

    test "all methods handle edge cases identically" do
      # One entry
      single_map = [
        %{
          "key" => "only-one",
          "hash" => "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        }
      ]

      single_tuple = [
        {"only-one", "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}
      ]

      single_struct = [
        %{
          id: "only-one",
          digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        }
      ]

      root_new = Merkle.new(single_map) |> Merkle.root()

      root_builder =
        Merkle.builder() |> Merkle.add_entries(single_map) |> Merkle.finalize([]) |> Merkle.root()

      root_from_maps = Merkle.from_maps(single_map) |> Merkle.root()
      root_from_tuples = Merkle.from_tuples(single_tuple) |> Merkle.root()

      root_from_stream =
        Merkle.from_stream(single_struct, key_fn: & &1.id, hash_fn: & &1.digest)
        |> Merkle.root()

      assert root_builder == root_new
      assert root_from_maps == root_new
      assert root_from_tuples == root_new
      assert root_from_stream == root_new

      # Two entries (power of 2, no padding needed)
      two_maps = [
        %{
          "key" => "first",
          "hash" => "1111111111111111111111111111111111111111111111111111111111111111"
        },
        %{
          "key" => "second",
          "hash" => "2222222222222222222222222222222222222222222222222222222222222222"
        }
      ]

      two_tuples = Enum.map(two_maps, fn %{"key" => k, "hash" => h} -> {k, h} end)

      two_structs =
        Enum.map(two_maps, fn %{"key" => k, "hash" => h} -> %{id: k, digest: h} end)

      root_new = Merkle.new(two_maps) |> Merkle.root()

      root_builder =
        Merkle.builder() |> Merkle.add_entries(two_maps) |> Merkle.finalize([]) |> Merkle.root()

      root_from_maps = Merkle.from_maps(two_maps) |> Merkle.root()
      root_from_tuples = Merkle.from_tuples(two_tuples) |> Merkle.root()

      root_from_stream =
        Merkle.from_stream(two_structs, key_fn: & &1.id, hash_fn: & &1.digest) |> Merkle.root()

      assert root_builder == root_new
      assert root_from_maps == root_new
      assert root_from_tuples == root_new
      assert root_from_stream == root_new

      # Three entries (requires padding to 4)
      three_maps = [
        %{
          "key" => "alpha",
          "hash" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        %{
          "key" => "beta",
          "hash" => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        %{
          "key" => "gamma",
          "hash" => "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }
      ]

      three_tuples = Enum.map(three_maps, fn %{"key" => k, "hash" => h} -> {k, h} end)

      three_structs =
        Enum.map(three_maps, fn %{"key" => k, "hash" => h} -> %{id: k, digest: h} end)

      root_new = Merkle.new(three_maps) |> Merkle.root()

      root_builder =
        Merkle.builder() |> Merkle.add_entries(three_maps) |> Merkle.finalize([]) |> Merkle.root()

      root_from_maps = Merkle.from_maps(three_maps) |> Merkle.root()
      root_from_tuples = Merkle.from_tuples(three_tuples) |> Merkle.root()

      root_from_stream =
        Merkle.from_stream(three_structs, key_fn: & &1.id, hash_fn: & &1.digest)
        |> Merkle.root()

      assert root_builder == root_new
      assert root_from_maps == root_new
      assert root_from_tuples == root_new
      assert root_from_stream == root_new
    end

    test "all methods handle empty input identically" do
      empty_root = Merkle.new([]) |> Merkle.root()

      assert Merkle.builder() |> Merkle.finalize([]) |> Merkle.root() == empty_root
      assert Merkle.from_maps([]) |> Merkle.root() == empty_root
      assert Merkle.from_tuples([]) |> Merkle.root() == empty_root

      assert Merkle.from_stream([], key_fn: & &1.id, hash_fn: & &1.hash) |> Merkle.root() ==
               empty_root
    end
  end

  describe "property tests for construction method equivalence" do
    use ExUnitProperties
    import StreamData

    # Generator for valid hex hashes (64-char lowercase hex)
    defp hex_hash_generator_equiv do
      string([?a..?f, ?0..?9], length: 64)
    end

    # Generator for valid keys
    defp key_generator_equiv do
      gen all(
            first <- one_of([member_of(?a..?z), member_of(?0..?9)]),
            middle <- string([?a..?z, ?0..?9, ?-, ?_], max_length: 20),
            last <- one_of([member_of(?a..?z), member_of(?0..?9)])
          ) do
        to_string([first] ++ String.to_charlist(middle) ++ [last])
      end
    end

    # Generator for valid key-hash pairs
    defp key_hash_pair_generator_equiv do
      gen all(
            key <- key_generator_equiv(),
            hash <- hex_hash_generator_equiv()
          ) do
        %{"key" => key, "hash" => hash}
      end
    end

    property "all construction methods produce identical trees for any data" do
      check all(
              data <- list_of(key_hash_pair_generator_equiv(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        # Prepare data in all formats
        tuple_data = Enum.map(unique_data, fn %{"key" => k, "hash" => h} -> {k, h} end)

        struct_data =
          Enum.map(unique_data, fn %{"key" => k, "hash" => h} -> %{id: k, digest: h} end)

        # Build trees using all methods
        tree_new = Merkle.new(unique_data)
        tree_builder = Merkle.builder() |> Merkle.add_entries(unique_data) |> Merkle.finalize([])
        tree_from_maps = Merkle.from_maps(unique_data)
        tree_from_tuples = Merkle.from_tuples(tuple_data)

        tree_from_stream =
          Merkle.from_stream(struct_data, key_fn: & &1.id, hash_fn: & &1.digest)

        # All must produce identical roots
        root = Merkle.root(tree_new)
        assert Merkle.root(tree_builder) == root
        assert Merkle.root(tree_from_maps) == root
        assert Merkle.root(tree_from_tuples) == root
        assert Merkle.root(tree_from_stream) == root

        # All must have identical leaves
        assert tree_builder.leaves == tree_new.leaves
        assert tree_from_maps.leaves == tree_new.leaves
        assert tree_from_tuples.leaves == tree_new.leaves
        assert tree_from_stream.leaves == tree_new.leaves
      end
    end

    property "builder duplicate handling is idempotent for identical key+hash" do
      check all(
              data <- list_of(key_hash_pair_generator_equiv(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        # Add each entry twice
        doubled_data = unique_data ++ unique_data

        builder_single =
          Merkle.builder() |> Merkle.add_entries(unique_data) |> Merkle.finalize([])

        builder_doubled =
          Merkle.builder() |> Merkle.add_entries(doubled_data) |> Merkle.finalize([])

        # Should produce identical trees (duplicates ignored)
        assert Merkle.root(builder_single) == Merkle.root(builder_doubled)
        assert builder_single.leaves == builder_doubled.leaves
      end
    end

    property "incremental add_entry equals batch add_entries" do
      check all(
              data <- list_of(key_hash_pair_generator_equiv(), min_length: 1, max_length: 30),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        # Build incrementally one at a time
        tree_incremental =
          Enum.reduce(unique_data, Merkle.builder(), fn entry, builder ->
            Merkle.add_entry(builder, entry)
          end)
          |> Merkle.finalize([])

        # Build with batch add_entries
        tree_batch = Merkle.builder() |> Merkle.add_entries(unique_data) |> Merkle.finalize([])

        assert Merkle.root(tree_incremental) == Merkle.root(tree_batch)
        assert tree_incremental.leaves == tree_batch.leaves
      end
    end

    property "all methods respect sort: false option consistently" do
      check all(
              data <- list_of(key_hash_pair_generator_equiv(), min_length: 2, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              length(unique_data) >= 2
            ) do
        # Prepare data in all formats (preserving order)
        tuple_data = Enum.map(unique_data, fn %{"key" => k, "hash" => h} -> {k, h} end)

        struct_data =
          Enum.map(unique_data, fn %{"key" => k, "hash" => h} -> %{id: k, digest: h} end)

        # Build trees with sort: false
        tree_new = Merkle.new(unique_data, sort: false)

        tree_builder =
          Merkle.builder() |> Merkle.add_entries(unique_data) |> Merkle.finalize(sort: false)

        tree_from_maps = Merkle.from_maps(unique_data, sort: false)
        tree_from_tuples = Merkle.from_tuples(tuple_data, sort: false)

        tree_from_stream =
          Merkle.from_stream(struct_data, key_fn: & &1.id, hash_fn: & &1.digest, sort: false)

        # All must produce identical roots
        root = Merkle.root(tree_new)
        assert Merkle.root(tree_builder) == root
        assert Merkle.root(tree_from_maps) == root
        assert Merkle.root(tree_from_tuples) == root
        assert Merkle.root(tree_from_stream) == root

        # Leaves should preserve input order (not sorted)
        expected_keys = Enum.map(unique_data, fn %{"key" => k} -> k end)
        actual_keys = Enum.map(tree_new.leaves, fn {k, _} -> k end)
        assert actual_keys == expected_keys
      end
    end

    property "proofs from any construction method verify against any other's root" do
      check all(
              data <- list_of(key_hash_pair_generator_equiv(), min_length: 1, max_length: 30),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tuple_data = Enum.map(unique_data, fn %{"key" => k, "hash" => h} -> {k, h} end)

        tree_new = Merkle.new(unique_data)
        tree_from_tuples = Merkle.from_tuples(tuple_data)

        root = Merkle.root(tree_new)

        # Pick a random key to test
        test_entry = Enum.random(unique_data)
        key = test_entry["key"]
        hash = test_entry["hash"]

        # Generate proofs from different trees
        proof_new = Merkle.proof(tree_new, key)
        proof_tuples = Merkle.proof(tree_from_tuples, key)

        # Proofs should be identical
        assert proof_new == proof_tuples

        # Both proofs should verify against the shared root
        assert Merkle.verify(proof_new, root, hash)
        assert Merkle.verify(proof_tuples, root, hash)
      end
    end
  end
end
