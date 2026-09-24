# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.TreeTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle
  alias Truestamp.Merkle.Generators

  describe "new/2" do
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
      assert Merkle.verify(hash, Merkle.proof(tree, "key-a"), root)
      assert Merkle.verify(hash, Merkle.proof(tree, "key-b"), root)
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
        assert Merkle.verify(hash, Merkle.proof(tree, key), root), "#{key} is not provable"
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

  describe "determinism" do
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
          Merkle.verify(hash, proof, root)
        end)

      assert Enum.all?(results, &(&1 == true))
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
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof_z,
               root
             )

      assert Merkle.verify(
               "b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
               proof_a,
               root
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
              data <- list_of(Generators.entry(), min_length: 1, max_length: 20),
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

        assert Merkle.root(tree1) == Merkle.root(tree2)
        assert Merkle.root(tree2) == Merkle.root(tree3)
      end
    end

    property "unsorted trees preserve exact input order" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data, sort: false)

        # Extract keys from leaves
        leaf_keys = Enum.map(tree.leaves, fn {key, _hash} -> key end)
        input_keys = Enum.map(unique_data, fn %{"key" => key} -> key end)

        # Keys should be in exact same order
        assert leaf_keys == input_keys
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
      refute Merkle.verify(padding_constant(), forged, root)
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

      assert Merkle.verify(last_real_hash(), proof, root)
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
end
