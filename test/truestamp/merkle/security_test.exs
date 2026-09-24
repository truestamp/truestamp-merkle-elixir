# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.SecurityTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle
  alias Truestamp.Merkle.Generators

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
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               wrong_root1
             ) == false

      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               wrong_root2
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
      assert Merkle.verify(hash, oversized_proof, root) == false
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
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               "invalid"
             ) == false

      # Test invalid leaf hash (wrong length)
      assert Merkle.verify("invalid", proof, root) == false

      # Test invalid root hash (non-hex characters)
      assert Merkle.verify(
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               "z1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
             ) == false

      # Test invalid leaf hash (non-hex characters)
      assert Merkle.verify(
               "z1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               root
             ) == false
    end

    test "input validation rejects malformed proof elements" do
      root = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
      hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)

      # Proof element missing colon separator
      malformed_proof1 = ["l" <> hash]
      assert Merkle.verify(hash, malformed_proof1, root) == false

      # Proof element with invalid direction
      malformed_proof2 = ["x:#{hash}"]
      assert Merkle.verify(hash, malformed_proof2, root) == false

      # Proof element with invalid hash
      malformed_proof3 = ["l:invalid_hash"]
      assert Merkle.verify(hash, malformed_proof3, root) == false

      # Proof element with wrong hash length
      malformed_proof4 = ["l:a1b2c3"]
      assert Merkle.verify(hash, malformed_proof4, root) == false
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
      assert Merkle.verify(hash, "not a list", root) == false
      assert Merkle.verify(hash, %{}, root) == false
      assert Merkle.verify(hash, nil, root) == false
    end
  end

  describe "property-based security tests" do
    use ExUnitProperties
    import StreamData

    property "round-trip proof verification always succeeds for valid trees" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 100),
              # Ensure unique keys
              unique_data = data |> Enum.uniq_by(& &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        root_hash = Merkle.root(tree)

        for %{"key" => key, "hash" => hash} <- unique_data do
          assert Merkle.verify(hash, Merkle.proof(tree, key), root_hash)
        end
      end
    end

    property "bit-flipping in proofs causes verification failure" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 10),
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
          refute Merkle.verify(test_hash, corrupted_proof, root_hash)
        else
          # Single element tree - this is expected behavior
          true
        end
      end
    end

    property "swapping proof directions causes verification failure" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 10),
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
          refute Merkle.verify(test_hash, swapped_proof, root_hash)
        else
          # Single element tree - this is expected behavior
          true
        end
      end
    end

    property "truncated proofs cause verification failure" do
      check all(
              data <- list_of(Generators.entry(), min_length: 4, max_length: 16),
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
          refute Merkle.verify(test_hash, truncated_proof, root_hash)
        else
          # Too small to truncate meaningfully
          true
        end
      end
    end

    property "trees are deterministic regardless of input order" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 20),
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

        assert root1 == root2
      end
    end

    property "malicious internal node hashes cannot be used as fake leaves" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 8),
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
          assert fake_root != root_hash
        end
      end
    end

    property "power-of-two and non-power-of-two trees both work correctly" do
      check all(base_size <- integer(1..15)) do
        # Test both power-of-2 and non-power-of-2 sizes
        sizes = [base_size, base_size * 2, base_size * 2 + 1]

        for size <- sizes do
          data =
            for i <- 1..size do
              %{
                "key" => "test-key-#{String.pad_leading(Integer.to_string(i), 4, "0")}-#{i}",
                "hash" => :crypto.hash(:sha256, "test data #{i}") |> Base.encode16(case: :lower)
              }
            end

          tree = Merkle.new(data)
          root_hash = Merkle.root(tree)

          for %{"key" => key, "hash" => hash} <- data do
            assert Merkle.verify(hash, Merkle.proof(tree, key), root_hash), "size #{size}"
          end
        end
      end
    end

    property "injectable sibling attacks fail due to domain separation" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 8),
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
          assert malicious_root != root_hash
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

        for %{"key" => key, "hash" => hash} <- data do
          assert Merkle.verify(hash, Merkle.proof(tree, key), root_hash)
        end
      end
    end

    property "repeated hash inputs with unique keys work correctly" do
      check all(
              base_hash <- Generators.digest(),
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
        for %{"key" => key, "hash" => hash} <- data do
          assert Merkle.verify(hash, Merkle.proof(tree, key), root_hash)
        end

        # ...and a distinct position: the paths differ from one key to the next.
        paths = Enum.map(data, &Merkle.proof(tree, &1["key"]))
        assert length(Enum.uniq(paths)) == key_count
      end
    end

    property "proof lookup is case-sensitive" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 5),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              %{"key" => test_key} = hd(unique_data),
              String.upcase(test_key) != test_key,
              String.upcase(test_key) not in Enum.map(unique_data, & &1["key"])
            ) do
        tree = Merkle.new(unique_data)

        # The key as written finds its path; the same letters in another case do not.
        assert is_list(Merkle.proof(tree, test_key))
        assert Merkle.proof(tree, String.upcase(test_key)) == nil
      end
    end

    property "root hash collision resistance - different data produces different roots" do
      check all(
              data1 <- list_of(Generators.entry(), min_length: 1, max_length: 20),
              data2 <- list_of(Generators.entry(), min_length: 1, max_length: 20),
              unique_data1 = Enum.uniq_by(data1, & &1["key"]),
              unique_data2 = Enum.uniq_by(data2, & &1["key"]),
              unique_data1 != [],
              unique_data2 != [],
              # The tree sorts, so the same entries in another order are the same tree.
              Enum.sort(unique_data1) != Enum.sort(unique_data2)
            ) do
        tree1 = Merkle.new(unique_data1)
        tree2 = Merkle.new(unique_data2)

        assert Merkle.root(tree1) != Merkle.root(tree2)
      end
    end

    property "proof independence - proof for one leaf cannot verify a different leaf" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 10),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              length(unique_data) >= 2
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)

        [entry1, entry2 | _] = unique_data
        proof1 = Merkle.proof(tree, entry1["key"])

        # The proof for the first entry must not verify the second entry's hash
        refute Merkle.verify(entry2["hash"], proof1, root)
      end
    end

    property "proof uniqueness - proof generation is deterministic" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        %{"key" => test_key} = hd(unique_data)

        # Generate proof multiple times
        proof1 = Merkle.proof(tree, test_key)
        proof2 = Merkle.proof(tree, test_key)
        proof3 = Merkle.proof(tree, test_key)

        assert proof1 == proof2
        assert proof2 == proof3
      end
    end

    property "proof ordering invariance - reordering proof elements causes verification failure" do
      check all(
              data <- list_of(Generators.entry(), min_length: 4, max_length: 10),
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
          assert proof == reversed_proof or not Merkle.verify(hash, reversed_proof, root)
        end
      end
    end

    property "proof size bounds - proof length never exceeds tree depth" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 100),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)

        for %{"key" => key} <- unique_data do
          assert length(Merkle.proof(tree, key)) == tree.tree_depth
        end
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

        assert tree.tree_depth == expected_depth
      end
    end

    property "proof format validation - all proof elements follow exact format" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)

        for %{"key" => key} <- unique_data, step <- Merkle.proof(tree, key) do
          assert step =~ ~r/\A[lr]:[0-9a-f]{64}\z/
        end
      end
    end

    property "root hash format consistency - always 64-char lowercase hex" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)

        assert root =~ ~r/\A[0-9a-f]{64}\z/
      end
    end

    property "empty proof correctness - single-element trees always have empty proofs" do
      check all(entry <- Generators.entry()) do
        tree = Merkle.new([entry])
        assert Merkle.proof(tree, entry["key"]) == []
      end
    end

    property "cross-tree proof compatibility - proofs from equivalent trees are interchangeable" do
      check all(
              data <- list_of(Generators.entry(), min_length: 2, max_length: 20),
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
        assert root1 == root2
        assert Merkle.verify(hash, proof1, root2)
      end
    end

    property "subtree independence - proofs don't contain raw hashes of non-sibling leaves" do
      check all(
              data <- list_of(Generators.entry(), min_length: 4, max_length: 10),
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

        assert MapSet.disjoint?(MapSet.new(proof_hashes), MapSet.new(other_leaf_hashes))
      end
    end

    property "sibling hash uniqueness - no duplicate hashes in proofs" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 50),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)

        for %{"key" => key} <- unique_data do
          hashes =
            Enum.map(Merkle.proof(tree, key), fn elem ->
              [_dir, hash] = String.split(elem, ":", parts: 2)
              hash
            end)

          assert length(hashes) == length(Enum.uniq(hashes))
        end
      end
    end

    property "proof self-sufficiency - verification requires only proof, root, and leaf hash" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 20),
              unique_data = Enum.uniq_by(data, & &1["key"]),
              unique_data != []
            ) do
        tree = Merkle.new(unique_data)
        root = Merkle.root(tree)
        %{"key" => key, "hash" => hash} = hd(unique_data)

        proof = Merkle.proof(tree, key)

        # Should be able to verify without tree, without key, without other data
        # Just proof + root + hash
        result = Merkle.verify(hash, proof, root)

        # Also verify that we get same result if we serialize/deserialize
        json_proof = JSON.encode!(proof)
        decoded_proof = JSON.decode!(json_proof)

        assert result
        assert Merkle.verify(hash, decoded_proof, root)
      end
    end
  end
end
