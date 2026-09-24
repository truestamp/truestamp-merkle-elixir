# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.BuilderTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle
  alias Truestamp.Merkle.Generators

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
               "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
               proof,
               root
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

  describe "builder and new/2 agree" do
    test "a 100-entry tree is the same either way" do
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
        assert Merkle.verify(hash, proof_new, root), "proof verification failed for #{key}"
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

    property "all construction methods produce identical trees for any data" do
      check all(
              data <- list_of(Generators.entry(), min_length: 1, max_length: 50),
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
              data <- list_of(Generators.entry(), min_length: 1, max_length: 20),
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
              data <- list_of(Generators.entry(), min_length: 1, max_length: 30),
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
              data <- list_of(Generators.entry(), min_length: 2, max_length: 20),
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
              data <- list_of(Generators.entry(), min_length: 1, max_length: 30),
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
        assert Merkle.verify(hash, proof_new, root)
        assert Merkle.verify(hash, proof_tuples, root)
      end
    end
  end
end
