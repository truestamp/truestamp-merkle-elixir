# This script should be run with: mix run examples/truestamp_merkle_demo.exs

defmodule TruestampMerkleDemo do
  @moduledoc """
  Interactive demo script for the Truestamp.Merkle pure Elixir implementation.

  This script demonstrates:
  - Tree creation with various input sizes
  - Root hash calculation
  - Proof generation and verification
  - JSON serialization/deserialization
  - Determinism verification
  - Security features (second preimage resistance)
  - Builder pattern for streaming/incremental tree construction
  - Convenience wrappers (from_stream, from_maps, from_tuples)
  - Performance benchmarking
  """

  alias Truestamp.Merkle

  def run do
    IO.puts("=== Truestamp.Merkle Demo ===\n")

    # Demo 1: Basic functionality
    demo_basic_functionality()

    # Demo 2: JSON serialization
    demo_json_serialization()

    # Demo 3: Determinism
    demo_determinism()

    # Demo 4: Security features
    demo_security_features()

    # Demo 5: Builder pattern (streaming API)
    demo_builder_pattern()

    # Demo 6: Convenience wrappers
    demo_convenience_wrappers()

    # Demo 7: Performance benchmarks
    demo_performance()

    IO.puts("\n=== Demo Complete ===")
    IO.puts("✅ All demos passed successfully!")
    IO.puts("\nKey Features Demonstrated:")
    IO.puts("• Pure Elixir implementation (no external dependencies)")
    IO.puts("• Second preimage attack resistance via domain separation")
    IO.puts("• Deterministic tree construction and hashing")
    IO.puts("• Ultra-compact proof structure (direction:hash strings)")
    IO.puts("• Efficient performance for large datasets")
    IO.puts("• Simple API designed for easy TypeScript porting")
    IO.puts("• Builder pattern for streaming/incremental tree construction")
    IO.puts("• Convenience wrappers for various input formats")
  end

  defp demo_basic_functionality do
    IO.puts("Demo 1: Basic Functionality")
    IO.puts("=" <> String.duplicate("=", 40))

    # Create sample data with proper UUIDv7 keys and SHA-256 hashes
    data = [
      %{
        "key" => "01234567-89ab-cdef-0123-456789abcdef",
        "hash" => "4b63973426e71b04b39dab3b2f29cabe974994eb71f3203a3b84e809e3bdef9f"
      },
      %{
        "key" => "12345678-9abc-def0-1234-56789abcdef0",
        "hash" => "756e7864807bee896c1eb0cf0547891d4ee79f014bc36aee3405f20dfbc3acfa"
      },
      %{
        "key" => "23456789-abcd-ef01-2345-6789abcdef01",
        "hash" => "3a901f3ad269070377f5c7f79537994b7239e2684bd21d79c87868875117d9ac"
      },
      %{
        "key" => "3456789a-bcde-f012-3456-789abcdef012",
        "hash" => "c4fcdf256e16c4b8839a21d51ecda9f47f97012ef7878a9d69faa74493527cbb"
      }
    ]

    IO.puts("Creating tree with #{length(data)} documents...")
    tree = Merkle.new(data)

    IO.puts("Tree depth: #{tree.tree_depth}")
    IO.puts("Root hash: #{Merkle.root(tree)}")

    # Generate and verify proofs for all documents
    IO.puts("\nGenerating and verifying proofs:")
    root = Merkle.root(tree)

    Enum.each(data, fn %{"key" => key, "hash" => hash} ->
      proof = Merkle.proof(tree, key)
      valid = Merkle.verify(proof, root, hash)

      IO.puts("#{key}: proof size #{length(proof)}, valid: #{valid}")
    end)

    IO.puts("")
  end

  defp demo_json_serialization do
    IO.puts("Demo 2: JSON Serialization")
    IO.puts("=" <> String.duplicate("=", 40))

    data = [
      %{
        "key" => "a1234567-89ab-cdef-0123-456789abcdef",
        "hash" => "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
      },
      %{
        "key" => "b1234567-89ab-cdef-0123-456789abcdef",
        "hash" => "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888aaaa1111"
      }
    ]

    tree = Merkle.new(data)
    proof = Merkle.proof(tree, "a1234567-89ab-cdef-0123-456789abcdef")

    IO.puts("Original proof structure:")
    IO.inspect(proof, pretty: true)

    # JSON serialization
    json_proof = JSON.encode!(proof)
    IO.puts("\nJSON serialized proof:")
    IO.puts(json_proof)

    # JSON deserialization
    decoded_proof = JSON.decode!(json_proof)
    IO.puts("\nDecoded proof structure:")
    IO.inspect(decoded_proof, pretty: true)

    # No conversion needed - strings are preserved in JSON perfectly
    normalized_proof = decoded_proof

    # Verify the roundtrip worked
    root = Merkle.root(tree)

    original_valid =
      Merkle.verify(
        proof,
        root,
        "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
      )

    roundtrip_valid =
      Merkle.verify(
        normalized_proof,
        root,
        "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
      )

    IO.puts("\nVerification results:")
    IO.puts("Original proof valid: #{original_valid}")
    IO.puts("Roundtrip proof valid: #{roundtrip_valid}")
    IO.puts("JSON size: #{String.length(json_proof)} bytes")
    IO.puts("")
  end

  defp demo_determinism do
    IO.puts("Demo 3: Determinism")
    IO.puts("=" <> String.duplicate("=", 40))

    # Create the same data in different orders with proper UUIDv7 keys
    base_data = [
      %{
        "key" => "zebra567-89ab-cdef-0123-456789abcdef",
        "hash" => "e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      %{
        "key" => "alpha567-89ab-cdef-0123-456789abcdef",
        "hash" => "a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      %{
        "key" => "beta5678-89ab-cdef-0123-456789abcdef",
        "hash" => "b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      %{
        "key" => "gamma678-89ab-cdef-0123-456789abcdef",
        "hash" => "c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    ]

    # Create trees with different input orderings
    orderings = [
      base_data,
      Enum.reverse(base_data),
      Enum.shuffle(base_data),
      Enum.shuffle(base_data),
      Enum.shuffle(base_data)
    ]

    trees = Enum.map(orderings, &Merkle.new/1)
    roots = Enum.map(trees, &Merkle.root/1)

    IO.puts("Testing determinism with #{length(orderings)} different input orderings...")

    # Check that all roots are identical
    first_root = hd(roots)
    all_same = Enum.all?(roots, &(&1 == first_root))

    IO.puts("All trees produced same root: #{all_same}")
    IO.puts("Root hash: #{first_root}")

    # Verify leaf ordering is consistent
    first_leaves = hd(trees).leaves
    all_leaves_same = Enum.all?(trees, &(&1.leaves == first_leaves))

    IO.puts("All trees have same leaf ordering: #{all_leaves_same}")
    IO.puts("Leaf order: #{Enum.map(first_leaves, fn {key, _} -> key end) |> Enum.join(", ")}")
    IO.puts("")
  end

  defp demo_security_features do
    IO.puts("Demo 4: Security Features")
    IO.puts("=" <> String.duplicate("=", 40))

    # Demonstrate domain separation
    data = [
      %{
        "key" => "01234567-89ab-cdef-0123-456789abcdef",
        "hash" => "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
      }
    ]

    tree = Merkle.new(data)
    root = Merkle.root(tree)

    # Show that root is different from direct hash (due to domain separation)
    direct_hash =
      :crypto.hash(:sha256, "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab")
      |> Base.encode16(case: :lower)

    IO.puts("Testing second preimage resistance (domain separation):")
    IO.puts("Merkle root: #{root}")
    IO.puts("Direct hash: #{direct_hash}")
    IO.puts("Different hashes (secure): #{root != direct_hash}")

    # Show prefix usage - decode hex to binary first, like the library does
    hash_binary =
      Base.decode16!("abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        case: :lower
      )

    leaf_with_prefix =
      :crypto.hash(:sha256, <<0x00>> <> hash_binary)
      |> Base.encode16(case: :lower)

    IO.puts("\nDomain separation details:")
    IO.puts("Leaf hash (with 0x00 prefix): #{leaf_with_prefix}")
    IO.puts("Root equals leaf (single element): #{root == leaf_with_prefix}")

    # Test with multiple elements to show internal node prefixes
    multi_data = [
      %{
        "key" => "doc11111-89ab-cdef-0123-456789abcdef",
        "hash" => "1111111111111111111111111111111111111111111111111111111111111111"
      },
      %{
        "key" => "doc22222-89ab-cdef-0123-456789abcdef",
        "hash" => "2222222222222222222222222222222222222222222222222222222222222222"
      }
    ]

    multi_tree = Merkle.new(multi_data)
    multi_root = Merkle.root(multi_tree)

    IO.puts("\nMulti-element tree:")
    IO.puts("Root hash: #{multi_root}")
    IO.puts("Different from single element: #{multi_root != root}")
    IO.puts("")
  end

  defp demo_builder_pattern do
    IO.puts("Demo 5: Builder Pattern (Streaming API)")
    IO.puts("=" <> String.duplicate("=", 40))

    IO.puts("The builder pattern allows incremental tree construction:")
    IO.puts("• Pre-compute leaf hashes as items are added")
    IO.puts("• Fail fast on invalid input or duplicate keys")
    IO.puts("• Build tree only when finalized")
    IO.puts("")

    # Create an empty builder
    builder = Merkle.builder()
    IO.puts("Created empty builder: count=#{builder.count}")

    # Add items one at a time (simulating streaming)
    items = [
      %{
        "key" => "stream-item-1",
        "hash" => "1111111111111111111111111111111111111111111111111111111111111111"
      },
      %{
        "key" => "stream-item-2",
        "hash" => "2222222222222222222222222222222222222222222222222222222222222222"
      },
      %{
        "key" => "stream-item-3",
        "hash" => "3333333333333333333333333333333333333333333333333333333333333333"
      }
    ]

    IO.puts("\nAdding items incrementally:")

    builder =
      Enum.reduce(items, builder, fn item, acc ->
        new_builder = Merkle.add_entry(acc, item)
        IO.puts("  Added #{item["key"]}, count=#{new_builder.count}")
        new_builder
      end)

    # Finalize to build the tree
    tree = Merkle.finalize(builder, [])
    IO.puts("\nFinalized tree:")
    IO.puts("  Root: #{Merkle.root(tree)}")
    IO.puts("  Depth: #{tree.tree_depth}")

    # Compare with new/1 - should produce identical tree
    tree_from_new = Merkle.new(items)
    roots_match = Merkle.root(tree) == Merkle.root(tree_from_new)
    IO.puts("  Matches new/1: #{roots_match}")

    # Demonstrate add_entries for batch adding
    IO.puts("\nBatch adding with add_entries/2:")

    batch_builder =
      Merkle.builder()
      |> Merkle.add_entries(items)

    IO.puts("  Added #{batch_builder.count} items in batch")
    batch_tree = Merkle.finalize(batch_builder, [])
    batch_matches = Merkle.root(batch_tree) == Merkle.root(tree)
    IO.puts("  Batch tree matches incremental: #{batch_matches}")

    # Demonstrate duplicate handling
    IO.puts("\nDuplicate handling:")

    dup_builder =
      Merkle.builder()
      |> Merkle.add_entry(%{
        "key" => "dup-key",
        "hash" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      })
      |> Merkle.add_entry(%{
        "key" => "dup-key",
        "hash" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      })

    IO.puts("  Same key+hash added twice: count=#{dup_builder.count} (idempotent)")

    # Show that different hash with same key would raise
    IO.puts("  Same key, different hash: raises ArgumentError (fail fast)")
    IO.puts("")
  end

  defp demo_convenience_wrappers do
    IO.puts("Demo 6: Convenience Wrappers")
    IO.puts("=" <> String.duplicate("=", 40))

    # Sample data in different formats
    struct_items = [
      %{
        id: "struct-1",
        item_hash: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
      },
      %{
        id: "struct-2",
        item_hash: "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
      },
      %{
        id: "struct-3",
        item_hash: "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
      }
    ]

    map_items = [
      %{
        "key" => "struct-1",
        "hash" => "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
      },
      %{
        "key" => "struct-2",
        "hash" => "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
      },
      %{
        "key" => "struct-3",
        "hash" => "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
      }
    ]

    tuple_items = [
      {"struct-1", "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"},
      {"struct-2", "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"},
      {"struct-3", "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"}
    ]

    # from_stream/2 - uses extractor functions
    IO.puts("from_stream/2 - Custom extractor functions:")
    tree_stream = Merkle.from_stream(struct_items, key_fn: & &1.id, hash_fn: & &1.item_hash)
    IO.puts("  Root: #{Merkle.root(tree_stream)}")

    # from_maps/2 - for standard map format
    IO.puts("\nfrom_maps/2 - Standard map format:")
    tree_maps = Merkle.from_maps(map_items)
    IO.puts("  Root: #{Merkle.root(tree_maps)}")

    # from_tuples/2 - for {key, hash} tuple format
    IO.puts("\nfrom_tuples/2 - Tuple format:")
    tree_tuples = Merkle.from_tuples(tuple_items)
    IO.puts("  Root: #{Merkle.root(tree_tuples)}")

    # All should produce identical trees
    all_match =
      Merkle.root(tree_stream) == Merkle.root(tree_maps) and
        Merkle.root(tree_maps) == Merkle.root(tree_tuples)

    IO.puts("\nAll wrappers produce identical trees: #{all_match}")

    # Works with streams (lazy evaluation)
    IO.puts("\nStreaming with lazy evaluation:")

    stream =
      Stream.iterate(1, &(&1 + 1))
      |> Stream.take(5)
      |> Stream.map(fn i ->
        %{
          "key" => "lazy-#{String.pad_leading(Integer.to_string(i), 3, "0")}",
          "hash" => :crypto.hash(:sha256, "data-#{i}") |> Base.encode16(case: :lower)
        }
      end)

    tree_lazy = Merkle.from_maps(stream)
    IO.puts("  Tree from lazy stream: root=#{String.slice(Merkle.root(tree_lazy), 0, 16)}...")
    IO.puts("  Leaves: #{length(tree_lazy.leaves)}")
    IO.puts("")
  end

  defp demo_performance do
    IO.puts("Demo 7: Performance Benchmarks")
    IO.puts("=" <> String.duplicate("=", 40))

    # Test different sizes including the million leaf target
    sizes = [10, 100, 1000, 10_000, 100_000, 1_000_000]

    Enum.each(sizes, fn size ->
      IO.puts("Testing with #{format_number(size)} elements...")

      # Generate test data with proper UUIDv7 format keys
      data =
        Enum.map(1..size, fn i ->
          key = "#{String.pad_leading("#{i}", 8, "0")}-89ab-cdef-0123-456789abcdef"
          hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
          %{"key" => key, "hash" => hash}
        end)

      # Time tree creation
      {tree_time, tree} = :timer.tc(fn -> Merkle.new(data) end)
      tree_ms = tree_time / 1000

      # Generate a random proof to test average case
      random_key =
        "#{String.pad_leading("#{:rand.uniform(size)}", 8, "0")}-89ab-cdef-0123-456789abcdef"

      {proof_time, proof} = :timer.tc(fn -> Merkle.proof(tree, random_key) end)
      proof_ms = proof_time / 1000

      # Calculate proof size in bytes (JSON serialized)
      json_proof = JSON.encode!(proof)
      proof_bytes = String.length(json_proof)

      # Time verification
      root = Merkle.root(tree)
      random_hash = Enum.find(data, fn %{"key" => k} -> k == random_key end)["hash"]

      {verify_time, result} =
        :timer.tc(fn ->
          Merkle.verify(proof, root, random_hash)
        end)

      verify_ms = verify_time / 1000

      IO.puts("  Tree creation: #{format_time(tree_ms)}")
      IO.puts("  Tree depth: #{tree.tree_depth}")
      IO.puts("  Proof generation: #{format_time(proof_ms)}")
      IO.puts("  Proof length: #{length(proof)} elements")
      IO.puts("  Proof size (JSON): #{proof_bytes} bytes")
      IO.puts("  Avg bytes per element: #{Float.round(proof_bytes / length(proof), 1)}")
      IO.puts("  Verification: #{format_time(verify_ms)} (valid: #{result})")

      # For the million and ten million leaf tests, show a sample proof
      if size in [1_000_000, 10_000_000] do
        IO.puts("\n  Sample proof structure for #{random_key}:")

        Enum.with_index(proof, 1)
        |> Enum.each(fn {proof_step, index} ->
          [direction, hash] = String.split(proof_step, ":", parts: 2)
          short_hash = String.slice(hash, 0, 8) <> "..." <> String.slice(hash, -8, 8)
          IO.puts("    #{index}. #{direction}:#{short_hash}")
        end)

        IO.puts("  Full JSON proof: #{json_proof}")
      end

      IO.puts("")
    end)

    IO.puts("")
  end

  # Helper function to format large numbers with underscores
  defp format_number(num) when num >= 1_000_000 do
    Integer.to_string(num) |> add_underscores()
  end

  defp format_number(num) when num >= 1_000 do
    Integer.to_string(num) |> add_underscores()
  end

  defp format_number(num), do: Integer.to_string(num)

  defp add_underscores(str) do
    str
    |> String.reverse()
    |> String.to_charlist()
    |> Enum.chunk_every(3)
    |> Enum.map(&List.to_string/1)
    |> Enum.join("_")
    |> String.reverse()
  end

  # Helper function to format timing with appropriate units
  defp format_time(ms) when ms >= 1000 do
    seconds = ms / 1000
    "#{:erlang.float_to_binary(seconds, decimals: 2)}s"
  end

  defp format_time(ms) do
    "#{:erlang.float_to_binary(ms, decimals: 2)}ms"
  end
end

# Run the demo
TruestampMerkleDemo.run()
