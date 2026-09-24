#!/usr/bin/env elixir
# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# This script should be run with: mix run bench/proof_generation_benchmark.exs

defmodule ProofGenerationBenchmark do
  @moduledoc """
  Benchmark script to test Merkle tree proof generation performance.

  This script specifically focuses on measuring:
  - Proof generation performance for large trees (O(log n) per proof)
  - Builder pattern vs new/1 performance comparison
  - Convenience wrapper performance
  """

  alias Truestamp.Merkle

  def run do
    IO.puts("=== Merkle Tree Proof Generation Benchmark ===\n")

    # Test with progressively larger trees
    sizes = [1_000, 5_000, 10_000, 20_000, 50_000]

    Enum.each(sizes, fn size ->
      IO.puts("Testing #{format_number(size)} leaf tree...")
      benchmark_tree_size(size)
      IO.puts("")
    end)

    # Builder pattern benchmarks
    IO.puts("\n" <> String.duplicate("=", 60))
    IO.puts("=== Builder Pattern Benchmarks ===")
    IO.puts(String.duplicate("=", 60) <> "\n")

    builder_sizes = [1_000, 10_000, 50_000, 100_000]

    Enum.each(builder_sizes, fn size ->
      IO.puts("Testing builder pattern with #{format_number(size)} items...")
      benchmark_builder_pattern(size)
      IO.puts("")
    end)

    IO.puts("=== Benchmark Complete ===")
  end

  defp benchmark_tree_size(size) do
    # Generate test data
    IO.puts("  Generating #{format_number(size)} test documents...")
    data = generate_test_data(size)

    # Create tree and measure construction time
    IO.puts("  Building Merkle tree...")
    {tree_time, tree} = :timer.tc(fn -> Merkle.new(data) end)
    tree_ms = tree_time / 1000

    IO.puts("  Tree created in #{format_time(tree_ms)}")
    IO.puts("  Tree depth: #{tree.tree_depth}")

    # Test proof generation performance with varying numbers of proofs
    proof_counts = [10, 100, 1000]

    Enum.each(proof_counts, fn proof_count ->
      benchmark_proof_generation(tree, data, proof_count, size)
    end)
  end

  defp benchmark_proof_generation(tree, data, proof_count, tree_size) do
    IO.puts("  Generating #{proof_count} proofs:")

    # Select random keys for proof generation
    random_keys =
      data
      |> Enum.take_random(proof_count)
      |> Enum.map(fn %{"key" => key} -> key end)

    # Time the proof generation
    {total_time, proofs} =
      :timer.tc(fn ->
        Enum.map(random_keys, fn key ->
          Merkle.proof(tree, key)
        end)
      end)

    total_ms = total_time / 1000
    avg_per_proof = total_ms / proof_count

    IO.puts("    Total time: #{format_time(total_ms)}")
    IO.puts("    Average per proof: #{format_time(avg_per_proof)}")
    IO.puts("    Proofs per second: #{Float.round(1000 / avg_per_proof, 1)}")

    # Verify a few proofs to ensure correctness
    root = Merkle.root(tree)
    verification_sample = Enum.zip(proofs, random_keys) |> Enum.take(5)

    all_valid =
      Enum.all?(verification_sample, fn {proof, key} ->
        hash = Enum.find(data, fn %{"key" => k} -> k == key end)["hash"]
        Merkle.verify(proof, root, hash)
      end)

    IO.puts("    Sample verification: #{if all_valid, do: "✅ All valid", else: "❌ Some invalid"}")

    # Calculate efficiency metrics
    theoretical_min_ops = proof_count * :math.log2(tree_size)

    IO.puts("    Theoretical min operations: #{Float.round(theoretical_min_ops, 0)}")

    # Show proof structure for the first proof
    if proof_count >= 1 and length(hd(proofs)) > 0 do
      sample_proof = hd(proofs)
      IO.puts("    Sample proof length: #{length(sample_proof)} steps")

      # Show proof size in JSON
      json_size = JSON.encode!(sample_proof) |> String.length()
      IO.puts("    Sample proof JSON size: #{json_size} bytes")
    end
  end

  defp benchmark_builder_pattern(size) do
    # Generate test data
    IO.puts("  Generating #{format_number(size)} test documents...")
    data = generate_test_data(size)

    # Also prepare data in different formats for wrapper benchmarks
    tuple_data = Enum.map(data, fn %{"key" => k, "hash" => h} -> {k, h} end)
    struct_data = Enum.map(data, fn %{"key" => k, "hash" => h} -> %{id: k, item_hash: h} end)

    # Benchmark new/1 (baseline)
    IO.puts("\n  Benchmark: new/1 (baseline)")
    {new_time, tree_new} = :timer.tc(fn -> Merkle.new(data) end)
    new_ms = new_time / 1000
    IO.puts("    Time: #{format_time(new_ms)}")
    IO.puts("    Root: #{String.slice(Merkle.root(tree_new), 0, 16)}...")

    # Benchmark builder with add_entries
    IO.puts("\n  Benchmark: builder + add_entries + finalize")

    {builder_time, tree_builder} =
      :timer.tc(fn ->
        Merkle.builder()
        |> Merkle.add_entries(data)
        |> Merkle.finalize([])
      end)

    builder_ms = builder_time / 1000
    IO.puts("    Time: #{format_time(builder_ms)}")
    IO.puts("    Root: #{String.slice(Merkle.root(tree_builder), 0, 16)}...")
    IO.puts("    Roots match: #{Merkle.root(tree_new) == Merkle.root(tree_builder)}")

    # Benchmark from_maps
    IO.puts("\n  Benchmark: from_maps/2")
    {maps_time, tree_maps} = :timer.tc(fn -> Merkle.from_maps(data) end)
    maps_ms = maps_time / 1000
    IO.puts("    Time: #{format_time(maps_ms)}")
    IO.puts("    Roots match: #{Merkle.root(tree_new) == Merkle.root(tree_maps)}")

    # Benchmark from_tuples
    IO.puts("\n  Benchmark: from_tuples/2")
    {tuples_time, tree_tuples} = :timer.tc(fn -> Merkle.from_tuples(tuple_data) end)
    tuples_ms = tuples_time / 1000
    IO.puts("    Time: #{format_time(tuples_ms)}")
    IO.puts("    Roots match: #{Merkle.root(tree_new) == Merkle.root(tree_tuples)}")

    # Benchmark from_stream with extractors
    IO.puts("\n  Benchmark: from_stream/2 (with extractor functions)")

    {stream_time, tree_stream} =
      :timer.tc(fn ->
        Merkle.from_stream(struct_data, key_fn: & &1.id, hash_fn: & &1.item_hash)
      end)

    stream_ms = stream_time / 1000
    IO.puts("    Time: #{format_time(stream_ms)}")
    IO.puts("    Roots match: #{Merkle.root(tree_new) == Merkle.root(tree_stream)}")

    # Benchmark incremental add_entry (simulating streaming)
    IO.puts("\n  Benchmark: builder + incremental add_entry (first 1000 items)")
    sample_data = Enum.take(data, 1000)

    {incremental_time, _builder} =
      :timer.tc(fn ->
        Enum.reduce(sample_data, Merkle.builder(), fn item, acc ->
          Merkle.add_entry(acc, item)
        end)
      end)

    incremental_ms = incremental_time / 1000
    avg_per_item = incremental_ms / 1000
    IO.puts("    Time for 1000 items: #{format_time(incremental_ms)}")
    IO.puts("    Average per item: #{format_time(avg_per_item)}")
    IO.puts("    Projected for #{format_number(size)}: #{format_time(avg_per_item * size)}")

    # Summary comparison
    IO.puts("\n  Performance Summary:")
    IO.puts("    new/1:        #{format_time(new_ms)} (baseline)")
    IO.puts("    from_maps:    #{format_time(maps_ms)} (#{format_ratio(maps_ms, new_ms)})")
    IO.puts("    from_tuples:  #{format_time(tuples_ms)} (#{format_ratio(tuples_ms, new_ms)})")
    IO.puts("    from_stream:  #{format_time(stream_ms)} (#{format_ratio(stream_ms, new_ms)})")
    IO.puts("    builder:      #{format_time(builder_ms)} (#{format_ratio(builder_ms, new_ms)})")
  end

  defp format_ratio(time, baseline) do
    ratio = time / baseline

    cond do
      ratio < 1.0 -> "#{Float.round((1 - ratio) * 100, 1)}% faster"
      ratio > 1.0 -> "#{Float.round((ratio - 1) * 100, 1)}% slower"
      true -> "same"
    end
  end

  defp generate_test_data(size) do
    Enum.map(1..size, fn i ->
      # Create UUIDv7-like keys
      key = "#{String.pad_leading(Integer.to_string(i), 8, "0")}-89ab-cdef-0123-456789abcdef"
      # Generate random SHA-256 hashes
      hash = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
      %{"key" => key, "hash" => hash}
    end)
  end

  # Helper function to format large numbers with underscores
  defp format_number(num) when num >= 1_000 do
    Integer.to_string(num)
    |> String.reverse()
    |> String.to_charlist()
    |> Enum.chunk_every(3)
    |> Enum.map(&List.to_string/1)
    |> Enum.join("_")
    |> String.reverse()
  end

  defp format_number(num), do: Integer.to_string(num)

  # Helper function to format timing with appropriate units
  defp format_time(ms) when ms >= 1000 do
    seconds = ms / 1000
    "#{:erlang.float_to_binary(seconds, decimals: 2)}s"
  end

  defp format_time(ms) do
    "#{:erlang.float_to_binary(ms, decimals: 2)}ms"
  end
end

# Run the benchmark
ProofGenerationBenchmark.run()
