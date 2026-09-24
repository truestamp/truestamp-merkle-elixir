#!/usr/bin/env elixir
# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# This script should be run with: mix run bench/proof_generation_benchmark.exs

defmodule ProofGenerationBenchmark do
  @moduledoc """
  Benchmark script to test Merkle tree proof generation performance.

  This script specifically focuses on measuring:
  - Proof generation performance for large trees (O(log n) per proof)
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
        Merkle.verify(hash, proof, root)
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
