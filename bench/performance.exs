# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Measures building a tree, generating proofs and verifying them. It prints an aligned
# table with a note on each column; --markdown prints the README's table instead.
#
#     mix run bench/performance.exs                      (task bench)
#     mix run bench/performance.exs --markdown           (task bench -- --markdown)
#     SIZES=1000,10000 mix run bench/performance.exs     (task bench SIZES=1000,10000)
#
# Timings are wall clock on one scheduler, and each runs in a fresh process so
# no run inherits another run's heap. A build time is the median of three
# builds; proof and verify times are means over up to 10,000 random entries.

defmodule Truestamp.Merkle.PerformanceBench do
  alias Truestamp.Merkle

  @default_sizes [1_000, 10_000, 100_000]

  # :erts_debug.size/1 is exact but slows sharply with term size (about 8 s at
  # 100,000 entries, minutes at a million), so larger trees skip it.
  @max_measured_memory 100_000
  @proof_samples 10_000

  # Column headings, and the width each takes in the aligned table.
  @columns [
    {"Entries", 9},
    {"Depth", 5},
    {"Build", 9},
    {"Build rate", 11},
    {"Tree memory", 11},
    {"Proof", 8},
    {"Verify", 8},
    {"Proof size", 10}
  ]

  def run do
    format = format!(System.argv())
    sizes = sizes()
    warm_up()
    IO.puts(environment())
    IO.puts("")

    case format do
      :markdown ->
        IO.puts("| " <> Enum.map_join(@columns, " | ", &elem(&1, 0)) <> " |")
        IO.puts("|" <> Enum.map_join(@columns, "|", fn _ -> "---:" end) <> "|")
        Enum.each(sizes, &IO.puts("| " <> Enum.join(row(&1), " | ") <> " |"))

      :text ->
        IO.puts(aligned(Enum.map(@columns, &elem(&1, 0))))
        IO.puts(aligned(Enum.map(@columns, fn {_, width} -> String.duplicate("-", width) end)))
        Enum.each(sizes, &IO.puts(aligned(row(&1))))
        IO.puts(notes())
    end
  end

  defp format!([]), do: :text
  defp format!(["--markdown"]), do: :markdown

  defp format!(args) do
    IO.puts(:stderr, "unknown arguments #{inspect(args)}; the only option is --markdown")
    System.halt(1)
  end

  # Each cell right-aligned to its column's width, two spaces apart.
  defp aligned(cells) do
    cells
    |> Enum.zip(@columns)
    |> Enum.map_join("  ", fn {cell, {_, width}} -> String.pad_leading(cell, width) end)
  end

  defp notes do
    """

      Build        median of three builds of the tree from its entries, in one process
      Build rate   entries per second at that median
      Tree memory  the finished tree's heap size, counting a shared term once
                   (1 KB = 1,024 bytes); "-" above #{format_int(@max_measured_memory)} entries
      Proof        mean time of proof/2 over up to #{format_int(@proof_samples)} random entries
      Verify       mean time of verify/4 over the same entries' proofs
      Proof size   the binary form of the longest of those proofs: 16 bytes, and 32 per node
    """
  end

  defp sizes do
    case System.get_env("SIZES") do
      nil -> @default_sizes
      csv -> csv |> String.split(",", trim: true) |> Enum.map(&String.to_integer(String.trim(&1)))
    end
  end

  # One small round first, so the first measured build does not pay for loading
  # and first-call costs.
  defp warm_up do
    entries = entries(1_000)
    tree = Merkle.new(entries)
    [%{"key" => key, "hash" => hash} | _] = entries
    true = Merkle.verify(hash, Merkle.proof(tree, key), Merkle.root(tree))
  end

  defp environment do
    otp = :erlang.system_info(:otp_release)
    arch = :erlang.system_info(:system_architecture)
    "Elixir #{System.version()}, OTP #{otp}, #{arch}"
  end

  defp row(n) do
    entries = entries(n)

    build_us = median(for _ <- 1..3, do: isolated(fn -> time_build(entries) end))

    tree = Merkle.new(entries)
    root = Merkle.root(tree)
    sample = Enum.take_random(entries, min(@proof_samples, n))
    keys = Enum.map(sample, & &1["key"])

    proof_us = isolated(fn -> per_call_us(keys, &Merkle.proof(tree, &1)) end)
    proofs = Enum.map(sample, &{Merkle.proof(tree, &1["key"]), &1["hash"]})

    verify_us =
      isolated(fn ->
        per_call_us(proofs, fn {proof, hash} -> true = Merkle.verify(hash, proof, root) end)
      end)

    {longest, _} = Enum.max_by(proofs, fn {proof, _} -> length(proof.path) end)

    [
      format_int(n),
      Integer.to_string(depth(tree, entries)),
      format_ms(build_us),
      format_int(round(n / (build_us / 1_000_000))) <> "/s",
      tree_memory(tree, n),
      format_us(proof_us),
      format_us(verify_us),
      "#{byte_size(Merkle.proof_to_binary(longest))} B"
    ]
  end

  # Keys are fixed width so byte order equals numeric order; digests are the
  # SHA-256 of the entry number.
  defp entries(n) do
    for i <- 1..n do
      %{
        "key" => "e" <> String.pad_leading(Integer.to_string(i), 9, "0"),
        "hash" => Base.encode16(:crypto.hash(:sha256, <<i::64>>), case: :lower)
      }
    end
  end

  # The first entry's path is the longest in the tree, one node per level.
  defp depth(tree, [%{"key" => first} | _]), do: length(Merkle.proof(tree, first).path)

  defp time_build(entries) do
    {us, _tree} = :timer.tc(fn -> Merkle.new(entries) end)
    us
  end

  defp median(values), do: values |> Enum.sort() |> Enum.at(div(length(values), 2))

  # The finished tree's heap size, counting a term the tree shares only once.
  defp tree_memory(tree, n) when n <= @max_measured_memory do
    bytes = :erts_debug.size(tree) * :erlang.system_info(:wordsize)

    if bytes >= 1_048_576,
      do: "#{Float.round(bytes / 1_048_576, 1)} MB",
      else: "#{Float.round(bytes / 1024, 1)} KB"
  end

  defp tree_memory(_tree, _n), do: "-"

  defp per_call_us(inputs, fun) do
    {us, _} = :timer.tc(fn -> Enum.each(inputs, fun) end)
    us / length(inputs)
  end

  # Runs fun in a fresh process and returns its result.
  defp isolated(fun) do
    task = Task.async(fun)
    Task.await(task, :infinity)
  end

  defp format_int(n) do
    n
    |> Integer.to_string()
    |> String.reverse()
    |> String.replace(~r/(\d{3})(?=\d)/, "\\1,")
    |> String.reverse()
  end

  defp format_ms(us) when us >= 1_000_000, do: "#{Float.round(us / 1_000_000, 2)} s"
  defp format_ms(us), do: "#{Float.round(us / 1_000, 1)} ms"

  # ASCII "us": Erlang writes latin1 when stdout is not a terminal.
  defp format_us(us), do: "#{Float.round(us, 1)} us"
end

Truestamp.Merkle.PerformanceBench.run()
