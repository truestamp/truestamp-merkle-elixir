# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Builder do
  @moduledoc """
  Accumulator for incrementally building a Merkle tree from streaming input.

  The Builder pattern allows you to add entries one at a time (or in batches)
  while pre-computing leaf hashes. Once every entry is in, call `finalize/2`
  to build the final tree.

  ## When to Use Builder vs `new/2`

  **Use `new/2`** when you have all your entries available upfront and don't need
  duplicate detection. It is the fastest option.

  **Use Builder** when you need:
  - Streaming/incremental input (entries arrive over time)
  - Fail-fast duplicate detection
  - Per-entry validation as entries are added

  ## Performance

  The builder trades throughput for streaming and duplicate detection. The cost that
  matters is the `seen` map: it grows by one key per entry added, so each `Map.get` and
  `Map.put` gets a little more expensive as it fills, while `new/2` sorts a list it was
  handed whole. The gap is small for small trees and grows with the entry count.
  `bench/proof_generation_benchmark.exs` compares the construction paths on your
  hardware; timings for this kind of work also swing with the calling process's heap
  state, so compare paths within one run rather than across runs.

  ## Type Safety

  `Builder.t()` and `Merkle.t()` are separate structs. Calling builder functions
  on a finalized tree (or vice versa) results in a FunctionClauseError.

  ## Example

      builder = Merkle.builder()
                |> Merkle.add_entry(%{"key" => "entry1", "hash" => "abc..."})
                |> Merkle.add_entry(%{"key" => "entry2", "hash" => "def..."})

      tree = Merkle.finalize(builder)  # Returns %Merkle{}, not %Builder{}

      # All existing APIs work on the finalized tree
      root = Merkle.root(tree)
      proof = Merkle.proof(tree, "entry1")
  """

  defstruct leaves: [], seen: %{}, count: 0

  @type t :: %__MODULE__{
          leaves: [{binary(), binary()}],
          seen: %{binary() => binary()},
          count: non_neg_integer()
        }
end
