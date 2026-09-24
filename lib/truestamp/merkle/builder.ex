defmodule Truestamp.Merkle.Builder do
  @moduledoc """
  Accumulator for incrementally building a Merkle tree from streaming input.

  The Builder pattern allows you to add entries one at a time (or in batches)
  while pre-computing leaf hashes. Once every entry is in, call `finalize/2`
  to build the final tree.

  ## When to Use Builder vs `new/1`

  **Use `new/1`** when you have all your entries available upfront and don't need
  duplicate detection. It is the fastest option, and its lead grows with the entry
  count rather than staying at a fixed percentage.

  **Use Builder** when you need:
  - Streaming/incremental input (entries arrive over time)
  - Fail-fast duplicate detection
  - Per-entry validation as entries are added

  ## Performance Characteristics

  The builder trades throughput for streaming and duplicate detection. The cost that
  matters is the `seen` map: it grows by one key per entry added, so each `Map.get`
  and `Map.put` gets a little more expensive as it fills, while `new/1` walks a
  list it was handed whole. The penalty is therefore small at ten thousand entries and
  substantial at a million.

  Read the tables below as indicative, not precise. They come from one machine, an
  Apple M-series laptop on Elixir 1.20 / OTP 29, with each build run in its own freshly
  spawned process, taking the median of seven runs at 100k entries and three at a million.
  Timings for this kind of work swing by a factor of two or more with nothing but the
  calling process's heap state: the same 100k build that takes 630 ms in a fresh process
  takes about 220 ms in one whose heap has already grown to fit it. The ratios between
  methods should travel to other hardware. The absolute numbers will not.

  100,000 unique entries:

  | Function | Time | Throughput | vs `new/1` |
  |----------|------|------------|------------|
  | `new/1` | ~630 ms | ~160k entries/sec | baseline |
  | `from_maps/2` | ~655 ms | ~155k entries/sec | ~1.05x |
  | `builder + finalize` | ~665 ms | ~150k entries/sec | ~1.05x |
  | `from_stream/2` | ~795 ms | ~125k entries/sec | ~1.25x |
  | `from_tuples/2` | ~950 ms | ~105k entries/sec | ~1.5x |

  1,000,000 unique entries:

  | Function | Time | Throughput | vs `new/1` |
  |----------|------|------------|------------|
  | `new/1` | ~6 s | ~165k entries/sec | baseline |
  | `builder + finalize` | ~15 s | ~66k entries/sec | ~2.5x |
  | `from_maps/2` | ~15 s | ~66k entries/sec | ~2.5x |

  `new/1` holds roughly the same throughput across that tenfold jump in size. The
  builder path loses more than half of its, which is the whole point of listing two
  sizes: a caller who sizes a million-entry job from the 100k row will be out by a
  factor of two and a half.

  ### Why Builder is Slower

  1. **Duplicate detection**: maintains a `seen` map with a `Map.get` and a `Map.put`
     per entry, and that map is the part whose cost grows with the entry count
  2. **Leaf reconstruction**: `finalize/2` reads every key back out of `seen` to rebuild
     the `{key, hash}` pairs, a second full pass over the map
  3. **Extra list operations**: reverses the accumulated leaves before sorting, since
     `add_entry/2` prepends

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
