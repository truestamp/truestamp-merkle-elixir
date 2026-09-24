# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Writes vectors/merkle.json, the library's known answers. README.md defines its fields.
#
#     elixir vectors/generate.exs           rewrite the file
#     elixir vectors/generate.exs --check   exit 1 if the file differs from this output
#
# This is a second implementation of the tree contract in README.md, written from the
# contract rather than from lib/. It uses only :crypto and Base, and runs with plain
# `elixir`, so it cannot load the library: a defect in one cannot hide in both.

defmodule MerkleVectors do
  @path Path.join(__DIR__, "merkle.json")

  def main(["--check"]) do
    if File.read!(@path) == render() do
      IO.puts("vectors/merkle.json is current")
    else
      IO.puts(:stderr, "vectors/merkle.json differs from what vectors/generate.exs writes")
      System.halt(1)
    end
  end

  def main([]) do
    File.write!(@path, render())
    IO.puts("wrote vectors/merkle.json")
  end

  def main(_), do: raise(ArgumentError, "usage: elixir vectors/generate.exs [--check]")

  # ── The contract ──────────────────────────────────────────────────────

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes)
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
  defp unhex(text), do: Base.decode16!(text, case: :lower)

  defp reserved_digest, do: sha256(<<0, 0>>)
  defp padding_leaf, do: sha256(<<0>> <> reserved_digest())
  defp leaf(digest_hex), do: sha256(<<0>> <> unhex(digest_hex))
  defp node(left, right), do: sha256(<<1>> <> left <> right)

  # Sort by key bytes, hash the leaves, append padding up to a power of two, then pair
  # adjacent hashes level by level. Returns the levels, leaves first.
  defp levels([]), do: []

  defp levels(entries) do
    leaves = entries |> Enum.sort_by(& &1.key) |> Enum.map(&leaf(&1.digest))
    size = power_of_two(length(leaves))
    build([leaves ++ List.duplicate(padding_leaf(), size - length(leaves))])
  end

  defp build([[_root] | _] = levels), do: Enum.reverse(levels)

  defp build([level | _] = levels) do
    above = level |> Enum.chunk_every(2) |> Enum.map(fn [l, r] -> node(l, r) end)
    build([above | levels])
  end

  defp power_of_two(n), do: Enum.find(Stream.iterate(1, &(&1 * 2)), &(&1 >= n))

  defp root([]), do: sha256(<<>>)
  defp root(levels), do: levels |> List.last() |> hd()

  defp path(levels, index) do
    {steps, _} =
      levels
      |> Enum.drop(-1)
      |> Enum.map_reduce(index, fn level, i ->
        sibling = Enum.at(level, Bitwise.bxor(i, 1))
        direction = if Bitwise.band(i, 1) == 0, do: "r:", else: "l:"
        {direction <> hex(sibling), div(i, 2)}
      end)

    steps
  end

  defp walk(digest_hex, steps) do
    steps
    |> Enum.reduce(leaf(digest_hex), fn
      "l:" <> sibling, running -> node(unhex(sibling), running)
      "r:" <> sibling, running -> node(running, unhex(sibling))
    end)
    |> hex()
  end

  # Strict RFC 6962: split at the largest power of two below n, no padding.
  defp rfc6962([]), do: sha256(<<>>)
  defp rfc6962([one]), do: leaf(one)

  defp rfc6962(digests) do
    k = div(power_of_two(length(digests)), 2)
    node(rfc6962(Enum.take(digests, k)), rfc6962(Enum.drop(digests, k)))
  end

  # depth byte, then ceil(depth/8) direction bytes least significant bit first
  # (bit N set when step N is r), then each sibling's 32 bytes.
  defp binary(steps) do
    depth = length(steps)

    bits =
      steps
      |> Enum.with_index()
      |> Enum.reduce(0, fn
        {"r:" <> _, i}, acc -> Bitwise.bor(acc, Bitwise.bsl(1, i))
        {"l:" <> _, _}, acc -> acc
      end)

    siblings = for <<_::binary-size(2), s::binary>> <- steps, into: <<>>, do: unhex(s)
    width = div(depth + 7, 8) * 8
    <<depth, bits::little-size(width), siblings::binary>>
  end

  # ── The vectors ───────────────────────────────────────────────────────

  defp digest_of(text), do: hex(sha256(text))

  defp entries(key_prefix, key_width, digest_prefix, count) do
    for i <- 1..count//1 do
      %{
        key: key_prefix <> String.pad_leading(Integer.to_string(i), key_width, "0"),
        digest: digest_of(digest_prefix <> Integer.to_string(i))
      }
    end
  end

  defp tree(name, entries, path_keys) do
    levels = levels(entries)
    sorted = Enum.sort_by(entries, & &1.key)
    depth = max(length(levels) - 1, 0)
    padded = if entries == [], do: 0, else: power_of_two(length(entries))
    root = hex(root(levels))
    strict = hex(rfc6962(Enum.map(sorted, & &1.digest)))

    paths =
      for key <- path_keys do
        index = Enum.find_index(sorted, &(&1.key == key))
        entry = Enum.at(sorted, index)
        steps = path(levels, index)
        bytes = binary(steps)

        obj([
          {"key", key},
          {"digest", entry.digest},
          {"steps", steps},
          {"binary_hex", hex(bytes)},
          {"base64url", Base.url_encode64(bytes, padding: false)}
        ])
      end

    obj([
      {"name", name},
      {"entries", Enum.map(entries, &obj([{"key", &1.key}, {"digest", &1.digest}]))},
      {"root", root},
      {"depth", depth},
      {"padded_size", padded},
      {"rfc6962_root", strict},
      {"paths", paths}
    ])
  end

  defp trees do
    small =
      for n <- 0..7 do
        entries = entries("key", 2, "leaf", n)
        tree("leaf-#{n}", entries, Enum.map(entries, & &1.key))
      end

    mixed = mixed_entries()

    small ++
      [
        tree("mixed-keys", mixed, Enum.map(mixed, & &1.key)),
        tree("bigleaf-300", entries("lk", 4, "bigleaf", 300), ["lk0001", "lk0150", "lk0300"])
      ]
  end

  # Listed out of byte order, so a port must sort: upper and lower case,
  # punctuation, digits that sort differently as text than as numbers, the longest
  # key allowed, and two keys that share a digest.
  defp mixed_entries do
    keys = ["b", "B", "A", "_x", "-x", ".x", "a", "a0", "10", "9", String.duplicate("k", 36)]

    for {key, i} <- Enum.with_index(keys, 1) do
      digest = if key in ["B", "_x"], do: digest_of("shared"), else: digest_of("mixed#{i}")
      %{key: key, digest: digest}
    end
  end

  defp valid_steps(count) do
    for i <- 1..count//1, do: "r:" <> digest_of("sibling#{i}")
  end

  # Paths at and inside the cap, which a walk must accept, with the root each implies.
  defp walk_accepts do
    digest = digest_of("leaf1")

    [
      {"no steps under a cap of 0", [], 0},
      {"32 steps under a cap of 32", valid_steps(32), 32},
      {"64 steps under the default cap", valid_steps(64), 64},
      {"left and right steps", ["l:" <> digest_of("s1"), "r:" <> digest_of("s2")], 64}
    ]
    |> Enum.map(fn {name, steps, cap} ->
      obj([
        {"name", name},
        {"digest", digest},
        {"steps", steps},
        {"max_steps", cap},
        {"root", walk(digest, steps)}
      ])
    end)
  end

  defp walk_refusals do
    digest = digest_of("leaf1")
    reserved = hex(reserved_digest())
    [first | _] = steps = valid_steps(2)
    "r:" <> sibling = first

    [
      {"uppercase digest", String.upcase(digest), steps, 64, "invalid_leaf"},
      {"digest with a trailing newline", digest <> "\n", steps, 64, "invalid_leaf"},
      {"63-character digest", binary_part(digest, 0, 63), steps, 64, "invalid_leaf"},
      {"reserved digest", reserved, steps, 64, "reserved_leaf"},
      {"33 steps under a cap of 32", digest, valid_steps(33), 32, "too_many_steps"},
      {"65 steps under the default cap", digest, valid_steps(65), 64, "too_many_steps"},
      {"one step under a cap of 0", digest, valid_steps(1), 0, "too_many_steps"},
      {"uppercase sibling", digest, ["r:" <> String.upcase(sibling)], 64, "invalid_step"},
      {"uppercase direction", digest, ["R:" <> sibling], 64, "invalid_step"},
      {"step with a trailing newline", digest, [first <> "\n"], 64, "invalid_step"},
      {"bare hash with no direction", digest, [sibling], 64, "invalid_step"},
      {"unknown direction", digest, ["x:" <> sibling], 64, "invalid_step"},
      {"63-character sibling", digest, ["r:" <> binary_part(sibling, 0, 63)], 64, "invalid_step"},
      {"a valid step, then a bad one", digest, [first, "R:" <> sibling], 64, "invalid_step"},
      {"digest checked before the step count", "bad", valid_steps(65), 64, "invalid_leaf"},
      {"reserved digest checked before the step count", reserved, valid_steps(65), 64,
       "reserved_leaf"},
      {"step count checked before any step", digest, List.duplicate("junk", 33), 32,
       "too_many_steps"}
    ]
    |> Enum.map(fn {name, digest, steps, cap, error} ->
      obj([
        {"name", name},
        {"digest", digest},
        {"steps", steps},
        {"max_steps", cap},
        {"error", error}
      ])
    end)
  end

  # Entry sets a tree must refuse to build from.
  defp entry_refusals do
    good = digest_of("good")
    other = digest_of("other")
    e = fn key, digest -> obj([{"key", key}, {"digest", digest}]) end

    [
      {"key of 37 characters", [e.(String.duplicate("k", 37), good)]},
      {"empty key", [e.("", good)]},
      {"key with a space", [e.("a b", good)]},
      {"key with a leading space", [e.(" a", good)]},
      {"key with a character outside the set", [e.("a/b", good)]},
      {"key with a non-ASCII character", [e.("\u00e9", good)]},
      {"key with the padding prefix", [e.("__pad__1", good)]},
      {"key with the padding prefix in another case", [e.("__PAD__1", good)]},
      {"the same key twice, same digest", [e.("a", good), e.("a", good)]},
      {"the same key twice, different digests", [e.("a", good), e.("a", other)]},
      {"uppercase digest", [e.("a", String.upcase(good))]},
      {"63-character digest", [e.("a", binary_part(good, 0, 63))]},
      {"65-character digest", [e.("a", good <> "0")]},
      {"reserved digest", [e.("a", hex(reserved_digest()))]}
    ]
    |> Enum.map(fn {name, entries} -> obj([{"name", name}, {"entries", entries}]) end)
  end

  defp binary_refusals do
    one = binary(valid_steps(1))
    three = binary(valid_steps(3))
    <<1, 1, siblings::binary>> = one

    [
      {"direction bit past the depth", <<1, 3>> <> siblings},
      {"highest unused bit of a 7-step path", with_bit(binary(valid_steps(7)), 7)},
      {"one byte too many", three <> <<0>>},
      {"one byte too few", binary_part(three, 0, byte_size(three) - 1)},
      {"depth 0 with a trailing byte", <<0, 0>>},
      {"depth 65", <<65>> <> :binary.copy(<<0>>, 9 + 65 * 32)},
      {"no bytes", <<>>}
    ]
    |> Enum.map(fn {name, bytes} -> obj([{"name", name}, {"binary_hex", hex(bytes)}]) end)
  end

  defp with_bit(<<depth, bits::little-size(8), rest::binary>>, bit) do
    <<depth, Bitwise.bor(bits, Bitwise.bsl(1, bit))::little-size(8), rest::binary>>
  end

  defp base64url_refusals do
    [text | _] =
      for i <- 1..100,
          text = Base.url_encode64(binary(valid_steps(i)), padding: false),
          String.contains?(text, "-") and String.contains?(text, "_"),
          do: text

    half = div(String.length(text), 2)

    [
      {"padded", "AA=="},
      {"stray low bits in the last character", "AB"},
      {"stray low bits, highest", "AP"},
      {"one character", "A"},
      {"standard alphabet plus in place of minus", String.replace(text, "-", "+")},
      {"standard alphabet slash in place of underscore", String.replace(text, "_", "/")},
      {"embedded newline",
       String.slice(text, 0, half) <> "\n" <> String.slice(text, half..-1//1)},
      {"embedded space", String.slice(text, 0, half) <> " " <> String.slice(text, half..-1//1)}
    ]
    |> Enum.map(fn {name, text} -> obj([{"name", name}, {"base64url", text}]) end)
  end

  defp document do
    obj([
      {"description",
       "Known answers for truestamp_merkle. README.md states the tree contract and defines every field here; vectors/generate.exs writes this file from that contract, independently of the library."},
      {"constants",
       obj([
         {"empty_root", hex(sha256(<<>>))},
         {"reserved_digest", hex(reserved_digest())},
         {"padding_leaf", hex(padding_leaf())},
         {"max_steps", 64}
       ])},
      {"trees", trees()},
      {"entry_refusals", entry_refusals()},
      {"walk_accepts", walk_accepts()},
      {"walk_refusals", walk_refusals()},
      {"binary_refusals", binary_refusals()},
      {"base64url_refusals", base64url_refusals()}
    ])
  end

  # ── Byte-stable JSON ──────────────────────────────────────────────────
  #
  # Objects keep the member order given here. Arrays of strings and objects put one
  # element per line; an object of scalars with at most two members stays on one line.

  defp obj(members), do: {:obj, members}

  defp render, do: IO.iodata_to_binary([emit(document(), 0), "\n"])

  defp emit({:obj, members}, indent) do
    if length(members) <= 2 and Enum.all?(members, fn {_, v} -> scalar?(v) end) do
      ["{", Enum.map_intersperse(members, ", ", &member(&1, indent)), "}"]
    else
      pad = String.duplicate("  ", indent + 1)
      body = Enum.map_intersperse(members, ",\n", &[pad, member(&1, indent + 1)])
      ["{\n", body, "\n", String.duplicate("  ", indent), "}"]
    end
  end

  defp emit([], _indent), do: "[]"

  defp emit(list, indent) when is_list(list) do
    pad = String.duplicate("  ", indent + 1)
    body = Enum.map_intersperse(list, ",\n", &[pad, emit(&1, indent + 1)])
    ["[\n", body, "\n", String.duplicate("  ", indent), "]"]
  end

  defp emit(value, _indent) when is_binary(value) or is_integer(value), do: JSON.encode!(value)

  defp member({key, value}, indent), do: [JSON.encode!(key), ": ", emit(value, indent)]

  defp scalar?(value), do: is_binary(value) or is_integer(value)
end

MerkleVectors.main(System.argv())
