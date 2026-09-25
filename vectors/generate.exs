# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Writes vectors/merkle.json, the library's known answers. README.md defines its fields.
#
#     elixir vectors/generate.exs           rewrite the file
#     elixir vectors/generate.exs --check   exit 1 if the file differs from this output
#
# This is a second implementation of the tree contract, transcribed from RFC 9162 section
# 2.1 rather than from lib/: the tree hash and audit path use the RFC's recursive
# definitions, where the library builds level by level. It uses only :crypto and Base
# and runs with plain `elixir`, so it cannot load the library: a defect in one cannot
# hide in both.

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

  # ── RFC 9162 section 2.1 ──────────────────────────────────────────────

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes)
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
  defp unhex(text), do: Base.decode16!(text, case: :lower)

  # k: the largest power of two smaller than n (n > 1).
  defp split(n), do: Enum.find(Stream.iterate(1, &(&1 * 2)), &(&1 * 2 >= n))

  # 2.1.1: MTH({}) = HASH(), MTH({d0}) = HASH(0x00 || d0),
  # MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])). Leaves are 32-byte digests.
  defp mth([]), do: sha256(<<>>)
  defp mth([digest]), do: sha256(<<0x00>> <> digest)

  defp mth(digests) do
    k = split(length(digests))
    sha256(<<0x01>> <> mth(Enum.take(digests, k)) <> mth(Enum.drop(digests, k)))
  end

  # 2.1.3.1: PATH(0, {d0}) = {}; for m < k, PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]);
  # for m >= k, PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k]).
  defp audit_path(0, [_digest]), do: []

  defp audit_path(m, digests) do
    k = split(length(digests))

    if m < k,
      do: audit_path(m, Enum.take(digests, k)) ++ [mth(Enum.drop(digests, k))],
      else: audit_path(m - k, Enum.drop(digests, k)) ++ [mth(Enum.take(digests, k))]
  end

  # 2.1.3.2, returning the root it reaches, or :fail where the RFC says to fail.
  defp walk(leaf_digest, index, size, path) do
    if index >= size,
      do: :fail,
      else: walk_loop(index, size - 1, sha256(<<0x00>> <> leaf_digest), path)
  end

  defp walk_loop(_fnum, snum, r, []), do: if(snum == 0, do: r, else: :fail)
  defp walk_loop(_fnum, 0, _r, [_ | _]), do: :fail

  defp walk_loop(fnum, snum, r, [p | rest]) do
    {fnum, snum, r} =
      if Bitwise.band(fnum, 1) == 1 or fnum == snum do
        {fnum, snum} = shift_to_odd(fnum, snum)
        {fnum, snum, sha256(<<0x01>> <> p <> r)}
      else
        {fnum, snum, sha256(<<0x01>> <> r <> p)}
      end

    walk_loop(Bitwise.bsr(fnum, 1), Bitwise.bsr(snum, 1), r, rest)
  end

  defp shift_to_odd(fnum, snum) do
    if Bitwise.band(fnum, 1) == 1 or fnum == 0,
      do: {fnum, snum},
      else: shift_to_odd(Bitwise.bsr(fnum, 1), Bitwise.bsr(snum, 1))
  end

  defp depth(0), do: 0
  defp depth(1), do: 0
  defp depth(n), do: Enum.find(0..64, &(Bitwise.bsl(1, &1) >= n))

  defp binary(index, size, path) do
    IO.iodata_to_binary([<<index::unsigned-big-64, size::unsigned-big-64>> | path])
  end

  # ── The vectors ───────────────────────────────────────────────────────

  defp digest_of(text), do: sha256(text)

  defp entries(key_prefix, key_width, digest_prefix, count) do
    for i <- 1..count//1 do
      %{
        key: key_prefix <> String.pad_leading(Integer.to_string(i), key_width, "0"),
        digest: hex(digest_of(digest_prefix <> Integer.to_string(i)))
      }
    end
  end

  defp tree(name, entries, path_keys) do
    sorted = Enum.sort_by(entries, & &1.key)
    digests = Enum.map(sorted, &unhex(&1.digest))
    size = length(entries)

    paths =
      for key <- path_keys do
        index = Enum.find_index(sorted, &(&1.key == key))
        path = audit_path(index, digests)

        obj([
          {"key", key},
          {"digest", Enum.at(sorted, index).digest},
          {"leaf_index", index},
          {"tree_size", size},
          {"path", Enum.map(path, &hex/1)},
          {"binary_hex", hex(binary(index, size, path))}
        ])
      end

    obj([
      {"name", name},
      {"entries", Enum.map(entries, &obj([{"key", &1.key}, {"digest", &1.digest}]))},
      {"root", hex(mth(digests))},
      {"depth", depth(size)},
      {"tree_size", size},
      {"paths", paths}
    ])
  end

  defp trees do
    small =
      for n <- 0..8 do
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

  # Listed out of byte order, so a port must sort: upper and lower case, punctuation,
  # digits that sort differently as text than as numbers, a key that is a prefix of
  # others ("a" before "a-", "a.", "a0" and "a_"), the longest key allowed, and two keys
  # that share a digest.
  defp mixed_entries do
    keys =
      ["b", "a_", "B", "A", "_x", "a.", "-x", ".x", "a-", "a", "a0", "10", "9"] ++
        [String.duplicate("k", 36)]

    for {key, i} <- Enum.with_index(keys, 1) do
      digest = if key in ["B", "_x"], do: digest_of("shared"), else: digest_of("mixed#{i}")
      %{key: key, digest: hex(digest)}
    end
  end

  defp nodes(count, label), do: for(i <- 1..count//1, do: digest_of("#{label}#{i}"))

  defp proof_obj(index, size, path) do
    obj([
      {"leaf_index", index},
      {"tree_size", size},
      {"path",
       Enum.map(path, fn p -> if is_binary(p) and byte_size(p) == 32, do: hex(p), else: p end)}
    ])
  end

  # Proofs a walk must accept, with the root each reaches.
  defp walk_accepts do
    d = digest_of("leaf1")
    three = Enum.map(1..3, &digest_of("leaf#{&1}"))
    size3_path = audit_path(0, three)

    [
      {"one entry, empty path", 0, 1, [], 64},
      {"last of three: one step, the carried leaf", 2, 3, nodes(1, "s"), 64},
      {"first of seven", 0, 7, nodes(3, "s"), 64},
      {"last of seven", 6, 7, nodes(2, "s"), 64},
      {"32 steps under a cap of 32", 0, Bitwise.bsl(1, 32), nodes(32, "s"), 32},
      {"64 steps under the default cap", 0, 0xFFFF_FFFF_FFFF_FFFF, nodes(64, "s"), 64},
      {"a size-3 path claimed at size 4 reaches the size-3 root", 0, 4, size3_path, 64},
      # Indexes with high bits set, so a verifier's index arithmetic must hold all 64
      # bits: each of the first two walks shifts the index right by 40 and 63 places at
      # once, and the last two take 63 and 64 steps at the largest tree size.
      {"the last of 2^40 + 1 entries", pow2(40), pow2(40) + 1,
       reaching(d, pow2(40), pow2(40) + 1), 64},
      {"the last of 2^63 + 1 entries", pow2(63), pow2(63) + 1,
       reaching(d, pow2(63), pow2(63) + 1), 64},
      {"index 2^64 - 2 of 2^64 - 1 entries", pow2(64) - 2, pow2(64) - 1,
       reaching(d, pow2(64) - 2, pow2(64) - 1), 64},
      {"index 2^63 - 1 of 2^64 - 1 entries", pow2(63) - 1, pow2(64) - 1,
       reaching(d, pow2(63) - 1, pow2(64) - 1), 64},
      # The cap limits a path's length, never the tree size a proof states.
      {"a one-node path at size 2^32 + 1 under a cap of 1", pow2(32), pow2(32) + 1,
       reaching(d, pow2(32), pow2(32) + 1), 1}
    ]
    |> Enum.map(fn {name, index, size, path, cap} ->
      digest = if String.starts_with?(name, "a size-3"), do: hd(three), else: d
      accept(name, digest, proof_obj(index, size, path), index, size, path, cap)
    end)
    |> Enum.concat([
      # A proof object's other members are ignored.
      accept(
        "a proof with another member",
        d,
        obj([
          {"leaf_index", 2},
          {"tree_size", 3},
          {"path", Enum.map(nodes(1, "s"), &hex/1)},
          {"note", "ignored"}
        ]),
        2,
        3,
        nodes(1, "s"),
        64
      )
    ])
  end

  defp accept(name, digest, proof, index, size, path, cap) do
    obj([
      {"name", name},
      {"digest", hex(digest)},
      {"proof", proof},
      {"max_steps", cap},
      {"root", hex(walk(digest, index, size, path))},
      {"binary_hex", hex(binary(index, size, path))}
    ])
  end

  defp pow2(k), do: Bitwise.bsl(1, k)

  # Arbitrary nodes, as many as the RFC's loop takes for this index and size.
  defp reaching(digest, index, size) do
    Enum.find_value(0..64, fn count ->
      path = nodes(count, "h")
      if walk(digest, index, size, path) != :fail, do: path
    end)
  end

  # Inputs a walk must refuse, with the error it names. "proof" is written as JSON, so a
  # case whose proof is not an object uses the value itself.
  defp walk_refusals do
    d = hex(digest_of("leaf1"))
    [s1, s2, s3] = Enum.map(nodes(3, "s"), &hex/1)
    good = proof_obj(0, 3, [s1, s2] |> Enum.map(&unhex/1))

    ([
       {"uppercase digest", String.upcase(d), good, 64, "invalid_leaf"},
       {"digest with a trailing newline", d <> "\n", good, 64, "invalid_leaf"},
       {"63-character digest", binary_part(d, 0, 63), good, 64, "invalid_leaf"},
       {"empty digest", "", good, 64, "invalid_leaf"},
       {"62-character digest", binary_part(d, 0, 62), good, 64, "invalid_leaf"},
       {"66-character digest", d <> "ab", good, 64, "invalid_leaf"},
       {"128-character digest", d <> d, good, 64, "invalid_leaf"},
       {"empty node", d, raw(0, 3, [s1, ""]), 64, "invalid_node"},
       {"62-character node", d, raw(0, 3, [s1, binary_part(s2, 0, 62)]), 64, "invalid_node"},
       {"66-character node", d, raw(0, 3, [s1, s2 <> "ab"]), 64, "invalid_node"},
       {"128-character node", d, raw(0, 3, [s1, s2 <> s2]), 64, "invalid_node"},
       {"leaf_index below 0", d, raw(-1, 3, [s1, s2]), 64, "invalid_proof"},
       {"tree_size 0", d, raw(0, 0, []), 64, "invalid_proof"},
       {"tree_size past 2^64 - 1", d, raw(0, 18_446_744_073_709_551_616, []), 64,
        "invalid_proof"},
       {"leaf_index as a string", d, raw("0", 3, [s1, s2]), 64, "invalid_proof"},
       {"no path member", d, obj([{"leaf_index", 0}, {"tree_size", 3}]), 64, "invalid_proof"},
       {"leaf_index equal to tree_size", d, raw(3, 3, [s1, s2]), 64, "index_out_of_range"},
       {"leaf_index past tree_size", d, raw(9, 3, [s1, s2]), 64, "index_out_of_range"},
       {"a 33-step path under a cap of 32", d, raw(0, Bitwise.bsl(1, 33), []), 32,
        "too_many_steps"},
       {"a whole 3-step path under a cap of 2", d, raw(0, 7, [s1, s2, s3]), 2, "too_many_steps"},
       {"one node short", d, raw(0, 3, [s1]), 64, "wrong_path_length"},
       {"one node extra", d, raw(0, 3, [s1, s2, s1]), 64, "wrong_path_length"},
       {"no nodes for two entries", d, raw(0, 2, []), 64, "wrong_path_length"},
       {"a node for one entry", d, raw(0, 1, [s1]), 64, "wrong_path_length"},
       {"path that is not a list", d, raw(0, 3, "not a list"), 64, "invalid_proof"},
       {"uppercase node", d, raw(0, 3, [String.upcase(s1), s2]), 64, "invalid_node"},
       {"node with a trailing newline", d, raw(0, 3, [s1 <> "\n", s2]), 64, "invalid_node"},
       {"63-character node", d, raw(0, 3, [binary_part(s1, 0, 63), s2]), 64, "invalid_node"},
       {"node with a two-character prefix", d, raw(0, 3, ["l:" <> s1, s2]), 64, "invalid_node"},
       {"the digest is checked before the proof", "bad", raw(9, 3, []), 64, "invalid_leaf"},
       {"the digest is checked before the proof's ranges", "bad", raw(0, 0, []), 64,
        "invalid_leaf"},
       {"the path's type is checked before the index", d, raw(9, 3, "not a list"), 64,
        "invalid_proof"},
       {"the index is checked before the step cap", d,
        raw(Bitwise.bsl(1, 40) - 1, Bitwise.bsl(1, 40) - 1, []), 32, "index_out_of_range"},
       {"the index is checked before the path length", d, raw(3, 3, []), 64,
        "index_out_of_range"},
       {"the path length is checked before any node", d, raw(0, 3, ["bad"]), 64,
        "wrong_path_length"},
       {"one node short at a high index", d, raw(pow2(40), pow2(40) + 1, []), 64,
        "wrong_path_length"},
       {"leaf_index and tree_size past 2^64 - 1", d, raw(pow2(64) + 1, pow2(64), []), 64,
        "invalid_proof"},
       {"leaf_index equal to a tree_size past 2^64 - 1", d, raw(pow2(64), pow2(64), []), 64,
        "invalid_proof"},
       {"a node that is null", d, raw(0, 3, [s1, nil]), 64, "invalid_node"},
       {"a node that is a number", d, raw(0, 3, [s1, 7]), 64, "invalid_node"}
     ] ++
       for(
         {label, tail} <- non_hex_tails(),
         refusal <- [
           {"64-character digest ending in #{label}", non_hex(d, tail), good, 64, "invalid_leaf"},
           {"64-character node ending in #{label}", d, raw(0, 3, [s1, non_hex(s2, tail)]), 64,
            "invalid_node"}
         ],
         do: refusal
       ))
    |> Enum.map(fn {name, digest, proof, cap, error} ->
      obj([
        {"name", name},
        {"digest", digest},
        {"proof", proof},
        {"max_steps", cap},
        {"error", error}
      ])
    end)
  end

  defp raw(index, size, path),
    do: obj([{"leaf_index", index}, {"tree_size", size}, {"path", path}])

  # Binary forms the decoder must refuse, with the error it names.
  defp binary_refusals do
    [p1, p2] = nodes(2, "s")
    three = binary(0, 3, [p1, p2])

    [
      {"no bytes", <<>>, "wrong_length"},
      {"15 bytes", :binary.copy(<<0>>, 15), "wrong_length"},
      {"tree_size 0", binary(0, 0, []), "index_out_of_range"},
      {"leaf_index equal to tree_size", binary(3, 3, [p1, p2]), "index_out_of_range"},
      {"one node short", binary(0, 3, [p1]), "wrong_length"},
      {"one node extra", binary(0, 3, [p1, p2, p1]), "wrong_length"},
      {"one byte extra", three <> <<0>>, "wrong_length"},
      {"one byte short", binary_part(three, 0, byte_size(three) - 1), "wrong_length"},
      {"the index is checked before the path length", binary(3, 3, []), "index_out_of_range"}
    ]
    |> Enum.map(fn {name, bytes, error} ->
      obj([{"name", name}, {"binary_hex", hex(bytes)}, {"error", error}])
    end)
  end

  # Entry sets a tree must refuse to build from.
  defp entry_refusals do
    good = hex(digest_of("good"))
    other = hex(digest_of("other"))
    e = fn key, digest -> obj([{"key", key}, {"digest", digest}]) end

    ([
       {"key of 37 characters", [e.(String.duplicate("k", 37), good)]},
       {"empty key", [e.("", good)]},
       {"key with a space", [e.("a b", good)]},
       {"key with a leading space", [e.(" a", good)]},
       {"key with a character outside the set", [e.("a/b", good)]},
       {"key with a non-ASCII character", [e.("é", good)]},
       {"the same key twice, same digest", [e.("a", good), e.("a", good)]},
       {"the same key twice, different digests", [e.("a", good), e.("a", other)]},
       {"uppercase digest", [e.("a", String.upcase(good))]},
       {"63-character digest", [e.("a", binary_part(good, 0, 63))]},
       {"65-character digest", [e.("a", good <> "0")]},
       {"empty digest", [e.("a", "")]},
       {"62-character digest", [e.("a", binary_part(good, 0, 62))]},
       {"66-character digest", [e.("a", good <> "ab")]},
       {"128-character digest", [e.("a", good <> good)]}
     ] ++
       for(
         {label, tail} <- non_hex_tails(),
         do: {"64-character digest ending in #{label}", [e.("a", non_hex(good, tail))]}
       ) ++
       for(
         char <- [":", "@", "[", "\\", "]", "^", "`", "{", ",", "+"],
         do: {"key with #{char}, next to the allowed characters", [e.("a" <> char <> "b", good)]}
       ))
    |> Enum.map(fn {name, entries} -> obj([{"name", name}, {"entries", entries}]) end)
  end

  # Values of exactly 64 characters whose last one or two are not lowercase hex: a
  # decoder that skips whitespace or stops at the first bad pair would accept them, and
  # the four single characters sit just outside the ranges 0-9 and a-f.
  defp non_hex_tails do
    [{"g", "g"}, {"/", "/"}, {":", ":"}, {"a backtick", "`"}, {"two spaces", "  "}] ++
      [{"zz", "zz"}, {"a NUL", <<0>>}]
  end

  defp non_hex(hex, tail), do: binary_part(hex, 0, 64 - byte_size(tail)) <> tail

  defp document do
    obj([
      {"description",
       "Known answers for truestamp_merkle: RFC 9162 section 2.1 Merkle Tree Hash and inclusion proofs over entries sorted by key. README.md defines every field; vectors/generate.exs writes this file from the RFC, independently of the library."},
      {"constants",
       obj([
         {"empty_root", hex(sha256(<<>>))},
         {"max_steps", 64},
         {"max_tree_size", 0xFFFF_FFFF_FFFF_FFFF}
       ])},
      {"trees", trees()},
      {"entry_refusals", entry_refusals()},
      {"walk_accepts", walk_accepts()},
      {"walk_refusals", walk_refusals()},
      {"binary_refusals", binary_refusals()}
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
  defp emit(nil, _indent), do: "null"

  defp member({key, value}, indent), do: [JSON.encode!(key), ": ", emit(value, indent)]

  defp scalar?(value), do: is_binary(value) or is_integer(value) or is_nil(value)
end

MerkleVectors.main(System.argv())
