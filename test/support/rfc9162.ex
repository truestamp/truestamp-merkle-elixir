# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.RFC9162 do
  @moduledoc false

  # RFC 9162 section 2.1 transcribed as directly as possible, for the tests to hold the
  # library to. It shares no code with lib/: the tree hash and audit path are the RFC's
  # recursive definitions, where the library builds level by level.

  import Bitwise

  def sha256(bytes), do: :crypto.hash(:sha256, bytes)
  def hex(bytes), do: Base.encode16(bytes, case: :lower)
  def unhex(text), do: Base.decode16!(text, case: :lower)

  # k: the largest power of two smaller than n (n > 1).
  def split(n), do: Enum.find(Stream.iterate(1, &(&1 * 2)), &(&1 * 2 >= n))

  # 2.1.1 Merkle Tree Hash over a list of 32-byte digests.
  def mth([]), do: sha256(<<>>)
  def mth([digest]), do: sha256(<<0x00>> <> digest)

  def mth(digests) do
    k = split(length(digests))
    sha256(<<0x01>> <> mth(Enum.take(digests, k)) <> mth(Enum.drop(digests, k)))
  end

  # 2.1.3.1 audit path, bottom to top.
  def path(0, [_digest]), do: []

  def path(m, digests) do
    k = split(length(digests))

    if m < k,
      do: path(m, Enum.take(digests, k)) ++ [mth(Enum.drop(digests, k))],
      else: path(m - k, Enum.drop(digests, k)) ++ [mth(Enum.take(digests, k))]
  end

  # The length of PATH(m, D[n]) from 2.1.3.1's recursion, without hashing anything.
  def path_length(0, 1), do: 0

  def path_length(m, n) do
    k = split(n)
    if m < k, do: 1 + path_length(m, k), else: 1 + path_length(m - k, n - k)
  end

  # 2.1.3.2: the root a proof reaches, or :fail.
  def walk(digest, index, size, path),
    do: walk_from(sha256(<<0x00>> <> digest), index, size, path)

  # The same loop started from any hash, leaf or node, as an attacker would run it.
  def walk_from(start, index, size, path) do
    if index >= size, do: :fail, else: loop(index, size - 1, start, path)
  end

  defp loop(_f, s, r, []), do: if(s == 0, do: r, else: :fail)
  defp loop(_f, 0, _r, [_ | _]), do: :fail

  defp loop(f, s, r, [p | rest]) do
    {f, s, r} =
      if (f &&& 1) == 1 or f == s do
        {f, s} = odd(f, s)
        {f, s, sha256(<<0x01>> <> p <> r)}
      else
        {f, s, sha256(<<0x01>> <> r <> p)}
      end

    loop(f >>> 1, s >>> 1, r, rest)
  end

  defp odd(f, s), do: if((f &&& 1) == 1 or f == 0, do: {f, s}, else: odd(f >>> 1, s >>> 1))

  # Entries whose keys sort in list order, with distinct digests.
  def entries(n, label \\ "e") do
    for i <- 1..n//1 do
      %{
        "key" => "k" <> String.pad_leading(Integer.to_string(i), 5, "0"),
        "hash" => hex(sha256("#{label}#{i}"))
      }
    end
  end

  def digests(entries), do: Enum.map(entries, &unhex(&1["hash"]))
end
