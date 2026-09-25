# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Input do
  @moduledoc false

  # The rules a caller's entries must meet before any of them is hashed. Each refusal
  # raises ArgumentError.

  alias Truestamp.Merkle.Hash

  @max_key_length 36

  @doc """
  Checks every entry of a list against the entry rules and returns `:ok`, or raises
  `ArgumentError` naming the first entry that breaks one.

  An entry is a map with a `"key"` of 1 to 36 characters, each an ASCII letter, a digit,
  `.`, `_` or `-`, and a `"hash"` of exactly 64 lowercase hex characters. Whether keys
  repeat is checked where the tree is built, not here.
  """
  @spec validate_entries!([term()]) :: :ok
  def validate_entries!(entries), do: Enum.each(entries, &validate_entry!/1)

  defp validate_entry!(%{"key" => key, "hash" => digest}) do
    validate_key!(key)
    validate_digest!(digest)
  end

  defp validate_entry!(invalid) do
    raise ArgumentError,
          "Invalid input entry format. Expected map with \"key\" and \"hash\" keys, got: #{inspect(invalid, limit: 10)}"
  end

  defp validate_key!(key) when is_binary(key) do
    if String.length(key) > @max_key_length do
      raise ArgumentError,
            "Invalid key length. Expected maximum #{@max_key_length} characters, got: #{String.length(key)}"
    end

    if String.trim(key) != key do
      raise ArgumentError,
            "Invalid key format. Keys must not have leading or trailing spaces, got: #{inspect(key, limit: 10)}"
    end

    if key == "" or not key_chars?(key) do
      raise ArgumentError,
            "Invalid key format. Expected alphanumeric characters with optional .-_ separators, got: #{inspect(key, limit: 10)}"
    end
  end

  defp validate_key!(invalid) do
    raise ArgumentError, "Invalid key type. Expected string, got: #{inspect(invalid, limit: 10)}"
  end

  defp validate_digest!(digest) when is_binary(digest) do
    unless Hash.digest_hex?(digest) do
      raise ArgumentError,
            "Invalid hash format. Expected #{Hash.digest_hex_chars()}-character lowercase hex SHA-256 hash (#{Hash.digest_bytes()} bytes), got: #{inspect(digest, limit: 10)}"
    end
  end

  defp validate_digest!(invalid) do
    raise ArgumentError, "Invalid hash type. Expected string, got: #{inspect(invalid, limit: 10)}"
  end

  # ASCII letters, digits, and the three separators. Byte-wise, so any multi-byte
  # character fails on its lead byte.
  defp key_chars?(<<>>), do: true

  defp key_chars?(<<c, rest::binary>>)
       when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?., ?_, ?-],
       do: key_chars?(rest)

  defp key_chars?(_), do: false
end
