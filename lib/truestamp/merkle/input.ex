# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Input do
  @moduledoc false

  # The rules a caller's entries must meet before any of them is hashed. Every
  # construction path runs them, and each refusal raises ArgumentError.

  alias Truestamp.Merkle.Hash

  @max_key_length 36

  def validate_entries!(entries), do: Enum.each(entries, &validate_entry!/1)

  defp validate_entry!(%{"key" => key, "hash" => digest}) do
    validate_key!(key)
    validate_digest!(digest)
  end

  defp validate_entry!(invalid) do
    raise ArgumentError,
          "Invalid input entry format. Expected map with \"key\" and \"hash\" keys, got: #{inspect(invalid, limit: 10)}"
  end

  def validate_key!(key) when is_binary(key) do
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

    # The README's tree contract reserves this prefix, in any case, though padding
    # slots carry no key.
    if String.starts_with?(String.downcase(key), "__pad__") do
      raise ArgumentError,
            "Invalid key format. Keys must not use reserved padding prefix, got: #{inspect(key, limit: 10)}"
    end
  end

  def validate_key!(invalid) do
    raise ArgumentError, "Invalid key type. Expected string, got: #{inspect(invalid, limit: 10)}"
  end

  def validate_digest!(digest) when is_binary(digest) do
    unless Hash.digest_hex?(digest) do
      raise ArgumentError,
            "Invalid hash format. Expected #{Hash.digest_hex_chars()}-character lowercase hex SHA-256 hash (#{Hash.digest_bytes()} bytes), got: #{inspect(digest, limit: 10)}"
    end

    # A padded slot stands for the reserved digest, but construction splices the
    # slot's leaf hash straight in and never routes the digest through here, so no
    # honest tree can carry it as a real entry. That invariant is what lets a walk
    # refuse it outright.
    if digest == Hash.reserved_digest_hex() do
      raise ArgumentError,
            "Invalid hash. #{Hash.reserved_digest_hex()} is the reserved Merkle padding constant and must not be used as an entry hash."
    end
  end

  def validate_digest!(invalid) do
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
