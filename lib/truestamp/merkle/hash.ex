# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Hash do
  @moduledoc false

  # The hashing and hex rules every other part of the library shares: RFC 9162 section
  # 2.1's leaf and node hashing with domain separation, and the canonical hex checks.

  # Every digest going in is 32 bytes, spelled as 64 lowercase hex characters. Holding
  # inputs to exactly that is defense in depth: the 0x00 and 0x01 prefixes are what stop
  # a 64-byte interior node from being presented as a leaf.
  @digest_bytes 32
  @digest_hex_chars @digest_bytes * 2

  # The root of a tree with no entries: SHA-256 of zero bytes (RFC 9162, MTH({}) = HASH()).
  @empty_root :crypto.hash(:sha256, <<>>)

  @doc "The size of a digest, and of every hash the tree holds, in bytes: 32."
  @spec digest_bytes() :: pos_integer()
  def digest_bytes, do: @digest_bytes

  @doc "The length of a digest spelled in hex: 64 characters."
  @spec digest_hex_chars() :: pos_integer()
  def digest_hex_chars, do: @digest_hex_chars

  @doc """
  The root of a tree with no entries, as raw bytes: SHA-256 of zero bytes, RFC 9162's
  `MTH({})`.
  """
  @spec empty_root() :: <<_::256>>
  def empty_root, do: @empty_root

  @doc """
  The leaf hash of a digest's raw bytes: `SHA-256(0x00 || digest)`, as raw bytes.

  The 0x00 prefix keeps a leaf hash out of the interior-node domain, so an interior node
  can never be presented as a leaf. Callers get the bytes from `parse_digest/1`.
  """
  @spec leaf(binary()) :: <<_::256>>
  def leaf(digest), do: :crypto.hash(:sha256, <<0x00>> <> digest)

  @doc """
  The hash of an interior node over its two children's raw hashes:
  `SHA-256(0x01 || left || right)`, as raw bytes.

  The 0x01 prefix keeps an interior hash out of the leaf domain, so a leaf can never be
  presented as an interior node.
  """
  @spec node(binary(), binary()) :: <<_::256>>
  def node(left, right), do: :crypto.hash(:sha256, <<0x01>> <> left <> right)

  @doc "Raw bytes spelled as lowercase hex."
  @spec to_hex(binary()) :: String.t()
  def to_hex(bytes), do: Base.encode16(bytes, case: :lower)

  @doc """
  A digest or hash spelled as exactly 64 lowercase hex characters, as its 32 raw bytes, or
  `:error` for anything else: the only spelling the library accepts, checked and decoded
  in one pass.
  """
  @spec parse_digest(term()) :: {:ok, <<_::256>>} | :error
  # Matching the 64-byte head first is what makes this exact: a trailing newline or any
  # other extra byte fails the match. (A regex ending in `$` would accept a hash followed
  # by one newline, because that is what `$` means in PCRE.) Base.decode16/2 with
  # case: :lower then refuses uppercase and every byte outside 0-9 and a-f. Refusing a
  # bad value costs one exception that Base raises and rescues inside decode16/2: bounded,
  # and cheaper than a walk of a valid proof.
  def parse_digest(<<hex::binary-size(@digest_hex_chars)>>), do: Base.decode16(hex, case: :lower)
  def parse_digest(_not_64_bytes), do: :error
end
