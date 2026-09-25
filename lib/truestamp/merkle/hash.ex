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
  The leaf hash of a digest given as 64 lowercase hex characters: `SHA-256(0x00 || d)`
  over the digest's 32 raw bytes, as raw bytes.

  The 0x00 prefix keeps a leaf hash out of the interior-node domain, so an interior node
  can never be presented as a leaf. Raises `ArgumentError` if the digest is not hex;
  callers check it with `digest_hex?/1` first.
  """
  @spec leaf(String.t()) :: <<_::256>>
  def leaf(digest_hex), do: :crypto.hash(:sha256, <<0x00>> <> from_hex!(digest_hex))

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

  @doc "Lowercase hex as raw bytes. Raises `ArgumentError` for anything else."
  @spec from_hex!(String.t()) :: binary()
  def from_hex!(hex), do: Base.decode16!(hex, case: :lower)

  @doc """
  Whether a term is exactly 64 bytes, every one of them lowercase hex: the only spelling
  of a digest or a hash the library accepts.
  """
  @spec digest_hex?(term()) :: boolean()
  # Matching the head width first is what makes this exact. A regex ending in `$`
  # would also accept a hash followed by a single newline, because that is what `$`
  # means in PCRE, and the trailing byte then blows up in Base.decode16!/2 well past
  # the point where the caller was promised a clean rejection. Walking the bytes is
  # also several times faster than a sigil in a function body, which the compiler
  # rebuilds on every call.
  def digest_hex?(<<hex::binary-size(@digest_hex_chars)>>), do: lowercase_hex?(hex)
  def digest_hex?(_), do: false

  @doc "Whether every byte of a binary is `0-9` or `a-f`. True for the empty binary."
  @spec lowercase_hex?(term()) :: boolean()
  def lowercase_hex?(<<>>), do: true

  def lowercase_hex?(<<c, rest::binary>>) when c in ?0..?9 or c in ?a..?f,
    do: lowercase_hex?(rest)

  def lowercase_hex?(_), do: false
end
