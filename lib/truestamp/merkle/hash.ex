# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Hash do
  @moduledoc false

  # The hashing and hex rules every other part of the library shares: leaf and node
  # hashing with domain separation, the padding values, and the canonical hex checks.

  # Every digest going in is 32 bytes, spelled as 64 lowercase hex characters. Holding
  # inputs to exactly that is defense in depth: the 0x00 and 0x01 prefixes are what stop
  # a 64-byte interior node from being presented as a leaf.
  @digest_bytes 32
  @digest_hex_chars @digest_bytes * 2

  # The digest every padding slot stands for when a tree is filled out to the next
  # power of two: SHA256(0x00 || 0x00).
  #
  # This constant is public and identical in every tree, so it conceals nothing. A
  # padding leaf is recognizable on sight: from one proof an observer can compute
  # SHA256(0x00 || reserved), then SHA256(0x01 || x || x) repeatedly to get the hash of
  # an all-padding subtree at any level, and match those against the proof's siblings.
  # That yields the tree depth, the proved leaf's index, and a range for the real leaf
  # count, which narrows to the exact count for a leaf near the end of the tree.
  #
  # That is accepted, not overlooked. Roots must be reproducible by any third party
  # from published data alone, so the padding has to be deterministic; random padding
  # would make a root unreproducible. If an approximate leaf count is sensitive in your
  # setting, that is a property to design around. In Truestamp's own deployment it is
  # published alongside every root anyway.
  @reserved_digest :crypto.hash(:sha256, <<0x00, 0x00>>)

  # The reserved digest's hex spelling. It is refused in both directions: as a
  # caller-supplied entry digest, and as the value a path is walked from. Only padding
  # slots carry it, and the tree places them itself, never a caller.
  @reserved_digest_hex Base.encode16(@reserved_digest, case: :lower)

  # The leaf hash every padding slot holds, SHA256(0x00 || reserved), so a padded tree
  # hashes identically whichever construction path built it.
  @padding_leaf :crypto.hash(:sha256, <<0x00>> <> @reserved_digest)

  # The root of a tree with no entries.
  @empty_root :crypto.hash(:sha256, <<>>)

  def digest_bytes, do: @digest_bytes
  def digest_hex_chars, do: @digest_hex_chars
  def reserved_digest_hex, do: @reserved_digest_hex
  def padding_leaf, do: @padding_leaf
  def empty_root, do: @empty_root

  # The 0x00 prefix keeps a leaf hash out of the interior-node domain, so an interior
  # node can never be presented as a leaf. Hashes the digest's raw bytes.
  def leaf(digest_hex), do: :crypto.hash(:sha256, <<0x00>> <> from_hex!(digest_hex))

  # The 0x01 prefix keeps an interior hash out of the leaf domain, so a leaf can never
  # be presented as an interior node.
  def node(left, right), do: :crypto.hash(:sha256, <<0x01>> <> left <> right)

  def to_hex(bytes), do: Base.encode16(bytes, case: :lower)
  def from_hex!(hex), do: Base.decode16!(hex, case: :lower)

  # Exactly 64 bytes, every one of them lowercase hex.
  #
  # Matching the head width first is what makes this exact. A regex ending in `$`
  # would also accept a hash followed by a single newline, because that is what `$`
  # means in PCRE, and the trailing byte then blows up in Base.decode16!/2 well past
  # the point where the caller was promised a clean rejection. Walking the bytes is
  # also several times faster than a sigil in a function body, which the compiler
  # rebuilds on every call.
  def digest_hex?(<<hex::binary-size(@digest_hex_chars)>>), do: lowercase_hex?(hex)
  def digest_hex?(_), do: false

  def lowercase_hex?(<<>>), do: true

  def lowercase_hex?(<<c, rest::binary>>) when c in ?0..?9 or c in ?a..?f,
    do: lowercase_hex?(rest)

  def lowercase_hex?(_), do: false
end
