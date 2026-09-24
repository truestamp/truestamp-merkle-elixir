# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Codec do
  @moduledoc false

  # The binary form of an inclusion proof, for storage:
  #
  #     leaf_index   unsigned 64-bit, big-endian
  #     tree_size    unsigned 64-bit, big-endian
  #     path         each sibling's 32 raw bytes, bottom to top: exactly as many as the
  #                  index and size imply
  #
  # Fixed-width fields and a path length the index and size fix give each proof exactly
  # one encoding.

  alias Truestamp.Merkle.{Hash, Paths}

  @digest_bytes Hash.digest_bytes()

  def proof_to_binary(proof) do
    with {:ok, _length} <- Paths.check_proof(proof, Paths.max_steps()),
         {:ok, siblings} <- siblings(proof.path, []) do
      IO.iodata_to_binary([
        <<proof.leaf_index::unsigned-big-64, proof.tree_size::unsigned-big-64>> | siblings
      ])
    else
      {:error, reason} ->
        raise ArgumentError, "Invalid proof (#{reason}): #{inspect(proof, limit: 10)}"
    end
  end

  # Checks run in this order: a binary at all, room for the two fields, the index
  # below the size, then the path's length.
  def proof_from_binary(<<index::unsigned-big-64, size::unsigned-big-64, path::binary>>) do
    cond do
      index >= size ->
        {:error, :index_out_of_range}

      byte_size(path) != Paths.path_length(index, size) * @digest_bytes ->
        {:error, :wrong_length}

      true ->
        {:ok,
         %{
           leaf_index: index,
           tree_size: size,
           path: for(<<node::binary-size(@digest_bytes) <- path>>, do: Hash.to_hex(node))
         }}
    end
  end

  def proof_from_binary(binary) when is_binary(binary), do: {:error, :wrong_length}
  def proof_from_binary(_not_a_binary), do: {:error, :invalid_binary}

  defp siblings([], parsed), do: {:ok, Enum.reverse(parsed)}

  defp siblings([node | rest], parsed) do
    case Paths.parse_node(node) do
      {:ok, sibling} -> siblings(rest, [sibling | parsed])
      :error -> {:error, :invalid_node}
    end
  end
end
