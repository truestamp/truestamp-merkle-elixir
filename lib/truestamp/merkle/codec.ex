# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Codec do
  @moduledoc false

  # The compact binary form of a path, and its base64url text form. Each path has
  # exactly one encoding, and the decoders accept only that one.
  #
  #     byte 0       depth, 0 to 64
  #     next bytes   ceil(depth / 8) direction bytes, least significant bit first:
  #                  bit N is 1 when step N is "r:", and every bit from depth up is 0
  #     the rest     each sibling's 32 raw bytes, bottom to top

  alias Truestamp.Merkle.{Hash, Path}

  @max_steps Path.max_steps()
  @digest_hex_chars Hash.digest_hex_chars()
  @digest_bytes Hash.digest_bytes()

  def steps_to_binary([]), do: <<0>>

  def steps_to_binary(steps) when is_list(steps) do
    depth = length(steps)

    if depth > @max_steps do
      raise ArgumentError,
            "Invalid proof length. Expected at most #{@max_steps} steps, got: #{depth}"
    end

    {bits, siblings} =
      steps
      |> Enum.with_index()
      |> Enum.reduce({0, []}, fn {step, i}, {bits, siblings} ->
        {direction, sibling} = encodable_step!(step)
        bits = if direction == ?r, do: Bitwise.bor(bits, Bitwise.bsl(1, i)), else: bits
        {bits, [sibling | siblings]}
      end)

    width = div(depth + 7, 8) * 8
    IO.iodata_to_binary([<<depth, bits::little-size(width)>> | Enum.reverse(siblings)])
  end

  def steps_from_binary(<<0>>), do: {:ok, []}

  def steps_from_binary(<<depth, rest::binary>>) when depth > 0 and depth <= @max_steps do
    width = div(depth + 7, 8) * 8
    sibling_bytes = depth * @digest_bytes

    case rest do
      <<bits::little-size(^width), siblings::binary-size(^sibling_bytes)>> ->
        if Bitwise.bsr(bits, depth) == 0 do
          {:ok, decode_steps(depth, bits, siblings)}
        else
          {:error, "Invalid proof binary: direction bits past depth #{depth} are set"}
        end

      _ ->
        {:error,
         "Invalid proof binary: expected #{div(width, 8) + sibling_bytes} bytes after depth, got #{byte_size(rest)}"}
    end
  end

  def steps_from_binary(<<depth, _rest::binary>>) when depth > @max_steps do
    {:error, "Proof depth #{depth} exceeds maximum #{@max_steps}"}
  end

  def steps_from_binary(_), do: {:error, "Invalid proof binary format"}

  def encode_proof_base64(steps),
    do: steps |> steps_to_binary() |> Base.url_encode64(padding: false)

  def decode_proof_base64(text) when is_binary(text) do
    # Base.url_decode64/2 ignores padding and the unused low bits of the last
    # character, so several strings decode to one binary. Re-encoding and comparing
    # keeps exactly one.
    with {:ok, binary} <- Base.url_decode64(text, padding: false),
         ^text <- Base.url_encode64(binary, padding: false) do
      steps_from_binary(binary)
    else
      _ -> {:error, "Invalid base64url encoding"}
    end
  end

  def decode_proof_base64(_not_a_binary), do: {:error, "Invalid base64url encoding"}

  defp decode_steps(depth, bits, siblings) do
    for i <- 0..(depth - 1) do
      direction = if Bitwise.band(Bitwise.bsr(bits, i), 1) == 1, do: "r:", else: "l:"
      direction <> Hash.to_hex(binary_part(siblings, i * @digest_bytes, @digest_bytes))
    end
  end

  defp encodable_step!(step) do
    case Path.parse_step(step) do
      {:ok, parsed} -> parsed
      :error -> raise ArgumentError, encoding_error(step)
    end
  end

  # A step with the right shape but hex that is not lowercase gets its own message.
  defp encoding_error(<<prefix::binary-size(2), _::binary-size(@digest_hex_chars)>> = step)
       when prefix in ["l:", "r:"] do
    "Invalid proof element hash. Expected #{@digest_hex_chars} lowercase hex characters, got: #{inspect(step)}"
  end

  defp encoding_error(step) do
    ~s(Invalid proof element format. Expected "l:" or "r:" followed by #{@digest_hex_chars} lowercase hex characters, got: #{inspect(step)})
  end
end
