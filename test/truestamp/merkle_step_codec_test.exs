# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.MerkleStepCodecTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Truestamp.Merkle

  defp digest(text), do: Base.encode16(:crypto.hash(:sha256, text), case: :lower)

  defp random_steps(count) do
    for _ <- 1..count//1 do
      Enum.random(["l:", "r:"]) <> Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    end
  end

  describe "round trips" do
    test "every length from 0 to 64 steps" do
      for count <- 0..64 do
        steps = random_steps(count)
        binary = Merkle.steps_to_binary(steps)

        assert byte_size(binary) == 1 + div(count + 7, 8) + 32 * count
        assert Merkle.steps_from_binary(binary) == {:ok, steps}, "#{count} steps"
      end
    end

    property "arbitrary bytes decode only when canonical, and then re-encode exactly" do
      check all(
              depth <- integer(0..64),
              bits <- binary(length: div(depth + 7, 8)),
              siblings <- binary(length: 32 * depth)
            ) do
        input = <<depth>> <> bits <> siblings
        unused_set? = Bitwise.bsr(:binary.decode_unsigned(bits, :little), depth) != 0

        case Merkle.steps_from_binary(input) do
          {:ok, steps} ->
            refute unused_set?
            assert Merkle.steps_to_binary(steps) == input

          {:error, _reason} ->
            assert unused_set?
        end
      end
    end
  end

  describe "refusals" do
    test "every set unused direction bit, at every depth that has one" do
      for depth <- 1..64, rem(depth, 8) != 0 do
        <<^depth, rest::binary>> = Merkle.steps_to_binary(random_steps(depth))
        bitfield_bytes = div(depth + 7, 8)
        <<bits::little-size(^bitfield_bytes * 8), siblings::binary>> = rest

        for bit <- depth..(bitfield_bytes * 8 - 1) do
          tampered = Bitwise.bor(bits, Bitwise.bsl(1, bit))
          binary = <<depth, tampered::little-size(bitfield_bytes * 8), siblings::binary>>

          assert {:error, _} = Merkle.steps_from_binary(binary), "depth #{depth}, bit #{bit}"
        end
      end
    end

    test "a used direction bit may be set" do
      binary = Merkle.steps_to_binary(["r:" <> digest("s")])
      assert <<1, 1, _::binary>> = binary
      assert {:ok, ["r:" <> _]} = Merkle.steps_from_binary(binary)
    end

    test "base64url text other than the one spelling the encoder writes" do
      assert Merkle.decode_proof_base64("AA") == {:ok, []}

      encoded = Merkle.encode_proof_base64(random_steps(1))
      assert {:ok, [_]} = Merkle.decode_proof_base64(encoded)

      for bad <- ["AA==", "AB", "AP", encoded <> "=", encoded <> "\n", "", "A", nil, 7] do
        assert {:error, _} = Merkle.decode_proof_base64(bad), inspect(bad)
      end
    end

    test "the wrong length, an excess depth, or no bytes at all" do
      binary = Merkle.steps_to_binary(random_steps(3))

      for bad <- [
            binary <> <<0>>,
            binary_part(binary, 0, byte_size(binary) - 1),
            <<0, 0>>,
            <<65>> <> :binary.copy(<<0>>, 9 + 65 * 32),
            <<>>
          ] do
        assert {:error, _} = Merkle.steps_from_binary(bad), inspect(bad, limit: 8)
      end
    end
  end
end
