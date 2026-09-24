# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.MerkleStepCodecTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Truestamp.Merkle

  # The compact encodings the whitepaper's Appendix C.7 prints for key01's path
  # in trees of n entries (keys key01 to keyNN, digests SHA-256("leaf<i>")).
  @c7_base64url [
    {1, "AA"},
    {2, "AQHXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wnw"},
    {3,
     "AgPXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6WnwpaiKaXUNgr2l7zaXej_e_K07FvdZzDBGR8oS9jdqZT"},
    {4,
     "AgPXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wn9L6rrJFX-bbqgjmTqwuSTXNK8ySEpNot-suxdxUYLdR"},
    {5,
     "AwfXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wn9L6rrJFX-bbqgjmTqwuSTXNK8ySEpNot-suxdxUYLdRvwKRsLzm6CsEBq1W6ZUGsz229IXvpMBBgHFE5jkej8M"},
    {6,
     "AwfXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wn9L6rrJFX-bbqgjmTqwuSTXNK8ySEpNot-suxdxUYLdRyFjVrlVrv68NB3q3LhpsY8fK7cZ-gIpz6RQ_JjthXuA"},
    {7,
     "AwfXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wn9L6rrJFX-bbqgjmTqwuSTXNK8ySEpNot-suxdxUYLdRTiYYWTzoEDuqwvXG_S9skQvk2SroR8-RqaLFV0sxnVQ"}
  ]

  # C.7's nine-step path for lk0001 in the 300-entry tree (keys lk0001 to
  # lk0300, digests SHA-256("bigleaf<i>")), whose bitfield is two bytes.
  @c7_300_hex Enum.join([
                "09ff017ae5473731274dc820c833c14c017faaabb40b4a1824951c15c8dae236",
                "a45439f75f2147efe8c29a2cd46f63d9de9ebc861c724e65fe332c0f0e776d0b",
                "b948b4f05f513ff50415599ebad3d80440597519f0cfc78205b869bf275c37b1",
                "47f74b10e72eb52ba44dd896ca50ccfe904ba65383aa13edd5e5399c891ca707",
                "c1e0d0d5fa31f9fed6197bdd86c5f3e3e51feab211309e5c930e6e2a50110b08",
                "7e80cd5a8ee767780a3727011c4c6a0b62f0b9475e593eceedd83810d41dae66",
                "0c3e1d41d929a6e8903f8cc219521f90311da9d57d469b017c7b5785253d01a7",
                "13fc146d695192b6352baa8f207a3c890264e53bd1bca4d3f83129f47e57bb0d",
                "6bd1183c9dd04c6c47fbe48f2e31598a04726a18ecbf651467390dd2e0217d4f",
                "598c1b"
              ])

  defp digest(text), do: Base.encode16(:crypto.hash(:sha256, text), case: :lower)

  defp path_for(prefix, width, text, count, key) do
    entries =
      for i <- 1..count do
        key = prefix <> String.pad_leading("#{i}", width, "0")
        %{"key" => key, "hash" => digest(text <> "#{i}")}
      end

    Merkle.proof(Merkle.new(entries), key)
  end

  defp random_steps(count) do
    for _ <- 1..count//1 do
      Enum.random(["l:", "r:"]) <> Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    end
  end

  describe "known answers" do
    test "encodes each C.7 path to the bytes C.7 prints" do
      for {n, encoded} <- @c7_base64url do
        bytes = Base.url_decode64!(encoded, padding: false)
        steps = path_for("key", 2, "leaf", n, "key01")

        assert Merkle.steps_to_binary(steps) == bytes, "n=#{n}"
        assert Merkle.steps_from_binary(bytes) == {:ok, steps}, "n=#{n}"
      end
    end

    test "encodes the nine-step path with its two-byte bitfield" do
      bytes = Base.decode16!(@c7_300_hex, case: :lower)
      steps = path_for("lk", 4, "bigleaf", 300, "lk0001")

      assert byte_size(bytes) == 1 + 2 + 9 * 32
      assert Merkle.steps_to_binary(steps) == bytes
      assert Merkle.steps_from_binary(bytes) == {:ok, steps}
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
