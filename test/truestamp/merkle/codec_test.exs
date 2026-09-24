# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.CodecTest do
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

  describe "compact proof encoding bidirectional roundtrip" do
    test "empty proof roundtrips through binary" do
      assert Merkle.steps_to_binary([]) == <<0>>
      assert {:ok, []} = Merkle.steps_from_binary(<<0>>)
    end

    test "empty proof roundtrips through base64" do
      encoded = Merkle.encode_proof_base64([])
      assert encoded == "AA"
      assert {:ok, []} = Merkle.decode_proof_base64(encoded)
    end

    test "single left sibling roundtrips" do
      proof = ["l:" <> String.duplicate("ab", 32)]
      binary = Merkle.steps_to_binary(proof)
      assert {:ok, ^proof} = Merkle.steps_from_binary(binary)
    end

    test "single right sibling roundtrips" do
      proof = ["r:" <> String.duplicate("cd", 32)]
      binary = Merkle.steps_to_binary(proof)
      assert {:ok, ^proof} = Merkle.steps_from_binary(binary)
    end

    test "multi-level mixed directions roundtrip through binary" do
      proof = [
        "l:" <> String.duplicate("11", 32),
        "r:" <> String.duplicate("22", 32),
        "l:" <> String.duplicate("33", 32),
        "r:" <> String.duplicate("44", 32),
        "l:" <> String.duplicate("55", 32)
      ]

      binary = Merkle.steps_to_binary(proof)
      assert {:ok, decoded} = Merkle.steps_from_binary(binary)
      assert decoded == proof
    end

    test "multi-level mixed directions roundtrip through base64" do
      proof = [
        "r:" <> String.duplicate("aa", 32),
        "l:" <> String.duplicate("bb", 32),
        "r:" <> String.duplicate("cc", 32),
        "l:" <> String.duplicate("dd", 32)
      ]

      encoded = Merkle.encode_proof_base64(proof)
      assert {:ok, decoded} = Merkle.decode_proof_base64(encoded)
      assert decoded == proof
    end

    test "roundtrip preserves direction bits for all-left proof" do
      proof = for _ <- 1..10, do: "l:" <> String.duplicate("ff", 32)
      {:ok, decoded} = proof |> Merkle.steps_to_binary() |> Merkle.steps_from_binary()
      assert decoded == proof
    end

    test "roundtrip preserves direction bits for all-right proof" do
      proof = for _ <- 1..10, do: "r:" <> String.duplicate("ee", 32)
      {:ok, decoded} = proof |> Merkle.steps_to_binary() |> Merkle.steps_from_binary()
      assert decoded == proof
    end

    test "roundtrip with real tree-generated proofs" do
      hashes =
        for i <- 1..16 do
          hash = :crypto.hash(:sha256, "entry-#{i}") |> Base.encode16(case: :lower)
          %{"key" => "entry-#{i}", "hash" => hash}
        end

      tree = Merkle.new(hashes)
      root = Merkle.root(tree)

      for %{"key" => key, "hash" => hash} <- hashes do
        proof = Merkle.proof(tree, key)
        assert is_list(proof)

        # Binary roundtrip
        binary = Merkle.steps_to_binary(proof)
        assert {:ok, decoded} = Merkle.steps_from_binary(binary)
        assert decoded == proof

        # Base64 roundtrip
        b64 = Merkle.encode_proof_base64(proof)
        assert {:ok, decoded_b64} = Merkle.decode_proof_base64(b64)
        assert decoded_b64 == proof

        # Decoded proof still verifies
        assert Merkle.verify(hash, decoded, root)
      end
    end

    test "decode rejects truncated binary" do
      proof = ["l:" <> String.duplicate("ab", 32)]
      binary = Merkle.steps_to_binary(proof)
      truncated = binary_part(binary, 0, byte_size(binary) - 1)
      assert {:error, _} = Merkle.steps_from_binary(truncated)
    end

    test "decode rejects invalid base64" do
      assert {:error, _} = Merkle.decode_proof_base64("not!valid!base64!!!")
    end

    test "decode rejects depth exceeding max" do
      # depth byte = 65 which exceeds @max_proof_depth (64)
      assert {:error, _} = Merkle.steps_from_binary(<<65, 0>>)
    end

    test "encode accepts a proof at the maximum depth" do
      # 64 steps is @max_proof_depth, the deepest proof the format can carry
      proof = for _ <- 1..64, do: "l:" <> String.duplicate("ab", 32)

      assert {:ok, decoded} = Merkle.steps_from_binary(Merkle.steps_to_binary(proof))
      assert decoded == proof
    end

    test "encode rejects a proof deeper than the maximum" do
      proof = for _ <- 1..65, do: "l:" <> String.duplicate("ab", 32)

      assert_raise ArgumentError, ~r/at most 64 steps/, fn ->
        Merkle.steps_to_binary(proof)
      end
    end

    test "encode rejects a proof long enough to wrap the depth byte" do
      proof = for _ <- 1..256, do: "l:" <> String.duplicate("ab", 32)

      assert_raise ArgumentError, ~r/at most 64 steps/, fn ->
        Merkle.steps_to_binary(proof)
      end
    end

    test "encode rejects an unknown direction prefix" do
      assert_raise ArgumentError, ~r/Invalid proof element format/, fn ->
        Merkle.steps_to_binary(["x:" <> String.duplicate("ab", 32)])
      end
    end

    test "encode rejects malformed elements" do
      malformed = [
        # no separator at all
        String.duplicate("ab", 32),
        # separator but no direction
        ":" <> String.duplicate("ab", 32),
        # hash too short
        "r:abcd",
        # hash too long
        "r:" <> String.duplicate("ab", 33),
        # odd number of hex characters
        "l:" <> String.duplicate("ab", 31) <> "a",
        # uppercase hex is not the canonical form
        "l:" <> String.duplicate("AB", 32),
        # non-hex characters of the right length
        "l:" <> String.duplicate("zz", 32),
        # not a string at all
        nil,
        :"l:abc",
        123
      ]

      for element <- malformed do
        assert_raise ArgumentError, fn -> Merkle.steps_to_binary([element]) end
      end
    end

    test "encode rejects a malformed element anywhere in the list" do
      good = "l:" <> String.duplicate("ab", 32)

      assert_raise ArgumentError, fn ->
        Merkle.steps_to_binary([good, good, "r:abcd", good])
      end
    end

    test "base64 encoding inherits the same validation" do
      assert_raise ArgumentError, ~r/Invalid proof element format/, fn ->
        Merkle.encode_proof_base64(["x:" <> String.duplicate("ab", 32)])
      end

      assert_raise ArgumentError, ~r/at most 64 steps/, fn ->
        Merkle.encode_proof_base64(for _ <- 1..65, do: "l:" <> String.duplicate("ab", 32))
      end
    end

    test "every proof from proof/2 encodes and roundtrips unchanged" do
      for leaf_count <- [1, 2, 3, 5, 8, 13, 17, 32] do
        data =
          for i <- 1..leaf_count do
            %{
              "key" => "entry-#{i}",
              "hash" =>
                :crypto.hash(:sha256, "leaf-#{leaf_count}-#{i}") |> Base.encode16(case: :lower)
            }
          end

        tree = Merkle.new(data)
        root = Merkle.root(tree)

        for %{"key" => key, "hash" => hash} <- data do
          proof = Merkle.proof(tree, key)

          assert {:ok, ^proof} = Merkle.steps_from_binary(Merkle.steps_to_binary(proof))
          assert {:ok, ^proof} = Merkle.decode_proof_base64(Merkle.encode_proof_base64(proof))
          assert Merkle.verify(hash, proof, root)
        end
      end
    end
  end
end
