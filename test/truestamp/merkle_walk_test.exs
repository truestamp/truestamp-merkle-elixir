# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.MerkleWalkTest do
  use ExUnit.Case, async: true

  alias Truestamp.Merkle

  # The whitepaper's Appendix C.7 vectors: n entries keyed key01 to keyNN with
  # digests SHA-256("leaf<i>"), and the path for key01. Each path was derived
  # independently of this library and checked against the compact encodings
  # C.7 prints, byte for byte.
  @c7 [
    {1, "e6f3e0324c47532b4584166b9cdcbfb5f1dceaac9b097512d0e9e8501977daa0", []},
    {2, "5d3d9c89b11a0055ba0e43c2aaf4d3814717c01a8079bc1d05db80c41852b0f5",
     [
       "r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f"
     ]},
    {3, "738707d8051d65bb5b11d36cac93f7e5dccdee4676e836800a5d4e5c444103f1",
     [
       "r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f",
       "r:0a5a88a69750d82bda5ef36977a3fdefcad3b16f759cc304647ca12f6376a653"
     ]},
    {4, "1d8219ac8846f635dab3201c241583de32a73ca2f1b361cec04a419ae7806324",
     [
       "r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f",
       "r:d2faaeb2455fe6dbaa08e64eac2e4935cd2bcc92129368b7eb2ec5dc5460b751"
     ]},
    {5, "2012533b81a14bd8c0ba9172d14ca4bd761449bf10065c5baf89bc487497e891",
     [
       "r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f",
       "r:d2faaeb2455fe6dbaa08e64eac2e4935cd2bcc92129368b7eb2ec5dc5460b751",
       "r:bf0291b0bce6e82b0406ad56e99506b33db6f485efa4c041807144e6391e8fc3"
     ]},
    {6, "148337559cd25959c1c5f80dc1b0518a05ec308fbff4db47f2e133a67234f898",
     [
       "r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f",
       "r:d2faaeb2455fe6dbaa08e64eac2e4935cd2bcc92129368b7eb2ec5dc5460b751",
       "r:c858d5ae556bbfaf0d077ab72e1a6c63c7caedc67e808a73e9143f263b615ee0"
     ]},
    {7, "a08d49ae18a1ad35c5925064aa8fba66a6dfdcc24cd1ba9047d0e87493230ed4",
     [
       "r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f",
       "r:d2faaeb2455fe6dbaa08e64eac2e4935cd2bcc92129368b7eb2ec5dc5460b751",
       "r:4e2618593ce8103baac2f5c6fd2f6c910be4d92ae847cf91a9a2c5574b319d54"
     ]}
  ]

  # C.7's 300-entry tree (keys lk0001 to lk0300, digests SHA-256("bigleaf<i>")),
  # whose path for lk0001 is nine steps deep.
  @c7_300_root "f8c3f9a207a67fc22a297edcdf1dc0f17840ee9c8648ee3c8a7e5a71e5e42b92"
  @c7_300_steps [
    "r:7ae5473731274dc820c833c14c017faaabb40b4a1824951c15c8dae236a45439",
    "r:f75f2147efe8c29a2cd46f63d9de9ebc861c724e65fe332c0f0e776d0bb948b4",
    "r:f05f513ff50415599ebad3d80440597519f0cfc78205b869bf275c37b147f74b",
    "r:10e72eb52ba44dd896ca50ccfe904ba65383aa13edd5e5399c891ca707c1e0d0",
    "r:d5fa31f9fed6197bdd86c5f3e3e51feab211309e5c930e6e2a50110b087e80cd",
    "r:5a8ee767780a3727011c4c6a0b62f0b9475e593eceedd83810d41dae660c3e1d",
    "r:41d929a6e8903f8cc219521f90311da9d57d469b017c7b5785253d01a713fc14",
    "r:6d695192b6352baa8f207a3c890264e53bd1bca4d3f83129f47e57bb0d6bd118",
    "r:3c9dd04c6c47fbe48f2e31598a04726a18ecbf651467390dd2e0217d4f598c1b"
  ]

  @reserved "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
  @padding_leaf "d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319"

  defp digest(text), do: Base.encode16(:crypto.hash(:sha256, text), case: :lower)
  # A syntactically valid path of `count` steps, for the step-count checks.
  defp steps(count), do: for(n <- 1..count//1, do: "r:" <> digest("sibling#{n}"))

  describe "walk/3 known answers" do
    test "reproduces every C.7 root from its path" do
      for {n, root, steps} <- @c7 do
        assert Merkle.walk(digest("leaf1"), steps) == {:ok, root}, "n=#{n}"
      end
    end

    test "reproduces the 300-entry root from a nine-step path" do
      assert length(@c7_300_steps) == 9
      assert Merkle.walk(digest("bigleaf1"), @c7_300_steps) == {:ok, @c7_300_root}
    end

    test "agrees with proof/2 for every C.7 tree" do
      for {n, root, steps} <- @c7 do
        entries =
          for i <- 1..n do
            %{"key" => "key" <> String.pad_leading("#{i}", 2, "0"), "hash" => digest("leaf#{i}")}
          end

        tree = Merkle.new(entries)
        assert Merkle.root(tree) == root
        assert Merkle.proof(tree, "key01") == steps
      end
    end

    test "walks every entry of a padded tree to its root" do
      entries = for i <- 1..13, do: %{"key" => "k#{i}", "hash" => digest("e#{i}")}
      tree = Merkle.new(entries)

      for %{"key" => key, "hash" => hash} <- entries do
        assert Merkle.walk(hash, Merkle.proof(tree, key)) == {:ok, Merkle.root(tree)}
      end
    end

    test "a left step puts the sibling on the left" do
      # C.7's two-entry tree, walked from key02: its sibling is key01's leaf hash,
      # which is the one-entry tree's root.
      leaf1_hash = "e6f3e0324c47532b4584166b9cdcbfb5f1dceaac9b097512d0e9e8501977daa0"
      {2, root, _steps} = Enum.find(@c7, &(elem(&1, 0) == 2))
      assert Merkle.walk(digest("leaf2"), ["l:" <> leaf1_hash]) == {:ok, root}
    end

    test "an empty path returns the leaf hash, a one-entry tree's root" do
      tree = Merkle.new([%{"key" => "only", "hash" => digest("only")}])
      assert Merkle.walk(digest("only"), []) == {:ok, Merkle.root(tree)}
    end

    test "the padding leaf's hash is an ordinary sibling" do
      {3, root, _steps} = Enum.find(@c7, &(elem(&1, 0) == 3))
      entries = for i <- 1..3, do: %{"key" => "key0#{i}", "hash" => digest("leaf#{i}")}
      path = Merkle.proof(Merkle.new(entries), "key03")

      assert ("r:" <> @padding_leaf) in path
      assert Merkle.walk(digest("leaf3"), path) == {:ok, root}
    end
  end

  describe "walk/3 refusals" do
    setup do
      {3, root, steps} = Enum.find(@c7, &(elem(&1, 0) == 3))
      %{leaf: digest("leaf1"), root: root, steps: steps}
    end

    test "a leaf that is not 64 lowercase hex characters", %{steps: steps, leaf: leaf} do
      for bad <- [String.upcase(leaf), leaf <> "\n", binary_part(leaf, 0, 63), "", nil, 42] do
        assert Merkle.walk(bad, steps) == {:error, :invalid_leaf}, inspect(bad)
      end
    end

    test "the reserved padding value as the leaf", %{steps: steps} do
      assert Merkle.walk(@reserved, steps) == {:error, :reserved_leaf}
      assert Merkle.walk(@reserved, []) == {:error, :reserved_leaf}
    end

    test "33 steps under a cap of 32, and 65 under the default of 64", %{leaf: leaf} do
      assert {:ok, _} = Merkle.walk(leaf, steps(32), max_steps: 32)
      assert Merkle.walk(leaf, steps(33), max_steps: 32) == {:error, :too_many_steps}
      assert {:ok, _} = Merkle.walk(leaf, steps(64))
      assert Merkle.walk(leaf, steps(65)) == {:error, :too_many_steps}
    end

    test "an oversized path is refused before any step is read", %{leaf: leaf} do
      junk = List.duplicate(:not_a_step, 33)
      assert Merkle.walk(leaf, junk, max_steps: 32) == {:error, :too_many_steps}
    end

    test "uppercase hex or direction in a step", %{leaf: leaf, steps: [first | rest]} do
      "r:" <> sibling = first
      assert Merkle.walk(leaf, ["r:" <> String.upcase(sibling) | rest]) == {:error, :invalid_step}
      assert Merkle.walk(leaf, ["R:" <> sibling | rest]) == {:error, :invalid_step}
    end

    test "a step with a trailing newline", %{leaf: leaf, steps: [first | rest]} do
      assert Merkle.walk(leaf, [first <> "\n" | rest]) == {:error, :invalid_step}
    end

    test "a bare hash with no direction", %{leaf: leaf, steps: [first | rest]} do
      "r:" <> sibling = first
      assert Merkle.walk(leaf, [sibling | rest]) == {:error, :invalid_step}
    end

    test "other malformed steps", %{leaf: leaf} do
      sibling = digest("s")

      for bad <- [
            "x:" <> sibling,
            "r" <> sibling,
            "r::" <> sibling,
            "r:" <> binary_part(sibling, 0, 63),
            :atom,
            7,
            nil
          ] do
        assert Merkle.walk(leaf, [bad]) == {:error, :invalid_step}, inspect(bad)
      end
    end

    test "steps that are not a proper list", %{leaf: leaf, steps: [first | _]} do
      for bad <- ["not a list", %{}, nil, [first | :tail]] do
        assert Merkle.walk(leaf, bad) == {:error, :invalid_step}, inspect(bad)
      end
    end

    test "the leaf is checked before the steps", %{leaf: leaf} do
      assert Merkle.walk("bad", steps(65)) == {:error, :invalid_leaf}
      assert Merkle.walk(@reserved, [:not_a_step]) == {:error, :reserved_leaf}
      assert Merkle.walk(leaf, [:not_a_step]) == {:error, :invalid_step}
    end
  end

  describe "options" do
    test ":max_steps must be an integer from 0 to 64" do
      leaf = digest("leaf1")
      assert {:ok, _} = Merkle.walk(leaf, [], max_steps: 0)
      assert Merkle.walk(leaf, steps(1), max_steps: 0) == {:error, :too_many_steps}

      for bad <- [65, -1, 1.5, nil, "32"] do
        assert_raise ArgumentError, fn -> Merkle.walk(leaf, [], max_steps: bad) end
        assert_raise ArgumentError, fn -> Merkle.verify(leaf, [], leaf, max_steps: bad) end
      end
    end

    test "an unknown option, or options that are not a keyword list, raise" do
      leaf = digest("leaf1")
      assert_raise ArgumentError, fn -> Merkle.walk(leaf, [], cap: 3) end

      for bad <- [%{max_steps: 3}, nil, "opts"] do
        assert_raise ArgumentError, fn -> Merkle.walk(leaf, [], bad) end
        assert_raise ArgumentError, fn -> Merkle.verify(leaf, [], leaf, bad) end
      end
    end
  end

  describe "verify/4" do
    setup do
      {5, root, steps} = Enum.find(@c7, &(elem(&1, 0) == 5))
      %{leaf: digest("leaf1"), root: root, steps: steps}
    end

    test "true for a path that reaches the root", %{leaf: leaf, root: root, steps: steps} do
      assert Merkle.verify(leaf, steps, root)
      assert Merkle.verify(digest("bigleaf1"), @c7_300_steps, @c7_300_root)
    end

    test "false for a different root or leaf", %{leaf: leaf, root: root, steps: steps} do
      refute Merkle.verify(leaf, steps, @c7_300_root)
      refute Merkle.verify(digest("leaf2"), steps, root)
    end

    test "false for every walk refusal", %{leaf: leaf, root: root, steps: steps} do
      refute Merkle.verify(String.upcase(leaf), steps, root)
      refute Merkle.verify(@reserved, steps, root)
      refute Merkle.verify(leaf, ["R" <> tl_string(hd(steps)) | tl(steps)], root)
      refute Merkle.verify(leaf, steps, root, max_steps: length(steps) - 1)
    end

    test "false for a root that is not 64 lowercase hex characters",
         %{leaf: leaf, root: root, steps: steps} do
      for bad <- [String.upcase(root), root <> "\n", binary_part(root, 0, 63), nil] do
        refute Merkle.verify(leaf, steps, bad), inspect(bad)
      end
    end
  end

  defp tl_string(<<_, rest::binary>>), do: rest
end
