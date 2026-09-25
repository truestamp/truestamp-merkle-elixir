# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.InteropTest do
  # Other implementations' published known answers, one file per implementation in
  # vectors/interop/. Most use leaf data other than a 32-byte digest, which the public
  # API does not take, so the checks run at the leaf-hash level through the same
  # internal functions the public API uses. vectors/interop/README.md names every
  # source, and each file's Go program in interop/go/ regenerates and checks it against
  # its implementation (the :go_interop tests below run those).
  use ExUnit.Case, async: true

  alias Truestamp.Merkle
  alias Truestamp.Merkle.{Hash, Paths, Tree}

  @root Path.expand("../../..", __DIR__)
  @files @root |> Path.join("vectors/interop/*.json") |> Path.wildcard() |> Enum.sort()
  @go_dirs @root
           |> Path.join("interop/go/*/go.mod")
           |> Path.wildcard()
           |> Enum.map(&Path.dirname/1)
           |> Enum.sort()

  # One file and one Go program per implementation, and no fewer than these.
  @implementations ~w(certificate-transparency-go codenotary-merkletree cometbft-crypto-merkle
                      production-logs sigsum-go transparency-dev-merkle x-mod-sumdb-tlog)

  # Decoded when a test runs, not at compile time: the files are too large to embed.
  defp load(file), do: file |> File.read!() |> JSON.decode!()

  defp unhex(text) when is_binary(text) do
    case Base.decode16(text, case: :lower) do
      {:ok, bytes} -> bytes
      :error -> :not_hex
    end
  end

  defp unhex(_other), do: :not_hex

  defp leaf_hash(data), do: :crypto.hash(:sha256, <<0x00>> <> data)

  # A tree's leaf hashes: listed, or computed from the rule its file gives.
  defp leaf_hashes(%{"leaf_hashes" => hashes}) when is_list(hashes),
    do: Enum.map(hashes, &unhex/1)

  defp leaf_hashes(%{"leaf_data_rule" => %{"encoding" => encoding, "first" => first}} = tree) do
    for i <- first..(first + tree["tree_size"] - 1)//1, do: leaf_hash(encode(encoding, i))
  end

  defp encode("u16le", i), do: <<i::little-16>>
  defp encode("u64be", i), do: <<i::big-64>>
  defp encode("decimal_ascii", i), do: Integer.to_string(i)
  defp encode(other, _i), do: flunk("unknown leaf_data_rule encoding #{inspect(other)}")

  # The RFC 9162 answer: rfc9162_valid where the file settles one (the implementation or
  # its upstream test disagreed with the RFC or with each other), else the verdict.
  defp expected(inclusion), do: Map.get(inclusion, "rfc9162_valid", inclusion["valid"])

  # What the library says, at the leaf-hash level. It must answer, never raise, for
  # anything a file holds, including negative indexes, empty hashes and size 0.
  defp library_accepts?(inclusion) do
    proof = %{
      leaf_index: inclusion["leaf_index"],
      tree_size: inclusion["tree_size"],
      path: inclusion["path"]
    }

    case unhex(inclusion["leaf_hash"]) do
      <<_::binary-size(32)>> = leaf ->
        case Paths.walk_leaf_hash(leaf, proof, Paths.max_steps()) do
          {:ok, root} -> Hash.to_hex(root) == inclusion["root"]
          {:error, _reason} -> false
        end

      _not_a_leaf_hash ->
        false
    end
  end

  test "there are fixture files, each with trees and inclusion cases" do
    assert Enum.map(@files, &Path.basename(&1, ".json")) == @implementations
    assert Enum.map(@go_dirs, &Path.basename/1) == @implementations

    for file <- @files do
      fixture = load(file)
      name = Path.basename(file)
      assert [_ | _] = fixture["trees"], name
      assert [_ | _] = fixture["inclusion"], name
      assert Enum.any?(fixture["inclusion"], &expected/1), name
      assert Enum.any?(fixture["inclusion"], &(not expected(&1))), name
    end

    # So the public-API test below runs on at least one tree somewhere.
    assert Enum.any?(@files, fn file -> Enum.any?(load(file)["trees"], &digest_leaves?/1) end)
  end

  defp digest_leaves?(%{"leaf_data" => [_ | _] = data}),
    do: Enum.all?(data, &match?(<<_::binary-size(64)>>, &1))

  defp digest_leaves?(_tree), do: false

  for file <- @files do
    @fixture_file file

    describe Path.basename(file, ".json") do
      test "the empty root and the node and 32-byte leaf hash checks" do
        fixture = load(@fixture_file)

        if fixture["empty_root"],
          do: assert(Hash.to_hex(Hash.empty_root()) == fixture["empty_root"])

        for check <- fixture["hash_checks"] do
          case check do
            %{"kind" => "node", "left" => left, "right" => right, "hash" => hash} ->
              assert Hash.to_hex(Hash.node(unhex(left), unhex(right))) == hash, check["name"]

            # The library hashes 32-byte digests only; other leaf data is checked through
            # the trees and proofs built on its leaf hashes.
            %{"kind" => "leaf", "input_hex" => <<input::binary-size(64)>>, "hash" => hash} ->
              assert Hash.to_hex(Hash.leaf(unhex(input))) == hash, check["name"]

            %{"kind" => "leaf"} ->
              :ok
          end
        end
      end

      test "every tree's root, from its leaf hashes" do
        for tree <- load(@fixture_file)["trees"] do
          leaves = leaf_hashes(tree)
          assert length(leaves) == tree["tree_size"], tree["name"]

          root = leaves |> Tree.levels() |> List.last() |> elem(0)
          assert Hash.to_hex(root) == tree["root"], tree["name"]
        end
      end

      test "every inclusion verdict" do
        for inclusion <- load(@fixture_file)["inclusion"] do
          assert library_accepts?(inclusion) == expected(inclusion),
                 "#{inclusion["name"]}: expected #{expected(inclusion)}"
        end
      end

      test "the library's own path for every accepted proof whose tree is in the file" do
        fixture = load(@fixture_file)

        levels =
          Map.new(fixture["trees"], fn tree ->
            {{tree["root"], tree["tree_size"]}, Tree.levels(leaf_hashes(tree))}
          end)

        for inclusion <- fixture["inclusion"],
            expected(inclusion),
            tree_levels = levels[{inclusion["root"], inclusion["tree_size"]}] do
          assert Paths.audit_path(tree_levels, inclusion["leaf_index"]) == inclusion["path"],
                 inclusion["name"]
        end
      end

      test "trees over 32-byte leaf data, through the public API" do
        for %{"leaf_data" => data} = tree <- load(@fixture_file)["trees"], digest_leaves?(tree) do
          # Keys that sort in list order keep the file's leaf order.
          entries =
            data
            |> Enum.with_index()
            |> Enum.map(fn {digest, i} ->
              %{
                "key" => "k" <> String.pad_leading(Integer.to_string(i), 9, "0"),
                "hash" => digest
              }
            end)

          merkle = Merkle.new(entries)
          root = Merkle.root(merkle)
          assert root == tree["root"], tree["name"]

          for %{"key" => key, "hash" => digest} <- entries do
            assert Merkle.verify(digest, Merkle.proof(merkle, key), root), tree["name"]
          end
        end
      end
    end
  end

  describe "the Go programs behind the files" do
    # Excluded unless asked for (`mix test --include go_interop`): they need go on the
    # PATH, and network the first time to fetch each implementation. Each program
    # rebuilds its file from its implementation's own code and fails if the committed
    # file differs, and checks vectors/merkle.json with its implementation's verifier.
    @describetag :go_interop
    # A cold build of a program and its implementation can take minutes on a CI runner.
    @describetag timeout: 600_000

    for dir <- @go_dirs do
      @go_dir dir

      test Path.basename(dir) do
        go = System.find_executable("go") || flunk("the :go_interop tests need go on the PATH")
        fixtures = Path.join(@root, "vectors/interop/#{Path.basename(@go_dir)}.json")
        ours = Path.join(@root, "vectors/merkle.json")

        {output, status} =
          System.cmd(go, ["run", ".", "-fixtures", fixtures, "-ours", ours],
            cd: @go_dir,
            stderr_to_stdout: true
          )

        assert status == 0, output
      end
    end
  end
end
