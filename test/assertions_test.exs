# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.AssertionsTest do
  # Guards against tests that cannot fail. ExUnit passes a test with no assertion, and
  # StreamData ignores what a `check all` body returns, so a property ending in a bare
  # boolean passes whatever it computes. Every test and property here must assert, and
  # an assertion that only checks a type does not count on its own.
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @assertions [
    :assert,
    :refute,
    :assert_raise,
    :assert_receive,
    :assert_received,
    :refute_receive,
    :refute_received,
    :flunk,
    :assert_in_delta
  ]
  @type_checks [:is_binary, :is_list, :is_map, :is_integer, :is_atom, :is_tuple, :is_nil]

  test "every test, property and check all body asserts something beyond a type" do
    files = Path.wildcard(Path.join(@root, "test/**/*_test.exs"))
    assert files != []

    problems =
      for file <- files,
          {:ok, ast} = file |> File.read!() |> Code.string_to_quoted(),
          problem <- problems(ast),
          do: "#{Path.relative_to(file, @root)}:#{problem}"

    assert problems == []
  end

  defp problems(ast) do
    {_, found} =
      Macro.prewalk(ast, [], fn
        {kind, meta, [name | rest]} = node, acc when kind in [:test, :property] ->
          if test_name?(name),
            do: {node, check(body(rest), "#{meta[:line]} #{kind} #{Macro.to_string(name)}", acc)},
            else: {node, acc}

        {:check, meta, [{:all, _, clauses} | rest]} = node, acc ->
          {node, check(body(rest) || body(clauses), "#{meta[:line]} check all", acc)}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(found)
  end

  # A literal name, or one built by interpolation.
  defp test_name?(name), do: is_binary(name) or match?({:<<>>, _, _}, name)

  defp check(nil, _where, acc), do: acc

  defp check(body, where, acc) do
    case strengths(body) do
      [] -> ["#{where} asserts nothing" | acc]
      strengths -> if :strong in strengths, do: acc, else: ["#{where} only checks types" | acc]
    end
  end

  defp body(args) when is_list(args) do
    Enum.find_value(args, fn
      kw when is_list(kw) -> Keyword.get(kw, :do)
      _ -> nil
    end)
  end

  defp strengths(body) do
    {_, found} =
      Macro.prewalk(body, [], fn
        {a, _, [{t, _, [_]} | _]} = node, acc
        when a in [:assert, :refute] and t in @type_checks ->
          {node, [:weak | acc]}

        {a, _, args} = node, acc when a in @assertions and is_list(args) ->
          {node, [:strong | acc]}

        node, acc ->
          {node, acc}
      end)

    found
  end
end
