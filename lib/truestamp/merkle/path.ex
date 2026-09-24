# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.Path do
  @moduledoc false

  # Inclusion paths: producing one from a built tree, and walking one back up to the
  # root it implies. A step is "l:" or "r:" followed by the sibling's 64 lowercase hex
  # characters, bottom to top.

  alias Truestamp.Merkle.Hash

  # Longest path a walk or the codec will process, and so the ceiling on the hashing
  # an untrusted path can ask for. 64 steps spans a tree of
  # 2^64 = 18,446,744,073,709,551,616 leaves, past anything that could be built.
  @max_steps 64

  @digest_hex_chars Hash.digest_hex_chars()

  def max_steps, do: @max_steps

  # The path for the leaf at `position`. Every level is a tuple, so each sibling is one
  # elem/2 away.
  def steps(levels, position, depth) do
    {steps, _position} =
      levels
      |> Enum.take(depth)
      |> Enum.map_reduce(position, fn level, i -> {step(level, i), div(i, 2)} end)

    steps
  end

  defp step(level, i) when rem(i, 2) == 0, do: "r:" <> Hash.to_hex(elem(level, i + 1))
  defp step(level, i), do: "l:" <> Hash.to_hex(elem(level, i - 1))

  def walk(leaf_hex, steps, opts) do
    max_steps = max_steps!(opts)

    with {:ok, root} <- walk_to_root(leaf_hex, steps, max_steps) do
      {:ok, Hash.to_hex(root)}
    end
  end

  def verify(leaf_hex, steps, root_hex, opts) do
    max_steps = max_steps!(opts)

    with true <- Hash.digest_hex?(root_hex),
         {:ok, root} <- walk_to_root(leaf_hex, steps, max_steps) do
      # Constant-time comparison, kept as a matter of habit rather than because
      # anything depends on it. The computed root, the expected root, the path and
      # the leaf value are all public, so there is no secret for the comparison to
      # leak and no timing channel to close. It costs nothing and keeps the door
      # shut if a caller ever compares something that is not public. Both sides
      # are 32 bytes here; :crypto.hash_equals/2 requires OTP 25 or newer.
      :crypto.hash_equals(root, Hash.from_hex!(root_hex))
    else
      _refused -> false
    end
  end

  # "l:" or "r:" and exactly 64 lowercase hex characters, nothing more. The fixed width
  # is what refuses a trailing newline and a bare hash. Returns the direction byte and
  # the sibling's raw 32 bytes.
  def parse_step(<<direction, ?:, sibling::binary-size(@digest_hex_chars)>>)
      when direction in [?l, ?r] do
    if Hash.lowercase_hex?(sibling), do: {:ok, {direction, Hash.from_hex!(sibling)}}, else: :error
  end

  def parse_step(_step), do: :error

  defp max_steps!(opts) when not is_list(opts) do
    raise ArgumentError, "options must be a keyword list, got: #{inspect(opts)}"
  end

  defp max_steps!(opts) do
    opts = Keyword.validate!(opts, max_steps: @max_steps)

    case opts[:max_steps] do
      steps when is_integer(steps) and steps >= 0 and steps <= @max_steps ->
        steps

      other ->
        raise ArgumentError,
              ":max_steps must be an integer from 0 to #{@max_steps}, got: #{inspect(other)}"
    end
  end

  defp walk_to_root(leaf_hex, steps, max_steps) do
    with :ok <- check_leaf(leaf_hex),
         :ok <- count_steps(steps, max_steps, 0),
         {:ok, siblings} <- parse_steps(steps, []) do
      {:ok, Enum.reduce(siblings, Hash.leaf(leaf_hex), &apply_step/2)}
    end
  end

  # A path walked FROM the reserved digest leads to a padding slot, not to a real
  # entry, and no honest tree carries the digest as an entry. Only the value proved is
  # refused: the padding leaf's hash is a normal sibling in most padded paths, so
  # parse_step/1 does not look for it.
  defp check_leaf(leaf_hex) do
    cond do
      not Hash.digest_hex?(leaf_hex) -> {:error, :invalid_leaf}
      leaf_hex == Hash.reserved_digest_hex() -> {:error, :reserved_leaf}
      true -> :ok
    end
  end

  # Counts no further than one step past the cap, so an oversized path is refused
  # without reading it, whatever its length.
  defp count_steps([], _max_steps, _count), do: :ok

  defp count_steps([_ | _], max_steps, count) when count >= max_steps,
    do: {:error, :too_many_steps}

  defp count_steps([_ | rest], max_steps, count), do: count_steps(rest, max_steps, count + 1)
  defp count_steps(_not_a_list, _max_steps, _count), do: {:error, :invalid_step}

  defp parse_steps([], parsed), do: {:ok, Enum.reverse(parsed)}

  defp parse_steps([step | rest], parsed) do
    case parse_step(step) do
      {:ok, sibling} -> parse_steps(rest, [sibling | parsed])
      :error -> {:error, :invalid_step}
    end
  end

  defp apply_step({?l, sibling}, running), do: Hash.node(sibling, running)
  defp apply_step({?r, sibling}, running), do: Hash.node(running, sibling)
end
