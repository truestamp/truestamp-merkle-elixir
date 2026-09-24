# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.LicenseHeaderTest do
  # Every source and document file opens with the copyright line and the SPDX
  # identifier, in its own comment syntax, after a shebang if it has one. Data
  # and machine-managed files (LICENSE, mix.lock, .gitignore, .tool-versions)
  # carry none.
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @copyright "Copyright (c) 2025-2026 Truestamp, Inc."
  @spdx "SPDX-License-Identifier: Apache-2.0"

  @patterns [
    "mix.exs",
    ".formatter.exs",
    "*.md",
    "{lib,test,bench,examples}/**/*.{ex,exs}",
    ".github/**/*.{yml,yaml}"
  ]

  test "every source and document file carries the header" do
    files =
      @patterns
      |> Enum.flat_map(&Path.wildcard(Path.join(@root, &1), match_dot: true))
      |> Enum.uniq()

    assert files != []

    missing =
      for file <- files, not header?(file), do: Path.relative_to(file, @root)

    assert missing == [], "missing the copyright and SPDX header: #{inspect(missing)}"
  end

  defp header?(file) do
    lines =
      file
      |> File.read!()
      |> String.split("\n")
      |> Enum.drop_while(&String.starts_with?(&1, "#!"))
      |> Enum.take(4)

    case lines do
      ["# " <> @copyright, "# " <> @spdx | _] -> true
      ["<!--", @copyright, @spdx, "-->"] -> true
      _ -> false
    end
  end
end
