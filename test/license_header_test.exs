# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.LicenseHeaderTest do
  # Every source and document file opens with the copyright line and the SPDX
  # identifier, in its own comment syntax, after a shebang if it has one. Data
  # and machine-managed files (LICENSE, mix.lock, .gitignore, .tool-versions,
  # vectors/merkle.json, vectors/interop/*.json, go.mod, go.sum, the interop programs'
  # NOTICE and LICENSE-* files) carry none, and neither do upstream files kept byte for
  # byte under a testdata/ directory. A Go or assembly file holding another project's
  # material names that project's license after Apache-2.0 in its SPDX expression.
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @copyright "Copyright (c) 2025-2026 Truestamp, Inc."
  @spdx "SPDX-License-Identifier: Apache-2.0"

  @patterns [
    "mix.exs",
    ".formatter.exs",
    ".credo.exs",
    "Taskfile.yml",
    "*.md",
    "{lib,test,bench,examples,vectors}/**/*.{ex,exs}",
    "{vectors,interop}/**/*.md",
    "interop/**/*.{go,s}",
    ".github/**/*.{yml,yaml}"
  ]

  test "every source and document file carries the header" do
    files =
      @patterns
      |> Enum.flat_map(&Path.wildcard(Path.join(@root, &1), match_dot: true))
      |> Enum.reject(&(&1 |> Path.relative_to(@root) |> Path.split() |> Enum.member?("testdata")))
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
      ["# " <> @copyright, "# " <> @spdx | _] ->
        true

      ["<!--", @copyright, @spdx, "-->"] ->
        true

      ["// " <> @copyright, "// " <> @spdx <> rest | _] ->
        rest =~ ~r/\A( AND [A-Za-z0-9.+-]+)*\z/

      _ ->
        false
    end
  end
end
