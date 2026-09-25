# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Merkle.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/truestamp/truestamp-merkle-elixir"

  def project do
    [
      app: :truestamp_merkle,
      version: @version,
      # The Elixir CI tests (on OTP 27, 28 and 29); see SECURITY.md, Platform requirements.
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description: "Deterministic SHA-256 Merkle trees with inclusion proofs, in pure Elixir.",
      package: package(),
      docs: docs(),
      # The PLTs live under _build, which CI caches.
      dialyzer: [plt_core_path: "_build/plts", plt_local_path: "_build/plts"],
      source_url: @source_url
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:stream_data, "~> 1.0", only: :test}
    ]
  end

  # The package ships the library and the documents its docs cite; the tests, the interop
  # programs and the scripts stay in the repository, which the docs link to.
  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README.md SECURITY.md LICENSE vectors/merkle.json),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "Truestamp.Merkle",
      extras: ["README.md", "SECURITY.md", "LICENSE"],
      source_ref: "v#{@version}"
    ]
  end
end
