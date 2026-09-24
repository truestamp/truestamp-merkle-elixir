defmodule Truestamp.Merkle.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/truestamp/truestamp-merkle-elixir"

  def project do
    [
      app: :truestamp_merkle,
      version: @version,
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "SHA-256 Merkle trees with inclusion proofs, built to the frozen tree contract behind Truestamp's block roots.",
      package: package(),
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      {:stream_data, "~> 1.0", only: :test}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
