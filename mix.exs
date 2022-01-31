defmodule Mnemonic.MixProject do
  use Mix.Project

  @github_url "https://github.com/LanfordCai/mnemonic"

  def project do
    [
      app: :mnemonic,
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      source_url: @github_url,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 1.1", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.28", only: :dev}
    ]
  end

  defp description do
    """
    Elixir BIP39 implementation (Mnemonic)
    """
  end

  defp package do
    [
      name: "mnemonic_ex",
      files: ~w(lib priv .formatter.exs mix.exs README* LICENSE*),
      licenses: ["MIT"],
      maintainers: ["lanfordcai@outlook.com"],
      links: %{
        "GitHub" => @github_url
      }
    ]
  end
end
