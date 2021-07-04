defmodule Iptrie.MixProject do
  use Mix.Project

  # Before publishing to Hex:
  # - set version tag in mix.exs, README.md
  # - mix test
  # - mix docz
  # - mix dialyzer
  # - git tag -a vx.y.z -m 'Release vx.y.z'
  # - git push --tags
  # mix hex.publish

  @version "0.1.0"
  @url "https://github.com/hertogp/iptrie"

  def project do
    [
      app: :iptrie,
      version: @version,
      name: "Iptrie",
      description: "A longest prefix match IP lookup for IPv4, IPv6 prefixes (and others)",
      elixir: "~> 1.11",
      deps: deps(),
      docs: docs(),
      aliases: aliases(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    []
  end

  defp docs() do
    [
      main: Iptrie,
      extras: ["README.md", "CHANGELOG.md"],
      source_url: @url
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:radix, "~> 0.1.1"},
      {:pfx, "~> 0.2.1"},
      {:ex_doc, "~> 0.18", only: :dev, runtime: false},
      {:credo, "~> 0.8", only: [:dev, :test]}
    ]
  end

  defp aliases do
    [
      docz: [
        "docs",
        "cmd $(for f in doc/img/*.dot; do dot -T png ${f} > ${f}.png; done)"
      ]
    ]
  end

  defp package do
    %{
      licenses: ["MIT"],
      maintainers: ["hertogp"],
      links: %{"GitHub" => @url}
    }
  end
end
