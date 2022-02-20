defmodule Iptrie.MixProject do
  use Mix.Project

  # Before publishing to Hex:
  # - update CHANGELOG.md for changes in new version
  # - set new version tag in mix.exs, README.md
  # - mix test
  # - mix docs
  # - mix dialyzer
  # - git tag -a vx.y.z -m 'Release vx.y.z'
  # - git push --tags
  # mix hex.publish

  @source_url "https://github.com/hertogp/iptrie"
  @version "0.8.0"

  def project do
    [
      app: :iptrie,
      version: @version,
      elixir: "~> 1.11",
      name: "Iptrie",
      deps: deps(),
      docs: docs(),
      package: package(),
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    []
  end

  defp docs() do
    [
      extras: [
        "CHANGELOG.md": [],
        "LICENSE.md": [title: "License"],
        "README.md": [title: "Overview"]
      ],
      main: "readme",
      assets: "assets",
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"]
    ]
  end

  defp package do
    [
      description: "IP lookup, with longest prefix match, for IPv4, IPv6 prefixes (and others).",
      licenses: ["MIT"],
      maintainers: ["hertogp"],
      links: %{
        "Changelog" => "https://hexdocs.pm/iptrie/changelog.html",
        "GitHub" => @source_url
      }
    ]
  end

  defp deps do
    [
      {:radix, "~> 0.3"},
      {:pfx, "~> 0.6"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:benchee, "~> 1.0", only: :dev}
    ]
  end

  defp aliases() do
    [
      docs: ["docs", &gen_images/1]
    ]
  end

  # process all assets/*.dot files into assets/*.dot.png image files
  defp gen_images(_) do
    for dot <- Path.wildcard("assets/*.dot") do
      System.cmd("dot", ["-O", "-Tpng", dot])
    end
  end
end
