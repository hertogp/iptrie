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

  @version "0.2.0"
  @url "https://github.com/hertogp/iptrie"

  def project do
    [
      app: :iptrie,
      version: @version,
      elixir: "~> 1.11",
      name: "Iptrie",
      description: "IP lookup, with longest prefix match, for IPv4, IPv6 prefixes (and others).",
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
      main: Iptrie,
      source_url: @url,
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end

  defp package do
    %{
      licenses: ["MIT"],
      maintainers: ["hertogp"],
      links: %{"GitHub" => @url}
    }
  end

  defp deps do
    [
      {:radix, "~> 0.1.1"},
      {:pfx, "~> 0.2.1"},
      {:ex_doc, ">= 0.24.0", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:credo, "~> 0.8", only: [:dev, :test]}
    ]
  end

  defp aliases() do
    [docz: ["docs", &cp_images/1]]
  end

  defp cp_images(_) do
    # the repo doesn't track `/doc/` or any of its subdirectories.  Github
    # links work if documentation links to images like `![xx](img/a.png)`
    #
    # While on hex.pm, image links are taken to be relative to the repo's
    # root/doc directory.  Hence, the img/*.dot files are processed into
    # img/*.png files, after which the img/*.png files are copied to
    # doc/img/*.png so everybody is happy.
    #
    # Also note, that doing it this way (img/*.png -> doc/img/*.png) keeps
    # the CI from failing, since the doc/img dir does not exist so doctests
    # that simply try to write to e.g. doc/img/a.png will fail.

    # ensure the (untracked) doc/img directory for hex.pm
    Path.join("doc", "img")
    |> File.mkdir_p!()

    # process all img/*.dot files into img/*.dot.png image files
    Path.wildcard("img/*.dot")
    |> Enum.map(fn file -> System.cmd("dot", ["-O", "-Tpng", file]) end)

    # copy img/*.png to doc/img/*.png
    Path.wildcard("img/*.png")
    |> Enum.map(fn src -> {src, Path.join("doc", src)} end)
    |> Enum.map(fn {src, dst} -> File.cp!(src, dst) end)
  end
end
