defmodule Iptrie.MixProject do
  use Mix.Project

  def project do
    [
      app: :iptrie,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
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
end
