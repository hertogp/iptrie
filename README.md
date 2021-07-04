# README

![Pfx test](https://github.com/hertogp/iptrie/actions/workflows/elixir.yml/badge.svg)

[Online Documentation](https://hexdocs.pm/iptrie).

<!-- @MODULEDOC -->

A longest prefix match IP lookup for IPv4, IPv6 prefixes (and others).

Iptrie manages multiple `Radix` trees, one for each type of prefix used as
determined by their `maxlen` property.  That way, IPv4 prefixes (`maxlen: 32`)
use a different radix than say IPv6 (`maxlen: 128`).

Iptrie has a bias towards IPv4 and IPv6 since it uses `Pfx` to convert
arguments to a `t:Pfx.t` struct.  So, doing other types of prefixes will
require the actual `Pfx` structs as arguments for the various Iptrie functions.

## Example

    iex> ipt = new()
    ...> |> put("1.2.3.0/24", "v4")
    ...> |> put("acdc:1975::/32", "v6")
    ...> |> put("0.0.0.0/0", "v4 default")
    ...> |> put("::/0", "v6 default")
    ...> |> put(%Pfx{bits: <<0xaa, 0xbb, 0xcc, 0xdd>>, maxlen: 48}, "some OUI")
    iex>
    iex> lookup(ipt, "1.2.3.128")
    {"1.2.3.0/24", "v4"}
    iex>
    iex> lookup(ipt, "10.11.12.13")
    {"0.0.0.0/0", "v4 default"}
    iex>
    iex> lookup(ipt, "abba::")
    {"0:0:0:0:0:0:0:0/0", "v6 default"}
    iex>
    iex> lookup(ipt, %Pfx{bits: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee>>, maxlen: 48})
    {%Pfx{bits: <<0xAA, 0xBB, 0xCC, 0xDD>>, maxlen: 48}, "some OUI"}
    iex>
    iex> # uses three separate radix trees:
    iex>
    iex> Map.get(ipt, 32)
    {0, {7, [{"", "v4 default"}], [{<<1, 2, 3>>, "v4"}]}, nil}
    iex>
    iex> Map.get(ipt, 128)
    {0, [{"", "v6 default"}], [{<<172, 220, 25, 117>>, "v6"}]}
    iex>
    iex> Map.get(ipt, 48)
    {0, nil, [{<<170, 187, 204, 221>>, "some OUI"}]}

<!-- @MODULEDOC -->

## Installation

[Iptrie](https://hexdocs.pm/iptrie) can be installed by adding `iptrie` to your
list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:iptrie, "~> 0.1.0"}
  ]
end
```

Repositiory is on [github](https://github.com/hertogp/iptrie).

