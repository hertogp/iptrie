# Iptrie

[![Test](https://github.com/hertogp/iptrie/actions/workflows/elixir.yml/badge.svg)](https://github.com/hertogp/iptrie/actions/workflows/elixir.yml)
[![Module Version](https://img.shields.io/hexpm/v/iptrie.svg)](https://hex.pm/packages/iptrie)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/iptrie/)
[![Total Download](https://img.shields.io/hexpm/dt/iptrie.svg)](https://hex.pm/packages/iptrie)
[![License](https://img.shields.io/hexpm/l/iptrie.svg)](https://github.com/hertogp/iptrie/blob/master/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/hertogp/iptrie.svg)](https://github.com/hertogp/iptrie/commits/master)

<!-- @MODULEDOC -->

IP lookup, with longest prefix match, for IPv4, IPv6 prefixes (and others).

Iptrie manages multiple `Radix` trees, one for each type of
`t:Pfx.t/0` prefix used as determined by their `maxlen` property.  That way,
IPv4 prefixes (`maxlen: 32`) use a different radix tree as opposed to e.g. IPv6
(`maxlen: 128`).

Iptrie has a bias towards IPv4, IPv6, EUI-48 and EUI-64, since it uses `Pfx` to
convert arguments to a `t:Pfx.t/0` struct.  Other types of prefixes will
require the actual `t:Pfx.t/0` structs as arguments for the various Iptrie
functions.

Like `Pfx`, Iptrie tries to mirror the representation of results to the
argument(s) given, if possible.

## IPv4/IPv6

    iex> ipt = new()
    ...> |> put("1.2.3.0/24", "v4")
    ...> |> put("128.0.0.0/8", "v4-128")
    ...> |> put("acdc:1975::/32", "T.N.T")
    ...> |> put("acdc:1978::/32", "Powerage")
    ...> |> put("0.0.0.0/0", "v4 default")
    ...> |> put("::/0", "no dynamite")
    iex>
    iex> lookup(ipt, "1.2.3.128")
    {"1.2.3.0/24", "v4"}
    iex> lookup(ipt, "acdc:1975::")
    {"acdc:1975:0:0:0:0:0:0/32", "T.N.T"}
    iex>
    iex> # separate trees, separate default routes
    iex> lookup(ipt, "10.11.12.13")
    {"0.0.0.0/0", "v4 default"}
    iex> lookup(ipt, "abba::")
    {"0:0:0:0:0:0:0:0/0", "no dynamite"}
    iex>
    iex> # visualize the IPv4 & IPv6 radix trees
    iex> kv32 = fn {k, v} -> "#{Pfx.new(k, 32)}<br/>#{v}" end
    iex> radix(ipt, 32)
    ...> |> Radix.dot(label: "IPv4", kv_tostr: kv32)
    ...> |> (&File.write("img/ipv4.dot", &1)).()
    iex> kv128 = fn {k, v} -> "#{Pfx.new(k, 128)}<br/>#{v}" end
    iex> radix(ipt, 128)
    ...> |> Radix.dot(label: "IPv6", kv_tostr: kv128)
    ...> |> (&File.write("img/ipv6.dot", &1)).()


Where the radix trees for the IP prefixes look like:

![ipv4](assets/ipv4.dot.png) ![ipv6](assets/ipv6.dot.png)

## Others

Iptrie can also be used to do longest prefix match lookup for other types of
prefixes, like e.g. MAC addresses:

    iex> ipt = new()
    ...> |> put("00-22-72-00-00-00/24", "American Micro-Fuel Device")
    ...> |> put("00-d0-ef-00-00-00/24", "IGT")
    ...> |> put("08-61-95-00-00-00/24", "Rockwell Automation")
    iex>
    iex> lookup(ipt, "00-d0-ef-aa-bb-cc")
    {"00-D0-EF-00-00-00/24", "IGT"}
    iex>
    iex> # longest match for partial prefix
    iex> lookup(ipt, "08-61-95-11-22-00/40") |> elem(1)
    "Rockwell Automation"
    iex>
    iex> kv48 = fn {k, v} -> "#{Pfx.new(k, 48)}<br/>#{v}" end
    iex> radix(ipt, 48)
    ...> |> Radix.dot(label: "MAC OUI", kv_tostr: kv48)
    ...> |> (&File.write("img/mac.dot", &1)).()

![mac](assets/mac.dot.png)

`Iptrie` recognizes EUI-48 addresses and EUI-64, but only when using '-'s
as punctuation, otherwise `Pfx` will turn it into an IPv6 prefix.

Since prefixes are stored in specific radix trees based on the `maxlen` of
given prefix, you could also mix IPv4, IPv6, EUI-48, EUI-64 prefixes and
possibly others, in a single Iptrie.

<!-- @MODULEDOC -->

## Installation

[Iptrie](https://hexdocs.pm/iptrie) can be installed by adding `:iptrie` to your
list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:iptrie, "~> 0.3.0"}
  ]
end
```

## Copyright and License

Copyright (c) 2020 hertogp

The source code is licensed under the [MIT License](./LICENSE.md).
