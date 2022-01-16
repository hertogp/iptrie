defmodule Iptrie.Iana do
  @moduledoc ~S"""
  Functions to access or retrieve a snapshot of the IANA IPv4/6 Special-Purpose Address Registries.

  They include:

  - [IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
  - [IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)

  There are only two functions:
  - `Iptrie.Iana.get/1` to retrieve the list of prefixes and properties for IPv4 or IPv6 prefixes.
  - `Iptrie.Iana.lookup/2` to retrieve a single property or all properties for a given prefix.

  See `Pfx.iana_special/2` for more information.

  ## Examples

      iex> Iptrie.Iana.lookup("10.10.10.10")
      {"10.0.0.0/8",
       %{
         allocation: "1996-02",
         destination: true,
         forward: true,
         global: false,
         name: "private-use",
         prefix: "10.0.0.0/8",
         reserved: false,
         source: true,
         spec: ["rfc1918"]
       }}

       iex> Iptrie.Iana.lookup("fc00::", :global)
       false

       iex> Iptrie.Iana.lookup("fc00::", :name)
       "unique-local"

  """

  @iana Iptrie.new()
        |> Iptrie.put(Pfx.iana_special(:ip4))
        |> Iptrie.put(Pfx.iana_special(:ip6))

  @doc ~S"""
  Returns the list of IPv4 or IPv6 prefixes and their IANA special purpose address properties in a map.

  ## Examples

      iex> get(:ip4) |> length()
      25

      iex> get(:ip4) |> hd()
      {%Pfx{bits: <<0, 0, 0, 0>>, maxlen: 32},
       %{
         allocation: "1981-09",
         destination: false,
         forward: false,
         global: false,
         name: "this-host-on-this-network",
         prefix: "0.0.0.0/32",
         reserved: true,
         source: true,
         spec: ["rfc1122"]
       }}

      iex> get(:ip6) |> length()
      20

      iex> get(:ip6) |> hd()
      {%Pfx{bits: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>, maxlen: 128},
       %{
         allocation: "2006-02",
         destination: false,
         forward: false,
         global: false,
         name: "unspecified-address", 
         prefix: "::/128",
         reserved: true,
         source: true,
         spec: ["rfc4291"]
       }}

  """
  @spec get(:ip4 | :ip6) :: [{Pfx.t(), map}]
  def get(:ip4),
    do: Iptrie.to_list(@iana, 32)

  def get(:ip6),
    do: Iptrie.to_list(@iana, 128)

  @doc """
  Returns either nil, a property value or property map for given prefix

  ## Examples

      iex> lookup("10.10.10.10")
      {"10.0.0.0/8",
       %{
         allocation: "1996-02",
         destination: true,
         forward: true,
         global: false,
         name: "private-use",
         prefix: "10.0.0.0/8",
         reserved: false,
         source: true,
         spec: ["rfc1918"]
       }}

      # non-existing property
      iex> lookup("10.10.10.10", :missing)
      nil

      iex> lookup("::ffff:0:0/96", :global)
      false

      iex> lookup("::ffff:0:0/96", :name)
      "ipv4-mapped-address"

  """
  @spec lookup(Pfx.prefix(), atom | nil) :: nil | map | any
  def lookup(prefix, property \\ nil)

  def lookup(prefix, nil),
    do: Iptrie.lookup(@iana, prefix)

  def lookup(prefix, property) do
    with {_pfx, m} <- Iptrie.lookup(@iana, prefix),
         do: Map.get(m, property)
  end
end
