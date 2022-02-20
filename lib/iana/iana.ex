defmodule Iptrie.Iana do
  @moduledoc ~S"""
  Functions to access a local snapshot of the IANA IPv4/6 Special-Purpose Address Registries.

  See also:

  - [IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
  - [IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)

  At compile time, this module builds an Iptrie.t using Pfx's local copy of the
  IANA special-purpose address registries, which can then be accessed using:

  - `Iptrie.Iana.get/1` to retrieve the list of prefixes and properties for IPv4 or IPv6 prefixes
  - `Iptrie.Iana.lookup/2` to retrieve a single or all properties for a given prefix, and
  - `Iptrie.iana_special/2`, which delegates to `Iptrie.Iana.lookup/2`.

  Running `mix iana.special` will show the number of records and last update of
  these registries by Iana, as well as that of the local snapshot.  If the
  snapshot is out-of-date, it will be updated with the new information, in
  which case both Pfx and Iptrie.Iana module will need to be recompiled.

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
         spec: ["rfc1918"],
         termination: :na
       }}

      iex> Iptrie.iana_special("fc00::")
      {"fc00::/7",
        %{
          allocation: "2005-10",
          destination: true,
          forward: true,
          global: false,
          name: "unique-local",
          prefix: "fc00::/7",
          reserved: false,
          source: true,
          spec: ["rfc4193", "rfc8190"],
          termination: :na
       }}

      # retrieve a single property
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
         spec: ["rfc1122"],
         termination: :na
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
         spec: ["rfc4291"],
         termination: :na
       }}

      # get all non-globally-routed IPv4 prefixes
      iex> get(:ip4)
      ...> |> Enum.filter(fn {_, m} -> m.global != true end)
      ...> |> Enum.map(fn {pfx, _} -> "#{pfx}" end)
      [
        "0.0.0.0", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29", "192.0.0.0/24", "192.0.0.8",
        "192.0.0.170", "192.0.0.171", "192.0.2.0/24", "192.88.99.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "240.0.0.0/4", "255.255.255.255"
      ]

  """
  @spec get(:ip4 | :ip6) :: [{Pfx.t(), map}]
  def get(:ip4),
    do: Iptrie.to_list(@iana, 32)

  def get(:ip6),
    do: Iptrie.to_list(@iana, 128)

  @doc """
  Performs a longest prefix match against the local IPv4 and IPv6 special
  purpose address registries and Returns either nil, a property value or
  property map for given search prefix.

  ## Examples

    iex(16)> lookup("0.0.0.0")
    {"0.0.0.0",
     %{
       allocation: "1981-09",
       destination: false,
       forward: false,
       global: false,
       name: "this-host-on-this-network",
       prefix: "0.0.0.0/32",
       reserved: true,
       source: true,
       spec: ["rfc1122"],
       termination: :na
     }}

    iex(17)> lookup("0.0.0.1")
    {"0.0.0.0/8",
     %{
       allocation: "1981-09",
       destination: false,
       forward: false,
       global: false,
       name: "this-network",
       prefix: "0.0.0.0/8",
       reserved: true,
       source: true,
       spec: ["rfc791"],
       termination: :na
     }}

      # a non-existing property `:missing`
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
