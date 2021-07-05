defmodule Iptrie do
  @external_resource "README.md"

  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)

  require Pfx
  alias Radix

  defstruct []

  @typedoc """
  An Iptrie struct that contains a `Radix` tree per type of `t:Pfx.t/0` used.

  A [prefix'](`Pfx`) _type_ is determined by its `maxlen` property: IPv4 has `maxlen:
  32`, IPv6 has `maxlen: 128`, MAC addresses have `maxlen: 48` and so on.

  Although Iptrie facilitates lpm lookups of any type of prefix, it has a bias
  towards IP prefixes. So, any binaries (strings) are interpreted as
  CIDR-strings and tuples of address digits and/or {address-digits, length) are
  interpreted as IPv4 or IPv6 representations.

  """
  @type t :: %__MODULE__{}

  @typedoc """
  A prefix represented as an opague `t:Pfx.t/0` struct, an
  `t:Pfx.ip_address/0`, `t:Pfx.ip_prefix/0` or CIDR string.

  See: `Pfx`.

  """
  @type prefix :: Pfx.prefix()

  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      %Iptrie{}


  """
  @spec new() :: t()
  def new,
    do: %__MODULE__{}

  @doc """
  Create a new `t:Iptrie.t/0` populated via a list of {`t:prefix/0`, `t:any/0`}-pairs.

  ## Example

      iex> ipt = Iptrie.new([{"1.1.1.0/24", "net1"}, {"acdc:1975::/32", "TNT"}])
      iex> Map.get(ipt, 32)
      {0, [{<<1, 1, 1>>, "net1"}], nil}
      iex> Map.get(ipt, 128)
      {0, nil, [{<<172, 220, 25, 117>>, "TNT"}]}

  """
  @spec new(list({prefix(), any})) :: t
  def new(elements) when is_list(elements),
    do: Enum.reduce(elements, new(), fn {prefix, value}, trie -> put(trie, prefix, value) end)

  @doc """
  Return the {key,val}-pair where key is an exact match for given `prefix`,
  or a list of pairs for a list of prefixes.

  ## Examples

      iex> ipt = new([{"1.1.1.0/30", "A"}, {"1.1.1.0/31", "B"}, {"1.1.1.0", "C"}])
      iex> get(ipt, "1.1.1.0/31")
      {"1.1.1.0/31", "B"}
      iex>
      iex> get(ipt, {{1, 1, 1, 0}, 30})
      {{{1, 1, 1, 0}, 30}, "A"}


  """
  @spec get(t, prefix() | list(prefix())) :: {prefix(), any} | nil | list({prefix(), any})
  def get(%__MODULE__{} = trie, prefixes) when is_list(prefixes) do
    Enum.map(prefixes, fn prefix -> get(trie, prefix) end)
  end

  def get(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.get(tree, pfx.bits) do
        nil -> nil
        {bits, value} -> {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
      end
    rescue
      ArgumentError -> nil
    end
  end

  @doc """
  Enter a single {prefix,value}-pair into an iptrie.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.  Any errors are silently ignored as the tree is always returned.

  ## Examples

  """
  @spec put(t, list({prefix(), any})) :: t
  def put(%__MODULE__{} = trie, elements) when is_list(elements) do
    Enum.reduce(elements, trie, fn {k, v}, t -> put(t, k, v) end)
  end

  @spec put(t, prefix(), any) :: t
  def put(%__MODULE__{} = trie, prefix, value) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()
      Map.put(trie, pfx.maxlen, Radix.put(tree, pfx.bits, value))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Delete one or more entries from an Iptrie.

  The list of prefixes to delete can be mixed, so all sorts of prefixes can be
  deleted from multiple radix trees in one go.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", "one")
      ...> |> put("2.2.2.0/24", "two")
      iex>
      iex> lookup(ipt, "1.1.1.1")
      {"1.1.1.0/24", "one"}
      iex>
      iex> Map.get(ipt, 32) |> Radix.keys()
      [<<1, 1, 1>>, <<2, 2, 2>>]
      iex>
      iex> ipt = delete(ipt, "1.1.1.0/24")
      iex>
      iex> lookup(ipt, "1.1.1.1")
      nil
      iex>
      iex> Map.get(ipt, 32) |> Radix.keys()
      [<<2, 2, 2>>]

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", "one")
      ...> |> put("2.2.2.0/24", "two")
      ...> |> put("abba:1973::/32", "Ring Ring")
      ...> |> put("acdc:1975::/32", "T.N.T")
      iex>
      iex> ipt = delete(ipt, ["1.1.1.0/24", "abba:1973::/32"])
      iex>
      iex> Map.get(ipt, 32) |> Radix.keys()
      [<<2, 2, 2>>]
      iex>
      iex> Map.get(ipt, 128) |> Radix.keys()
      [<<0xacdc::16, 0x1975::16>>]

  """
  @spec delete(t, prefix) :: t
  def delete(%__MODULE__{} = trie, prefixes) when is_list(prefixes),
    do: Enum.reduce(prefixes, trie, fn pfx, trie -> delete(trie, pfx) end)

  def delete(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen)
      Map.put(trie, pfx.maxlen, Radix.delete(tree, pfx.bits))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Return the `t:prefix.t/0`,value--pair, whose key represents the longest possible
  prefix for the given search *prefix* or `nil` if nothing matched.

  Silently ignores any errors when encoding given *prefix* by returning nil.

  ## Example

  """
  @spec lookup(t(), prefix()) :: {prefix(), any} | nil
  def lookup(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.lookup(tree, pfx.bits) do
        nil -> nil
        {bits, value} -> {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
      end
    rescue
      ArgumentError -> nil
    end
  end

  @doc """
  Return all the `t:prefix.t/0`,value--pairs where the given search `prefix` is
  a prefix for the stored radix key.

  Note that any bitstring is always a prefix of itself.  So, if present, the
  search key will be included in the result.

  If `prefix` is not valid, or cannot be encoded as an Ipv4 op IPv6 `Pfx`, nil
  is returned.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/25", "A25-lower")
      ...> |> put("1.1.1.128/25", "A25-upper")
      ...> |> put("1.1.1.0/30", "A30")
      ...> |> put("1.1.2.0/24", "B24")
      iex>
      iex> more(ipt, "1.1.1.0/24")
      [
        {"1.1.1.0/30", "A30"},
        {"1.1.1.0/25", "A25-lower"},
        {"1.1.1.128/25", "A25-upper"}
      ]

  """
  @spec more(t(), prefix()) :: list({prefix(), any})
  def more(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.more(tree, pfx.bits) do
        [] ->
          []

        list ->
          Enum.map(list, fn {bits, value} ->
            {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
          end)
      end
    rescue
      ArgumentError -> []
    end
  end

  @doc """
  Return all the `t:prefix.t/0`,value--pairs whose `t:prefix.t/0` bits are a
  prefix to given search `prefix`.

  Note that any bitstring is always a prefix of itself.  So, if present, the
  search key will be included in the result.

  If `prefix` is not present or not valid, or cannot be encoded as an Ipv4 op
  IPv6 `Pfx`, an empty list is returned.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/25", "A25-lower")
      ...> |> put("1.1.1.128/25", "A25-upper")
      ...> |> put("1.1.1.0/30", "A30")
      ...> |> put("1.1.2.0/24", "B24")
      iex>
      iex> less(ipt, "1.1.1.0/30")
      [
        {"1.1.1.0/30", "A30"},
        {"1.1.1.0/25", "A25-lower"},
      ]
      iex> less(ipt, "2.2.2.2")
      []

  """
  @spec less(t(), prefix()) :: list({prefix(), any})
  def less(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.less(tree, pfx.bits) do
        [] ->
          []

        list ->
          Enum.map(list, fn {bits, value} ->
            {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
          end)
      end
    rescue
      ArgumentError -> []
    end
  end
end
