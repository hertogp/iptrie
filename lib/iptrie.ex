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
  Create a new Iptrie, populated via a list of {`t:prefix/0`, `t:any/0`}-pairs.

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
  Return one or more prefix,value-pair(s) using an exact match for given `prefix(es)`.

  ## Examples

      iex> ipt = new([{"1.1.1.0/30", "A"}, {"1.1.1.0/31", "B"}, {"1.1.1.0", "C"}])
      iex>
      iex> get(ipt, "1.1.1.0/31")
      {"1.1.1.0/31", "B"}
      iex>
      iex> # or get a list of entries
      iex>
      iex> get(ipt, ["1.1.1.0/30", "1.1.1.0"])
      [{"1.1.1.0/30", "A"}, {"1.1.1.0", "C"}]

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
  Populate the `trie` with a list of {prefix,value}-pairs.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.  Any errors are silently ignored as the trie is always returned.

  ## Example

      iex> ipt = new([{"1.1.1.0/24", 0}, {"1.1.1.1", 0}, {"1.1.1.1", "x"}])
      iex>
      iex> get(ipt, "1.1.1.1")
      {"1.1.1.1", "x"}

  """
  @spec put(t, list({prefix(), any})) :: t
  def put(%__MODULE__{} = trie, elements) when is_list(elements) do
    Enum.reduce(elements, trie, fn {k, v}, t -> put(t, k, v) end)
  end

  @doc """
  Puts `value` under `prefix` in the `trie`.

  This always uses an exact match for *prefix*, replacing its value if it
  exists.  Any errors are silently ignored as the tree is always returned.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 0)
      ...> |> put("1.1.1.1", 1)
      ...> |> put("1.1.1.1", "x")
      iex>
      iex> get(ipt, "1.1.1.1")
      {"1.1.1.1", "x"}

  """
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
  Delete one or more prefix, value-pair(s) from the `trie` using an exact match.

  The list of prefixes to delete may contains all __types__, so all sorts of
  prefixes can be deleted from multiple radix trees in one go.

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

  @doc ~S"""
  Return the  prefixes stored in the radix tree(s) in `trie` for given `type`.

  Where `type` is a single maxlen or a list thereof.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> keys(ipt, 32)
      [
        %Pfx{bits: <<1, 1, 1>>, maxlen: 32},
        %Pfx{bits: <<2, 2, 2>>, maxlen: 32}
      ]
      iex>
      iex> keys(ipt, 128)
      [
        %Pfx{bits: <<0xacdc::16, 0x1975::16>>, maxlen: 128},
        %Pfx{bits: <<0xacdc::16, 0x2021::16>>, maxlen: 128}
      ]
      iex>
      iex> keys(ipt, 48)
      []
      iex>
      iex> keys(ipt, [32, 48, 128])
      [
        %Pfx{bits: <<1, 1, 1>>, maxlen: 32},
        %Pfx{bits: <<2, 2, 2>>, maxlen: 32},
        %Pfx{bits: <<0xacdc::16, 0x1975::16>>, maxlen: 128},
        %Pfx{bits: <<0xacdc::16, 0x2021::16>>, maxlen: 128}
      ]

  """
  @spec keys(t, integer | list(integer)) :: list(prefix)
  def keys(%Iptrie{} = trie, type) when is_integer(type) do
    tree = Map.get(trie, type) || Radix.new()

    tree
    |> Radix.keys()
    |> Enum.map(fn bits -> Pfx.new(bits, type) end)
  end

  def keys(%Iptrie{} = trie, types) when is_list(types) do
    Enum.map(types, fn type -> keys(trie, type) end)
    |> List.flatten()
  end

  @doc ~S"""
  Return all prefixes stored in all available radix trees in `trie`.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> keys(ipt)
      ...> |> Enum.map(fn x -> "#{x}" end)
      [
        "1.1.1.0/24",
        "2.2.2.0/24",
        "acdc:1975:0:0:0:0:0:0/32",
        "acdc:2021:0:0:0:0:0:0/32"
      ]

  """
  @spec keys(t) :: list(prefix)
  def keys(%Iptrie{} = trie) do
    types =
      Map.keys(trie)
      |> Enum.filter(fn x -> is_integer(x) end)

    keys(trie, types)
  end

  @doc ~S"""
  Return the values stored in the radix trees in `trie` for given `type`.

  Where `type` is a either single maxlen or a list thereof.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> values(ipt, 32)
      [1, 2]
      iex>
      iex> values(ipt, 128)
      [3, 4]
      iex>
      iex> values(ipt, 48)
      []
      iex>
      iex> values(ipt, [32, 48, 128])
      [1, 2, 3, 4]

  """
  @spec values(t, integer | list(integer)) :: list(any)
  def values(%Iptrie{} = trie, type) when is_integer(type) do
    tree = Map.get(trie, type) || Radix.new()
    Radix.values(tree)
  end

  def values(%Iptrie{} = trie, types) when is_list(types) do
    Enum.map(types, fn type -> values(trie, type) end)
    |> List.flatten()
  end

  @doc ~S"""
  Return all the values stored in all radix trees in `trie`.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> values(ipt)
      [1, 2, 3, 4]

  """
  @spec values(t) :: list(any)
  def values(%Iptrie{} = trie) do
    types =
      Map.keys(trie)
      |> Enum.filter(fn x -> is_integer(x) end)

    values(trie, types)
  end

  @doc """
  Return the prefix,value-pair, whose prefix is the longest match for given search `prefix`.

  Returns nil if there is no match for search `prefix`.  
  Silently ignores any errors when encoding the given search `prefix` by returning nil.

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
  Return all the prefix,value-pairs where the search `prefix` is a prefix for
  the stored prefix.

  This returns the more specific entries that are enclosed by given search
  `prefix`.  Note that any bitstring is always a prefix of itself.  So, if
  present, the search `prefix` will be included in the result.

  If `prefix` is not valid, or cannot be encoded as an Ipv4 op IPv6 `t:Pfx.t`, nil
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
  Return all the prefix,value-pairs whose prefix is a prefix for the given
  search `prefix`.

  This returns the less specific entries that enclose the given search
  `prefix`.  Note that any bitstring is always a prefix of itself.  So, if
  present, the search key will be included in the result.

  If `prefix` is not present or not valid, or cannot be encoded as an Ipv4 op
  IPv6 `t:Pfx.t/0`, an empty list is returned.

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

  @doc """
  Lookup `prefix` and update the matched entry, only if found.

  Uses longest prefix match, so search `prefix` is usually matched by some less
  specific prefix.  If matched, `fun` is called on its value.  If
  `prefix` had no longest prefix match, the `trie` is returned unchanged.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 0)
      ...> |> update("1.1.1.0", fn x -> x + 1 end)
      ...> |> update("1.1.1.1", fn x -> x + 1 end)
      ...> |> update("2.2.2.2", fn x -> x + 1 end)
      iex> get(ipt, "1.1.1.0/24")
      {"1.1.1.0/24", 2}
      iex> lookup(ipt, "2.2.2.2")
      nil

  """
  @spec update(t, prefix, (any -> any)) :: t
  def update(%__MODULE__{} = trie, prefix, fun) when is_function(fun, 1) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.lookup(tree, pfx.bits) do
        nil -> trie
        {bits, value} -> Map.put(trie, pfx.maxlen, Radix.put(tree, bits, fun.(value)))
      end
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Lookup `prefix` and, if found,  update its value or insert the default.

  Uses longest prefix match, so search `prefix` is usually matched by some less
  specific prefix.  If matched, `fun` is called on the entry's value.  If
  `prefix` had no longest prefix match, the default is inserted and `fun` is
  not called.

  ## Example

      iex> ipt = new()
      ...> |> update("1.1.1.0/24", 0, fn x -> x + 1 end)
      ...> |> update("1.1.1.0", 0, fn x -> x + 1 end)
      ...> |> update("1.1.1.1", 0, fn x -> x + 1 end)
      iex> lookup(ipt, "1.1.1.2")
      {"1.1.1.0/24", 2}

  """
  @spec update(t, prefix, any, (any -> any)) :: t
  def update(%__MODULE__{} = trie, prefix, default, fun) when is_function(fun, 1) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()
      Map.put(trie, pfx.maxlen, Radix.update(tree, pfx.bits, default, fun))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Returns all prefix,values-pairs from a radix tree in `trie` for given `type`

  If the radix tree for `type` does not exist, an empty list is returned.
  If `type` is a list of types, a flat list of all prefix,value-pairs of all
  radix trees of given types is returned.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> to_list(ipt, 32)
      [
        {%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, 1},
        {%Pfx{bits: <<2, 2, 2>>, maxlen: 32}, 2}
      ]
      iex> to_list(ipt, [32, 48, 128])
      [
        {%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, 1},
        {%Pfx{bits: <<2, 2, 2>>, maxlen: 32}, 2},
        {%Pfx{bits: <<0xacdc::16, 0x1975::16>>, maxlen: 128}, 3},
        {%Pfx{bits: <<0xacdc::16, 0x2021::16>>, maxlen: 128}, 4}
      ]

  """
  @spec to_list(t, non_neg_integer | list(non_neg_integer)) :: list({prefix, any})
  def to_list(%Iptrie{} = trie, type) when is_integer(type) do
    tree = Map.get(trie, type) || Radix.new()

    Radix.to_list(tree)
    |> Enum.map(fn {bits, value} -> {Pfx.new(bits, type), value} end)
  end

  def to_list(%Iptrie{} = trie, types) when is_list(types) do
    types
    |> Enum.map(fn type -> to_list(trie, type) end)
    |> List.flatten()
  end

  @doc """
  Return all prefix,value-pairs from all available radix trees in `trie`.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> to_list(ipt)
      [
        {%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, 1},
        {%Pfx{bits: <<2, 2, 2>>, maxlen: 32}, 2},
        {%Pfx{bits: <<0xacdc::16, 0x1975::16>>, maxlen: 128}, 3},
        {%Pfx{bits: <<0xacdc::16, 0x2021::16>>, maxlen: 128}, 4}
      ]

  """
  @spec to_list(t) :: list({prefix, any})
  def to_list(%Iptrie{} = trie) do
    types =
      Map.keys(trie)
      |> Enum.filter(fn x -> is_integer(x) end)

    to_list(trie, types)
  end
end
