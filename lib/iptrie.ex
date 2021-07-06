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

  @empty_rdx {0, nil, nil}

  # Helpers

  defp types(%Iptrie{} = trie),
    do: Map.keys(trie) |> Enum.filter(fn x -> is_integer(x) end)

  # defp radixes(%Iptrie{} = trie),
  #   do: Map.values(trie) |> Enum.filter(fn x -> is_tuple(x) end)

  # API
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
  def get(%__MODULE__{} = trie, prefixes) when is_list(prefixes),
    do: Enum.map(prefixes, fn prefix -> get(trie, prefix) end)

  def get(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)

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
  def put(%__MODULE__{} = trie, elements) when is_list(elements),
    do: Enum.reduce(elements, trie, fn {k, v}, t -> put(t, k, v) end)

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
      tree = radix(trie, pfx.maxlen)
      Map.put(trie, pfx.maxlen, Radix.put(tree, pfx.bits, value))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Delete one or more prefix, value-pairs from the `trie` using an exact match.

  The list of prefixes to delete may contain all _types_, so all sorts of
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
  @spec delete(t, prefix | list(prefix)) :: t
  def delete(%__MODULE__{} = trie, prefixes) when is_list(prefixes),
    do: Enum.reduce(prefixes, trie, fn pfx, trie -> delete(trie, pfx) end)

  def delete(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)
      Map.put(trie, pfx.maxlen, Radix.delete(tree, pfx.bits))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Fetches the prefix,value-pair for given `prefix` from `trie` (exact match).

  In case of success, returns {:ok, {prefix, value}}.  
  If `prefix` is not present, returns `{:error, :notfound}`.  
  In case of encoding errors for `prefix`, returns `{:error, :notprefix}`

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", "one")
      ...> |> put("2.2.2.0/24", "two")
      iex>
      iex> fetch(ipt, "1.1.1.0/24")
      {:ok, {"1.1.1.0/24", "one"}}
      iex>
      iex> fetch(ipt, "12.12.12.12")
      {:error, :notfound}
      iex>
      iex> fetch(ipt, "13.13.13.333")
      {:error, :notprefix}

  """
  @spec fetch(t, prefix) :: {:ok, {prefix, any}} | {:error, atom}
  def fetch(%Iptrie{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)

      case Radix.get(tree, pfx.bits) do
        nil -> {:error, :notfound}
        {bits, value} -> {:ok, {Pfx.marshall(%{pfx | bits: bits}, prefix), value}}
      end
    rescue
      ArgumentError -> {:error, :notprefix}
    end
  end

  @doc """
  Fetches the prefix,value-pair for given `prefix` from `trie` (exact match).

  In case of success, returns {prefix, value}.  
  If `prefix` is not present, raises a `KeyError`.  
  If `prefix` could not be encoded, raises an `ArgumentError`.

  ## Example

      iex> ipt = new()
      ...> |> put("10.10.10.0/24", "ten")
      ...> |> put("11.11.11.0/24", "eleven")
      iex>
      iex> fetch!(ipt, "10.10.10.0/24")
      {"10.10.10.0/24", "ten"}
      iex>
      iex> fetch!(ipt, "12.12.12.12")
      ** (KeyError) prefix "12.12.12.12" not found

      iex> ipt = new()
      iex> fetch!(ipt, "13.13.13.333")
      ** (ArgumentError) invalid prefix "13.13.13.333"

  """
  @spec fetch!(t, prefix) :: {prefix, any} | KeyError | ArgumentError
  def fetch!(%Iptrie{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)

      case Radix.get(tree, pfx.bits) do
        nil -> raise KeyError, "prefix #{inspect(prefix)} not found"
        {bits, value} -> {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
      end
    rescue
      ArgumentError -> raise ArgumentError, "invalid prefix #{inspect(prefix)}"
    end
  end

  @doc """
  Finds a prefix,value-pair for given `prefix` from `trie` (longest match).

  In case of success, returns {:ok, {prefix, value}}.  
  If `prefix` had no match, returns `{:error, :notfound}`.  
  In case of encoding errors for `prefix`, returns `{:error, :notprefix}`

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", "one")
      ...> |> put("2.2.2.0/24", "two")
      iex>
      iex> find(ipt, "1.1.1.0/24")
      {:ok, {"1.1.1.0/24", "one"}}
      iex>
      iex> find(ipt, "12.12.12.12")
      {:error, :notfound}
      iex>
      iex> find(ipt, "13.13.13.333")
      {:error, :notprefix}

  """
  @spec find(t, prefix) :: {:ok, {prefix, any}} | {:error, atom}
  def find(%Iptrie{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)

      case Radix.lookup(tree, pfx.bits) do
        nil -> {:error, :notfound}
        {bits, value} -> {:ok, {Pfx.marshall(%{pfx | bits: bits}, prefix), value}}
      end
    rescue
      ArgumentError -> {:error, :notprefix}
    end
  end

  @doc """
  Finds a prefix,value-pair for given `prefix` from `trie` (longest match).

  In case of success, returns {prefix, value}.  
  If `prefix` had no match, raises a `KeyError`.  
  If `prefix` could not be encoded, raises an `ArgumentError`.

  ## Example

      iex> ipt = new()
      ...> |> put("10.10.10.0/24", "ten")
      ...> |> put("11.11.11.0/24", "eleven")
      iex>
      iex> find!(ipt, "10.10.10.0/24")
      {"10.10.10.0/24", "ten"}
      iex>
      iex> find!(ipt, "12.12.12.12")
      ** (KeyError) prefix "12.12.12.12" not found

      iex> ipt = new()
      iex> find!(ipt, "13.13.13.333")
      ** (ArgumentError) invalid prefix "13.13.13.333"

  """
  @spec find!(t, prefix) :: {prefix, any} | KeyError | ArgumentError
  def find!(%Iptrie{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)

      case Radix.lookup(tree, pfx.bits) do
        nil -> raise KeyError, "prefix #{inspect(prefix)} not found"
        {bits, value} -> {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
      end
    rescue
      ArgumentError -> raise ArgumentError, "invalid prefix #{inspect(prefix)}"
    end
  end

  @doc ~S"""
  Returns a new Iptrie, keeping only the entries for which `fun` returns _truthy_.

  The signature for `fun` is (key, maxlen, value -> boolean), where the (radix)
  key is the original bitstring of the prefix of type maxlen, used to store some
  value in that particular radix tree in given `trie`.

  Radix trees that are empty, are removed from the new Iptrie.

  Note that, if need be, `Pfx.new(key, maxlen)` reconstructs the original
  prefix used to store the value in the `trie`.


  ## Example

      iex> ipt = new()
      ...> |> put("acdc:1975::/32", "rock")
      ...> |> put("acdc:1976::/32", "rock")
      ...> |> put("abba:1975::/32", "pop")
      ...> |> put("abba:1976::/32", "pop")
      ...> |> put("1.1.1.0/24", "v4")
      iex>
      iex> filter(ipt, fn _bits, maxlen, _value -> maxlen == 32 end)
      ...> |> to_list()
      [{%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, "v4"}]
      iex>
      iex> filter(ipt, fn _bits, _max, value -> value == "rock" end)
      ...> |> to_list()
      ...> |> Enum.map(fn {pfx, value} -> {"#{pfx}", value} end)
      [
        {"acdc:1975:0:0:0:0:0:0/32", "rock"},
        {"acdc:1976:0:0:0:0:0:0/32", "rock"}
      ]

  """
  @spec filter(t, (bitstring, non_neg_integer, any -> boolean)) :: t
  def filter(%Iptrie{} = trie, fun) when is_function(fun, 3) do
    types(trie)
    |> Enum.map(fn type -> {type, filterp(radix(trie, type), type, fun)} end)
    |> Enum.filter(fn {_t, rdx} -> rdx != @empty_rdx end)
    |> Enum.reduce(Iptrie.new(), fn {type, rdx}, ipt -> Map.put(ipt, type, rdx) end)
  end

  defp filterp(rdx, type, fun) do
    keep = fn key, val, acc ->
      if fun.(key, type, val), do: Radix.put(acc, key, val), else: acc
    end

    Radix.reduce(rdx, Radix.new(), keep)
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
    radix(trie, type)
    |> Radix.keys()
    |> Enum.map(fn bits -> Pfx.new(bits, type) end)
  end

  def keys(%Iptrie{} = trie, types) when is_list(types) do
    Enum.map(types, fn type -> keys(trie, type) end)
    |> List.flatten()
  end

  @doc ~S"""
  Return all prefixes stored in all available radix trees in `trie`.

  The prefixes are reconstructed as `t:Pfx.t/0` by combining the stored bitstrings
  with the `Radix`-tree's type.e. maxlen property).

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> keys(ipt)
      [
        %Pfx{bits: <<1, 1, 1>>, maxlen: 32},
        %Pfx{bits: <<2, 2, 2>>, maxlen: 32},
        %Pfx{bits: <<0xacdc::16, 0x1975::16>>, maxlen: 128},
        %Pfx{bits: <<0xacdc::16, 0x2021::16>>, maxlen: 128}
      ]
      iex>
      iex> radix(ipt, 32) |> Radix.keys()
      [
        <<1, 1, 1>>,
        <<2, 2, 2>>
      ]

  """
  @spec keys(t) :: list(prefix)
  def keys(%Iptrie{} = trie) do
    keys(trie, types(trie))
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
  def values(%Iptrie{} = trie, type) when is_integer(type),
    do: radix(trie, type) |> Radix.values()

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
    values(trie, types(trie))
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
      tree = radix(trie, pfx.maxlen)

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
      tree = radix(trie, pfx.maxlen)

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
      tree = radix(trie, pfx.maxlen)

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
      tree = radix(trie, pfx.maxlen)

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
      ...> |> update("2.2.2.2", 0, fn x -> x + 1 end)
      iex> lookup(ipt, "1.1.1.2")
      {"1.1.1.0/24", 2}
      iex>
      iex> # probably not what you wanted:
      iex>
      iex> lookup(ipt, "2.2.2.2")
      {"2.2.2.2", 0}

  """
  @spec update(t, prefix, any, (any -> any)) :: t
  def update(%__MODULE__{} = trie, prefix, default, fun) when is_function(fun, 1) do
    try do
      pfx = Pfx.new(prefix)
      tree = radix(trie, pfx.maxlen)
      Map.put(trie, pfx.maxlen, Radix.update(tree, pfx.bits, default, fun))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Returns the prefix,value-pairs from the radix trees in `trie` for given
  `type`(s).

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
    tree = radix(trie, type)

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
    to_list(trie, types(trie))
  end

  @doc """
  Invoke `fun` on each prefix,value-pair in the radix tree for given `type`

  This simply wraps `Radix.reduce/3` for the radix tree in `trie` at given
  `type`.  The function `fun` is called with the radix key, value and `acc`
  accumulator and should return an updated accumulator.  The result is the last
  `acc` accumulator returned.

  If `type` is a list of `type`'s, the `acc` accumulator is updated across all
  radix trees of `type`'s.  Probably not entirely usefull, but there you go.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> reduce(ipt, 32, 0, fn _key, value, acc -> acc + value end)
      3
      iex> reduce(ipt, 48, 0, fn _key, value, acc -> acc + value end)
      0
      iex> reduce(ipt, 128, 0, fn _key, value, acc -> acc + value end)
      7
      iex>
      iex> reduce(ipt, [32, 48, 128], 0, fn _key, value, acc -> acc + value end)
      10

  """
  @spec reduce(t, non_neg_integer | list(non_neg_integer), any, (bitstring, any, any -> any)) ::
          any
  def reduce(%Iptrie{} = trie, type, acc, fun) when is_integer(type) and is_function(fun, 3),
    do: radix(trie, type) |> Radix.reduce(acc, fun)

  def reduce(%Iptrie{} = trie, types, acc, fun) when is_list(types) and is_function(fun, 3) do
    types
    |> Enum.map(fn type -> radix(trie, type) end)
    |> Enum.reduce(acc, fn tree, acc -> Radix.reduce(tree, acc, fun) end)
  end

  @doc """
  Invoke `fun` on all prefix,value-pairs in all radix trees in the `trie`.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> reduce(ipt, 0, fn _key, value, acc -> acc + value end)
      10
      iex>
      iex> reduce(ipt, %{}, fn key, value, acc -> Map.put(acc, key, value) end)
      %{<<1, 1, 1>> => 1, <<2, 2, 2>> => 2, <<172, 220, 25, 117>> => 3, <<172, 220, 32, 33>> => 4}

  """
  @spec reduce(t, any, (bitstring, any, any -> any)) :: any
  def reduce(%Iptrie{} = trie, acc, fun) do
    reduce(trie, types(trie), acc, fun)
  end

  @doc """
  Return the radix tree for given `type` or a new empty tree.

  If there is no `Radix` tree for given `type`, an empty radix will be returned
  without storing it in the `trie`.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> radix(ipt, 32)
      {0, {6, [{<<1, 1, 1>>, 1}], [{<<2, 2, 2>>, 2}]}, nil}
      iex>
      iex> radix(ipt, 128)
      {0, nil, {18, [{<<172, 220, 25, 117>>, 3}], [{<<172, 220, 32, 33>>, 4}]}}
      iex> radix(ipt, 48)
      {0, nil, nil}

  """
  @spec radix(t, integer) :: Radix.tree()
  def radix(%Iptrie{} = trie, type) when is_integer(type),
    do: Map.get(trie, type) || @empty_rdx
end
