defmodule Iptrie do
  # 10cc

  @moduledoc """
  A Key,Value-store for IPv4 and IPv6 networks or addresses with
  longest prefix matching.

  ## Example

      iex> elements = [{"1.1.1.0/24", 24}, {"3.0.0.0/8", 8},
      ...>  {"1.1.1.0/25", "lower"}, {"1.1.1.128/25", "upper"},
      ...>  {"acdc:1975::", "T.N.T"}, {"acdc:1976::", "High Voltage"},
      ...>  {"10cc:1973::", "10cc"}, {"10cc:1978::", "Bloody Tourist"}]
      iex> ipt = new(elements)
      iex> Iptrie.Dot.write(ipt, "./doc/img/example.dot", "Iptrie")
      :ok

  ![example](img/example.dot.png)

  """
  import Prefix
  import Prefix.IP
  alias PrefixError
  alias Radix
  alias Iptrie.Dot

  defstruct root: nil

  @typedoc """
  An Iptrie struct whose root is a `Radix` tree.

  See `t:Radix.tree/0`.

  """
  @type t :: %__MODULE__{root: Radix.tree() | nil}

  @typedoc """
  A prefix value: either a CIDR-string, address-tuple, {address,len}-tuple or a Prefix struct.

  Examples:
  - "1.1.1.1" or "1.1.1.0/24" as an IPv4 CIDR-string
  - {1, 1, 1, 1} IPv4 address-tuple
  - {{1, 1, 1, 0}, 24} IPv4 {address, len}-tuple
  - %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 32} a IPv4 prefix
  - "acdc:1976::" or "acdc:1976::/32" as an IPv6 CIDR-string
  - {0xacdc, 0x1976, 0, 0, 0, 0, 0, 0} IPv6 address-tuple
  - {{0xacdc, 0x1976, 0, 0, 0, 0, 0, 0}, 32} IPv6 {address, len}-tuple
  - %Prefix{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128} an IPv6 prefix

  """
  @type prefix :: Prefix.t() | Prefix.IP.address() | Prefix.IP.digits() | String.t()

  @typedoc """
  A {prefix,value}-pair which can be stored in an Iptrie as a {key,value}-pair.

  Note that the *prefix* will be encoded as a radix key, see `t:rdx_key/0`,
  which can be translated back into a CIDR-string or a Prefix struct.

  """
  @type pfxval :: {prefix(), any()}

  @typedoc """
  A radix key used to navigate the tree and store any value in its leafs.

  A radix key is basically a `t:Prefix.t/0`'s `bits` field, prepended with
  either a `0`-bit (IPv4) or a `1`-bit (IPv6).  Hence, an Iptrie's `root`
  left subtree is all IPv4, while its `root` right subtree contains all the
  IPv6 prefixes.

  """
  @type rdx_key :: bitstring

  @typedoc """
  A {key, value}-pair as *stored* in the Iptrie.

  The radix key consists of the encoded `t:prefix/0`-bits with either a `0`-bit
  prepended for an IPv4 prefix or a `1`-bit for IPv6 prefixes.

  """
  @type keyval :: {rdx_key(), any()}

  # IP v4/v6 markers
  @ip4 <<0::1>>
  @ip6 <<1::1>>

  # Key/Unkey
  # - key returns a prefix's bits with an IPv4/IPv6 marker preprended
  # - unkey does the opposite and returns the original prefix
  # used so both IPv4 and IPv6 can be stuffed down the same Radix tree

  @doc """
  Turn a `t:Prefix.t/0` into a radix key.

  A radix key simply consists of the prefix's bitstring with a `0` or `1`-bit
  prepended to differentiate between IPv4 resp. IPv6 prefixes.  The radix tree
  used by Iptrie will have IPv4 as its root's left subtree, while the right
  subtree holds all IPv6 prefixes.

  """
  @spec key(Prefix.t()) :: rdx_key()
  def key(%Prefix{bits: bits, maxlen: 32}),
    do: <<@ip4, bits::bitstring>>

  def key(%Prefix{bits: bits, maxlen: 128}),
    do: <<@ip6, bits::bitstring>>

  @spec unkey(rdx_key()) :: Prefix.t()
  def unkey(<<@ip4, bits::bitstring>>),
    do: %Prefix{bits: bits, maxlen: 32}

  def unkey(<<@ip6, bits::bitstring>>),
    do: %Prefix{bits: bits, maxlen: 128}

  @doc """
  Turn a radix key back into a readable string in CIDR-notation.

  Used by the `Dot` module when dumping a `Radix` tree to a graphviz dot file.
  Otherwise, only useful for the curious when wanting to inspect the radix key
  after retrieving a `t:keyval/0` value from the iptrie.

  ## Example

      iex> rdx_key_tostr(<<0, 128, 128, 1::size(1)>>)
      "1.1.1.0/24"

  """
  @spec rdx_key_tostr(rdx_key()) :: String.t()
  def rdx_key_tostr(key) do
    key
    |> unkey()
    |> decode()
  end

  # Tree functions

  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      %Iptrie{root: {0, nil, nil}}

  """
  @spec new() :: t()
  def new,
    do: %__MODULE__{root: Radix.new()}

  @doc """
  Create a new Iptrie populated with the given {`t:prefix/0`,value}-pairs.

  ## Example

      iex> elements = [
      ...> {"1.1.1.0/24", "A"},
      ...> {{{1, 1, 1, 0}, 25}, "A1"},
      ...> {%Prefix{bits: <<1, 1, 1, 1::1>>, maxlen: 32}, "A2"},
      ...> {{{44252, 6517, 0, 0, 0, 0, 0, 0}, 32}, "TNT"} ]
      iex>
      iex> new(elements)
      %Iptrie{root: {0,
                      {25, [{<<0::1, 1, 1, 1, 0::1>>, "A1"}, {<<0::1, 1, 1, 1>>, "A"}],
                      [{<<0::1, 1, 1, 1, 1::1>>, "A2"}]},
                      [{<<1::1, 0xACDC::16, 0x1975::16>>, "TNT"}]
                    }
      }

  """
  @spec new(list(pfxval())) :: t()
  def new(elements),
    do: new() |> set(elements)

  @doc """
  Return the {key,val}-pair where key is an exact match for given *prefix*,
  or a list of pairs for a list of prefixes.

  ## Examples

      iex> tree = new([{"1.1.1.0/30", "A"}, {"1.1.1.0/31", "B"}, {"1.1.1.0", "C"}])
      iex> get(tree, "1.1.1.0/31")
      {<<0::1, 1, 1, 1, 0::7>>, "B"}
      #
      iex> get(tree, "1.1.1.0/30")
      {<<0::1, 1, 1, 1, 0::6>>, "A"}
      #
      iex> get(tree, "1.1.1.0")
      {<<0::1, 1, 1, 1, 0>>, "C"}
      #
      iex> get(tree, {1, 1, 1, 0})
      {<<0::1, 1, 1, 1, 0>>, "C"}
      #
      iex> get(tree, {{1, 1, 1, 0}, 31})
      {<<0::1, 1, 1, 1, 0::7>>, "B"}
      #
      iex> get(tree, %Prefix{bits: <<1, 1, 1, 0::7>>, maxlen: 32})
      {<<0::1, 1, 1, 1, 0::7>>, "B"}

      iex> new() |> get("2.2.2.2")
      nil

      iex> new() |> get("2.2.2.256")
      %PrefixError{id: :encode, detail: "2.2.2.256"}

      iex> tree = new([{"1.1.1.0/30", "A"}, {"1.1.1.0/31", "B"}, {"1.1.1.0", "C"}])
      iex> get(tree, ["1.1.1.0/31", "1.1.1.0/30"])
      [{<<0::1, 1, 1, 1, 0::7>>, "B"}, {<<0::1, 1, 1, 1, 0::6>>, "A"}]

  """
  @spec get(t(), list(prefix())) :: list(pfxval() | PrefixError.t())
  def get(%__MODULE__{} = tree, prefixes) when is_list(prefixes) do
    Enum.map(prefixes, fn x -> get(tree, x) end)
  end

  @spec get(t(), prefix()) :: pfxval() | PrefixError.t()
  def get(%__MODULE__{} = tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> x
      x -> Radix.get(tree.root, key(x))
    end
  end

  @doc """
  Enter a single {prefix,value}-pair into an iptrie.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.  Any errors are silently ignored as the tree is always returned.

  ## Examples

      iex> new() |> set({"1.1.1.0/24", "A"})
      %Iptrie{root: {0, [{<<0, 128, 128, 1::size(1)>>, "A"}], nil}}

      iex> elements = [
      ...>  {"1.1.1.0/24", "A"},
      ...>  {{{1, 1, 2, 0}, 24}, "B"},
      ...>  {%Prefix{bits: <<1, 1, 3>>, maxlen: 32}, "C"}]
      iex>
      iex> new() |> set(elements)
      %Iptrie{root: {0, {23, [{<<0, 128, 128, 1::size(1)>>, "A"}],
                             {24, [{<<0, 128, 129, 0::size(1)>>, "B"}], 
                                  [{<<0, 128, 129, 1::size(1)>>, "C"}]}},
                         nil}}

      iex> new() |> set({"1.1.1.0/33", "illegal"})
      %Iptrie{root: {0, nil, nil}}

  """
  @spec set(t(), list(pfxval())) :: t()
  def set(%__MODULE__{} = tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn kv, t -> set(t, kv) end)
  end

  @spec set(t(), {prefix(), any()}) :: t() | PrefixError.t()
  def set(%__MODULE__{} = tree, {prefix, value}) do
    case encode(prefix) do
      x when is_exception(x) -> tree
      x -> %{tree | root: Radix.set(tree.root, key(x), value)}
    end
  end

  @doc """
  Delete a {key, value}-pair where key is an exact match for a given *prefix*,
  or delete {key, value}-pairs for a list of prefixes.

  If there is no match for given *prefix* it is silently ignored, as are any
  errors in encoding *prefix*.

  ## Example

      iex> t = new([{"1.1.1.0/24", "A"}, {"1.1.1.0/25", "A1"}])
      %Iptrie{root: {0, [{<<0, 128, 128, 2::size(2)>>, "A1"},
                         {<<0, 128, 128, 1::size(1)>>, "A"}],
                        nil}}
      #
      iex> del(t, "1.1.1.0/24")
      %Iptrie{root: {0, [{<<0, 128, 128, 2::size(2)>>, "A1"}], nil}}
      #
      iex> del(t, {{1, 1, 1, 0}, 24})
      %Iptrie{root: {0, [{<<0, 128, 128, 2::size(2)>>, "A1"}], nil}}
      #
      iex> del(t, %Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      %Iptrie{root: {0, [{<<0, 128, 128, 2::size(2)>>, "A1"}], nil}}


  """
  @spec del(t(), list(prefix())) :: t()
  def del(%__MODULE__{} = tree, prefixes) when is_list(prefixes) do
    Enum.reduce(prefixes, tree, fn pfx, t -> del(t, pfx) end)
  end

  @spec del(t(), prefix()) :: t()
  def del(%__MODULE__{} = tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> tree
      x -> %{tree | root: Radix.del(tree.root, key(x))}
    end
  end

  @doc """
  Return the `t:keyval/0`-pair, whose key represents the longest possible
  prefix for the given search *prefix* or `nil` if nothing matched.

  Silently ignores any errors when encoding given *prefix* by returning nil.

  ## Example

      iex> t = new([{"1.1.1.0/24", "A"}, {"1.1.1.0/25", "A1"}])
      iex> lookup(t, "1.1.1.127")
      {<<0::1, 1, 1, 1, 0::1>>, "A1"}
      iex> lookup(t, "1.1.1.127") |> elem(1)
      "A1"
      iex> lookup(t, {1, 1, 1, 127}) |> elem(1)
      "A1"
      iex> lookup(t, {{1, 1, 1, 127}, 32}) |> elem(1)
      "A1"
      iex> lookup(t, %Prefix{bits: <<1, 1, 1, 127>>, maxlen: 32}) |> elem(1)
      "A1"
      iex> lookup(t, "1.1.1.127") |> elem(0) |> rdx_key_tostr()
      "1.1.1.0/25"
      #
      iex> lookup(t, "2.2.2.2")
      nil

      # erroneous input simply yields nil too
      iex> new() |> lookup(42)
      nil

  """
  @spec lookup(t(), prefix()) :: term
  def lookup(%__MODULE__{} = tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> nil
      x -> Radix.lpm(tree.root, key(x))
    end
  end

  def lookup(_, _), do: nil

  @doc """
  Return all {key, value}-pairs where given *prefix* is a prefix of the key.

  This returns all subnets for given prefix, including itself if present.

  ## Example

      iex> tree = new([{"1.1.0.0/16", "A"}, {"1.1.1.0/24", "B"}, {"1.1.1.0/25", "C"}])
      iex> subnets(tree, "1.1.0.0/16")
      [
        {<<0::1, 1, 1, 1, 0::1>>, "C"},
        {<<0::1, 1, 1, 1>>, "B"},
        {<<0::1, 1, 1>>, "A"}
      ]
      #
      iex> subnets(tree, "1.1.1.0/24")
      [
        {<<0::1, 1, 1, 1, 0::1>>, "C"},
        {<<0::1, 1, 1, 1>>, "B"}
      ]
      #
      iex> subnets(tree, "1.1.1.0/25")
      [{<<0::1, 1, 1, 1, 0::1>>, "C"}]
      #
      # same as
      iex> subnets(tree, {{1,1,1,0}, 25})
      [{<<0::1, 1, 1, 1, 0::1>>, "C"}]
      #
      # same as
      iex> subnets(tree, %Prefix{bits: <<1, 1, 1, 0::1>>, maxlen: 32})
      [{<<0::1, 1, 1, 1, 0::1>>, "C"}]

  """
  @spec subnets(t(), prefix()) :: list(pfxval()) | PrefixError.t()
  def subnets(tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> x
      x -> Radix.rpm(tree.root, key(x))
    end
  end

  @doc """
  Return all {key, value}-pairs whose key is a prefix of given *prefix*.

  This returns all supernets including the given *prefix* if present or
  a `PrefixError` if given *prefix* is invalid.

  ## Example

      iex> tree = new([{"1.1.0.0/16", "A"}, {"1.1.1.0/24", "B"}, {"1.1.1.0/25", "C"}])
      iex> supernets(tree, "1.1.1.0")
      [
        {<<0::1, 1, 1, 1, 0::1>>, "C"},
        {<<0::1, 1, 1, 1>>, "B"},
        {<<0::1, 1, 1>>, "A"}
      ]
      #
      iex> supernets(tree, "1.1.1.0/25")
      [
        {<<0::1, 1, 1, 1, 0::1>>, "C"},
        {<<0::1, 1, 1, 1>>, "B"},
        {<<0::1, 1, 1>>, "A"}
      ]
      #
      iex> supernets(tree, "1.1.0.0/24")
      [
        {<<0::1, 1, 1>>, "A"}
      ]
      iex> supernets(tree, "2.2.2.2")
      []

  """
  @spec supernets(t(), prefix()) :: list(pfxval()) | PrefixError.t()
  def supernets(tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> x
      x -> Radix.apm(tree.root, key(x))
    end
  end

  @doc """
  Execute function *func* on all {key, value}-pairs in the Iptrie.

  The leafs are visited in-order and function `func` takes a stored
  {key,value}-pair and an accumulator of choice and returns the updated
  accumulator.

  ## Examples

  Convert an `t:Iptrie.t/0` to a map.

      iex> tree = new([{"1.1.0.0/16", "A"}, {"1.1.1.0/24", "C"}, {"1.1.1.0/25", "B"}])
      iex> m = map(tree, fn {k, v}, acc -> Map.put(acc, rdx_key_tostr(k), v) end, %{})
      iex> map_size(m)
      3
      iex> m["1.1.0.0/16"]
      "A"
      iex> m["1.1.1.0/25"]
      "B"
      iex> m["1.1.1.0/24"]
      "C"

  Collect all values into a list.  The leafs will be visited in-order, so the
  leaf in the left subtree is for "1.1.0.0/16" while the leaf in the right
  subtree holds "1.1.1.0/25" and "1.1.1.0/24" (in that order)

      iex> tree = new([{"1.1.0.0/16", "A"}, {"1.1.1.0/24", "C"}, {"1.1.1.0/25", "B"}])
      iex> map(tree, fn {_k,v}, acc -> [v | acc] end, []) |> Enum.reverse()
      ["A", "B", "C"]


  """
  @spec map(t(), (keyval(), any -> any), any) :: any
  def map(%__MODULE__{} = tree, func, acc) when is_function(func) do
    Radix.exec(tree.root, func, acc)
  end

  @doc """
  Execute function *func* on all {key, value}-pairs in the Iptrie and collect
  the results in a list.

  ## Example

      iex> tree = new([{"1.1.0.0/16", "A"}, {"1.1.1.0/24", "C"}, {"1.1.1.0/25", "B"}])
      iex> map(tree, fn {_k,v} -> v end)
      ["A", "B", "C"]

  """
  @spec map(t(), (keyval() -> any)) :: list()
  def map(%__MODULE__{} = tree, func) when is_function(func) do
    f = fn kv, acc -> [func.(kv) | acc] end

    tree
    |> map(f, [])
    |> Enum.reverse()
  end

  @doc """
  Dump an Iptrie to a simple graphviz dot file.  Returns `:ok` on success.

  """
  @spec dot(t(), binary) :: atom
  def dot(%__MODULE__{} = tree, fname),
    do: Dot.write(tree, fname)

  # Prefix functions

  @doc """
  Return the this-network address in CIDR-notation for given *prefix*.

  ## Examples

      iex> network("1.1.1.10/24")
      "1.1.1.0"

      iex> network({{1, 1, 1, 10}, 24})
      "1.1.1.0"

      iex> network(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.0"

      iex> network({1, 1, 1, 1})
      "1.1.1.1"

      iex> network(42)
      %PrefixError{id: :encode, detail: 42}
  """
  @spec network(prefix()) :: String.t() | PrefixError.t()
  def network(prefix) do
    prefix
    |> encode()
    |> padr()
    |> decode()
  end

  @doc """
  Return the broadcast address for given *prefix*.

  ## Examples

      iex> broadcast("1.1.1.10/24")
      "1.1.1.255"

      iex> broadcast({{1, 1, 1, 10}, 24})
      "1.1.1.255"

      iex> broadcast(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.255"

      iex> broadcast({1, 1, 1, 1})
      "1.1.1.1"

      iex> broadcast("1.1.1.256")
      %PrefixError{id: :encode, detail: "1.1.1.256"}

  """
  @spec broadcast(prefix()) :: String.t() | PrefixError.t()
  def broadcast(prefix) do
    prefix
    |> encode()
    |> padr(1)
    |> decode()
  end

  @doc """
  Return the list of host addresses for given *prefix*.

  ## Examples

      iex> hosts("1.1.1.0/30")
      ["1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"]

      iex> hosts({{1, 1, 1, 0}, 30})
      ["1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"]

      iex> hosts(%Prefix{bits: <<1, 1, 1, 0::6>>, maxlen: 32})
      ["1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"]

      iex> hosts("1.1.1.0/33")
      %PrefixError{detail: {{1, 1, 1, 0}, 33}, id: :encode}

  """
  @spec hosts(prefix()) :: list(String.t()) | PrefixError.t()
  def hosts(prefix) do
    prefix
    |> encode()
    |> case do
      x when is_exception(x) -> x
      x -> Enum.map(x, fn ip -> decode(ip) end)
    end
  end

  @doc """
  Returns the mask for given prefix.

  ## Examples

      iex> mask("1.1.1.0/22")
      "255.255.252.0"

      iex> mask({{1, 1, 1, 0}, 22})
      "255.255.252.0"

      iex> mask(%Prefix{bits: <<1, 1, 1::6>>, maxlen: 32})
      "255.255.252.0"

      iex> mask("1.1.1.256/24")
      %PrefixError{id: :encode, detail: "1.1.1.256/24"}

  """
  @spec mask(prefix()) :: String.t() | PrefixError.t()
  def mask(prefix) do
    prefix
    |> encode()
    |> bset(1)
    |> padr()
    |> decode()
  end

  @doc """
  Returns the inverse mask for given prefix.

  ## Example

      iex> inv_mask("1.1.1.0/23")
      "0.0.1.255"

      iex> inv_mask({{1, 1, 1, 0}, 23})
      "0.0.1.255"

      iex> inv_mask(%Prefix{bits: <<1, 1, 1::7>>, maxlen: 32})
      "0.0.1.255"

      iex> inv_mask("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec inv_mask(prefix()) :: String.t() | PrefixError.t()
  def inv_mask(prefix) do
    prefix
    |> encode()
    |> bset(0)
    |> padr(1)
    |> decode()
  end

  @doc """
  Returns the neighboring prefix such that both can be combined in a supernet.

  ## Example

      iex> neighbor("1.1.1.0/25")
      "1.1.1.128/25"

      iex> neighbor("1.1.1.128/25")
      "1.1.1.0/25"

      iex> neighbor({{1, 1, 1, 128}, 25})
      "1.1.1.0/25"

      iex> neighbor({1, 1, 1, 1})
      "1.1.1.0"

      iex> neighbor(%Prefix{bits: <<1, 1, 1, 1::1>>, maxlen: 32})
      "1.1.1.0/25"

      iex> neighbor("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  def neighbor(prefix) do
    {x, offset} =
      case encode(prefix) do
        x when is_exception(x) -> {x, 0}
        x -> {x, 1 - 2 * bit(x, bit_size(x.bits) - 1)}
      end

    sibling(x, offset)
    |> decode()
  end

  @doc """
  Jump to another prefix at distance `n`.

  This will wrap around the available address space without warning.

  ## Examples

      iex> jump("1.1.1.0/24", 0)
      "1.1.1.0/24"

      iex> jump("1.1.1.0/24", 1)
      "1.1.2.0/24"

      iex> jump("1.1.1.0/24", 256)
      "1.2.1.0/24"

      iex> jump("1.1.1.0/24", 256*256)
      "2.1.1.0/24"

      iex> jump("1.1.1.0/24", 256*256*256)
      "1.1.1.0/24"

      iex> jump("1.1.1.0/24", 1)
      "1.1.2.0/24"

      # other examples of wrapping around
      iex> jump("1.1.1.0/30", 64)
      "1.1.2.0/30"

      iex> jump("0.0.0.0", -1)
      "255.255.255.255"

      iex> jump("255.255.255.255", 1)
      "0.0.0.0"

      iex> jump({{255, 255, 255, 255}, 32}, 1)
      "0.0.0.0"

      iex> jump({255, 255, 255, 255}, 1)
      "0.0.0.0"

      iex> jump(%Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32}, 1)
      "0.0.0.0"

      # invalid prefix yields a PrefixError struct
      iex> jump("1.1.1.0/33", 1)
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec jump(prefix(), integer) :: String.t() | PrefixError.t()
  def jump(prefix, n) do
    prefix
    |> encode()
    |> sibling(n)
    |> decode()
  end

  @doc """
  Return the host address for the *nth*-member of the prefix.

  This will wrap around the available address space without warning.

  ## Examples

      iex> host("1.1.1.0/24", 129)
      "1.1.1.129"

      iex> host("1.1.1.0/24", 256)
      "1.1.1.0"

      iex> host({{1, 1, 1, 0}, 24}, 128)
      "1.1.1.128"

      iex> host(%Prefix{bits: <<1, 1, 1>>, maxlen:  32}, 128)
      "1.1.1.128"

      iex> host("1.1.1.0/33", 1)
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec host(prefix(), integer) :: String.t() | PrefixError.t()
  def host(prefix, nth) do
    prefix
    |> encode()
    |> member(nth)
    |> decode()
  end

  @doc """
  Return the number of host addresses available in given *prefix*.

  ## Example

      iex> numhosts("acdc:1976::/32")
      79228162514264337593543950336

      iex> numhosts("1.1.1.0/23")
      512

      iex> numhosts({{1, 1, 1, 0}, 23})
      512

      iex> numhosts(%Prefix{bits: <<1, 1, 1::7>>, maxlen: 32})
      512

      iex> numhosts({1, 1, 1, 1})
      1

      iex> numhosts("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec numhosts(prefix()) :: non_neg_integer | PrefixError.t()
  def numhosts(prefix) do
    prefix
    |> encode()
    |> size()
  end

  # IPv6 Addresses
  # - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  # - https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  # - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
  # - https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv
  # - https://en.wikipedia.org/wiki/IPv6_address
  # - https://en.wikipedia.org/wiki/6to4

  @doc """
  Returns true if *prefix* is a teredo address, false otherwise

  See [rfc4380](https://www.iana.org/go/rfc4380).

  ## Example

      iex> teredo?("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      true

      iex> teredo?("1.1.1.1")
      false

  """
  @spec teredo?(prefix() | PrefixError.t()) :: boolean
  def teredo?(prefix) do
    prefix
    |> encode()
    |> member?(%Prefix{bits: <<0x2001::16, 0::16>>, maxlen: 128})
  end

  @doc """
  Returns a map with the teredo address components or nil.

  Returns nil if *prefix* is not a teredo address, or simply invalid.

  ## Example

      # https://en.wikipedia.org/wiki/Teredo_tunneling#IPv6_addressing
      iex> teredo("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      %{
        prefix: "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        client: "192.0.2.45",
        server: "65.54.227.120",
        flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        port: 40000
      }
  """
  @spec teredo(prefix) :: map | nil
  def teredo(prefix) do
    # https://www.rfc-editor.org/rfc/rfc4380.html#section-4
    x = encode(prefix)

    if teredo?(x) do
      %{
        server: cut(x, 32, 32) |> decode(),
        client: cut(x, 96, 32) |> bnot() |> decode(),
        port: cut(x, 80, 16) |> bnot() |> cast(),
        flags: cut(x, 64, 16) |> digits(1) |> elem(0),
        prefix: prefix
      }
    else
      nil
    end
  end

  @doc """
  Returns true is *prefix* is a multicast prefix, false otherwise

  ## Examples

      iex> multicast?("224.0.0.1")
      true

      iex> multicast?("ff02::1")
      true

  """
  @spec multicast?(prefix | PrefixError.t()) :: boolean
  def multicast?(prefix) do
    x = encode(prefix)

    cond do
      member?(x, %Prefix{bits: <<14::4>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<0xFF>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Returns a map with multicast address components.

  Returns nil if *prefix* is not a multicast address, or simply invalid.

  ## Examples

      iex> x = multicast("ff02::1")
      iex> x.preamble
      255
      iex> x.flags
      {0, 0, 0, 0}
      iex> x.scope
      2
      iex> x.groupID
      <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
      iex> x.address
      %Prefix{bits: <<0xff02::16, 0::104, 1::8>>, maxlen: 128}

  """
  @spec multicast(prefix) :: map | nil
  def multicast(prefix) do
    x = encode(prefix)

    if multicast?(x) do
      case x.maxlen do
        128 ->
          %{
            preamble: cut(x, 0, 8) |> cast(),
            flags: cut(x, 8, 4) |> digits(1) |> elem(0),
            scope: cut(x, 12, 4) |> cast(),
            groupID: bits(x, 16, 112),
            address: x
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            groupID: bits(x, 4, 28),
            address: x
          }
      end
    else
      nil
    end
  end

  @doc """
  Returns true if *prefix* is a link-local prefix, false otherwise

  See:
  - https://tools.ietf.org/html/rfc1122, 0.0.0.0/8       -> this-network (link)
  - https://www.iana.org/go/rfc3927,     169.254.0.0/16  -> link-local
  - https://tools.ietf.org/html/rfc4291, fe80::/16       -> link-local
  """
  @spec link_local?(prefix | PrefixError.t()) :: boolean
  def link_local?(prefix) do
    # rfc3927 and rfc4271 & friends
    # and https://en.wikipedia.org/wiki/IPv6_address#Default_address_selection
    x = encode(prefix)

    cond do
      member?(x, %Prefix{bits: <<169, 254>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<0>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<0xFE80::16, 0::48>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Return a map with link-local address components.

  Returns nil if *prefix* is not link-local or simply invalid.

  See:
  - https://www.iana.org/go/rfc3927
  - 
  """
  @spec link_local(prefix) :: map | nil
  def link_local(prefix) do
    x = encode(prefix)

    if link_local?(x) do
      case x.maxlen do
        128 ->
          %{
            preamble: cut(x, 0, 10) |> cast(),
            network: %Prefix{bits: bits(x, 0, 64), maxlen: 128} |> decode(),
            interfaceID: bits(x, 64, 64),
            prefix: prefix
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            network: %Prefix{bits: bits(x, 0, 16), maxlen: 32} |> decode(),
            hostID: bits(x, 16, 16),
            prefix: prefix
          }
      end
    end
  end

  @doc """
  Returns true if *prefix* is designated as "private-use".

  For IPv4 this includes the [rfc1918](https://www.iana.org/go/rfc1918)
  prefixes 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.  For IPv6 this
  includes the [rfc4193](https://www.iana.org/go/rfc4193) prefix fc00::/7.

  ## Examples

      iex> unique_local?("172.31.255.255")
      true

      iex> unique_local?("10.10.10.10")
      true

      iex> unique_local?("fc00:acdc::")
      true

      iex> unique_local?("172.32.0.0")
      false

  """
  def unique_local?(prefix) do
    x = encode(prefix)

    cond do
      member?(x, %Prefix{bits: <<10>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<172, 1::4>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<192, 168>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<126::7>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Returns true if *prefix* is matched by the Well-Known Prefixes as per
  [rfc6052](https://www.iana.org/go/rfc6052) and/or
  [rfc8215](https://www.iana.org/go/rfc8215), false otherwise.

  ## Example

      iex> nat64?("64:ff9b::10.10.10.10")
      true

      iex> nat64?("64:ff9b:1::10.10.10.10")
      true

  """
  @spec nat64?(prefix | PrefixError.t()) :: boolean
  def nat64?(prefix) do
    x = encode(prefix)

    member?(x, %Prefix{bits: <<0x0064::16, 0xFF9B::16, 0::64>>, maxlen: 128}) or
      member?(x, %Prefix{bits: <<0x0064::16, 0xFF9B::16, 1::16>>, maxlen: 128})
  end

  @doc """
  Return a map with ipv6 *prefix* and embedded *ipv4* address.

  Returns nil if the *prefix* given is not a full IPv6 address (or simply invalid)
  or *plen* is not one of: 32, 40, 48, 56, 64, or 96.

  *plen* defaults to `96`, but is also auto-corrected to either 96 or 48 if the
  *prefix* given is either the Well-Known prefix of
  [rfc6052](https://www.iana.org/go/rfc6052) or the Well-Known prefix of
  [rfc8215](https://www.iana.org/go/rfc8215).  Otherwise the *plen* must be
  specified for Network Specific prefixes.

  ## Example

      iex> nat64("64:ff9b::10.10.10.10")
      %{prefix: "64:ff9b::/96", ipv4: "10.10.10.10"}

      # auto-correct plen for Well-Known prefix
      iex> nat64("64:ff9b::10.10.10.10", 48)
      %{prefix: "64:ff9b::/96", ipv4: "10.10.10.10"}

      iex> nat64("64:ff9b:1:0a0a:000a:0a00::")
      %{prefix: "64:ff9b:1::/48", ipv4: "10.10.10.10"}

      # examples from rfc6052, section 2.4

      iex> nat64("2001:db8:c000:221::", 32)
      %{prefix: "2001:db8::/32", ipv4: "192.0.2.33"}

      iex> nat64("2001:db8:1c0:2:21::", 40)
      %{prefix: "2001:db8:100::/40", ipv4: "192.0.2.33"}

      iex> nat64("2001:db8:122:c000:2:2100::", 48)
      %{prefix: "2001:db8:122::/48", ipv4: "192.0.2.33"}

      iex> nat64("2001:db8:122:3c0:0:221::", 56)
      %{prefix: "2001:db8:122:300::/56", ipv4: "192.0.2.33"}

      iex> nat64("2001:db8:122:344:c0:2:2100::", 64)
      %{prefix: "2001:db8:122:344::/64", ipv4: "192.0.2.33"}

      iex> nat64("2001:db8:122:344::192.0.2.33", 96)
      %{prefix: "2001:db8:122:344::/96", ipv4: "192.0.2.33"}

      # legal lengths are 96, 64, 56, 48, 40 and 32
      iex> nat64("2001:db8:122:344::192.0.2.33", 90)
      nil

  """
  @spec nat64(prefix(), pos_integer) :: map | nil
  def nat64(prefix, plen \\ 96) do
    prefix
    |> encode()
    |> nat64p(plen)
  end

  defp nat64p(x, _) when is_exception(x), do: nil

  defp nat64p(x, l) when l in [96, 64, 56, 48, 40, 32] and bit_size(x.bits) == 128 do
    # auto-correct plen's value for Well-Known prefixes of rfc6052 or rfc8215
    plen =
      cond do
        member?(x, %Prefix{bits: <<0x0064::16, 0xFF9B::16, 0::64>>, maxlen: 128}) -> 96
        member?(x, %Prefix{bits: <<0x0064::16, 0xFF9B::16, 1::16>>, maxlen: 128}) -> 48
        true -> l
      end

    x = if plen < 96, do: %{x | bits: bits(x, [{0, 64}, {72, 56}])}, else: x

    %{
      prefix: %Prefix{bits: bits(x, 0, plen), maxlen: 128} |> decode(),
      ipv4: %Prefix{bits: bits(x, plen, 32), maxlen: 32} |> decode()
    }
  end

  defp nat64p(_, _), do: nil

  @spec nat46(prefix(), prefix()) :: String.t() | PrefixError.t()
  @doc """
  Return the IPv4-embedded IPv6 address or nil in case of errors.

  """
  def nat46(ip6, _ip4) when is_exception(ip6), do: ip6
  def nat46(_ip6, ip4) when is_exception(ip4), do: ip4

  def nat46(prefix, ip4) do
    "" <> prefix <> ip4
  end

  # TODO
  #
  # o hosts_lazy :: return stream that returns hosts addresses
  # o map_lazy?
  # o Enumerable for Iptrie?
  # o dns_ptr(prefix) -> reverse dns name
  # o read/write from/to file?
  #
  # See also:
  # - https://en.wikipedia.org/wiki/IPv6_address
  # - https://en.wikipedia.org/wiki/6to4
end
