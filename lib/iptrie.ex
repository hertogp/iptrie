defmodule Iptrie do
  @moduledoc """
  A Key,Value-store for IPv4 and IPv6 networks or addresses with longest prefix matching.

  ## Example

      iex> elements = [{"1.1.1.0/24", 24}, {"3.0.0.0/8", 8},
      ...>  {"1.1.1.0/25", "lower"}, {"1.1.1.128/25", "upper"},
      ...>  {"acdc:1975::", "T.N.T"}, {"acdc:1976::", "High Voltage"},
      ...>  {"10cc:1973::", "10cc"}, {"10cc:1978::", "Bloody Tourists"}]
      iex> ipt = new(elements)
      iex> Iptrie.Dot.write(ipt, "./doc/img/example.dot", "Iptrie")
      :ok

  ![example](img/example.dot.png)

  """
  import Prefix.IP
  alias PrefixError
  alias Radix

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

  # IP<x> markers
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

  This returns all subnets for given *prefix*, including itself if present or
  a `t:PrefixError/0`if given *prefix* is invalid.

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

  This returns all supernets for given *prefix*, including itself if present or
  a `t:PrefixError/0`if given *prefix* is invalid.

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
  Execute funtion *fun* on all {key, value}-pairs in the Iptrie.

  The leafs are visited in-order and funtion `fun` takes a stored
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
  def map(%__MODULE__{} = tree, fun, acc) when is_function(fun) do
    Radix.exec(tree.root, fun, acc)
  end

  @doc """
  Execute funtion *fun* on all {key, value}-pairs in the Iptrie and collect
  the results in a list.

  ## Example

      iex> tree = new([{"1.1.0.0/16", "A"}, {"1.1.1.0/24", "C"}, {"1.1.1.0/25", "B"}])
      iex> map(tree, fn {_k,v} -> v end)
      ["A", "B", "C"]

  """
  @spec map(t(), (keyval() -> any)) :: list()
  def map(%__MODULE__{} = tree, fun) when is_function(fun) do
    f = fn kv, acc -> [fun.(kv) | acc] end

    tree
    |> map(f, [])
    |> Enum.reverse()
  end
end
