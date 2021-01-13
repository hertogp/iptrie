defmodule Iptrie do
  @moduledoc """
  A Key,Value-store for IPv4 and IPv6 networks or addresses with
  longest prefix matching.

  ## Examples

      iex> elms = [{"1.1.1.0/24", 24}, {"3.0.0.0/8", 8},
      ...>  {"1.1.1.0/25", "lower"}, {"1.1.1.128/25", "upper"},
      ...>  {"acdc:1975::", "T.N.T"}, {"acdc:1976::", "High Voltage"},
      ...>  {"abba:1975::", "abba"}, {"abba:1976::", "Arrival"}]
      iex> ipt = new(elms)
      iex> Iptrie.Dot.write(ipt, "doc/img/example.dot", "example")

  # ![example](img/example.dot.png)

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

  Examples include:
  - "1.1.1.1" or "1.1.1.0/24" as CIDR-string
  - {1, 1, 1, 1} address-tuple
  - {{1, 1, 1, 0}, 24} digits-tuple
  - %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 32}


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
  # used so both types can be stuffed down the same Radix tree
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

  # Trie functions

  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      %Iptrie{root: {0, nil, nil}}

  """
  @spec new() :: t()
  def new, do: %__MODULE__{root: Radix.new()}

  @doc """
  Create a new Iptrie populated with the given {prefix,value}-pairs.

  ## Example

      iex> new([{"1.1.1.0/24", "A"}, {"1.1.1.0/25", "A1"}])
      %Iptrie{
        root: {0, [{<<0, 128, 128, 2::size(2)>>, "A1"},
                   {<<0, 128, 128, 1::size(1)>>, "A"}
                  ],
                  nil
              }
      }
  """
  @spec new(list(pfxval())) :: t()
  def new(elements), do: new() |> set(elements)

  @doc """
  Enter a single {prefix,value}-pair into an iptrie.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.

  ## Examples

      iex> new() |> set("1.1.1.0/24", "A")
      %Iptrie{root: {0, [{<<0, 128, 128, 1::size(1)>>, "A"}], nil}}

      iex> new() |> set("1.1.1.0/33", "?")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec set(t(), prefix(), any()) :: t() | PrefixError.t()
  def set(tree, prefix, value) do
    case encode(prefix) do
      x when is_exception(x) -> x
      x -> %{tree | root: Radix.set(tree.root, key(x), value)}
    end
  end

  @doc """
  Enter a list of {prefix,value}-pairs into an Iptrie.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.

  """
  @spec set(t(), list(pfxval())) :: t()
  def set(tree, elements) do
    Enum.reduce(elements, tree, fn {k, v}, t -> set(t, k, v) end)
  end

  @doc """
  Return the `t:keyval/0`-pair, whose key represents the longest possible
  prefix for the given search *prefix* or `nil` if nothing matched.

  ## Example

      iex> t = new([{"1.1.1.0/24", "A"}, {"1.1.1.0/25", "A1"}])
      iex> keyval = lookup(t, "1.1.1.127")
      iex> elem(keyval, 1)
      "A1"
      iex> rdx_key_tostr(elem(keyval, 0))
      "1.1.1.0/25"
      #
      iex> lookup(t, "2.2.2.2")
      nil

      # erroneous input simply yields nil too
      iex> new() |> lookup(42)
      nil

  """
  @spec lookup(t(), prefix()) :: term
  def lookup(%__MODULE__{} = tree, prefix) when is_binary(prefix),
    do: lookup(tree, encode(prefix))

  def lookup(%__MODULE__{} = tree, x) when is_tuple(x),
    do: lookup(tree, encode(x))

  def lookup(%__MODULE__{} = tree, %Prefix{} = x),
    do: Radix.lpm(tree.root, key(x))

  def lookup(_, _), do: nil

  def dot(tree, fname),
    do: Dot.write(tree, fname)

  # IP functions

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

  ## Example

      iex> hosts("1.1.1.0/30")
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

  ## Example

      iex> mask("1.1.1.0/24")
      "255.255.255.0"

      iex> mask("1.1.1.0/22")
      "255.255.252.0"
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

      iex> inv_mask("1.1.1.0/24")
      "0.0.0.255"

      iex> inv_mask("1.1.1.0/23")
      "0.0.1.255"

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

      iex> jump("1.1.1.0/24", 1)
      "1.1.2.0/24"

      iex> jump("1.1.1.0/30", 64)
      "1.1.2.0/30"

      iex> jump("0.0.0.0", -1)
      "255.255.255.255"

      iex> jump("255.255.255.255", 1)
      "0.0.0.0"

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

      iex> numhosts("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec numhosts(prefix()) :: non_neg_integer
  def numhosts(prefix) do
    prefix
    |> encode()
    |> size()
  end

  # TODO Table funcs
  # o get :: get exact match
  # o less :: return all less specifics (option inclusive)
  # o more :: return all more specifics (option inclusive)
  # o map :: apply function to all {k,v}-pairs

  # TODO Prefix funcs
  # o hosts_lazy :: return stream that returns hosts addresses
end
