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

  A [prefix'](`Pfx`) _type_ is determined by its `maxlen` property: IPv4 has
  `maxlen: 32`, IPv6 has `maxlen: 128`, MAC addresses have `maxlen: 48` and so
  on.

  Although Iptrie facilitates lpm lookups of any type of prefix, it has a bias
  towards IP prefixes. So, any binaries (strings) are interpreted as
  CIDR-strings and tuples of address digits and/or {address-digits, length} are
  interpreted as IPv4 or IPv6 representations.

  """
  @type t :: %__MODULE__{}

  @typedoc """
  The type of a prefix is its maxlen property

  """
  @type type :: non_neg_integer()

  @typedoc """
  A prefix represented as an opague `t:Pfx.t/0` struct, an
  `t:Pfx.ip_address/0`, `t:Pfx.ip_prefix/0`, IP CIDR string or EUI-48/64 string.

  See: `Pfx`.

  """
  @type prefix :: Pfx.prefix()

  # Guards
  defguardp is_type(type) when is_integer(type) and type >= 0

  # Helpers

  @spec arg_err(atom, any) :: Exception.t()
  defp arg_err(:bad_keyvals, arg),
    do: ArgumentError.exception("expected a valid {key,value}-list, got #{inspect(arg)}")

  defp arg_err(:bad_trie, arg),
    do: ArgumentError.exception("expected an Iptrie, got #{inspect(arg)}")

  defp arg_err(:bad_pfxs, arg),
    do: ArgumentError.exception("expected a list of valid prefixes, got #{inspect(arg)}")

  defp arg_err(:bad_pfx, arg),
    do: ArgumentError.exception("expected a valid prefix, got #{inspect(arg)}")

  defp arg_err(:bad_fun, {fun, arity}),
    do: ArgumentError.exception("expected a function/#{arity}, got #{inspect(fun)}")

  defp arg_err(:bad_types, arg),
    do: ArgumentError.exception("expected a list of maxlen's, got #{inspect(arg)}")

  defp arg_err(:bad_type, arg),
    do: ArgumentError.exception("expected a maxlen (non_neg_integer) value, got #{inspect(arg)}")

  # API
  @doc """
  Create an new, empty Iptrie.

  ## Examples

      iex> Iptrie.new()
      %Iptrie{}


  """
  @spec new() :: t()
  def new,
    do: %__MODULE__{}

  @doc """
  Create a new Iptrie, populated via a list of {`t:prefix/0`, `t:any/0`}-pairs.

  ## Example

      iex> elements = [
      ...>  {"1.1.1.0/24", "net1"},
      ...>  {{{1, 1, 2, 0}, 24}, "net2"},
      ...>  {"acdc:1975::/32", "TNT"}
      ...> ]
      iex> ipt = Iptrie.new(elements)
      iex> Map.get(ipt, 32)
      {0, {22, [{<<1, 1, 1>>, "net1"}], [{<<1, 1, 2>>, "net2"}]}, nil}
      iex> Map.get(ipt, 128)
      {0, nil, [{<<172, 220, 25, 117>>, "TNT"}]}

  """
  @spec new(list({prefix(), any})) :: t
  def new(elements) when is_list(elements) do
    Enum.reduce(elements, new(), fn {prefix, value}, trie -> put(trie, prefix, value) end)
  rescue
    FunctionClauseError -> raise arg_err(:bad_keyvals, elements)
  end

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
  rescue
    _ -> raise arg_err(:bad_keyvals, prefixes)
  end

  def get(%__MODULE__{} = trie, prefix) do
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)

    case Radix.get(tree, pfx.bits) do
      nil -> nil
      {bits, value} -> {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
    end
  rescue
    err -> raise err
  end

  def get(trie, _prefix),
    do: raise(arg_err(:bad_trie, trie))

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

  def put(%__MODULE__{} = _trie, elements),
    do: raise(arg_err(:bad_keyvals, elements))

  def put(trie, _elements),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Puts `value` under `prefix` in the `trie`.

  This always uses an exact match for `prefix`, replacing its value if it
  exists.

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
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)
    Map.put(trie, pfx.maxlen, Radix.put(tree, pfx.bits, value))
  rescue
    err -> raise err
  end

  def put(trie, _prefix, _value),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Delete one or more prefix, value-pairs from the `trie` using an exact match.

  The list of prefixes to delete may contain all _types_, so all sorts of
  prefixes can be deleted from multiple radix trees in one go.

  ## Examples

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
  def delete(%__MODULE__{} = trie, prefixes) when is_list(prefixes) do
    Enum.reduce(prefixes, trie, fn pfx, trie -> delete(trie, pfx) end)
  rescue
    _ -> raise arg_err(:bad_pfxs, prefixes)
  end

  def delete(%__MODULE__{} = trie, prefix) do
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)
    Map.put(trie, pfx.maxlen, Radix.delete(tree, pfx.bits))
  rescue
    err -> raise err
  end

  def delete(trie, _prefix),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Fetches the prefix,value-pair for given `prefix` from `trie`.

  Returns one of:
  - `{:ok, {prefix, value}}` in case of success
  - `{:error, :notfound}` if `prefix` is not present in `trie`
  - `{:error, :einval}` in case of an invalid `prefix`, and
  - `{:error, :bad_trie}` in case `trie` is not an `t:Iptrie.t/0`

  Optionally fetches based on a longest prefix match by specifying `match: :lpm`.

  ## Example

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", "one")
      ...> |> put("2.2.2.0/24", "two")
      iex>
      iex> fetch(ipt, "1.1.1.0/24")
      {:ok, {"1.1.1.0/24", "one"}}
      iex>
      iex> fetch(ipt, "1.1.1.1")
      {:error, :notfound}
      iex>
      iex> fetch(ipt, "1.1.1.1", match: :lpm)
      {:ok, {"1.1.1.0/24", "one"}}
      iex>
      iex> fetch(ipt, "13.13.13.333")
      {:error, :einval}

  """
  @spec fetch(t, prefix, keyword) :: {:ok, {prefix, any}} | {:error, atom}
  def fetch(trie, prefix, opts \\ [])

  def fetch(%__MODULE__{} = trie, prefix, opts) do
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)

    case Radix.fetch(tree, pfx.bits, opts) do
      :error -> {:error, :notfound}
      {:ok, {bits, value}} -> {:ok, {Pfx.marshall(%{pfx | bits: bits}, prefix), value}}
    end
  rescue
    _ -> {:error, :einval}
  end

  def fetch(_trie, _prefix, _opts),
    do: {:error, :bad_trie}

  # raise(arg_err(:bad_trie, trie))

  @doc """
  Fetches the prefix,value-pair for given `prefix` from `trie` (exact match).

  In case of success, returns `{prefix, value}`.
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
      ** (ArgumentError) expected a valid prefix, got "13.13.13.333"

  """
  @spec fetch!(t, prefix, keyword) :: {prefix, any} | KeyError | ArgumentError
  def fetch!(trie, prefix, opts \\ [])

  def fetch!(trie, prefix, opts) do
    case fetch(trie, prefix, opts) do
      {:ok, result} -> result
      {:error, :notfound} -> raise KeyError, "prefix #{inspect(prefix)} not found"
      {:error, :einval} -> raise arg_err(:bad_pfx, prefix)
      {:error, :bad_trie} -> raise arg_err(:bad_trie, trie)
    end
  rescue
    err -> raise err
  end

  @doc """
  Fetch a prefix,value-pair for given `prefix` from `trie` using a longest
  prefix match.

  Convenience wrapper for `Iptrie.fetch/3` with `match: :lpm`.

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
      {:error, :einval}

  """
  @spec find(t, prefix) :: {:ok, {prefix, any}} | {:error, atom}
  def find(trie, prefix),
    do: fetch(trie, prefix, match: :lpm)

  @doc """
  Fetch! a prefix,value-pair for given `prefix` from `trie` using a longest
  prefix match.

  Convenience wrapper for `Iptrie.fetch!/3` with `match: :lpm`.

  ## Examples

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
      ** (ArgumentError) expected a valid prefix, got "13.13.13.333"

  """
  @spec find!(t, prefix) :: {prefix, any} | KeyError | ArgumentError
  def find!(trie, prefix) do
    fetch!(trie, prefix)
  rescue
    err -> raise err
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
  def filter(%__MODULE__{} = trie, fun) when is_function(fun, 3) do
    types(trie)
    |> Enum.map(fn type -> {type, filterp(radix(trie, type), type, fun)} end)
    |> Enum.filter(fn {_t, rdx} -> not Radix.empty?(rdx) end)
    |> Enum.reduce(Iptrie.new(), fn {type, rdx}, ipt -> Map.put(ipt, type, rdx) end)
  end

  def filter(%__MODULE__{} = _trie, fun),
    do: raise(arg_err(:bad_fun, {fun, 3}))

  def filter(trie, _fun),
    do: raise(arg_err(:bad_trie, trie))

  defp filterp(rdx, type, fun) do
    keep = fn key, val, acc ->
      if fun.(key, type, val), do: Radix.put(acc, key, val), else: acc
    end

    Radix.reduce(rdx, Radix.new(), keep)
  end

  @doc """
  Returns true if `trie` has given `type`, false otherwise.

  An Iptrie groups prefixes into radix trees by their maxlen property, also known
  as the type of prefix.

  ## Example

  iex> t = new([{"1.1.1.1", 1}])
  iex> has_type?(t, 32)
  true
  iex> has_type?(t, 128)
  false

  """
  @spec has_type?(t, type) :: boolean
  def has_type?(%__MODULE__{} = trie, type) when is_type(type),
    do: Map.has_key?(trie, type)

  def has_type?(%__MODULE__{} = _trie, type),
    do: raise(arg_err(:bad_type, type))

  def has_type?(trie, _type),
    do: raise(arg_err(:bad_trie, trie))

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
  def keys(%__MODULE__{} = trie),
    do: keys(trie, types(trie))

  def keys(trie),
    do: raise(arg_err(:bad_trie, trie))

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
  def keys(%__MODULE__{} = trie, type) when is_integer(type) do
    radix(trie, type)
    |> Radix.keys()
    |> Enum.map(fn bits -> Pfx.new(bits, type) end)
  end

  def keys(%__MODULE__{} = trie, types) when is_list(types) do
    Enum.map(types, fn type -> keys(trie, type) end)
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
  def values(%__MODULE__{} = trie),
    do: values(trie, types(trie))

  def values(trie),
    do: raise(arg_err(:bad_trie, trie))

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
  def values(%__MODULE__{} = trie, type) when is_integer(type),
    do: radix(trie, type) |> Radix.values()

  def values(%__MODULE__{} = trie, types) when is_list(types) do
    Enum.map(types, fn type -> values(trie, type) end)
    |> List.flatten()
  end

  @doc """
  Return the prefix,value-pair, whose prefix is the longest match for given search `prefix`.

  Returns nil if there is no match for search `prefix`.
  Silently ignores any errors when encoding the given search `prefix` by returning nil.

  ## Examples

      iex> ipt = new()
      ...> |> put("1.1.1.0/24", 1)
      ...> |> put("2.2.2.0/24", 2)
      ...> |> put("acdc:1975::/32", 3)
      ...> |> put("acdc:2021::/32", 4)
      iex>
      iex> lookup(ipt, "1.1.1.1")
      {"1.1.1.0/24", 1}
      iex> lookup(ipt, "acdc:1975:1::")
      {"acdc:1975:0:0:0:0:0:0/32", 3}
      iex>
      iex> lookup(ipt, "3.3.3.3")
      nil
      iex> lookup(ipt, "3.3.3.300")
      ** (ArgumentError) expected a ipv4/ipv6 CIDR or EUI-48/64 string, got "3.3.3.300"

  """
  @spec lookup(t(), prefix()) :: {prefix(), any} | nil
  def lookup(%__MODULE__{} = trie, prefix) do
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)

    case Radix.lookup(tree, pfx.bits) do
      nil -> nil
      {bits, value} -> {Pfx.marshall(%{pfx | bits: bits}, prefix), value}
    end
  rescue
    err -> raise err
  end

  def lookup(trie, _prefix),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return all the prefix,value-pairs where the search `prefix` is a prefix for
  the stored prefix.

  This returns the more specific entries that are enclosed by given search
  `prefix`.  Note that any bitstring is always a prefix of itself.  So, if
  present, the search `prefix` will be included in the result.

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
    err -> raise err
  end

  def more(trie, _prefix),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return all the prefix,value-pairs whose prefix is a prefix for the given
  search `prefix`.

  This returns the less specific entries that enclose the given search
  `prefix`.  Note that any bitstring is always a prefix of itself.  So, if
  present, the search key will be included in the result.

  If `prefix` is not present an empty list is returned.

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
    err -> raise err
  end

  def less(trie, _prefix),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Lookup `prefix` and update the matched entry, only if found.

  Uses longest prefix match, so search `prefix` is usually matched by some less
  specific prefix.  If matched, `fun` is called on its value.  If
  `prefix` had no longest prefix match, the `trie` is returned unchanged.

  ## Examples

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
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)

    case Radix.lookup(tree, pfx.bits) do
      nil -> trie
      {bits, value} -> Map.put(trie, pfx.maxlen, Radix.put(tree, bits, fun.(value)))
    end
  rescue
    err -> raise err
  end

  def update(%__MODULE__{} = _trie, _prefix, fun),
    do: raise(arg_err(:bad_fun, {fun, 1}))

  def update(trie, _prefix, _fun),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Lookup `prefix` and, if found,  update its value or insert the default.

  Uses longest prefix match, so search `prefix` is usually matched by some less
  specific prefix.  If matched, `fun` is called on the entry's value.  If
  `prefix` had no longest prefix match, the default is inserted and `fun` is
  not called.

  ## Examples

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
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)
    Map.put(trie, pfx.maxlen, Radix.update(tree, pfx.bits, default, fun))
  rescue
    err -> raise err
  end

  def update(%__MODULE__{} = _trie, _prefix, _default, fun),
    do: raise(arg_err(:bad_fun, {fun, 1}))

  def update(trie, _prefix, _default, _fun),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return all prefix,value-pairs from all available radix trees in `trie`.

  ## Examples

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
  def to_list(%__MODULE__{} = trie),
    do: to_list(trie, types(trie))

  def to_list(trie),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Returns the prefix,value-pairs from the radix trees in `trie` for given
  `type`(s).

  If the radix tree for `type` does not exist, an empty list is returned.
  If `type` is a list of types, a flat list of all prefix,value-pairs of all
  radix trees of given types is returned.

  ## Examples

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
  def to_list(%__MODULE__{} = trie, type) when is_integer(type) do
    # and type >= 0 do
    tree = radix(trie, type)

    Radix.to_list(tree)
    |> Enum.map(fn {bits, value} -> {Pfx.new(bits, type), value} end)
  end

  def to_list(%__MODULE__{} = trie, types) when is_list(types) do
    types
    |> Enum.map(fn type -> to_list(trie, type) end)
    |> List.flatten()
  end

  def to_list(%__MODULE__{} = _trie, types),
    do: raise(arg_err(:bad_types, types))

  def to_list(trie, _types),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Invoke `fun` on all prefix,value-pairs in all radix trees in the `trie`.

  The function `fun` is called with the radix key, value and `acc` accumulator
  and should return an updated accumulator.  The result is the last `acc`
  accumulator returned.

  ## Examples

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
  def reduce(%__MODULE__{} = trie, acc, fun) when is_function(fun, 3) do
    reduce(trie, types(trie), acc, fun)
  rescue
    err -> raise err
  end

  def reduce(trie, _acc, _fun),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Invoke `fun` on each prefix,value-pair in the radix tree for given `type`

  The function `fun` is called with the radix key, value and `acc` accumulator
  and should return an updated accumulator.  The result is the last `acc`
  accumulator returned.

  If `type` is a list of `type`'s, the `acc` accumulator is updated across all
  radix trees of `type`'s.  Probably not entirely usefull, but there you go.

  ## Examples

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
  @spec reduce(t, type | list(type), any, (bitstring, any, any -> any)) :: any
  def reduce(%__MODULE__{} = trie, type, acc, fun) when is_integer(type) and is_function(fun, 3),
    do: radix(trie, type) |> Radix.reduce(acc, fun)

  def reduce(%__MODULE__{} = trie, types, acc, fun) when is_list(types) and is_function(fun, 3) do
    types
    |> Enum.map(fn type -> radix(trie, type) end)
    |> Enum.reduce(acc, fn tree, acc -> Radix.reduce(tree, acc, fun) end)
  end

  def reduce(%__MODULE__{} = _trie, types, _acc, fun) when is_function(fun, 3),
    do: raise(arg_err(:bad_types, types))

  def reduce(%__MODULE__{} = _trie, _types, _acc, fun),
    do: raise(arg_err(:bad_fun, {fun, 3}))

  def reduce(trie, _types, _acc, _fun),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return the radix tree for given `type` or a new empty tree.

  If there is no `Radix` tree for given `type`, an empty radix will be returned.

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
      iex>
      iex> has_type?(ipt, 48)
      false

  """
  @spec radix(t, integer) :: Radix.tree()
  def radix(%__MODULE__{} = trie, type) when is_integer(type) and type >= 0,
    do: Map.get(trie, type) || Radix.new()

  def radix(%__MODULE__{} = _trie, type),
    do: raise(arg_err(:bad_type, type))

  def radix(trie, _type),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return a list of types available in given `trie`.

  ## Example

      iex> new([{"1.1.1.1", 1}, {"2001:db8::", 2}])
      ...> |> types()
      [32, 128]

  """
  @spec types(t) :: [type]
  def types(%__MODULE__{} = trie),
    do: Map.keys(trie) |> Enum.filter(fn x -> is_type(x) end)

  def types(trie),
    do: raise(arg_err(:bad_trie, trie))
end
