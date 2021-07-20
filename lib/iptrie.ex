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

  @spec match(keyword) :: function
  defp match(opts) do
    case Keyword.get(opts, :match) do
      :longest -> &lookup/2
      :lpm -> &lookup/2
      _ -> &get/2
    end
  end

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
  Returns the number of entries in given `trie`.

  Note that this requires traversal of radix trees present.

  ## Example

      iex> t = new([{"1.1.1.1", 1}, {"acdc::", 2}])
      iex> count(t)
      2
  """
  @spec count(t) :: non_neg_integer()
  def count(%__MODULE__{} = trie) do
    types(trie)
    |> Enum.map(fn type -> count(trie, type) end)
    |> Enum.sum()
  end

  def count(trie),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Returns the number of entries for given `type` in the `trie`.

  Returns `0` is given `type` does not exist in the `trie`.

  ## Example

      iex> t = new([{"1.1.1.1", 1}, {"acdc::", 2}])
      iex> count(t, 32)
      1
      iex> count(t, 128)
      1
      iex> types(t)
      ...> |> Enum.map(fn type -> count(t, type) end)
      [1, 1]

  """
  @spec count(t, type) :: non_neg_integer
  def count(%__MODULE__{} = trie, type) when is_type(type),
    do: radix(trie, type) |> Radix.count()

  def count(%__MODULE__{} = _trie, type),
    do: raise(arg_err(:bad_type, type))

  def count(trie, _type),
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

  @doc ~S"""
  Drops given `prefixes` from `trie` using an exact match.

  If a given prefix does not exist in `trie` it is ignored.

  ## Example

      # drop 2 existing prefixes and ignore the third
      iex> t = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"11-22-33-00-00-00/24", 3}])
      iex> t2 = drop(t, ["1.1.1.0/24", "11-22-33-00-00-00/24", "3.3.3.3"])
      iex> keys(t2) |> Enum.map(fn pfx -> "#{pfx}" end)
      ["2.2.2.0/24"]

  """
  @spec drop(t, [prefix]) :: t
  def drop(%__MODULE__{} = trie, prefixes) when is_list(prefixes) do
    prefixes
    |> Enum.map(fn pfx -> Pfx.new(pfx) end)
    |> Enum.reduce(trie, fn pfx, acc -> delete(acc, pfx) end)
  rescue
    err -> raise err
  end

  def drop(%__MODULE__{} = _trie, prefixes),
    do: raise(arg_err(:bad_pfxs, prefixes))

  def drop(trie, _prefixes),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return true if the given `trie` is empty, false otherwise

  ## Examples

     iex> t = new([{"1.1.1.1", 1}, {"11-22-33-44-55-66", 2}])
     iex> empty?(t)
     false

     iex> new() |> empty?()
     true

  """
  @spec empty?(t) :: boolean
  def empty?(%__MODULE__{} = trie) do
    types(trie)
    |> Enum.map(fn type -> empty?(trie, type) end)
    |> Enum.all?()
  end

  def empty?(trie),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return true if the radix tree for given `type` in `trie` is empty, false otherwise

  ## Example

     iex> t = new([{"1.1.1.1", 1}, {"11-22-33-44-55-66", 2}])
     iex> empty?(t, 32)
     false
     iex> empty?(t, 48)
     false
     iex> empty?(t, 128)
     true

  """
  @spec empty?(t, type) :: boolean
  def empty?(%__MODULE__{} = trie, type) when is_type(type),
    do: radix(trie, type) |> Radix.empty?()

  def empty?(%__MODULE__{} = _trie, type),
    do: raise(arg_err(:bad_type, type))

  def empty?(trie, _type),
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

  Optionally fetches based on a longest prefix match by specifying `match:
  :lpm`.

  ## Example

      iex> ipt = new()
      ...> |> put("10.10.10.0/24", "ten")
      ...> |> put("11.11.11.0/24", "eleven")
      iex>
      iex> fetch!(ipt, "10.10.10.0/24")
      {"10.10.10.0/24", "ten"}
      iex>
      iex> fetch!(ipt, "11.11.11.11", match: :lpm)
      {"11.11.11.0/24", "eleven"}
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
  Find a prefix,value-pair for given `prefix` from `trie` using a longest
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
  def find(trie, prefix) do
    fetch(trie, prefix, match: :lpm)
  rescue
    err -> raise err
  end

  @doc """
  Find a prefix,value-pair for given `prefix` from `trie` using a longest
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
      iex> find!(ipt, "10.10.10.10")
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
    fetch!(trie, prefix, match: :lpm)
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
  Returns true if given `prefix` is present in `trie`, false otherwise.

  The check is done based on an exact match.

  ## Example

      iex> t = new([{"1.1.1.1", 1}, {"1.1.1.0/24", 2}, {"acdc::/16", 3}])
      iex> has_prefix?(t, "1.1.1.2")
      false
      iex> has_prefix?(t, "1.1.1.1")
      true
      iex> has_prefix?(t, "acdc::/16")
      true

  """
  @spec has_prefix?(t, prefix) :: boolean
  def has_prefix?(%__MODULE__{} = trie, prefix) do
    case get(trie, prefix) do
      nil -> false
      _ -> true
    end
  rescue
    err -> raise err
  end

  def has_prefix?(trie, _prefix),
    do: raise(arg_err(:bad_trie, trie))

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
  Merge `trie1` and `trie2` into a new `t:Iptrie.t/0`.

  Adds all prefix,value-pairs of `trie2` to `trie1`, overwriting any existing
  entries when prefixes match (based on exact match).

  ## Example

      iex> t1 = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}])
      iex> t2 = new([{"2.2.2.0/24", 22}, {"3.3.3.0/24", 3}])
      iex> t = merge(t1, t2)
      iex> count(t)
      3
      iex> get(t, "1.1.1.0/24")
      {"1.1.1.0/24", 1}
      iex> get(t, "2.2.2.0/24")
      {"2.2.2.0/24", 22}
      iex> get(t, "3.3.3.0/24")
      {"3.3.3.0/24", 3}

  """
  @spec merge(t, t) :: t
  def merge(%__MODULE__{} = trie1, %__MODULE__{} = trie2) do
    reduce(trie2, trie1, fn pfx, val, acc -> put(acc, pfx, val) end)
  rescue
    err -> raise err
  end

  def merge(trie1, %__MODULE__{} = _trie2),
    do: raise(arg_err(:bad_trie, trie1))

  def merge(_trie1, trie2),
    do: raise(arg_err(:bad_trie, trie2))

  @doc ~S"""
  Merge `trie1` and `trie2` into a new `t:Iptrie.t/0`, resolving conflicts through `fun`.

  In cases where a prefix is present in both tries, the conflict is resolved by calling
  `fun` with the prefix (a `t:Pfx.t/0`), its value in `trie1` and its value in
  `trie2`.  The function's return value will be stored under the prefix in the
  merged trie.

  ## Example

       iex> t1 = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"acdc:1975::/32", 3}])
       iex> t2 = new([{"3.3.3.0/24", 4}, {"2.2.2.0/24", 5}, {"acdc:2021::/32", 6}])
       iex> t = merge(t1, t2, fn _pfx, v1, v2 -> v1 + v2 end)
       iex> count(t)
       5
       iex> get(t, "2.2.2.0/24")
       {"2.2.2.0/24", 7}
       iex> for ip4 <- keys(t, 32), do: "#{ip4}"
       ["1.1.1.0/24", "2.2.2.0/24", "3.3.3.0/24"]
       iex> for ip6 <- keys(t, 128), do: "#{ip6}"
       ["acdc:1975:0:0:0:0:0:0/32", "acdc:2021:0:0:0:0:0:0/32"]
       iex> values(t) |> Enum.sum()
       1 + 7 + 3 + 4 + 6

  """
  @spec merge(t, t, (prefix, any, any -> any)) :: t
  def merge(%__MODULE__{} = trie1, %__MODULE__{} = trie2, fun) when is_function(fun, 3) do
    f = fn k2, v2, acc ->
      case get(trie1, k2) do
        nil -> put(acc, k2, v2)
        {^k2, v1} -> put(acc, k2, fun.(k2, v1, v2))
      end
    end

    reduce(trie2, trie1, f)
  rescue
    err -> raise err
  end

  def merge(%__MODULE__{} = _trie1, %__MODULE__{} = _trie2, fun),
    do: raise(arg_err(:bad_fun, {fun, 3}))

  def merge(trie1, %__MODULE__{} = _trie2, _fun),
    do: raise(arg_err(:bad_trie, trie1))

  def merge(_trie1, trie2, _fun),
    do: raise(arg_err(:bad_trie, trie2))

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
  Create an new, empty Iptrie.

  ## Examples

      iex> Iptrie.new()
      %Iptrie{}


  """
  @spec new() :: t()
  def new(),
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
  Removes the value associated with `prefix` and returns the matched prefix,value-pair and the new trie.

  Options include:
  - `default: value` to return if `prefix` could not be matched (defaults to nil)
  - `match: :lpm` to match on longest prefix instead of an exact match

  ## Examples

      iex> t = new([{"1.1.1.0/24", 1}, {"1.1.1.99", 2}, {"acdc:1975::/32", 3}])
      iex> {{"1.1.1.99", 2}, t2} = pop(t, "1.1.1.99")
      iex> get(t2, "1.1.1.99")
      nil

      iex> t = new([{"1.1.1.0/24", 1}, {"1.1.1.99", 2}, {"acdc:1975::/32", 3}])
      iex> # t is unchanged
      iex> {{"1.1.1.33", :notfound}, ^t} = pop(t, "1.1.1.33", default: :notfound)

      iex> t = new([{"1.1.1.0/24", 1}, {"1.1.1.99", 2}, {"acdc:1975::/32", 3}])
      iex> # lpm match
      iex> {{"1.1.1.0/24", 1}, t2} = pop(t, "1.1.1.33", match: :lpm)
      iex> get(t2, "1.1.1.0/24")
      nil

  """
  @spec pop(t, prefix, keyword) :: {{prefix, any}, t}
  def pop(trie, prefix, opts \\ [])

  def pop(%__MODULE__{} = trie, prefix, opts) do
    pfx = Pfx.new(prefix)
    tree = radix(trie, pfx.maxlen)
    {{bits, val}, rdx} = Radix.pop(tree, pfx.bits, opts)

    {
      {Pfx.marshall(%{pfx | bits: bits}, prefix), val},
      Map.put(trie, pfx.maxlen, rdx)
    }
  rescue
    err -> raise err
  end

  def pop(trie, _prefix, _opts),
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
  Return the `Radix` tree for given `type` in an Iptrie, or a new empty tree.

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

  @doc ~S"""
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
      iex> reduce(ipt, 0, fn _pfx, value, acc -> acc + value end)
      10
      iex>
      iex> reduce(ipt, %{}, fn pfx, value, acc -> Map.put(acc, "#{pfx}", value) end)
      %{
        "1.1.1.0/24" => 1,
        "2.2.2.0/24" => 2,
        "acdc:1975:0:0:0:0:0:0/32" => 3,
        "acdc:2021:0:0:0:0:0:0/32" => 4
      }

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
  def reduce(%__MODULE__{} = trie, type, acc, fun) when is_type(type) and is_function(fun, 3) do
    reducer = fn bits, val, acc -> fun.(Pfx.new(bits, type), val, acc) end

    radix(trie, type)
    |> Radix.reduce(acc, reducer)
  end

  def reduce(%__MODULE__{} = trie, types, acc, fun) when is_list(types) and is_function(fun, 3) do
    types
    |> Enum.reduce(acc, fn type, acc -> reduce(trie, type, acc, fun) end)
  end

  def reduce(%__MODULE__{} = _trie, types, _acc, fun) when is_function(fun, 3),
    do: raise(arg_err(:bad_types, types))

  def reduce(%__MODULE__{} = _trie, _types, _acc, fun),
    do: raise(arg_err(:bad_fun, {fun, 3}))

  def reduce(trie, _types, _acc, _fun),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Split `trie` into two tries using given list of `prefixes`.

  Returns a new trie with prefix,value-pairs that were matched by given
  `prefixes` and the old trie with those pairs removed.  If a prefix was not
  found in given `trie` it is ignored.

  By default an exact match is used, specify `match: :lpm` to use longest
  prefix match instead.

  ## Example

      iex> t = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"3.3.3.0/30", 3}])
      iex> {t2, t3} = split(t, ["2.2.2.0/24", "3.3.3.0/30"])
      iex> count(t2)
      2
      iex> get(t2, "2.2.2.0/24")
      {"2.2.2.0/24", 2}
      iex> get(t2, "3.3.3.0/30")
      {"3.3.3.0/30", 3}
      iex> count(t3)
      1
      iex> get(t3, "1.1.1.0/24")
      {"1.1.1.0/24", 1}

      # use longest prefix match
      iex> t = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"3.3.3.0/30", 3}])
      iex> {t4, t5} = split(t, ["2.2.2.2", "3.3.3.3"], match: :lpm)
      iex> count(t4)
      2
      iex> get(t4, "2.2.2.0/24")
      {"2.2.2.0/24", 2}
      iex> get(t4, "3.3.3.0/30")
      {"3.3.3.0/30", 3}
      iex> count(t5)
      1
      iex> get(t5, "1.1.1.0/24")
      {"1.1.1.0/24", 1}

  """
  @spec split(t, [prefix], keyword) :: {t, t}
  def split(trie, prefixes, opts \\ [])

  def split(%__MODULE__{} = trie, prefixes, opts) when is_list(prefixes) do
    t = take(trie, prefixes, opts)
    {t, drop(trie, keys(t))}
  rescue
    err -> raise err
  end

  def split(%__MODULE__{} = _trie, prefixes, _opts),
    do: raise(arg_err(:bad_pfxs, prefixes))

  def split(trie, _prefixes, _opts),
    do: raise(arg_err(:bad_trie, trie))

  @doc """
  Return a new Iptrie containing only given `prefixes` that were found in `trie`.

  If a given prefix does not exist, it is ignored.  Optionally specifiy `match:
  :lpm` to use a longest prefix match instead of exact, which is the default.

  ## Examples

      iex> t = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"acdc::/16", 3}])
      iex> t2 = take(t, ["1.1.1.0/24", "acdc::/16"])
      iex> count(t2)
      2
      iex> get(t2, "1.1.1.0/24")
      {"1.1.1.0/24", 1}
      iex> get(t2, "acdc::/16")
      {"acdc:0:0:0:0:0:0:0/16", 3}

      # use longest match
      iex> t = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"acdc::/16", 3}])
      iex> t3 = take(t, ["1.1.1.1", "acdc:1975::1"], match: :lpm)
      iex> count(t3)
      2
      iex> get(t3, "1.1.1.0/24")
      {"1.1.1.0/24", 1}
      iex> get(t3, "acdc::/16")
      {"acdc:0:0:0:0:0:0:0/16", 3}

      # ignore missing prefixes
      iex> t = new([{"1.1.1.0/24", 1}, {"2.2.2.0/24", 2}, {"acdc::/16", 3}])
      iex> t4 = take(t, ["1.1.1.1", "3.3.3.3"], match: :lpm)
      iex> count(t4)
      1
      iex> get(t4, "1.1.1.0/24")
      {"1.1.1.0/24", 1}

  """
  @spec take(t, [prefix], keyword) :: t
  def take(trie, prefixes, opts \\ [])

  def take(%__MODULE__{} = trie, prefixes, opts) when is_list(prefixes) do
    fun = fn pfx, t ->
      case match(opts).(trie, pfx) do
        nil -> t
        {pfx, val} -> put(t, pfx, val)
      end
    end

    Enum.reduce(prefixes, new(), fun)
  rescue
    err -> raise err
  end

  def take(%__MODULE__{} = _trie, prefixes, _opts),
    do: raise(arg_err(:bad_pfxs, prefixes))

  def take(trie, _prefixes, _opts),
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
  Return a list of types available in given `trie`.

  ## Example

      iex> t = new([{"1.1.1.1", 1}, {"2001:db8::", 2}])
      iex> types(t)
      [32, 128]

  """
  @spec types(t) :: [type]
  def types(%__MODULE__{} = trie),
    do: Map.keys(trie) |> Enum.filter(fn x -> is_type(x) end)

  def types(trie),
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
  `prefix` had no longest prefix match, the `default` is inserted and `fun` is
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
end
