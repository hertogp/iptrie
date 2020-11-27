defmodule Iptrie do
  @moduledoc """
  `Iptrie` Ip lookup table using longest prefix match.

  """
  alias Iptrie.Pfx
  alias Iptrie.Rdx
  alias Iptrie.Dot

  # HELPERS

  def ascii(key), do: Pfx.to_ascii(key) |> Pfx.ok()

  # Api
  @doc """
  Create and return a new Ip lookup table, referred to as `Iptrie`, for both
  IPv4 and IPv6 addresses or prefixes.

  The tree may be initialized by a list of {key,value} pairs.  The first bit of
  a key denotes an IPv4 (bit is 0) or an IPv6 address (bit is 1).  Hence, the
  root node has a IPv4 subtree on its left and an IPv6 subtree on its right.

  ## Examples

    iex> Iptrie.new()
    {0, nil, nil}

    iex> Iptrie.new([{"1.1.1.1", "1.1.1.1"}, {"1.1.1.0/30", "1.1.1.0/30"}])
    {0,
     {32, {-1, [{<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"}]},
      {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]}}, nil}

    iex> Iptrie.new([{"1.1.1.1", "1.1.1.1"}, {"acdc::1976/16", "jailbreak"}])
    {0,
      {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]},
      {-1, [{<<214, 110, 0::size(1)>>, "jailbreak"}]}
    }

  """
  def new, do: Rdx.new()

  def new(kvs) when is_list(kvs) do
    Enum.reduce(kvs, Rdx.new(), fn kv, t -> add(t, kv) end)
  end

  # ADD: (or update) a new {key, val} in the tree, where key is a prefix-string
  @doc """
  Add a {key,value} pair to the Iptrie or a list thereof.

  ## Example

      iex> Iptrie.new()
      ...> |> Iptrie.add([{"1.1.1.0/30", "1.1.1.0/30"}, {"1.1.1.1", "1.1.1.1"}])
      {0,
       {32, {-1, [{<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"}]},
        {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]}}, nil}

      iex> Iptrie.new()
      ...> |> Iptrie.add({"1.1.1.1", "1.1.1.1"})
      ...> |> Iptrie.add({"acdc::1976/16", "jailbreak"})
      {0,
        {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]},
        {-1, [{<<214, 110, 0::size(1)>>, "jailbreak"}]}
      }

  """
  def add(tree, {key, val}) do
    case Pfx.to_key(key) do
      {:ok, key} -> Rdx.add(tree, {key, val})
      {:error, reason} -> {:error, reason}
    end
  end

  # for convenience: add a list of [{k,v},...] to a tree
  def add(tree, kvs) when is_list(kvs) do
    Enum.reduce(kvs, tree, fn kv, t -> add(t, kv) end)
  end

  @doc """
  Lookup the longest matching prefix given a Iptrie and a prefix or address.
  Returns the {key, value} pair when a match was found, nil otherwise.

  ## Examples

      iex> Iptrie.new([{"1.1.1.1", "1.1.1.1"}, {"1.1.1.0/30", "1.1.1.0/30"}])
      ...> |> Iptrie.lookup("1.1.1.3")
      {<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"}


      iex> Iptrie.new([{"1.1.1.1", "1.1.1.1"}, {"1.1.1.0/30", "1.1.1.0/30"}])
      ...> |> Iptrie.lookup("1.1.1.5")
      nil

  """
  def lookup(bst, key) do
    case Pfx.to_key(key) do
      {:ok, key} -> Rdx.lpm(bst, key)
      {:error, reason} -> {:error, reason}
    end
  end

  def dot(bst, fname) do
    File.write(fname, Dot.dotify(bst, fname))
    bst
  end
end
