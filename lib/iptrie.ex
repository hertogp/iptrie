defmodule Iptrie do
  @moduledoc """
  An Ip lookup table for both IPv4 and IPv6.

  Iptrie provides an interface to store, retrieve or modify prefix,value-pairs
  in an IP lookup table, where the prefix is a regular string like "1.1.1.0/30"
  or "acdc:1976::/32".

  It uses `Iptrie.Pfx` to convert prefixes between their string- and bitstring
  formats which are used as keys to index into a radix tree (r=2), as provided
  by the `Iptrie.Rdx` module.

  By convention,  *pfx* refers to a prefix in its string-form, while *key*
  refers to the bitstring-encoded form as used by the radix tree.

  ## Examples

      iex> ipt = new([
      ...> {"1.1.1.0/30", "1.1.1.0/30"},
      ...> {"1.1.1.252/30", "1.1.1.252/30"},
      ...> {"1.1.1.0/24", "1.1.1.0/24"},
      ...> {"acdc:1975::/32", "High Voltage"},
      ...> {"acdc:1976::/32", "Jailbreak"},
      ...> {"acdc:1977::/32", "Dog eat dog"},
      ...>])
      iex>
      iex> lookup(ipt, "acdc:1976:abba::")
      {<<1::1, 0xacdc::16, 0x1976::16>>, "Jailbreak"}
      iex>
      iex> lookup(ipt, "1.1.1.3")
      {<<0::1, 1::8, 1::8, 1::8, 0::6>>, "1.1.1.0/30"}
      iex>
      iex> lookup(ipt, "1.1.1.45")
      {<<0::1, 1::8, 1::8, 1::8>>, "1.1.1.0/24"}
      iex>
      iex> ipt
      {0,
        {25,
          {-1, [{<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"},
            {<<0, 128, 128, 1::size(1)>>, "1.1.1.0/24"}]},
          {-1, [{<<0, 128, 128, 127::size(7)>>, "1.1.1.252/30"}]}
        },
        {31,
          {-1, [{<<214, 110, 12, 186, 1::size(1)>>, "High Voltage"}]},
          {32, {-1, [{<<214, 110, 12, 187, 0::size(1)>>, "Jailbreak"}]},
               {-1, [{<<214, 110, 12, 187, 1::size(1)>>, "Dog eat dog"}]}
          }
        }
      }
      iex>
      iex> Iptrie.Dot.dotify(ipt, "doc/img/example.dot")

  ![example2](img/example.dot.png)

  """
  alias Iptrie.Pfx
  alias Iptrie.PfxError
  alias Iptrie.Rdx

  # TODO
  # - use pfx instead of key(s), the latter is used in Rdx only

  # HELPERS

  @doc """
  Return a prefix-string representation of a radix key or `{:error, reason}`

  ## Examples

      iex> ascii(<<0::1, 1::8, 1::8>>)
      "1.1.0.0/16"

      iex> ascii(<<1::1, 0xacdc::16, 0x1979::16>>)
      "acdc:1979::/32"

      iex> ascii(<<0::1, 1::33>>)  # an IPv4 key with too many bits
      {:error, :eaddress}
  """
  def ascii(key), do: Pfx.to_ascii(key) |> Pfx.ok()

  # Api
  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      {0, nil, nil}

  """
  def new, do: Rdx.new()

  @doc """
  Create a new Iptrie populated with the given list of prefix-value pairs.

  The prefixes are converted into radix keys whose first bit indicates whether it
  is an IPv4 address or an IPv6 address.  Hence, the left subtree of the root
  node is the v4-tree and its right subtree is the v6-tree.

  ## Example
      iex> elements = [{"1.1.1.1", "1.1.1.1"}, {"1.1.1.0/30", "1.1.1.0/30"}]
      iex> new(elements)
      {0,
        {32, {-1, [{<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"}]},
             {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]}
        },
        nil
      }

  """
  def new(elements) when is_list(elements) do
    Enum.reduce(elements, Rdx.new(), fn elm, t -> set(t, elm) end)
  end

  # for convenience: add a list of [{k,v},...] to a tree
  @doc """
  Enter a single prefix-value pair or list thereof, into an iptrie.

  ## Example

      iex> new()
      ...> |> set([{"1.1.1.0/30", "1.1.1.0/30"}, {"1.1.1.1", "1.1.1.1"}])
      {0,
        {32, {-1, [{<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"}]},
             {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]}
        },
        nil}

      iex> new()
      ...> |> set({"1.1.1.1", "1.1.1.1"})
      ...> |> set({"acdc::1976/16", "jailbreak"})
      {0,
        {-1, [{<<0, 128, 128, 128, 1::size(1)>>, "1.1.1.1"}]},
        {-1, [{<<214, 110, 0::size(1)>>, "jailbreak"}]}
      }
  """
  def set(tree, element_or_elements)

  def set(tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn elm, t -> set(t, elm) end)
  end

  def set(tree, {pfx, val}) do
    case Pfx.to_key(pfx) do
      {:ok, key} -> Rdx.set(tree, {key, val})
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Lookup the longest matching prefix given a Iptrie and a prefix or address.
  Returns the {key, value}-pair when a match was found, nil otherwise.  Note
  that the key, in bitstring format, is not converted to its string form.

  ## Examples

      iex> table = new([{"1.1.1.1", "1.1.1.1"}, {"1.1.1.0/30", "1.1.1.0/30"}])
      iex> lookup(table, "1.1.1.3")
      {<<0, 128, 128, 64::size(7)>>, "1.1.1.0/30"}
      iex>
      iex> lookup(table, "1.1.1.5")
      nil
      iex>
      iex> lookup(table, "1.1.1.1")
      {<<0::1, 1::8, 1::8, 1::8, 1::8>>, "1.1.1.1"}

  """
  def lookup(tree, key) do
    case Pfx.to_key(key) do
      {:ok, key} -> Rdx.lpm(tree, key)
      {:error, reason} -> {:error, reason}
    end
  end
end
