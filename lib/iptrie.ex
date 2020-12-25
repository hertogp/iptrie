defmodule Iptrie do
  @moduledoc """
  A Key,Value-store for IPv4 and IPv6 networks or addresses with
  longest prefix matching.

  ## Examples

  # iex> Iptrie.Dot.write(ipt, "doc/img/example.dot")

  # ![example](img/example.dot.png)

  """
  alias Prefix.IP
  alias PrefixError
  alias Radix

  @enforce_keys [:ip4, :ip6]
  defstruct ip4: nil, ip6: nil

  # HELPERS

  # Api
  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      %Iptrie{ip4: {0, nil, nil}, ip6: {0, nil, nil}}

  """
  def new, do: %__MODULE__{ip4: Radix.new(), ip6: Radix.new()}

  @doc """
  Create a new Iptrie populated with the given prefix,value pair(s).

  """
  def new(elements) when is_list(elements) do
    Enum.reduce(elements, Radix.new(), fn elm, t -> set(t, elm) end)
  end

  # for convenience: add a list of [{k,v},...] to a tree
  @doc """
  Enter a single prefix-value pair or list thereof, into an iptrie.

  """
  def set(tree, element_or_elements)

  def set(tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn elm, t -> set(t, elm) end)
  end

  def set(tree, {pfx, val}) do
    case IP.encode(pfx) do
      %PrefixError{} = x -> x
      key -> Radix.set(tree, {key, val})
    end
  end

  @doc """
  Look for the longest matching prefix in an Iptrie.

  """
  def lookup(tree, key) do
    case IP.encode(key) do
      %PrefixError{} = x -> x
      key -> Radix.lpm(tree, key)
    end
  end
end
