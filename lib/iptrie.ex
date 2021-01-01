defmodule Iptrie do
  @moduledoc """
  A Key,Value-store for IPv4 and IPv6 networks or addresses with
  longest prefix matching.

  ## Examples

  # iex> Iptrie.Dot.write(ipt, "doc/img/example.dot")

  # ![example](img/example.dot.png)

  """
  import Prefix
  import Prefix.IP
  alias PrefixError
  alias Radix

  @enforce_keys [:ip4, :ip6]
  defstruct ip4: nil, ip6: nil

  @type t :: %__MODULE__{}
  # HELPERS

  # Data
  @ip4 Radix.new([
         {encode("10.0.0.0/8").bits, "rfc1918"},
         {encode("172.16.0.0/12").bits, "rfc1918"},
         {encode("192.168.0.0/16").bits, "rfc1918"}
       ])
  @ip6 Radix.new([{<<0xACDC::16>>, "rock"}])

  @ip %{__struct__: __MODULE__, ip4: @ip4, ip6: @ip6}

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
  def new(elements) do
    Enum.reduce(elements, new(), fn elm, t -> set(t, elm) end)
  end

  # for convenience: add a list of [{k,v},...] to a tree
  @doc """
  Enter a single prefix-value pair or list thereof, into an iptrie.

  """
  def set(tree, element_or_elements)

  def set(tree, {pfx, val}) do
    case encode(pfx) do
      x when prefix4?(x) -> %{tree | ip4: Radix.set(tree.ip4, x.bits, val)}
      x when prefix6?(x) -> %{tree | ip6: Radix.set(tree.ip6, x.bits, val)}
      x when is_exception(x) -> raise x
      _ -> raise PrefixError.new(:set, {pfx, val})
    end
  end

  def set(tree, elements) do
    Enum.reduce(elements, tree, fn elm, t -> set(t, elm) end)
  end

  @doc """
  Look for the longest matching prefix in an Iptrie.

  """
  # def lookup(%__MODULE__{} = tree, pfx) do
  #   case encode(pfx) do
  #     x when prefix4?(x) -> Radix.lpm(tree.ip4, x.bits)
  #     x when prefix6?(x) -> Radix.lpm(tree.ip6, x.bits)
  #     x -> x
  #   end
  # end
  @spec lookup(t(), String.t() | Prefix.t() | :inet.ip_address()) ::
          term
  def lookup(%__MODULE__{} = tree, pfx) when is_binary(pfx),
    do: lookup(tree, encode(pfx))

  def lookup(%__MODULE__{} = tree, x) when is_tuple(x),
    do: lookup(tree, encode(x))

  def lookup(%__MODULE__{} = tree, x) when prefix4?(x),
    do: Radix.lpm(tree.ip4, x.bits)

  def lookup(%__MODULE__{} = tree, x) when prefix6?(x),
    do: Radix.lpm(tree.ip6, x.bits)

  def lookup(_, _), do: nil

  # IP prefix functions

  def info(prefix) do
    lookup(@ip, prefix)
  end

  def network(prefix) do
    prefix
    |> encode()
    |> padright(0)
    |> decode()
  end

  def broadcast(prefix) do
    prefix
    |> encode()
    |> padright(1)
    |> decode()
  end

  def hosts(prefix) do
    prefix
    |> encode()
    |> Enum.map(fn ip -> decode(ip) end)
  end

  def mask(prefix) do
    prefix
    |> encode()
    |> replace(0, 1)
    |> padright(0)
    |> decode()
  end

  def inv_mask(prefix) do
    prefix
    |> encode()
    |> replace(1, 0)
    |> padright(1)
    |> decode()
  end

  def neighbor(prefix) do
    x = encode(prefix)

    case bit(x, bit_size(x.bits) - 1) do
      0 -> offset(x, 1)
      1 -> offset(x, -1)
    end
    |> decode()
  end

  def moveto(prefix, n) do
    prefix
    |> encode()
    |> offset(n)
    |> decode()
  end

  def host(prefix, nth) do
    prefix
    |> encode()
    |> member(nth)
    |> decode()
  end

  def numhosts(prefix) do
    prefix
    |> encode()
    |> size()
  end

  # TODO Table funcs
  # x new :: create a new iptrie
  # x set :: set exact match
  # o get :: get exact match
  # x lpm :: longest prefix match
  # o map :: apply function to all {k,v}-pairs
  # o more :: return all more specifics (option inclusive)
  # o less :: return all less specifics (option inclusive)
  # o exec :: apply function to all nodes & leafs
  #
  # TODO Prefix funcs
  # x network :: return network address
  # x broadcast :: return broadcast address
  # x hosts :: return list of host addresses
  # o hosts_lazy :: return stream that returns hosts addresses
  # x mask :: return network mask
  # x inv_mask :: return inverse mask
  # x neighbor :: return prefix that will combine with arg into a supernet
  # x moveto :: return another prefix, offset removed from original
  # x host :: return host address in prefix
  # x numhosts :: return number of host in the prefix
end
