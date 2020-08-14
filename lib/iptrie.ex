defmodule Iptrie do
  @moduledoc """
  `Iptrie` provides an IP lookup table for both IPv4 and IPv6, as well as
  some functions to manipulate prefixes.


  """
  alias Iptrie.Key

  @doc """
  Encode a prefix string `"address/len"` into a `key` used for lookup's in the
  iptrie.  A key is bitstring whose first bit indicates either an IPv4 or an
  IPv6 address, the remaining bits are the network address bits provided. This
  means only contiguous masks are supported.  If the `len` is omitted, it
  defaults to the address family's maximum mask.

  ## Examples

      iex> Iptrie.encode("10.10.10.22/24")
      {:ok, <<0::1, 10::8, 10::8, 10::8>>}

      iex> Iptrie.encode("abcd::/16")
      {:ok, <<1::1, 0xabcd::16>>}

  Omitting a mask:

      iex> Iptrie.encode("10.10.10.10")
      {:ok, <<0::1, 10::8, 10::8, 10::8, 10::8>>}


  Zero length prefix is also valid:

      iex> Iptrie.encode("255.255.255.255/0")
      {:ok, <<0::1>>}

      iex> Iptrie.encode("abcd::/0")
      {:ok, <<1::1>>}

  """
  def encode(prefix) do
    Key.encode(prefix)
  end

  @doc """
  Given a key, decode it back into its regular string form.  If the
  intermediate form of decoded key is required, use `Iptrie.Key.decode/1`
  instead.

      iex> Iptrie.decode(<<0::1, 10::8, 10::8, 10::8>>)
      {:ok, "10.10.10.0/24"}

      iex> Iptrie.decode(<<0::1, 10::8, 10::8, 10::8, 10::8>>)
      {:ok, "10.10.10.10/32"}

      iex> Iptrie.decode(<<0::1>>)
      {:ok, "0.0.0.0/0"}

      iex> Iptrie.decode(<<1::1, 0xacdc::16, 0xabba::16, 0xdada::16>>)
      {:ok, "acdc:abba:dada::/48"}

      iex> Iptrie.decode(<<1::1>>)
      {:ok, "::/0"}

  """

  def decode(key) do
    Key.decode(key)
    |> Key.format(mask: true)
  end

  @doc """
  Parse the address portion from a given prefix.  The mask (if any) is ignored
  completely so its validity is never checked.

  ## Examples

      iex> Iptrie.address("10.10.10.10/24")
      {:ok, "10.10.10.10"}

      # wonders of :inet.ntoa/1
      iex> Iptrie.address("::ffff/128")
      {:ok, "::0.0.255.255"}

  """

  def address(prefix) when is_binary(prefix) do
    prefix
    |> String.split("/", parts: 2)
    |> List.first()
    |> Key.encode()
    |> Key.digits(0)
    |> Key.format(mask: false)
  end

  def address(_), do: {:error, :eaddress}

  @doc """
  Get the network address for a given prefix.  A second optional argument
  specifies whether the prefix length should be included in the result
  (defaults to false).

      iex> Iptrie.network("10.10.10.10/24")
      {:ok, "10.10.10.0"}

      iex> Iptrie.network("10.10.10.10/24", true)
      {:ok, "10.10.10.0/24"}

      iex> Iptrie.network("acdc::abba/128")
      {:ok, "acdc::abba"}

  """

  def network(prefix, with_mask \\ false) do
    prefix
    |> Key.encode()
    |> Key.decode()
    |> Key.format(mask: with_mask)
  end

  @doc """
  Get the broadcast address for a given prefix. An optional second arguments
  may be given to include the prefix length in the result (defaults to false).

  ## Examples

     iex> Iptrie.broadcast("10.10.10.0/24")
     {:ok, "10.10.10.255"}

     iex> Iptrie.broadcast("10.10.10.0/24", true)
     {:ok, "10.10.10.255/24"}

     iex> Iptrie.broadcast("1234:5678::/32")
     {:ok, "1234:5678:ffff:ffff:ffff:ffff:ffff:ffff"}

  """

  def broadcast(prefix, with_mask \\ false) do
    prefix
    |> Key.encode()
    |> Key.digits(1)
    |> Key.format(mask: with_mask)
  end
end
