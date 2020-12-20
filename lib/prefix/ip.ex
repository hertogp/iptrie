defmodule Prefix.IP do
  @moduledoc """
  Functions to encode/decode IP prefixes.

  """

  use Bitwise
  import Prefix
  alias PrefixError

  @typedoc """
  An IP prefix in bitstring-format: an 8bit protocol marker, followed by zero
  or more network bits.

  For example: <<0, v4_network::bits>> or <<1, v6_network::bits>>

  The marker identifies the protocol (v4 vs v6) and also helps to differentiate
  between a prefix bitstring and a regular binary.  The latter is the reason
  the marker is 8 bits instead of just 1 bit.

  """
  @type t :: <<_::8, _::_*1>>
  @typep dig4 :: {{0..255, 0..255, 0..255, 0..255}, -1..32}
  @typep dig6 ::
           {{0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535},
            -1..128}

  @typedoc """
  An IP prefix in {digits, len}-format.
  """
  @type dig :: dig4() | dig6()

  # IPv4/6 markers.
  @ip4 <<0::8>>
  @ip6 <<1::8>>

  # GUARDS

  # guards for {digits, len}, -1 denotes absence of mask
  defguardp len4?(l) when is_integer(l) and l in -1..32
  defguardp len6?(l) when is_integer(l) and l in -1..128

  defguardp ip4?(t)
            when is_tuple(t) and
                   tuple_size(t) == 4 and
                   elem(t, 0) in 0..255 and
                   elem(t, 1) in 0..255 and
                   elem(t, 2) in 0..255 and
                   elem(t, 3) in 0..255

  defguardp ip6?(t)
            when is_tuple(t) and
                   tuple_size(t) == 8 and
                   elem(t, 0) in 0..65535 and
                   elem(t, 1) in 0..65535 and
                   elem(t, 2) in 0..65535 and
                   elem(t, 3) in 0..65535 and
                   elem(t, 4) in 0..65535 and
                   elem(t, 5) in 0..65535 and
                   elem(t, 6) in 0..65535 and
                   elem(t, 7) in 0..65535

  defguardp dig4?(digits, len) when ip4?(digits) and len4?(len)
  defguardp dig6?(digits, len) when ip6?(digits) and len6?(len)
  defguardp dig?(digits, len) when dig4?(digits, len) or dig6?(digits, len)

  # guards for bitstrings
  defguardp size4?(b) when bit_size(b) < 33
  defguardp size6?(b) when bit_size(b) < 129
  defguardp key4?(v, b) when v == @ip4 and size4?(b)
  defguardp key6?(v, b) when v == @ip6 and size6?(b)
  defguardp key?(v, b) when key4?(v, b) or key6?(v, b)

  defp error(id, details), do: PrefixError.new(id, details)
  #
  # API
  #
  # TODO:
  # Implement Enumerable protocol for a prefix %Prefix{proto: :ip4, <<bits>>}
  # Perhaps something similar to the Range type.
  # iex> Enumerable.reduce(0..5, {:cont, []}, fn x, acc -> {:cont, [IO.inspect(x) | IO.inspect(acc)]} end) |> elem(1) |> Enum.reverse()
  # Encode

  @doc """
  Encode an IP prefix into a `t:pfx/0`-bitstring.

  The prefix can be given as a string (using cidr notation), or as a
  `t:dig/0`-tuple.  Any `t:pfx/0`-bitstrings that are valid are passed
  through, as are any exceptions.

  Returns a `t:pfx/0` on success, an `t:PrefixError.t/0` otherwise.

  ## Examples

      iex> Prefix.encode("1.1.1.0/24")
      <<0, 1, 1, 1>>

      # one bit too many for an IPv4 prefix-bitstring
      iex> Prefix.encode(<<0, 1, 1, 1, 1, 0::1>>)
      %PrefixError{id: :eaddress, detail: "<<0, 1, 1, 1, 1, 0::size(1)>>"}

      # illegal digit
      iex> Prefix.encode("1.1.1.256/24")
      %PrefixError{id: :eaddress, detail: "1.1.1.256/24"}

      # illegal prefix length
      iex> Prefix.encode("acdc:1976::/129")
      %PrefixError{id: :emask, detail: "acdc:1976::/129"}

  """
  def encode(prefix) when is_exception(prefix), do: prefix

  # passthrough valid pfx-bitstrings, error out on invalid pfx-bitstrings
  def encode(<<@ip4, addr::bits>> = pfx) when len4?(bit_size(addr)), do: pfx
  def encode(<<@ip4, _::bits>> = pfx), do: error(:eaddress, "#{inspect(pfx)}")
  def encode(<<@ip6, addr::bits>> = pfx) when len6?(bit_size(addr)), do: pfx
  def encode(<<@ip6, _::bits>> = pfx), do: error(:eaddress, "#{inspect(pfx)}")

  # by now, any binary should be a prefix in regular string form
  # - Integer.parse returns either :error or {number, rest}, in the latter case
  #   rest must be "" or else it is also an error
  def encode(pfx) when is_binary(pfx) do
    {addr, len} =
      pfx
      |> String.split("/", parts: 2)
      |> case do
        [addr, len] -> {addr, Integer.parse(len)}
        [addr] -> {addr, {-1, ""}}
      end

    digits =
      addr
      |> String.to_charlist()
      |> :inet.parse_address()
      |> case do
        {:error, _} -> error(:eaddress, "#{pfx}")
        {:ok, digits} -> digits
      end

    case {digits, len} do
      {x, _} when is_exception(x) -> x
      {_, :error} -> error(:emask, "#{pfx}")
      {digits, {len, ""}} when dig?(digits, len) -> encode({digits, len})
      _ -> error(:emask, "#{pfx}")
    end
  end

  def encode({digits, -1}) when tuple_size(digits) == 4,
    do: encode({digits, 32})

  def encode({digits, -1}) when tuple_size(digits) == 8,
    do: encode({digits, 128})

  def encode({digits = {a, b, c, d}, len}) when dig4?(digits, len) do
    len = len + bit_size(@ip4)
    <<key::bitstring-size(len), _::bitstring>> = <<@ip4, a::8, b::8, c::8, d::8>>

    key
  end

  def encode({digits = {a, b, c, d, e, f, g, h}, len}) when dig6?(digits, len) do
    len = len + bit_size(@ip6)

    <<key::bitstring-size(len), _::bitstring>> =
      <<@ip6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    key
  end

  def encode({digits, len}) when ip4?(digits) or ip6?(digits),
    do: error(:emask, "#{inspect({digits, len})}")

  def encode({digits, len}), do: error(:eaddress, "#{inspect({digits, len})}")

  # Decode(bits) :: nums

  @doc """
  Decode an IP prefix into a `t:dig/0`-tuple.

  The prefix can be given as a `t:pfx/0`-bitstring or a `t:dig/0`-tuple.  In
  the latter case, -1 for len denotes absence of mask information and is decoded
  as the maximum mask allowed for the protocol in question.  When valid, a
  `t:dig/0`-tuple is returned.

  Returns a `t:dig/0` on success, an `t:PrefixError.t/0` otherwise.

  ## Examples
      iex> Prefix.decode(<<0, 1, 1, 1>>)
      {{1, 1, 1, 0}, 24}

      # passthrough valid {digits,len}-forms
      iex> Prefix.decode({{1, 1, 1, 0}, 16})
      {{1, 1, 1, 0}, 16}

      # and a bit too much
      iex> Prefix.decode(<<0, 1, 1, 1, 1, 1::size(1)>>)
      %PrefixError{id: :eaddress, detail: "<<0, 1, 1, 1, 1, 1::size(1)>>"}

  """
  def decode(prefix) when is_exception(prefix), do: prefix

  def decode(<<@ip4, addr::bitstring>>) when len4?(bit_size(addr)) do
    <<a::8, b::8, c::8, d::8>> = padright(addr, 32)
    {{a, b, c, d}, bit_size(addr)}
  end

  def decode(<<@ip6, addr::bitstring>>) when len6?(bit_size(addr)) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = padright(addr, 128)
    {{a, b, c, d, e, f, g, h}, bit_size(addr)}
  end

  def decode({digits, len}) when dig4?(digits, len) or dig6?(digits, len),
    do: {digits, len}

  def decode({digits, -1}) when ip4?(digits),
    do: {digits, 32}

  def decode({digits, -1}) when ip6?(digits),
    do: {digits, 128}

  def decode({digits, len}) when ip4?(digits) or ip6?(digits),
    do: error(:emask, "#{inspect({digits, len})}")

  def decode(x),
    do: error(:eaddress, "#{inspect(x)}")

  # Format

  @doc """
  Format a prefix as a regular `t:String.t/0` with optional mask and mask-format.

  The prefix given can be a `t:pfx/0`-bitstring, a `t:dig/0`-{digits,len}-tuple.
  Options include:
  - `mask:` `:none`, to avoid any mask in the resulting string
  - `mask:` `:dotted`, to include a quad dotted mask (IPv4 only)
  - otherwise, the mask defaults to cidr-notation and will be included

  Invalid prefixes result in an `t:PrefixError.t/0`-error.

  ## Examples

      iex> Prefix.format(<<0, 1, 1, 1>>)
      "1.1.1.0/24"

      iex> Prefix.format(<<0,1,1,1>>, mask: :none)
      "1.1.1.0"

      iex> Prefix.format(<<0, 1, 1, 1>>, mask: :dotted)
      "1.1.1.0 255.255.255.0"

      iex> Prefix.format({{1,1,1,1}, 24}, mask: :dotted)
      "1.1.1.1 255.255.255.0"

  """
  def format1(pfx, opts \\ [])

  def format1(pfx, _opts) when is_exception(pfx), do: pfx

  def format1(<<v::binary-size(1), b::bitstring>> = pfx, opts) when key?(v, b),
    do:
      pfx
      |> decode()
      |> formatp(opts)

  def format1({digits, -1}, opts) when ip4?(digits),
    do: formatp({digits, 32}, opts)

  def format1({digits, -1}, opts) when ip6?(digits),
    do: formatp({digits, 128}, opts)

  def format1({digits, len}, opts) when dig?(digits, len),
    do: formatp({digits, len}, opts)

  # if the digits are good, it must be a bad mask
  def format1({digits, len}, _opts) when ip4?(digits) or ip6?(digits),
    do: error(:emask, "#{inspect({digits, len})}")

  # otherwise, it'll be either bad digits or a bad pfx-bitstring
  def format1(x, _),
    do: error(:eaddress, "#{inspect(x)}")

  #
  # formatp only called with valid digits,len
  #
  defp formatp({digits = {_, _, _, _}, len}, opts) do
    mask = Keyword.get(opts, :mask, :cidr)

    case :inet.ntoa(digits) do
      {:error, _} ->
        error(:eaddress, "#{inspect({digits, len})}")

      address ->
        case mask do
          :none -> "#{address}"
          :dotted -> "#{address} #{format(<<@ip4, -1::size(len)>>, mask: :none)}"
          _ -> "#{address}/#{len}"
        end
    end
  end

  # for IPv6 the :dotted option is ignored
  defp formatp({digits, len}, opts) do
    mask = Keyword.get(opts, :mask, :cidr)

    case :inet.ntoa(digits) do
      {:error, _} ->
        error(:eaddress, "#{inspect({digits, len})}")

      address ->
        case mask do
          :none -> "#{address}"
          _ -> "#{address}/#{len}"
        end
    end
  end

  # OFFSET

  def offset(<<v::1, addr::bitstring>>, offset) do
    len = bit_size(addr)
    pad = byte_size(addr) * 8 - len
    # padding left to add offset to the network-bits, not host-bits
    tmp = offset + :binary.decode_unsigned(padleft(addr, pad))

    if tmp < 0 do
      {:error, :eoffset}
    else
      # bits = :binary.encode_unsigned(tmp <<< pad)
      bits = :binary.encode_unsigned(tmp)
      pad = len - bit_size(bits)

      if pad < 0 do
        {:error, :eoffset}
      else
        <<v::1, padleft(bits, pad)::bitstring>>
      end
    end
  end

  @doc """
  Returns an atom indicating the adress family for `prefix` or
  an exception struct on any error.

  """
  def af_family(prefix) when is_exception(prefix), do: prefix
  def af_family(<<@ip4, bits::bits>>) when size4?(bits), do: :ip4
  def af_family(<<@ip6, bits::bits>>) when size6?(bits), do: :ip6
  def af_family({digits, len}) when dig4?(digits, len), do: :ip4
  def af_family({digits, len}) when dig6?(digits, len), do: :ip6
  def af_family(x), do: error(:eaddress, "#{inspect(x)}")

  # compare, used by Enum.sort/2 to sort {k,v}-pairs in {:desc, Iptrie.Key}-order
  # :eq  keys are equal
  # :lt  key1 less than key2
  # :gt  key1 greater than key2
  #
  def compari({k1, _v1}, {k2, _v2}), do: compare(k1, k2)

  def compari(key1, key2) do
    cond do
      key1 == key2 -> :eq
      bit_size(key1) < bit_size(key2) -> :lt
      bit_size(key1) > bit_size(key2) -> :gt
      key1 < key2 -> :lt
      true -> :gt
    end
  end

  # Match keys:
  # :default  key1 or key2 is a default match(er) (i.e. a /0)
  # :nomatch  key1 and key2 have no match at all
  # :equal    key1 equals key2
  # :more     key1 is more specific than key2, same network address
  # :less     key1 is less specific than key2, same network address
  # :subnet   key1 is more specific than key2 (diff network address)
  # :supernet key1 is less specific than key2 (diff network address)
  def match(key1, key2) when bit_size(key1) == 0 or bit_size(key2) == 0, do: :default
  def match(key1, key2) when key1 == key2, do: :equal

  def match(key1, key2) when bit_size(key1) > bit_size(key2) do
    len = bit_size(key2)

    <<k1::bitstring-size(len), _::bitstring>> = key1

    case k1 == key2 do
      true ->
        if padright(key2, bit_size(key1)) == key1, do: :more, else: :subnet

      false ->
        :nomatch
    end
  end

  def match(key1, key2) do
    len = bit_size(key1)
    <<k2::bitstring-size(len), _::bitstring>> = key2

    case k2 == key1 do
      true ->
        if padright(key1, bit_size(key2)) == key2, do: :less, else: :supernet

      false ->
        :nomatch
    end
  end
end
