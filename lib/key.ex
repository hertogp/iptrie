defmodule Iptrie.Key do
  @moduledoc """
  The `Key` module provides all the functions for encoding, decoding and manipulating
  keys.  Keys are prefixes encoded as a bitstring whose frst bit indicates whether
  it is an IPv4 or an IPv6 address.


  """

  use Bitwise

  use Iptrie.Constants

  # ENCODE

  @doc ~S"""

  Encode a prefix string into a bitstring (aka key) used to index into the
  iptrie.  The first bit represents the ip protocol version (0 for ipv4, 1 for
  ipv6).  If the prefix length is omitted it defaults to the corresponding
  maximum mask.  The main IPtrie module basically wraps this module's encoding
  function for ease of use.

  ## Examples

      iex> Iptrie.Key.encode("1.2.3.4")
      {:ok, <<0::1, 1::8, 2::8, 3::8, 4::8>>}

      iex> Iptrie.Key.encode("1.2.3.4/16")
      {:ok, <<0::1, 1::8, 2::8>>}



  """

  def encode({:error, reason}), do: {:error, reason}

  def encode(prefix) when is_binary(prefix) do
    [addr | mask] = String.split(prefix, "/", parts: 2)

    len =
      case mask do
        [] ->
          -1

        [str] ->
          try do
            String.to_integer(str)
          rescue
            ArgumentError -> -2
          end
      end

    case :inet.parse_address(String.to_charlist(addr)) do
      {:error, _} -> {:error, :eaddress}
      {:ok, digits} -> encode(digits, len)
    end
  end

  # non-binary prefix argument
  def encode(_), do: {:error, :eaddress}

  # bad mask (not a number)
  def encode(_, -2), do: {:error, :emask}

  # omitted mask turns into full mask
  def encode(digits, -1) when is_tuple(digits) do
    case tuple_size(digits) do
      @ip4_digits -> encode(digits, @ip4_maxlen)
      @ip6_digits -> encode(digits, @ip6_maxlen)
      _ -> {:error, :eaddress}
    end
  end

  def encode({a, b, c, d}, len) when len in @ip4_masks do
    len = len + 1

    <<key::bitstring-size(len), _::bitstring>> = <<@ip4, a::8, b::8, c::8, d::8>>

    {:ok, key}
  end

  def encode({a, b, c, d, e, f, g, h}, len) when len in @ip6_masks do
    len = len + 1

    <<key::bitstring-size(len), _::bitstring>> =
      <<@ip6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    {:ok, key}
  end

  # bad mask (outside the valid ranges)
  def encode(_, _), do: {:error, :emask}

  # DECODE

  @doc """
  Decode a given key into its digits and mask.

      iex> Iptrie.Key.decode(<<0::1, 10::8>>)
      {:ok, {[10, 0, 0, 0], 8}}

      iex> Iptrie.Key.decode(<<0::1, 1::8, 2::8, 3::8, 4::8, 5::8>>)
      {:error, :eaddress}

      iex> Iptrie.Key.decode(<<1::1, 0xacdc::16, 0xabba::16>>)
      {:ok, {[0xacdc, 0xabba, 0, 0, 0, 0, 0, 0], 32}}

  """

  def decode({:error, reason}), do: {:error, reason}
  def decode({:ok, key}) when is_bitstring(key), do: digits({:ok, key}, 0)
  def decode(key), do: digits({:ok, key}, 0)

  # AF info

  def af_length(<<@ip4, _::bitstring>>), do: @ip4_maxlen
  def af_length(<<@ip6, _::bitstring>>), do: @ip6_maxlen

  def af_chunks(<<@ip4, _::bitstring>>), do: @ip4_chunk
  def af_chunks(<<@ip6, _::bitstring>>), do: @ip6_chunk

  def af_family(<<@ip4, _::bitstring>>), do: :ip4
  def af_family(<<@ip6, _::bitstring>>), do: :ip6

  # Format

  @doc """
  Format a list of numbers using :inet_ntoa. 

  ## Examples

      iex> key = Iptrie.encode("10.11.12.13/24")
      iex> Iptrie.Key.format(Iptrie.Key.decode(key))
      { :ok, "10.11.12.0/24" }
      iex> Iptrie.Key.format(Iptrie.Key.decode(key), [mask: false])
      { :ok, "10.11.12.0" }

      iex> Iptrie.Key.format({{1, 2, 3, 4, 5, 6, 7, 8}, 128})
      { :ok, "1:2:3:4:5:6:7:8/128" }

      iex> Iptrie.Key.format({{10, 100, 1000, 0}, 24})
      {:error, :eaddress}

      iex> Iptrie.Key.format({{1, 2, 3, 4, 5, 6, 7, 8}, 129})
      {:error, :emask}
  """
  def format(arg, opts \\ [])

  def format({:error, reason}, _opts), do: {:error, reason}
  def format({:ok, {digits, len}}, opts), do: format({digits, len}, opts)

  def format({digits, len}, opts) when is_list(digits) do
    format({List.to_tuple(digits), len}, opts)
  end

  def format({digits, len}, opts) when is_tuple(digits) do
    mask = Keyword.get(opts, :mask, true)

    case validity(digits, len) do
      :ok ->
        case :inet.ntoa(digits) do
          {:error, _} ->
            {:error, :eaddress}

          address ->
            case mask do
              true -> {:ok, "#{address}/#{len}"}
              false -> {:ok, "#{address}"}
            end
        end

      err ->
        {:error, err}
    end
  end

  defp validity({a, b, c, d}, len) do
    if a in @ip4_digit and
         b in @ip4_digit and
         c in @ip4_digit and
         d in @ip4_digit do
      if len in @ip4_masks do
        :ok
      else
        :emask
      end
    else
      :eaddress
    end
  end

  defp validity({a, b, c, d, e, f, g, h}, len) do
    if a in @ip6_digit and
         b in @ip6_digit and
         c in @ip6_digit and
         d in @ip6_digit and
         e in @ip6_digit and
         f in @ip6_digit and
         g in @ip6_digit and
         h in @ip6_digit do
      if len in @ip6_masks do
        :ok
      else
        :emask
      end
    else
      :eaddress
    end
  end

  defp validity(_, _), do: :eaddress

  # PADDING KEYS
  # - functions to pad the *address portion* of a *key* to a specific length
  # - length provided is the *address* length, not key length
  # - the padding funcs account for the extra bit that indicates ipv4 vs ipv6.

  # def padding(fill, len, acc \\ <<>>)
  # def padding(fill, len, acc) when len > 0 do
  #   chunk = min(len, 16)
  #   num = (65535 >>> (16 - chunk)) * fill
  #   padding(fill, len - chunk, <<acc::bitstring, num::size(chunk)>>)
  # end
  # def padding(_fill, _len, acc), do: acc

  defp bitsp(_, 0), do: <<>>

  defp bitsp(0, len) when len in @all_size do
    <<series::bitstring-size(len), _::bitstring>> = @all_zeros
    series
  end

  defp bitsp(1, len) when len in @all_size do
    <<series::bitstring-size(len), _::bitstring>> = @all_ones
    series
  end

  # any bad request simpy yields an empty bitstring (caller beware..)
  defp bitsp(_, _), do: <<>>

  # - PADRight

  def padr({:ok, key}, fill), do: padr({:ok, key}, fill, af_length(key))
  def padr({:error, reason}, _fill, _len), do: {:error, reason}

  def padr({:ok, key}, fill, len) when bit_size(key) - 1 < len do
    case key do
      <<@ip4, addr::bitstring>> when len in @ip4_masks ->
        bits = bitsp(fill, max(0, len - bit_size(addr)))
        {:ok, <<@ip4, addr::bitstring, bits::bitstring>>}

      <<@ip6, addr::bitstring>> when len in @ip6_masks ->
        bits = bitsp(fill, max(0, len - bit_size(addr)))
        {:ok, <<@ip6, addr::bitstring, bits::bitstring>>}

      _ ->
        # bad padding length
        {:error, :epadr}
    end
  end

  # ignore padr request if bitsize(addr) >= len
  def padr({:ok, key}, _fill, _len), do: {:ok, key}

  # - PADLeft
  def padl({:ok, key}, fill), do: padl({:ok, key}, fill, af_length(key))
  def padl({:error, reason}, _fill, _len), do: {:error, reason}

  def padl({:ok, key}, fill, len) when bit_size(key) - 1 < len do
    case(key) do
      <<@ip4, addr::bitstring>> when len in @ip4_masks ->
        bits = bitsp(fill, max(0, len - bit_size(addr)))
        {:ok, <<@ip4, bits::bitstring, addr::bitstring>>}

      <<@ip6, addr::bitstring>> when len in @ip6_masks ->
        bits = bitsp(fill, max(0, len - bit_size(addr)))
        {:ok, <<@ip6, bits::bitstring, addr::bitstring>>}

      _ ->
        # bad padding length
        {:error, :epadl}
    end
  end

  # ignore padl request if bitsize of addr in key is already >= len
  def padl({:ok, key}, _fill, _len), do: {:ok, key}

  # KEY DIGITS
  def split({:error, reason}), do: {:error, reason}
  def split({:ok, key}), do: split(key)
  def split(<<af::bitstring-size(1), addr::bitstring>>), do: {af, <<addr::bitstring>>}

  @doc """
  Return the `{digits, masklen}` for a given key, filling the hosts bits in 
  with either `zeros` or all `ones` as per fill argument.  `digits` is a list
  of digit of the ipv4/6 address.

  ## Examples

      iex> Iptrie.Key.digits({:ok, <<@ip4, 1::8, 2::8, 129::8>>}, 0)
      {:ok, {[1, 2, 129, 0], 24}}

      iex> Iptrie.Key.digits({:ok, <<@ip4, 1::8, 2::8, 129::8>>}, 1)
      {:ok, {[1, 2, 129, 255], 24}}

      iex> Iptrie.Key.digits({:ok, <<@ip6, 0xacdc::16, 0xabba::16>>}, 0)
      {:ok, {[44252, 43962, 0, 0, 0, 0, 0, 0], 32}}


  """

  def digits(arg, fill \\ 0)

  def digits({:error, reason}, _fill), do: {:error, reason}

  def digits({:ok, key}, fill) when is_bitstring(key) and fill in 0..1 do
    msklen = bit_size(key) - 1

    case padr({:ok, key}, fill, af_length(key)) do
      {:ok, <<@ip4, addr::bitstring>>} when bit_size(addr) in @ip4_masks ->
        {:ok, {bits_todigits(addr, @ip4_chunk), msklen}}

      {:ok, <<@ip6, addr::bitstring>>} when bit_size(addr) in @ip6_masks ->
        {:ok, {bits_todigits(addr, @ip6_chunk), msklen}}

      {:error, reason} ->
        # incase padr gives an error reason
        {:error, reason}

      _ ->
        # incase key has illegal length
        {:error, :eaddress}
    end
  end

  def bits_todigits(bitstr, size, acc \\ [])

  def bits_todigits(bitstr, size, acc) when bit_size(bitstr) <= size do
    # - the remaining bits are padded right to fit 'size' first
    # - and then padded left to arrive at a multiple of 8 bits
    padright = bitsp(0, size - bit_size(bitstr))
    padleft = bitsp(0, 8 * ceil(size / 8) - size)
    bits = <<padleft::bitstring, bitstr::bitstring, padright::bitstring>>

    [:binary.decode_unsigned(bits) | acc]
    |> Enum.reverse()
  end

  def bits_todigits(bitstr, size, acc) do
    <<num::bitstring-size(size), rest::bitstring>> = bitstr

    # size might be < N*8, so padd left with 0's for the encode_unsigend call
    padleft = bitsp(0, 8 * ceil(size / 8) - size)
    num = <<padleft::bitstring, num::bitstring-size(size)>>
    bits_todigits(rest, size, [:binary.decode_unsigned(num) | acc])
  end
end
