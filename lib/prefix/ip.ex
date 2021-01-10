defmodule Prefix.IP do
  @behaviour Prefix
  @moduledoc """
  Encode/decode IP prefixes.

  Succesfull encoding yields a `t:Prefix.t/0` result, while decoding results in
  a string in CIDR notation upon success.  In case of any errors, both
  return a `t:PrefixError.t/0` exception.

  """

  use Bitwise
  require Prefix
  alias PrefixError

  @typedoc """
  An `:inet` IPv4 or IPv6 address tuple.

  """
  @type address :: :inet.ip4_address() | :inet.ip6_address()

  @typedoc """
  An IPv4 or IPv6 prefix in `{address, length}`-format.
  """
  @type digits :: {:inet.ip4_address(), 0..32} | {:inet.ip6_address(), 0..128}

  # GUARDS

  defguardp len4?(len) when is_integer(len) and len > -1 and len < 33
  defguardp len6?(len) when is_integer(len) and len > -1 and len < 129
  defguardp dig4?(n) when is_integer(n) and n > -1 and n < 256
  defguardp dig6?(n) when is_integer(n) and n > -1 and n < 65536

  defguardp ip4?(t)
            when tuple_size(t) == 4 and
                   dig4?(elem(t, 0)) and
                   dig4?(elem(t, 1)) and
                   dig4?(elem(t, 2)) and
                   dig4?(elem(t, 3))

  defguardp ip6?(t)
            when tuple_size(t) == 8 and
                   dig6?(elem(t, 0)) and
                   dig6?(elem(t, 1)) and
                   dig6?(elem(t, 2)) and
                   dig6?(elem(t, 3)) and
                   dig6?(elem(t, 4)) and
                   dig6?(elem(t, 5)) and
                   dig6?(elem(t, 6)) and
                   dig6?(elem(t, 7))

  defguardp digits4?(digits, len) when ip4?(digits) and len4?(len)
  defguardp digits6?(digits, len) when ip6?(digits) and len6?(len)

  @compile inline: [error: 2]
  defp error(id, detail), do: PrefixError.new(id, detail)

  #
  # Encode
  #

  @doc """
  Encode *prefix* into `t:Prefix.t/0`.

  Note: encoding does not preserve the host bits of the address.

  ## Examples

      iex> encode("1.1.1.0/24")
      %Prefix{bits: <<1, 1, 1>>, maxlen: 32}

      iex> encode("1.1.1.1")
      %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 32}

      iex> encode({1,1,1,1})
      %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 32}

      # host bits are lost in translation
      iex> encode("1.1.1.1/24")
      %Prefix{bits: <<1, 1, 1>>, maxlen: 32}

      iex> encode("acdc:1976::/32")
      %Prefix{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128}

      # exceptions are passed through
      iex> decode({1, 2, 3, 256}) |> encode()
      %PrefixError{id: :decode, detail: {1, 2, 3, 256}}
  """

  @impl Prefix
  @spec encode(String.t() | address() | digits()) :: Prefix.t() | PrefixError.t()
  def encode(prefix) when is_binary(prefix) do
    charlist = String.to_charlist(prefix)
    {address, mask} = splitp(charlist, [])

    case {:inet.parse_address(address), mask} do
      {{:error, _}, _} -> error(:encode, prefix)
      {_, :error} -> error(:encode, prefix)
      {{:ok, digits}, mask} -> encode({digits, mask})
    end
  end

  # only check tuple_size, since next encode call checks all digits
  def encode({digits, nil}) when tuple_size(digits) == 4, do: encode({digits, 32})
  def encode({digits, nil}) when tuple_size(digits) == 8, do: encode({digits, 128})
  def encode(digits) when tuple_size(digits) == 4, do: encode({digits, 32})
  def encode(digits) when tuple_size(digits) == 8, do: encode({digits, 128})

  def encode({digits = {a, b, c, d}, len}) when digits4?(digits, len) do
    <<bits::bitstring-size(len), _::bitstring>> = <<a::8, b::8, c::8, d::8>>

    %Prefix{bits: bits, maxlen: 32}
  end

  def encode({digits = {a, b, c, d, e, f, g, h}, len}) when digits6?(digits, len) do
    <<bits::bitstring-size(len), _::bitstring>> =
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    %Prefix{bits: bits, maxlen: 128}
  end

  def encode(x) when is_exception(x), do: x
  def encode(x), do: error(:encode, x)

  # split a charlist with length into tuple w/ {'address', length}
  # notes:
  # - ugly code, but a tad faster than multiple func's w/ signatures
  # - crude length "parser":
  #   '1.1.1.1/024' -> {'1.1.1.1', 24}
  defp splitp(charlist, acc) do
    case charlist do
      [?/ | tail] ->
        length =
          case tail do
            [y, z] -> (y - ?0) * 10 + z - ?0
            [z] -> z - ?0
            [x, y, z] -> (x - ?0) * 100 + (y - ?0) * 10 + z - ?0
            _ -> :error
          end

        {Enum.reverse(acc), length}

      [x | tail] ->
        splitp(tail, [x | acc])

      [] ->
        {Enum.reverse(acc), nil}
    end
  end

  # Decode

  @doc """
  Decode *prefix* back into a string in CIDR notation.

  When decoding `t:digits/0`, the mask is *not* applied first.  For full length
  prefixes, the '/len' will be omitted in the result.

  ## Examples

      iex> decode(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.0/24"

      iex> decode({1, 1, 1, 1})
      "1.1.1.1"

      # host bits are preserved
      iex> decode({{1, 1, 1, 1}, 24})
      "1.1.1.1/24"

      # exceptions are passed through
      iex> encode("1.1.1.256") |> decode()
      %PrefixError{id: :encode, detail: "1.1.1.256"}

  """
  @impl Prefix
  @spec decode(Prefix.t() | address() | digits()) :: String.t() | PrefixError.t()
  def decode(%Prefix{maxlen: 32} = prefix) do
    prefix
    |> Prefix.digits(8)
    |> decode()
  end

  def decode(%Prefix{maxlen: 128} = prefix) do
    prefix
    |> Prefix.digits(16)
    |> decode()
  end

  def decode(digits) when ip4?(digits),
    do: "#{:inet.ntoa(digits)}"

  def decode(digits) when ip6?(digits),
    do: "#{:inet.ntoa(digits)}"

  def decode({digits, len}) when digits4?(digits, len) do
    pfx = :inet.ntoa(digits)
    if len < 32, do: "#{pfx}/#{len}", else: "#{pfx}"
  end

  def decode({digits, len}) when digits6?(digits, len) do
    pfx = :inet.ntoa(digits)
    if len < 128, do: "#{pfx}/#{len}", else: "#{pfx}"
  end

  # note: exceptions may get nested, like a stacktrace of sorts
  def decode(x) when is_exception(x), do: x
  def decode(x), do: error(:decode, x)
end
