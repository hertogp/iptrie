defmodule Prefix.IP do
  @behaviour Prefix
  @moduledoc """
  Encode/decode IP prefixes.

  An IP prefix can be given as:
  - a `t:String.t/0` using CIDR notation (mask is optional)
  - a `t::inet.ip_address/0`, or
  - a `t:digits/0`

  Succesfull encoding yields a `t:Prefix.t/0` result, while decoding always
  results in a string using CIDR-notation upon success.  In case of any errors,
  both return a `t:PrefixError/0` exception.

  """

  use Bitwise
  require Prefix
  alias PrefixError

  @typedoc """
  An :inet IPv4 or IPv6 address.

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
  defguardp digits?(digits, len) when digits4?(digits, len) or digits6?(digits, len)

  @compile inline: [error: 2]
  defp error(id, detail), do: PrefixError.new(id, detail)

  #
  # Encode
  #

  @doc """
  Encode an IP *prefix* into a `Prefix`.

  Where *prefix* is either a string using CIDR notation, a `t::inet.ip_address/0`
  or a `t:digits/0`

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

      iex> encode("acdc:1976::")
      %Prefix{bits: <<0xacdc::16, 0x1976::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0::16>>, maxlen: 128}

      # an exception as argument is passed through
      iex> decode("illegal") |> encode()
      %PrefixError{id: :decode, detail: "illegal"}

  """

  @impl Prefix
  @spec encode(String.t() | :inet.ip_address() | digits()) :: Prefix.t() | PrefixError.t()
  def encode(prefix) when is_binary(prefix) do
    {addr, len} =
      prefix
      |> String.split("/", parts: 2)
      |> case do
        [addr, len] -> {addr, Integer.parse(len)}
        [addr] -> {addr, :none}
      end

    digits =
      addr
      |> String.to_charlist()
      |> :inet.parse_address()
      |> case do
        {:error, _} -> :error
        {:ok, digits} -> digits
      end

    case {digits, len} do
      {:error, _} -> error(:encode, prefix)
      {_, :error} -> error(:encode, prefix)
      {digits, :none} -> encode(digits)
      {digits, {len, ""}} when digits?(digits, len) -> encode({digits, len})
      _ -> error(:encode, prefix)
    end
  end

  def encode(digits) when ip4?(digits), do: encode({digits, 32})
  def encode(digits) when ip6?(digits), do: encode({digits, 128})

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

  # Decode

  @doc """
  Decode a *prefix* back into string, using CIDR-notation.

  Where *prefix* is either a string using CIDR notation, a `t::inet.ip_address/0`
  or a `t:digits/0`

  For full addresses the '/length' is omitted.  When decoding a `t:digits/0`,
  the mask is *not* applied first.

  ## Examples

      iex> decode({1, 1, 1, 1})
      "1.1.1.1"

      iex> decode(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.0/24"

      # host bits are preserved
      iex> decode({{1, 1, 1, 1}, 24})
      "1.1.1.1/24"

      # an exception as argument is passed through
      iex> encode("illegal") |> decode()
      %PrefixError{id: :encode, detail: "illegal"}

  """
  @impl Prefix
  @spec decode(Prefix.t() | :inet.ip_address() | digits()) :: String.t() | PrefixError.t()
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

  def decode(x) when is_exception(x), do: x
  def decode(x), do: error(:decode, x)
end
