defmodule Prefix.IP do
  @behaviour Prefix
  @moduledoc """
  Functions to encode/decode IP prefixes.

  Note: prepends either a `0`- or an `1`-bit to distinguish between ip4 and ip6
  prefixes respectively.  That way, IP prefixes can be stored in a single
  radix tree referencing the prefix.bits directly.

  """

  use Bitwise
  require Prefix
  alias PrefixError

  @typedoc """
  An IPv4 prefix in `{digits, length}`-format.

  """
  @type digits4 :: {{0..255, 0..255, 0..255, 0..255}, 0..32}

  @typedoc """
  An IPv6 prefix in `{digits, length}`-format.

  """
  @type digits6 ::
          {{0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535},
           0..128}

  @typedoc """
  An IPv4 or IPv6 prefix in `{digits, length}`-format.
  """
  @type digits :: digits4() | digits6()

  # Markers
  @ip4 <<0::1>>
  @ip6 <<1::1>>

  # GUARDS

  # guards for {digits, len}
  defguard len4?(l) when is_integer(l) and l in 0..32
  defguard len6?(l) when is_integer(l) and l in 0..128

  defguard ip4?(t)
           when is_tuple(t) and
                  tuple_size(t) == 4 and
                  elem(t, 0) in 0..255 and
                  elem(t, 1) in 0..255 and
                  elem(t, 2) in 0..255 and
                  elem(t, 3) in 0..255

  defguard ip6?(t)
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

  defguard dig4?(digits, len) when ip4?(digits) and len4?(len)
  defguard dig6?(digits, len) when ip6?(digits) and len6?(len)
  defguard dig?(digits, len) when dig4?(digits, len) or dig6?(digits, len)

  # guards for prefixes
  defguard prefix4?(x) when Prefix.valid?(x) and x.maxlen == 33
  defguard prefix6?(x) when Prefix.valid?(x) and x.maxlen == 129

  @compile inline: [error: 2]
  defp error(id, detail), do: PrefixError.new(id, detail)

  #
  # Encode
  #

  @doc """
  Encode an IP *prefix* into a `Prefix`.

  The *prefix* can be a string using CIDR notation or in `{digits,
  length}`-format.

  ## Examples

      iex> encode("1.1.1.0/24")
      %Prefix{bits: <<0::1, 1, 1, 1>>, maxlen: 33}

      iex> encode("acdc:1976::/32")
      %Prefix{bits: <<1::1, 0xacdc::16, 0x1976::16>>, maxlen: 129}

  """

  @impl Prefix
  @spec encode(String.t() | :inet.ip_address() | digits()) :: Prefix.t() | PrefixError.t()
  def encode(prefix) when is_binary(prefix) do
    {addr, len} =
      prefix
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
        {:error, _} -> error(:encode, prefix)
        {:ok, digits} -> digits
      end

    case {digits, len} do
      {x, _} when is_exception(x) -> x
      {_, :error} -> error(:encode, prefix)
      {digits, {-1, ""}} -> encode(digits)
      {digits, {len, ""}} when dig?(digits, len) -> encode({digits, len})
      _ -> error(:encode, prefix)
    end
  end

  def encode(digits) when ip4?(digits), do: encode({digits, 32})
  def encode(digits) when ip6?(digits), do: encode({digits, 128})

  def encode({digits = {a, b, c, d}, len}) when dig4?(digits, len) do
    len = len + 1
    <<bits::bitstring-size(len), _::bitstring>> = <<@ip4, a::8, b::8, c::8, d::8>>
    %Prefix{bits: bits, maxlen: 33}
  end

  def encode({digits = {a, b, c, d, e, f, g, h}, len}) when dig6?(digits, len) do
    len = len + 1

    <<bits::bitstring-size(len), _::bitstring>> =
      <<@ip6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    %Prefix{bits: bits, maxlen: 129}
  end

  def encode(x) when is_exception(x), do: x
  def encode(x), do: error(:encode, x)

  # Decode

  @doc """
  Decode a *prefix* back into string, using CIDR-notation.

  Notes:
  - the `/len` is not added when `len` is at its maximum.
  - when converting from `digits` format, the mask is *not* applied first.

  ## Examples

      iex> decode({1, 1, 1, 1})
      "1.1.1.1"

      iex> decode(%Prefix{bits: <<0::1, 1, 1, 1>>, maxlen: 33})
      "1.1.1.0/24"

      # Note: mask is *not* applied when using `{digits, len}`-format
      iex> decode({{1, 1, 1, 1}, 24})
      "1.1.1.1/24"

      # an exception as argument is passed through
      iex> decode(%PrefixError{id: :func_x, detail: "some error"})
      %PrefixError{id: :func_x, detail: "some error"}

  """
  @impl Prefix
  @spec decode(Prefix.t() | :inet.ip_address() | digits()) :: String.t() | PrefixError.t()
  def decode(%Prefix{bits: <<@ip4, bits::bitstring>>, maxlen: 33}),
    do: Prefix.format(%Prefix{bits: bits, maxlen: 32})

  def decode(%Prefix{bits: <<@ip6, bits::bitstring>>, maxlen: 129}) do
    {digits, len} =
      %Prefix{bits: bits, maxlen: 128}
      |> Prefix.digits(16)

    pfx = :inet.ntoa(digits)
    if len < 128, do: "#{pfx}/#{len}", else: pfx
  end

  def decode(digits) when ip4?(digits),
    do: "#{:inet.ntoa(digits)}"

  def decode(digits) when ip6?(digits),
    do: "#{:inet.ntoa(digits)}"

  def decode({digits, len}) when dig4?(digits, len) do
    pfx = :inet.ntoa(digits)
    if len < 32, do: "#{pfx}/#{len}", else: pfx
  end

  def decode({digits, len}) when dig6?(digits, len) do
    pfx = :inet.ntoa(digits)
    if len < 128, do: "#{pfx}/#{len}", else: pfx
  end

  def decode(x) when is_exception(x), do: x
  def decode(x), do: error(:decode, x)
end
