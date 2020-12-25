defmodule Prefix.IP do
  @moduledoc """
  Functions to encode/decode IP prefixes.

  """

  use Bitwise
  require Prefix
  alias PrefixError

  @typedoc """
  An IPv4 prefix in `{digits, length}`-format.

  A `-1` as length means the source of the `digits` did not provide a length,
  which will default to maximum length.
  """
  @type digits4 :: {{0..255, 0..255, 0..255, 0..255}, -1..32}

  @typedoc """
  An IPv6 prefix in `{digits, length}`-format.

  A `-1` as length means the source of the `digits` did not provide a length,
  which will default to maximum length.
  """
  @type digits6 ::
          {{0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535, 0..65535},
           -1..128}
  @typedoc """
  An IPv4 or IPv6 prefix in `{digits, length}`-format.
  """
  @type digits :: digits4() | digits6()

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

  # guards for prefixes
  defguardp prefix4?(x) when Prefix.valid?(x) and x.maxlen == 32
  defguardp prefix6?(x) when Prefix.valid?(x) and x.maxlen == 128

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
      %Prefix{bits: <<1, 1, 1>>, maxlen: 32}

      iex> encode({{1, 1, 1, 1}, 24})
      %Prefix{bits: <<1, 1, 1>>, maxlen: 32}

      iex> encode({{1,1,1,1}, -1})
      %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 32}

      iex> encode("acdc:1976::/32")
      %Prefix{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128}

      # too many digits
      iex> encode("1.2.3.4.5")
      %PrefixError{id: :encode, detail: "1.2.3.4.5"}

      iex> encode({{1, 2, 3, 4, 5}, -1})
      %PrefixError{id: :encode, detail: {{1, 2, 3, 4, 5}, -1}}

      # illegal digit
      iex> encode("1.1.1.256/24")
      %PrefixError{id: :encode, detail: "1.1.1.256/24"}

      # illegal prefix length
      iex> encode("acdc:1976::/129")
      %PrefixError{id: :encode, detail: "acdc:1976::/129"}

      # an exception as argument is passed through
      iex> encode(%PrefixError{id: :func_x, detail: "some error"})
      %PrefixError{id: :func_x, detail: "some error"}
  """

  @spec encode(String.t() | digits()) :: Prefix.t() | PrefixError.t()
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
      {digits, {len, ""}} when dig?(digits, len) -> encode({digits, len})
      _ -> error(:encode, prefix)
    end
  end

  def encode({digits, -1}) when ip4?(digits), do: encode({digits, 32})
  def encode({digits, -1}) when ip6?(digits), do: encode({digits, 128})

  def encode({digits = {a, b, c, d}, len}) when dig4?(digits, len) do
    <<bits::bitstring-size(len), _::bitstring>> = <<a::8, b::8, c::8, d::8>>
    %Prefix{bits: bits, maxlen: 32}
  end

  def encode({digits = {a, b, c, d, e, f, g, h}, len}) when dig6?(digits, len) do
    <<bits::bitstring-size(len), _::bitstring>> =
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    %Prefix{bits: bits, maxlen: 128}
  end

  def encode(x) when is_exception(x), do: x
  def encode(x), do: error(:encode, x)

  # Decode

  @doc """
  Decode a *prefix* back into string, using CIDR-notation.

  Notes:
  - the `/len` is not added when `len` is at its maximum.
  - when converting from `t:digits/0` format, the mask is *not* applied first.

  ## Examples

      iex> decode(%Prefix{bits: <<1, 1, 1, 1>>, maxlen: 32})
      "1.1.1.1"

      iex> decode(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.0/24"

      # Note: mask is *not* applied when using `{digits, len}`-format
      iex> decode({{1, 1, 1, 1}, 24})
      "1.1.1.1/24"

      # invalid args yield an exception struct
      iex> decode(%Prefix{bits: <<1, 1, 1, 1, 1::size(1)>>, maxlen: 32})
      %PrefixError{detail: %Prefix{bits: <<1, 1, 1, 1, 1::size(1)>>, maxlen: 32}, id: :decode}

      # an exception as argument is passed through
      iex> decode(%PrefixError{id: :func_x, detail: "some error"})
      %PrefixError{id: :func_x, detail: "some error"}

  """
  @spec decode(Prefix.t() | digits()) :: String.t() | PrefixError.t()
  def decode(prefix) when prefix4?(prefix),
    do: Prefix.format(prefix)

  def decode(prefix) when prefix6?(prefix) do
    {digits, len} = Prefix.digits(prefix, 16)
    pfx = :inet.ntoa(digits)
    if len < 128, do: "#{pfx}/#{len}", else: pfx
  end

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

  @doc """
  Returns an atom indicating the adress family for `prefix` or
  an exception struct on any error.

  ## Examples

      iex> af_family(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      :ip4

      iex> af_family({{1,1,1,0}, 24})
      :ip4

      iex> af_family(%Prefix{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      :ip6

      iex> af_family({{44252, 6518, 0, 0, 0, 0, 0, 0}, 32})
      :ip6

      # invalid prefixes yield an exception struct
      iex> af_family(%Prefix{bits: <<>>, maxlen: -1})
      %PrefixError{id: :af_family, detail: %Prefix{bits: <<>>, maxlen: -1}}

      iex> af_family({{1, 1, 1, 1}, 33})
      %PrefixError{id: :af_family, detail: {{1, 1, 1, 1}, 33}}

      # an exception as argument is passed through
      iex> af_family(%PrefixError{id: :func_x, detail: "some error"})
      %PrefixError{id: :func_x, detail: "some error"}

  """
  @spec af_family(Prefix.t() | digits()) :: :ip4 | :ip6 | PrefixError.t()
  def af_family(prefix) when prefix4?(prefix), do: :ip4
  def af_family(prefix) when prefix6?(prefix), do: :ip6
  def af_family({digits, len}) when dig4?(digits, len), do: :ip4
  def af_family({digits, len}) when dig6?(digits, len), do: :ip6
  def af_family(x) when is_exception(x), do: x
  def af_family(x), do: error(:af_family, x)
end
