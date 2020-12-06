defmodule Iptrie.PfxError do
  defexception [:id, :detail]

  @type t :: %__MODULE__{id: Atom.t(), detail: String.t()}

  def new(id, detail),
    do: %__MODULE__{id: id, detail: detail}

  def message(x), do: format(x.id, x.detail)

  def format(:eaddress, address),
    do: "Bad address #{address}"

  def format(:emask, detail),
    do: "Bad mask #{detail}"

  def format(:multi, {v1, v2}),
    do: "Multiple reasons #{v1} -&- #{v2}"

  def format(unknown, detail),
    do: "Bad ultra: #{inspect({unknown, detail})}"
end

defmodule Iptrie.Pfx do
  @moduledoc """
  Encode/decode IP prefixes to/from radix keys.

  """

  use Bitwise
  alias Iptrie.PfxError

  @typedoc """
  An IPv4/IPv6 marker, followed by 0 or more actual prefix bits.

  For example: <<0, v4::bits>> or <<1, v6::bits>>

  The marker helps to distinguish between prefix bitstrings encoded as radix
  keys and regluar binaries.  This assumes the marker is unlikely to be used in
  a regular string.

  """
  @type t :: <<_::8, _::_*1>>
  @ip4 <<0::8>>
  @ip6 <<1::8>>

  # GUARDS

  @spec error?(any()) :: boolean()
  defguard error?(x) when is_struct(x) and is_map_key(x, :__exception__)

  @spec len4?(integer) :: boolean
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

  defguard nums4?(digits, len) when ip4?(digits) and len4?(len)
  defguard nums6?(digits, len) when ip6?(digits) and len6?(len)

  defguard key4?(v, b) when v == @ip4 and bit_size(b) < 33
  defguard key6?(v, b) when v == @ip6 and bit_size(b) < 129
  defguard key?(v, b) when key4?(v, b) or key6?(v, b)
  #
  # Encode
  #
  @doc """
  Encode a prefix as a bitstring with a IP version marker.

  ## Examples

      iex> Iptrie.Pfx.encode("1.1.1.0/24")
      <<0, 1, 1, 1>>

      iex> Iptrie.Pfx.encode("acdc:1975::/32")
      <<1, 0xacdc::16, 0x1975::16>>

  """
  def encode(x) when error?(x), do: x

  # passthrough radix-encoded keys.  Error if marker is ok, but bits are not.
  def encode(<<@ip4, addr::bits>> = pfx) when len4?(bit_size(addr)), do: pfx
  def encode(<<@ip4, _::bits>> = pfx), do: error(:eaddress, "#{inspect(pfx)}")
  def encode(<<@ip6, addr::bits>> = pfx) when len6?(bit_size(addr)), do: pfx
  def encode(<<@ip6, _::bits>> = pfx), do: error(:eaddress, "#{inspect(pfx)}")

  # by now, any binary should be a prefix in regular string form
  # Integer.parse:
  # - does not raise but yields either `:error` or `{num, "rest"}`
  # - note that we insist on `"rest"` being an empty string.
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
      {x, _} when error?(x) -> x
      {_, :error} -> error(:emask, "#{pfx}")
      {digits, {len, ""}} -> encode(digits, len)
      _ -> error(:emask, "#{inspect(pfx)}")
    end
  end

  def encode(digits, -1) when tuple_size(digits) == 4, do: encode(digits, 32)
  def encode(digits, -1) when tuple_size(digits) == 8, do: encode(digits, 128)

  def encode(digits = {a, b, c, d}, len) when nums4?(digits, len) do
    len = len + bit_size(@ip4)
    <<key::bitstring-size(len), _::bitstring>> = <<@ip4, a::8, b::8, c::8, d::8>>

    key
  end

  def encode(digits = {a, b, c, d, e, f, g, h}, len) when nums6?(digits, len) do
    len = len + bit_size(@ip6)

    <<key::bitstring-size(len), _::bitstring>> =
      <<@ip6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    key
  end

  def encode(digits, len) when ip4?(digits) or ip6?(digits),
    do: error(:emask, "#{inspect({digits, len})}")

  def encode(digits, len), do: error(:eaddress, "#{inspect({digits, len})}")

  #
  # Decode(bits) :: nums
  #
  def decode(x) when error?(x), do: x

  def decode(<<@ip4, addr::bitstring>>) when len4?(bit_size(addr)) do
    len = bit_size(addr)
    <<a::8, b::8, c::8, d::8>> = padright(addr, 32 - len)
    {{a, b, c, d}, len}
  end

  def decode(<<@ip6, addr::bitstring>>) when len6?(bit_size(addr)) do
    len = bit_size(addr)
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = padright(addr, 128 - len)
    {{a, b, c, d, e, f, g, h}, len}
  end

  def decode({digits, len}) when ip4?(digits) or ip6?(digits),
    do: error(:emask, "#{inspect({digits, len})}")

  def decode(x),
    do: error(:eaddress, "#{inspect(x)}")

  #
  # Format
  #
  def format(pfx, opts \\ [])

  def format(x, _opts) when error?(x), do: IO.inspect(x, label: "format error!")

  def format(<<v::binary-size(1), b::bitstring>> = pfx, opts) when key?(v, b),
    do:
      pfx
      |> decode()
      |> formatp(opts)

  def format({digits, -1}, opts) when ip4?(digits),
    do: formatp({digits, 32}, opts)

  def format({digits, -1}, opts) when ip6?(digits),
    do: formatp({digits, 128}, opts)

  def format({digits, len}, opts) when nums4?(digits, len) or nums6?(digits, len),
    do: formatp({digits, len}, opts)

  # when the digits are good, it must be a bad mask
  def format({digits, len}, _opts) when ip4?(digits) or ip6?(digits),
    do: error(:emask, "#{inspect({digits, len})}")

  # otherwise, it'll be a bad address
  def format(x, _),
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

  #
  # DECODE-helpers
  #

  def padright(bits, len) when len > -1 do
    <<bits::bitstring, 0::size(len)>>
  end

  def padright(bits, len, :inverted) when len > -1 do
    <<bits::bitstring, -1::size(len)>>
  end

  def padleft(bits, len) when len > -1 do
    <<0::size(len), bits::bitstring>>
  end

  def padleft(bits, len, :inverted) when len > -1 do
    <<-1::size(len), bits::bitstring>>
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

  # NTH-bit

  def nth_bit(<<@ip4, addr::bitstring>>, pos) when pos in 0..31 do
    if bit_size(addr) < pos + 1 do
      0
    else
      <<_::bitstring-size(pos), bit::bitstring-size(1), _::bitstring>> = addr

      case bit do
        <<0::size(1)>> -> 0
        <<1::size(1)>> -> 1
      end
    end
  end

  def nth_bit(<<@ip6, addr::bitstring>>, pos) when pos in 0..127 do
    if bit_size(addr) < pos + 1 do
      0
    else
      <<_::bitstring-size(pos), bit::bitstring-size(1), _::bitstring>> = addr

      case bit do
        <<0::size(1)>> -> 0
        <<1::size(1)>> -> 1
      end
    end
  end

  def nth_bit(_, _), do: {:error, :eindex}

  # BIT

  def bit({:error, reason}, _), do: {:error, reason}

  def bit(<<v::1, _::bitstring>>, pos) when pos == 0, do: v

  def bit(key, pos) when pos > bit_size(key) - 1, do: 0

  def bit(key, pos) when pos >= 0 do
    <<_::size(pos), bit::1, _::bitstring>> = key
    bit
  end

  def af_family(<<v::1, bits::bitstring>>) do
    case v do
      0 when bit_size(bits) < 33 -> :ip4
      1 when bit_size(bits) < 129 -> :ip6
      _ -> {:error, :eaddress}
    end
  end

  # compare, used by Enum.sort/2 to sort {k,v}-pairs in {:desc, Iptrie.Key}-order
  # :eq  keys are equal
  # :lt  key1 less than key2
  # :gt  key1 greater than key2
  #
  def compare({k1, _v1}, {k2, _v2}), do: compare(k1, k2)

  def compare(key1, key2) do
    cond do
      key1 == key2 -> :eq
      bit_size(key1) < bit_size(key2) -> :lt
      bit_size(key1) > bit_size(key2) -> :gt
      key1 < key2 -> :lt
      true -> :gt
    end
  end

  # get position of the first different bit in both keys
  def diffbit(key1, key2) do
    diffbit(0, key1, key2)
  end

  def diffbit(pos, key1, key2) when pos < bit_size(key1) or pos < bit_size(key2) do
    if bit(key1, pos) != bit(key2, pos), do: pos, else: diffbit(pos + 1, key1, key2)
  end

  def diffbit(pos, _key1, _key2), do: pos

  # get pos of the last different bit in both keys
  def diffbit_last(key1, key2) do
    max(bit_size(key1), bit_size(key2))
    |> diffbit_last(key1, key2)
  end

  def diffbit_last(pos, key1, key2) do
    if bit(key1, pos) != bit(key2, pos), do: pos, else: diffbit_last(pos - 1, key1, key2)
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
        pad = bit_size(key1) - len
        if padright(key2, pad) == key1, do: :more, else: :subnet

      false ->
        :nomatch
    end
  end

  def match(key1, key2) do
    len = bit_size(key1)
    <<k2::bitstring-size(len), _::bitstring>> = key2

    case k2 == key1 do
      true ->
        pad = bit_size(key2) - len
        if padright(key1, pad) == key2, do: :less, else: :supernet

      false ->
        :nomatch
    end
  end

  def test_pfx(prefix) do
    case String.split(prefix, "/", parts: 2) do
      [addr] -> error(:eaddress, "Missing pfxlen in #{addr}")
      [addr, ""] -> error(:eaddress, "Empty pfx len in #{addr}")
      [addr | len] -> "addr #{addr}, len #{len}"
      _ -> prefix
    end
  end

  def test_pfx2(x) when is_exception(x), do: x

  def test_pfx2(pfx) do
    IO.puts("We got --> #{pfx}")
  end

  def test_pfx2!(x) when is_exception(x), do: raise(x)

  @compile {:inline, error: 2}
  defp error(id, detail),
    do: PfxError.new(id, detail)
end
