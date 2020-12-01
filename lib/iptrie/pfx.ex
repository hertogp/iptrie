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
  Functions to convert and/or manipulate IP prefixes.

  """

  use Bitwise
  alias Iptrie.PfxError

  @ip4 <<0::1>>
  @ip6 <<1::1>>

  # GUARDS

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

  defguard key4?(k)
           when is_bitstring(k) and k < @ip6 and bit_size(k) < 34

  defguard key6?(k)
           when is_bitstring(k) and
                  k > @ip4 and
                  bit_size(k) < 130

  def ok({:ok, value}), do: value
  def ok({:error, reason}), do: {:error, reason}

  # TO_NUMBERS (string,key)->{:ok,{digits,len}}

  def to_numbers(prefix) when is_binary(prefix) do
    [addr | len] = String.split(prefix, "/", parts: 2)

    case :inet.parse_address(String.to_charlist(addr)) do
      {:error, _} -> {:error, :eaddress}
      {:ok, digits} -> to_numbersp(digits, len)
    end
  end

  def to_numbers(<<@ip4, addr::bitstring>>) when len4?(bit_size(addr)) do
    len = bit_size(addr)
    <<a::8, b::8, c::8, d::8>> = padright(addr, 32 - len)
    {:ok, {{a, b, c, d}, len}}
  end

  def to_numbers(<<@ip6, addr::bitstring>>) when len6?(bit_size(addr)) do
    len = bit_size(addr)
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = padright(addr, 128 - len)
    {:ok, {{a, b, c, d, e, f, g, h}, len}}
  end

  def to_numbers(_), do: {:error, :eaddress}

  defp to_numbersp(digits, [len]) do
    try do
      to_numbersp(digits, String.to_integer(len))
    rescue
      ArgumentError -> {:error, :emask}
    end
  end

  defp to_numbersp(digits, []) when ip4?(digits), do: to_numbersp(digits, 32)
  defp to_numbersp(digits, []) when ip6?(digits), do: to_numbersp(digits, 128)

  defp to_numbersp(digits, len) when is_integer(len) do
    case tuple_size(digits) do
      4 when len4?(len) -> {:ok, {digits, len}}
      8 when len6?(len) -> {:ok, {digits, len}}
      _ -> {:error, :emask}
    end
  end

  defp to_numbersp(_, _), do: {:error, :eaddress}

  # TO_BITS (string,key,numbers) -> bits

  def to_bits(<<@ip4, addr::bitstring>>) when len4?(bit_size(addr)) do
    bits = for <<(<<bit::1>> <- addr)>>, do: bit
    {:ip4, List.to_tuple(bits), bit_size(addr)}
  end

  def to_bits(<<@ip6, addr::bitstring>>) when len6?(bit_size(addr)) do
    bits = for <<(<<bit::1>> <- addr)>>, do: bit
    {:ip6, List.to_tuple(bits), bit_size(addr)}
  end

  def to_bits(arg) do
    case to_key(arg) do
      {:ok, key} -> to_bits(key)
      {:error, reason} -> {:error, reason}
    end
  end

  # TO_KEY (string,numbers)->key
  def to_key(x) when is_exception(x), do: x

  def to_key(prefix) when is_binary(prefix) do
    # prefix
    # |> to_numbers()
    # |> to_key()

    case to_numbers(prefix) do
      {:error, reason} -> {:error, reason}
      {:ok, nums} -> to_key(nums)
    end
  end

  def to_key({digits = {a, b, c, d}, len}) when ip4?(digits) and len4?(len) do
    len = len + 1

    <<key::bitstring-size(len), _::bitstring>> = <<@ip4, a::8, b::8, c::8, d::8>>

    {:ok, key}
  end

  def to_key({digits = {a, b, c, d, e, f, g, h}, len}) when ip6?(digits) and len6?(len) do
    len = len + 1

    <<key::bitstring-size(len), _::bitstring>> =
      <<@ip6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    {:ok, key}
  end

  def to_key({digits, _}) when ip4?(digits) or ip6?(digits), do: {:error, :emask}
  def to_key(_), do: {:error, :eaddress}

  # TO_ASCII (numbers,key)->string

  def to_ascii(<<@ip4, addr::bitstring>>) when len4?(bit_size(addr)) do
    len = bit_size(addr)
    <<a::8, b::8, c::8, d::8>> = padright(addr, 32 - len)
    to_ascii({{a, b, c, d}, len})
  end

  def to_ascii(<<@ip6, addr::bitstring>>) when len6?(bit_size(addr)) do
    len = bit_size(addr)
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = padright(addr, 128 - len)
    to_ascii({{a, b, c, d, e, f, g, h}, len})
  end

  def to_ascii({digits, len}) when ip4?(digits) and len4?(len) do
    case :inet.ntoa(digits) do
      {:error, _} -> {:error, :eaddress}
      address -> {:ok, "#{address}/#{len}"}
    end
  end

  def to_ascii({digits, len}) when ip6?(digits) and len6?(len) do
    case :inet.ntoa(digits) do
      {:error, _} -> {:error, :eaddress}
      address -> {:ok, "#{address}/#{len}"}
    end
  end

  def to_ascii({digits, _}) when ip4?(digits) or ip6?(digits), do: {:error, :emask}
  def to_ascii({:error, reason}), do: {:error, reason}
  def to_ascii(_), do: {:error, :eaddress}

  # DECODE-helpers

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

  # BITPOS

  def bitpos(key, pos) when key4?(key) or key6?(key) do
    if bit_size(key) - 2 < pos do
      0
    else
      <<_::1, _::bitstring-size(pos), bit::1, _::bitstring>> = key
      bit
    end
  end

  def bitpos(key, _) when key4?(key) or key6?(key),
    do: {:error, :eindex}

  def bitpos(_, _), do: {:error, :eaddress}

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
