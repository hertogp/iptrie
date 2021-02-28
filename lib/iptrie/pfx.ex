defmodule Iptrie.Pfx do
  @moduledoc """
  Functions to work with IPv4 and IPv6 prefixes.

  """
  import Prefix
  alias PrefixError

  defdelegate encode(prefix), to: Prefix.IP
  defdelegate decode(prefix), to: Prefix.IP

  @compile [:inline, 2]
  defp error(id, detail),
    do: %PrefixError{id: id, detail: detail}

  @type prefix :: Prefix.t() | Prefix.IP.address() | Prefix.IP.digits() | String.t()

  # valid prefix lengths to use for nat64
  @nat64_lengths [96, 64, 56, 48, 40, 32]

  @doc """
  Return the this-network address in CIDR-notation for given *prefix*.

  ## Examples

      iex> network("1.1.1.10/24")
      "1.1.1.0"

      iex> network({{1, 1, 1, 10}, 24})
      "1.1.1.0"

      iex> network(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.0"

      iex> network({1, 1, 1, 1})
      "1.1.1.1"

      iex> network(42)
      %PrefixError{id: :encode, detail: 42}
  """
  @spec network(prefix()) :: String.t() | PrefixError.t()
  def network(prefix) do
    prefix
    |> encode()
    |> padr(0)
    |> decode()
  end

  @doc """
  Return the broadcast address for given *prefix*.

  ## Examples

      iex> broadcast("1.1.1.10/24")
      "1.1.1.255"

      iex> broadcast({{1, 1, 1, 10}, 24})
      "1.1.1.255"

      iex> broadcast(%Prefix{bits: <<1, 1, 1>>, maxlen: 32})
      "1.1.1.255"

      iex> broadcast({1, 1, 1, 1})
      "1.1.1.1"

      iex> broadcast("1.1.1.256")
      %PrefixError{id: :encode, detail: "1.1.1.256"}

  """
  @spec broadcast(prefix()) :: String.t() | PrefixError.t()
  def broadcast(prefix) do
    prefix
    |> encode()
    |> padr(1)
    |> decode()
  end

  @doc """
  Return the list of host addresses for given *prefix*.

  ## Examples

      iex> hosts("1.1.1.0/30")
      ["1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"]

      iex> hosts({{1, 1, 1, 0}, 30})
      ["1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"]

      iex> hosts(%Prefix{bits: <<1, 1, 1, 0::6>>, maxlen: 32})
      ["1.1.1.0", "1.1.1.1", "1.1.1.2", "1.1.1.3"]

      iex> hosts("1.1.1.0/33")
      %PrefixError{detail: {{1, 1, 1, 0}, 33}, id: :encode}

  """
  @spec hosts(prefix()) :: list(String.t()) | PrefixError.t()
  def hosts(prefix) do
    prefix
    |> encode()
    |> case do
      x when is_exception(x) -> x
      x -> Enum.map(x, fn ip -> decode(ip) end)
    end
  end

  @doc """
  Returns the mask for given prefix.

  ## Examples

      iex> mask("1.1.1.0/22")
      "255.255.252.0"

      iex> mask({{1, 1, 1, 0}, 22})
      "255.255.252.0"

      iex> mask(%Prefix{bits: <<1, 1, 1::6>>, maxlen: 32})
      "255.255.252.0"

      iex> mask("1.1.1.256/24")
      %PrefixError{id: :encode, detail: "1.1.1.256/24"}

  """
  @spec mask(prefix()) :: String.t() | PrefixError.t()
  def mask(prefix) do
    prefix
    |> encode()
    |> bset(1)
    |> padr(0)
    |> decode()
  end

  @doc """
  Returns the inverse mask for given prefix.

  ## Example

      iex> inv_mask("1.1.1.0/23")
      "0.0.1.255"

      iex> inv_mask({{1, 1, 1, 0}, 23})
      "0.0.1.255"

      iex> inv_mask(%Prefix{bits: <<1, 1, 1::7>>, maxlen: 32})
      "0.0.1.255"

      iex> inv_mask("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec inv_mask(prefix()) :: String.t() | PrefixError.t()
  def inv_mask(prefix) do
    prefix
    |> encode()
    |> bset(0)
    |> padr(1)
    |> decode()
  end

  @doc """
  Returns the neighboring prefix such that both can be combined in a supernet.

  ## Example

      iex> neighbor("1.1.1.0/25")
      "1.1.1.128/25"

      iex> neighbor("1.1.1.128/25")
      "1.1.1.0/25"

      iex> neighbor({{1, 1, 1, 128}, 25})
      "1.1.1.0/25"

      iex> neighbor({1, 1, 1, 1})
      "1.1.1.0"

      iex> neighbor(%Prefix{bits: <<1, 1, 1, 1::1>>, maxlen: 32})
      "1.1.1.0/25"

      iex> neighbor("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  def neighbor(prefix) do
    {x, offset} =
      case encode(prefix) do
        x when is_exception(x) -> {x, 0}
        x -> {x, 1 - 2 * bit(x, bit_size(x.bits) - 1)}
      end

    sibling(x, offset)
    |> decode()
  end

  @doc """
  Jump to another prefix at distance `n`.

  This will wrap around the available address space without warning.

  ## Examples

      iex> jump("1.1.1.0/24", 0)
      "1.1.1.0/24"

      iex> jump("1.1.1.0/24", 1)
      "1.1.2.0/24"

      iex> jump("1.1.1.0/24", 256)
      "1.2.1.0/24"

      iex> jump("1.1.1.0/24", 256*256)
      "2.1.1.0/24"

      iex> jump("1.1.1.0/24", 256*256*256)
      "1.1.1.0/24"

      iex> jump("1.1.1.0/24", 1)
      "1.1.2.0/24"

      # other examples of wrapping around
      iex> jump("1.1.1.0/30", 64)
      "1.1.2.0/30"

      iex> jump("0.0.0.0", -1)
      "255.255.255.255"

      iex> jump("255.255.255.255", 1)
      "0.0.0.0"

      iex> jump({{255, 255, 255, 255}, 32}, 1)
      "0.0.0.0"

      iex> jump({255, 255, 255, 255}, 1)
      "0.0.0.0"

      iex> jump(%Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32}, 1)
      "0.0.0.0"

      # invalid prefix yields a PrefixError struct
      iex> jump("1.1.1.0/33", 1)
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec jump(prefix(), integer) :: String.t() | PrefixError.t()
  def jump(prefix, n) do
    prefix
    |> encode()
    |> sibling(n)
    |> decode()
  end

  @doc """
  Return the host address for the *nth*-member of the prefix.

  This will wrap around the available address space without warning.

  ## Examples

      iex> host("1.1.1.0/24", 129)
      "1.1.1.129"

      iex> host("1.1.1.0/24", 256)
      "1.1.1.0"

      iex> host({{1, 1, 1, 0}, 24}, 128)
      "1.1.1.128"

      iex> host(%Prefix{bits: <<1, 1, 1>>, maxlen:  32}, 128)
      "1.1.1.128"

      iex> host("1.1.1.0/33", 1)
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec host(prefix(), integer) :: String.t() | PrefixError.t()
  def host(prefix, nth) do
    prefix
    |> encode()
    |> member(nth)
    |> decode()
  end

  @doc """
  Return the number of host addresses available in given *prefix*.

  ## Example

      iex> numhosts("acdc:1976::/32")
      79228162514264337593543950336

      iex> numhosts("1.1.1.0/23")
      512

      iex> numhosts({{1, 1, 1, 0}, 23})
      512

      iex> numhosts(%Prefix{bits: <<1, 1, 1::7>>, maxlen: 32})
      512

      iex> numhosts({1, 1, 1, 1})
      1

      iex> numhosts("1.1.1.0/33")
      %PrefixError{id: :encode, detail: {{1, 1, 1, 0}, 33}}

  """
  @spec numhosts(prefix()) :: non_neg_integer | PrefixError.t()
  def numhosts(prefix) do
    prefix
    |> encode()
    |> size()
  end

  # IPv6 Addresses
  # - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  # - https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  # - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
  # - https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv
  # - https://en.wikipedia.org/wiki/IPv6_address
  # - https://en.wikipedia.org/wiki/6to4

  @doc """
  Returns true if *prefix* is a teredo address, false otherwise

  See [rfc4380](https://www.iana.org/go/rfc4380).

  ## Example

      iex> teredo?("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      true

      iex> teredo?("1.1.1.1")
      false

  """
  @spec teredo?(prefix() | PrefixError.t()) :: boolean
  def teredo?(prefix) do
    prefix
    |> encode()
    |> member?(%Prefix{bits: <<0x2001::16, 0::16>>, maxlen: 128})
  end

  @doc """
  Returns a map with the teredo address components or nil.

  Returns nil if *prefix* is not a teredo address, or simply invalid.

  ## Example

      # Example from https://en.wikipedia.org/wiki/Teredo_tunneling#IPv6_addressing
      iex> teredo("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      %{
        prefix: "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        client: "192.0.2.45",
        server: "65.54.227.120",
        flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        port: 40000
      }
  """
  @spec teredo(prefix) :: map | nil
  def teredo(prefix) do
    # https://www.rfc-editor.org/rfc/rfc4380.html#section-4
    x = encode(prefix)

    if teredo?(x) do
      %{
        server: cut(x, 32, 32) |> decode(),
        client: cut(x, 96, 32) |> bnot() |> decode(),
        port: cut(x, 80, 16) |> bnot() |> cast(),
        flags: cut(x, 64, 16) |> digits(1) |> elem(0),
        prefix: prefix
      }
    else
      nil
    end
  end

  @doc """
  Returns true is *prefix* is a multicast prefix, false otherwise

  ## Examples

      iex> multicast?("224.0.0.1")
      true

      iex> multicast?("ff02::1")
      true

  """
  @spec multicast?(prefix | PrefixError.t()) :: boolean
  def multicast?(prefix) do
    x = encode(prefix)

    cond do
      member?(x, %Prefix{bits: <<14::4>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<0xFF>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Returns a map with multicast address components.

  Returns nil if *prefix* is not a multicast address, or simply invalid.

  ## Examples

      iex> x = multicast("ff02::1")
      iex> x.preamble
      255
      iex> x.flags
      {0, 0, 0, 0}
      iex> x.scope
      2
      iex> x.groupID
      <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
      iex> x.address
      %Prefix{bits: <<0xff02::16, 0::104, 1::8>>, maxlen: 128}

  """
  @spec multicast(prefix) :: map | nil
  def multicast(prefix) do
    x = encode(prefix)

    if multicast?(x) do
      case x.maxlen do
        128 ->
          %{
            preamble: cut(x, 0, 8) |> cast(),
            flags: cut(x, 8, 4) |> digits(1) |> elem(0),
            scope: cut(x, 12, 4) |> cast(),
            groupID: bits(x, 16, 112),
            address: x
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            groupID: bits(x, 4, 28),
            address: x
          }
      end
    else
      nil
    end
  end

  @doc """
  Returns true if *prefix* is a link-local prefix, false otherwise

  Link local prefixes include:

  - `0.0.0.0/8`,          [rfc1122](https://tools.ietf.org/html/rfc1122), this-network (link)
  - `255.255.255.255/32`, [rfc1f22](https://www.iana.org/go/rfc1122), limited broadcast
  - `169.254.0.0/16`,     [rfc3927](https://www.iana.org/go/rfc3927), link-local
  - `fe80::/64`,          [rfc4291](https://tools.ietf.org/html/rfc4291), link-local

  ## Examples

      # first 256 addresses are reserved
      iex> link_local?("169.254.0.0")
      false

      # last 256 addresses are reserved
      iex> link_local?("169.254.255.0")
      false

      iex> link_local?("0.0.0.0")
      true

      iex> link_local?("0.255.255.255")
      true

      iex> link_local?("fe80::acdc:1975")
      true

  """
  @spec link_local?(prefix | PrefixError.t()) :: boolean
  def link_local?(prefix) do
    # rfc3927 and rfc4271 & friends
    # and https://en.wikipedia.org/wiki/IPv6_address#Default_address_selection
    x = encode(prefix)

    cond do
      member?(x, %Prefix{bits: <<169, 254, 0>>, maxlen: 32}) -> false
      member?(x, %Prefix{bits: <<169, 254, 255>>, maxlen: 32}) -> false
      member?(x, %Prefix{bits: <<169, 254>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<0>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<0xFE80::16, 0::48>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Return a map with link-local address components.

  Returns nil if *prefix* is not link-local or simply invalid.

  See:
  - [rfc3927](https://www.iana.org/go/rfc3927)

  ## Examples

      iex> x = link_local("169.254.128.233")
      iex> x
      %{ digits: {169, 254, 128, 233},
         prefix: "169.254.0.0/16",
         ifaceID: 33001,
         address: "169.254.128.233"
      }
      iex> host(x.prefix, x.ifaceID)
      "169.254.128.233"

      iex> y = link_local("fe80::acdc:1976")
      iex> y
      %{ preamble: 1018,
         prefix: "fe80::/64",
         ifaceID: 2900105590,
         address: "fe80::acdc:1976"
      }
      iex> host(y.prefix, y.ifaceID)
      "fe80::acdc:1976"

  """
  @spec link_local(prefix) :: map | nil
  def link_local(prefix) do
    x = encode(prefix)

    if link_local?(x) do
      case x.maxlen do
        128 ->
          %{
            preamble: cut(x, 0, 10) |> cast(),
            prefix: %Prefix{bits: bits(x, 0, 64), maxlen: 128} |> decode(),
            ifaceID: cut(x, 64, 64) |> cast(),
            address: prefix
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            prefix: %Prefix{bits: bits(x, 0, 16), maxlen: 32} |> decode(),
            ifaceID: cut(x, 16, 16) |> cast(),
            address: prefix
          }
      end
    end
  end

  @doc """
  Returns true if *prefix* is designated as "private-use".

  For IPv4 this includes the [rfc1918](https://www.iana.org/go/rfc1918)
  prefixes 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.  For IPv6 this
  includes the [rfc4193](https://www.iana.org/go/rfc4193) prefix fc00::/7.

  ## Examples

      iex> unique_local?("172.31.255.255")
      true

      iex> unique_local?("10.10.10.10")
      true

      iex> unique_local?("fc00:acdc::")
      true

      iex> unique_local?("172.32.0.0")
      false

  """
  def unique_local?(prefix) do
    # so what about the well-known nat64 address(es) that are used only
    # locally?
    x = encode(prefix)

    cond do
      member?(x, %Prefix{bits: <<10>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<172, 1::4>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<192, 168>>, maxlen: 32}) -> true
      member?(x, %Prefix{bits: <<126::7>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Returns true if *prefix* is matched by the Well-Known Prefixes defined in
  [rfc6053](https://www.iana.org/go/rfc6052) and
  [rfc8215](https://www.iana.org/go/rfc8215), false otherwise.

  Note that organisation specific prefixes might still be used for nat64.

  ## Example

      iex> nat64?("64:ff9b::10.10.10.10")
      true

      iex> nat64?("64:ff9b:1::10.10.10.10")
      true

  """
  @spec nat64?(prefix | PrefixError.t()) :: boolean
  def nat64?(prefix) do
    x = encode(prefix)

    member?(x, %Prefix{bits: <<0x0064::16, 0xFF9B::16, 0::64>>, maxlen: 128}) or
      member?(x, %Prefix{bits: <<0x0064::16, 0xFF9B::16, 1::16>>, maxlen: 128})
  end

  @doc """
  Return the embedded IPv4 address.

  The *ip6* prefix should be a full IPv6 address.  The *len* defaults to `96`, but if
  specified it should be one of [#{Enum.join(@nat64_lengths, ", ")}].

  ## Examples

      iex> nat64_decode("64:ff9b::10.10.10.10")
      "10.10.10.10"

      iex> nat64_decode("64:ff9b:1:0a0a:000a:0a00::", 48)
      "10.10.10.10"

      # from rfc6052, section 2.4

      iex> nat64_decode("2001:db8:c000:221::", 32)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:1c0:2:21::", 40)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:c000:2:2100::", 48)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:3c0:0:221::", 56)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344:c0:2:2100::", 64)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344::192.0.2.33", 96)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344::192.0.2.33", 90)
      %PrefixError{
        id: :nat64_decode,
        detail: "length 90 not in: [96, 64, 56, 48, 40, 32]"}

  """
  @spec nat64_decode(prefix(), integer) :: String.t() | PrefixError.t()
  def nat64_decode(ip6, len \\ 96)

  def nat64_decode(ip6, len) when len in @nat64_lengths do
    case encode(ip6) do
      p6 when is_exception(p6) -> p6
      p6 when bit_size(p6.bits) == 128 -> nat64_decodep(p6, len)
      _ -> error(:nat64_decode, "expected a full ipv6 address, got #{inspect(ip6)}")
    end
  end

  def nat64_decode(_, len),
    do: error(:nat64_decode, "length #{len} not in: [#{Enum.join(@nat64_lengths, ", ")}]")

  defp nat64_decodep(ip6, len) do
    ip6 = if len < 96, do: %{ip6 | bits: bits(ip6, [{0, 64}, {72, 56}])}, else: ip6

    %Prefix{bits: bits(ip6, len, 32), maxlen: 32}
    |> decode()
  end

  @doc """
  Return the IPv4 embedded IPv6 address.

  The IPv6 prefix' length should be one of [#{Enum.join(@nat64_lengths, ", ")}] as defined
  in [rfc6052](https://www.iana.org/go/rfc6052).  The IPv4 prefix should be a full address.
  Anything else will yield a `t:PrefixError/0`

  ## Examples

      # from rfc6052, section 2.2

      iex> nat64_encode("2001:db8::/32", "192.0.2.33")
      "2001:db8:c000:221::"

      iex> nat64_encode("2001:db8:100::/40", "192.0.2.33")
      "2001:db8:1c0:2:21::"

      iex> nat64_encode("2001:db8:122::/48", "192.0.2.33")
      "2001:db8:122:c000:2:2100::"

      iex> nat64_encode("2001:db8:122:300::/56", "192.0.2.33")
      "2001:db8:122:3c0:0:221::"

      # result is same as 2001:db8:122:344:c0:2:2100::
      iex> nat64_encode("2001:db8:122:344::/64", "192.0.2.33")
      "2001:db8:122:344:c0:2:2100:0"

      iex> nat64_encode("2001:db8:122:344::/96", "192.0.2.33")
      "2001:db8:122:344::c000:221"

  """
  @spec nat64_encode(prefix(), prefix()) :: String.t() | PrefixError.t()
  def nat64_encode(ip6, ip4) do
    case {encode(ip6), encode(ip4)} do
      {p6, _} when is_exception(p6) ->
        p6

      {_, p4} when is_exception(p4) ->
        p4

      {p6, _} when p6.maxlen != 128 ->
        error(:nat64_encode, "not IPv6: #{inspect(ip6)}")

      {_, p4} when p4.maxlen != 32 ->
        error(:nat64_encode, "Not ipv4: #{inspect(ip4)}")

      {p6, _} when bit_size(p6.bits) not in @nat64_lengths ->
        error(:nat64_encode, "Illegal IPv6 prefix length: #{inspect(ip6)}")

      {_, p4} when bit_size(p4.bits) != 32 ->
        error(:nat64_encode, "Expected a full ipv4 address, not #{inspect(ip4)}")

      {p6, p4} ->
        nat64_encodep(p6, p4)
    end
  end

  defp nat64_encodep(ip6, ip4) do
    ip6 = %{ip6 | bits: ip6.bits <> ip4.bits}

    if bit_size(ip6.bits) < 128 do
      %{
        ip6
        | bits:
            <<bits(ip6, [{0, 64}])::bitstring, 0::8,
              bits(ip6, [{64, bit_size(ip6.bits) - 64}])::bitstring>>
      }
      |> padr(0)
    else
      ip6
    end
    |> decode()
  end

  @doc """
  Return a DNS pointer record for given *prefix*.

  The prefix will be padded right with `0`-bits to a multiple of 8 for IPv4 prefixes and
  to a multiple of 4 for IPv6 prefixes.  Note that this might give unexpected results.
  So `dns_ptr/1` works best if the prefix given is actually a multiple of 4 or 8.

  If the given *prefix* is invalid, a `t:PrefixError/0` is returned instead.

  ## Examples

      iex> dns_ptr("10.10.0.0/16")
      "10.10.in-addr.arpa"

      # "1.2.3.0/23" actually encodes as %Prefix{bits: <<1, 2, 1::size(7)>>, maxlen: 32}
      iex> dns_ptr("1.2.3.0/23")
      "2.2.1.in-addr.arpa"

      iex> dns_ptr("acdc:1976::/32")
      "6.7.9.1.c.d.c.a.ip6.arpa"

      iex> dns_ptr("acdc:1976::")
      "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.7.9.1.c.d.c.a.ip6.arpa"

  """
  @spec dns_ptr(prefix()) :: String.t() | PrefixError.t()
  def dns_ptr(prefix) do
    case encode(prefix) do
      x when is_exception(x) -> x
      x when x.maxlen == 32 -> dns_ptrp(x, 8)
      x when x.maxlen == 128 -> dns_ptrp(x, 4)
      _ -> error(:dns_ptr, "expected IPv4/6 prefix, not: #{inspect(prefix)}")
    end
  end

  defp dns_ptrp(prefix, size) do
    n = rem(prefix.maxlen - bit_size(prefix.bits), size)

    {base, suffix} =
      case size do
        8 -> {10, "in-addr.arpa"}
        4 -> {16, "ip6.arpa"}
      end

    prefix
    |> padr(0, n)
    |> format(width: size, base: base, padding: false, reverse: true, mask: false)
    |> String.downcase()
    |> (&"#{&1}.#{suffix}").()
  end

  # TODO
  #
  # o hosts_lazy :: return stream that returns hosts addresses
  # o map_lazy?
  # o Enumerable for Iptrie?
  # o dns_ptr(prefix) -> reverse dns name
  # o read/write an Iptrie from/to file?
  #
  # See also:
  # - https://en.wikipedia.org/wiki/IPv6_address
  # - https://en.wikipedia.org/wiki/6to4
end
