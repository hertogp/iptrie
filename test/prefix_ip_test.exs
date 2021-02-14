defmodule PrefixIPTest do
  use ExUnit.Case
  doctest Prefix.IP, import: true
  import Prefix.IP

  # two exceptions
  @pfxError PrefixError.new(:my_id, :my_detail)
  @runError RuntimeError.exception("ouch")

  # an illegal prefix, since bit_size(bits) > maxlen
  @pfxIllegal %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 16}

  # IP4.encode normal
  test "IPv4 encode - normal" do
    pfx1 = %Prefix{bits: <<1, 2, 4, 8>>, maxlen: 32}

    # all possible input formats that are encode'able.
    assert pfx1 == encode("1.2.4.8")
    assert pfx1 == encode("1.2.4.8/32")
    assert pfx1 == encode({1, 2, 4, 8})
    assert pfx1 == encode({{1, 2, 4, 8}, 32})
    assert pfx1 == encode(pfx1)
  end

  # IP4.encode less normal
  test "IPv4 encode - less normal" do
    assert %Prefix{bits: <<0, 0, 0, 0>>, maxlen: 32} = encode("0.0.0.0")

    # /0
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("0.0.0.0/0")
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("255.255.255.255/0")
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("0/0")
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("255/0")
  end

  # IP4.encode aton antics
  test "IPv4 encode - aton antics" do
    # https://github.com/erlang/otp/blob/master/lib/kernel/src/inet_parse.erl#L471

    # d4
    assert %Prefix{bits: <<0, 0, 1, 0>>, maxlen: 32} = encode("256")
    assert %Prefix{bits: <<0, 0, 2, 0>>, maxlen: 32} = encode("512")
    assert %Prefix{bits: <<0, 0, 0, 10>>, maxlen: 32} = encode("10")
    assert %Prefix{bits: <<0, 0, 0>>, maxlen: 32} = encode("10/24")
    assert %Prefix{bits: <<0, 0>>, maxlen: 32} = encode("10/16")
    assert %Prefix{bits: <<0>>, maxlen: 32} = encode("10/8")
    # encode 2^31 - 1
    assert %Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32} = encode("4294967295")

    # d1.d4
    assert %Prefix{bits: <<10, 0, 0, 10>>, maxlen: 32} = encode("10.10")
    assert %Prefix{bits: <<10, 0, 0>>, maxlen: 32} = encode("10.10/24")
    assert %Prefix{bits: <<10, 0>>, maxlen: 32} = encode("10.10/16")
    assert %Prefix{bits: <<10>>, maxlen: 32} = encode("10.10/8")
    # d1.d4 where d4 spreads to cover 24 bits
    assert %Prefix{bits: <<1, 0, 1, 0>>, maxlen: 32} = encode("1.256")
    # but d1 does not
    assert %PrefixError{id: :encode} = encode("256.1")

    # d1.d2.d4
    assert %Prefix{bits: <<1, 2, 0, 8>>, maxlen: 32} = encode("1.2.8")
    # d1.d2.d4 where d4 spreads to cover 16 bits
    assert %Prefix{bits: <<1, 0, 1, 0>>, maxlen: 32} = encode("1.0.256")
  end

  # IP4.encode errors
  test "IPv4 encode - errors" do
    # illegal digit
    assert %PrefixError{id: :encode} = encode("1.1.1.256")
    assert %PrefixError{id: :encode} = encode("1.1.256.1")
    assert %PrefixError{id: :encode} = encode("1.256.1.1")
    assert %PrefixError{id: :encode} = encode("256.1.1.1")

    # in d1.d2.d4 -> d1,d2 must be in 0..255
    assert %PrefixError{id: :encode} = encode("256.1.1")
    assert %PrefixError{id: :encode} = encode("1.256.1")
    assert %PrefixError{id: :encode} = encode("256.1.1")

    # illegal prefix length
    assert %PrefixError{id: :encode} = encode("1.1.1.1/33")
    assert %PrefixError{id: :encode} = encode("1.1.1.1/128")
    assert %PrefixError{id: :encode} = encode("1.1.1.1/")
    assert %PrefixError{id: :encode} = encode("1.1.1.1/24b")

    # illegal %Prefix's
    assert %PrefixError{id: :encode, detail: @pfxIllegal} = encode(@pfxIllegal)

    # pass through any errors
    assert @pfxError = encode(@pfxError)
    assert @runError = encode(@runError)
  end

  # IP6.encode normal
  test "IPv6 encode" do
    pfx1 = %Prefix{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}

    assert pfx1 == encode("acdc:1976::")
    assert pfx1 == encode("acdc:1976::/128")
    assert pfx1 == encode({0xACDC, 0x1976, 0, 0, 0, 0, 0, 0})
    assert pfx1 == encode({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 128})
    assert pfx1 == encode(pfx1)

    # embedded IPv4
    assert %Prefix{bits: <<0xACDC::16, 0::80, 1, 2, 4, 8>>, maxlen: 128} = encode("acdc::1.2.4.8")
  end

  # IP6.encode errors
  test "IPv6 encode errors" do
    # illegal digit
    assert %PrefixError{id: :encode} = encode("acdc::1.2.4.256")
    assert %PrefixError{id: :encode} = encode("abcd:efg::")

    # illegal "ip6"-like prefix
    assert %PrefixError{id: :encode} =
             encode(%Prefix{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 127})
  end

  # IP4.decode normal
  test "IP4.decode normal" do
    assert "1.2.4.8" == decode(%Prefix{bits: <<1, 2, 4, 8>>, maxlen: 32})
    assert "1.2.0.0/16" == decode(%Prefix{bits: <<1, 2>>, maxlen: 32})
    assert "1.0.0.0/8" == decode(%Prefix{bits: <<1>>, maxlen: 32})

    assert "128.2.4.8" == decode(%Prefix{bits: <<128, 2, 4, 8>>, maxlen: 32})
    assert "128.2.0.0/16" == decode(%Prefix{bits: <<128, 2>>, maxlen: 32})
    assert "128.0.0.0/8" == decode(%Prefix{bits: <<128>>, maxlen: 32})

    assert "255.2.4.8" == decode(%Prefix{bits: <<255, 2, 4, 8>>, maxlen: 32})
    assert "255.2.0.0/16" == decode(%Prefix{bits: <<255, 2>>, maxlen: 32})
    assert "255.0.0.0/8" == decode(%Prefix{bits: <<255>>, maxlen: 32})
  end

  # IP4.decode less normal
  test "IP4.decode less normal" do
    assert "0.0.0.0" == decode(%Prefix{bits: <<0, 0, 0, 0>>, maxlen: 32})
    assert "0.0.0.0/0" == decode(%Prefix{bits: <<>>, maxlen: 32})
    assert "1.2.4.8/31" == decode(%Prefix{bits: <<1, 2, 4, 4::7>>, maxlen: 32})
    assert "255.255.255.255" == decode(%Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32})
  end

  # IP4.decode errors
  test "IP4.decode errors" do
    # illegal pfx
    assert %PrefixError{id: :decode, detail: @pfxIllegal} = decode(@pfxIllegal)
    # illegal maxlen
    assert %PrefixError{id: :decode} = decode(%Prefix{bits: <<1, 2, 4>>, maxlen: 24})

    # pass through any error
    assert @pfxError = decode(@pfxError)
    assert @runError = decode(@runError)
  end

  # IP6.decode normal
  test "IP6.decode normal" do
    assert "acdc:1976::/32" = decode(%Prefix{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128})
  end

  # IP6.decode less normal
  test "IP6.decode less normal" do
    assert "::" == decode(%Prefix{bits: <<0::128>>, maxlen: 128})
    assert "::/0" == decode(%Prefix{bits: <<>>, maxlen: 128})

    assert "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ==
             decode(%Prefix{bits: <<-1::128>>, maxlen: 128})

    assert "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127" ==
             decode(%Prefix{bits: <<-1::127>>, maxlen: 128})

    assert "ffff:ffff:ffff::/48" ==
             decode(%Prefix{bits: <<-1::48>>, maxlen: 128})
  end

  # IP6.decode errors
  test "IP6.decode errors" do
    # illegal "ip6"-like prefix
    assert %PrefixError{id: :decode} = decode(%Prefix{bits: <<0xACDC::16, 0::112>>, maxlen: 120})
    # illegal maxlen
    assert %PrefixError{id: :decode} = decode(%Prefix{bits: <<0xACDC::16, 0::112>>, maxlen: 129})
  end
end
