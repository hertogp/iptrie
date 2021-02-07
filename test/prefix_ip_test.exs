defmodule PrefixIPTest do
  use ExUnit.Case
  doctest Prefix.IP, import: true
  import Prefix.IP

  # two exceptions
  @pfxError PrefixError.new(:my_id, :my_detail)
  @runError RuntimeError.exception("ouch")

  # an illegal prefix, since bit_size(bits) > maxlen
  @pfxIllegal %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 16}

  # IP.encode
  test "IPv4 encode - normal" do
    pfx1 = %Prefix{bits: <<1, 2, 4, 8>>, maxlen: 32}

    # all possible input formats that are encode'able.
    assert pfx1 == encode("1.2.4.8")
    assert pfx1 == encode("1.2.4.8/32")
    assert pfx1 == encode({1, 2, 4, 8})
    assert pfx1 == encode({{1, 2, 4, 8}, 32})
    assert pfx1 == encode(pfx1)
  end

  test "IPv4 encode - less normal" do
    assert %Prefix{bits: <<0, 0, 0, 0>>, maxlen: 32} = encode("0.0.0.0")

    # /0
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("0.0.0.0/0")
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("255.255.255.255/0")
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("0/0")
    assert %Prefix{bits: <<>>, maxlen: 32} = encode("255/0")
  end

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

  test "IPv4 encode - errors" do
    # illegal digit
    assert %PrefixError{id: :encode} = encode("1.1.1.256")
    assert %PrefixError{id: :encode} = encode("1.1.256.1")
    assert %PrefixError{id: :encode} = encode("1.256.1.1")
    assert %PrefixError{id: :encode} = encode("256.1.1.1")

    assert %PrefixError{id: :encode} = encode("256.1.1")
    assert %PrefixError{id: :encode} = encode("1.256.1")
    assert %PrefixError{id: :encode} = encode("256.1.1")

    # illegal prefix length
    assert %PrefixError{id: :encode} = encode("1.1.1.1/33")
    assert %PrefixError{id: :encode} = encode("1.1.1.1/128")
    assert %PrefixError{id: :encode} = encode("1.1.1.1/")

    # illegal %Prefix's
    assert %PrefixError{id: :encode} = encode(@pfxIllegal)

    # pass through any errors
    assert @pfxError = encode(@pfxError)
    assert @runError = encode(@runError)
  end

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

  test "IPv6 encode errors" do
    assert %PrefixError{id: :encode} = encode("acdc::1.2.4.256")
  end
end
