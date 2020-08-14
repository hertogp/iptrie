defmodule Iptrie.KeyTest do
  use ExUnit.Case
  use Iptrie.Constants
  doctest Iptrie.Key
  alias Iptrie.Key

  # AF_funcs

  test "AF_funcs" do
    # af_family
    assert Key.af_family(<<@ip4>>) == :ip4
    assert Key.af_family(<<@ip4, 255::8>>) == :ip4
    assert Key.af_family(<<@ip6>>) == :ip6
    assert Key.af_family(<<@ip6, 65535::16>>) == :ip6

    # af_length
    assert Key.af_length(<<@ip4>>) == @ip4_maxlen
    assert Key.af_length(<<@ip6>>) == @ip6_maxlen

    # af_chunks
    assert Key.af_chunks(<<@ip4>>) == @ip4_chunk
    assert Key.af_chunks(<<@ip6>>) == @ip6_chunk
  end

  # En/decode SETUP

  setup do
    tests = [
      # ipv4 test cases, in addition to similar tests in iptrie_test
      {"0.0.0.0", <<@ip4, 0::32>>},
      {"0.0.0.0/32", <<@ip4, 0::32>>},
      # - no network bits at all, but still an ipv4 key
      {"0.0.0.0/0", <<@ip4>>},
      {"128.0.0.0/1", <<@ip4, 1::1>>},
      {"255.255.255.128/31", <<@ip4, 255::8, 255::8, 255::8, 255::7>>},
      {"255.255.255.255/32", <<@ip4, 255::8, 255::8, 255::8, 255::8>>},
      {"255.255.255.255", <<@ip4, 255::8, 255::8, 255::8, 255::8>>},

      # ipv6 test cases, again more in iptrie_test
      {"::/0", <<@ip6>>},
      {"::/1", <<@ip6, 0::1>>},
      {"1::/1", <<@ip6, 1::1>>},
      {"::", <<@ip6, 0::128>>}
    ]

    {:ok, encode_good: tests}
  end

  # ENCODE

  test "encode, good", context do
    check = fn {prefix, key} -> Key.encode(prefix) == {:ok, key} end
    Enum.all?(context[:encode_good], check)

    # encode also accepts {:ok, prefix} as argument
    check = fn {prefix, key} -> Key.encode({:ok, prefix}) == {:ok, key} end
    Enum.all?(context[:encode_good], check)
  end

  test "{de,en}code, error passthrough" do
    assert Key.encode({:error, "reason"}) == {:error, "reason"}
    assert Key.decode({:error, "reason"}) == {:error, "reason"}
  end

  # DECODE

  test "Decoding, good", context do
    tests =
      Enum.filter(context[:encode_good], fn {prefix, _} ->
        String.contains?(prefix, "/")
      end)

    check = fn {prefix, key} -> Key.decode(key) == {:ok, prefix} end
    Enum.all?(tests, check)

    # decode also accepts {:ok, key} argument
    check = fn {prefix, key} -> Key.decode({:ok, key}) == {:ok, prefix} end
    Enum.all?(tests, check)
  end

  # Key.format
  test "Key.format passthrough" do
    assert Key.format({:error, "reason"}) == {:error, "reason"}
  end

  test "Key.format good" do
    assert Key.format({{1, 2, 3, 4}, 24}) == {:ok, "1.2.3.4/24"}
    assert Key.format({[1, 2, 3, 4], 24}) == {:ok, "1.2.3.4/24"}

    # mask can be omitted
    assert Key.format({{1, 2, 3, 4}, 24}, mask: false) == {:ok, "1.2.3.4"}
    assert Key.format({[1, 2, 3, 4], 24}, mask: false) == {:ok, "1.2.3.4"}
  end

  test "Key.format bad" do
    # not enough digits
    assert Key.format({{1, 2, 3}, 24}) == {:error, :eaddress}
    assert Key.format({{1, 2, 3, 4, 5, 6, 7}, 64}) == {:error, :eaddress}

    # too many digits
    assert Key.format({{1, 2, 3, 4, 5}, 24}) == {:error, :eaddress}
    assert Key.format({{1, 2, 3, 4, 5, 6, 7, 8, 9}, 64}) == {:error, :eaddress}
  end

  # Key.padr
  # - Key.pad{r,l} implicitly test the private bitsp function

  test "Key.pad{r,l} passthrough" do
    assert Key.padr({:error, "reason"}, 0, 0) == {:error, "reason"}
    assert Key.padl({:error, "reason"}, 0, 0) == {:error, "reason"}
  end

  test "Key.padr good" do
    tests = [
      # ipv4
      # - pad with 0 bits
      {@ip4, 0, 0, <<@ip4>>},
      {@ip4, 1, 0, <<@ip4>>},
      {<<@ip4, 255::8>>, 1, 0, <<@ip4, 255::8>>},
      {<<@ip4, 255::8>>, 0, 0, <<@ip4, 255::8>>},

      # - pad with 1+ bits
      {@ip4, 0, 1, <<@ip4, 0::1>>},
      {@ip4, 1, 1, <<@ip4, 1::1>>},
      {<<@ip4, 255::8>>, 1, 9, <<@ip4, 255::8, 1::1>>},
      {<<@ip4, 255::8>>, 1, 15, <<@ip4, 255::8, 255::7>>},

      # - pad to less than current length leaves key untouched
      {<<@ip4, 255::8>>, 1, 7, <<@ip4, 255::8>>},
      {<<@ip4, 255::8>>, 0, 7, <<@ip4, 255::8>>},

      # ipv6
      # - pad with 0 bits
      {@ip6, 0, 0, @ip6},
      {@ip6, 1, 0, @ip6},

      # - pad with 1 bit
      {@ip6, 0, 1, <<@ip6, 0::1>>},
      {@ip6, 1, 1, <<@ip6, 1::1>>},

      # - pad with 2+ bits
      {@ip6, 0, 128, <<@ip6, 0::128>>},
      {@ip6, 1, 128,
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::16>>}
    ]

    check = fn {key, fill, len, result} ->
      Key.padr({:ok, key}, fill, len) == {:ok, result}
    end

    assert Enum.all?(tests, check)
  end

  test "Key.padr bad" do
    tests = [
      # ipv4
      {@ip4, 1, 33, {:error, :epadr}},
      {@ip4, 0, 33, {:error, :epadr}},
      {@ip4, 0, 129, {:error, :epadr}},

      # ipv6
      {@ip6, 1, 129, {:error, :epadr}},
      {@ip6, 0, 129, {:error, :epadr}}
    ]

    check = fn {key, fill, len, error} -> Key.padr({:ok, key}, fill, len) == error end
    assert Enum.all?(tests, check)
  end

  # Key.padl

  test "Key.padl good" do
    tests = [
      # ipv4
      # - pad with 0 bits
      {<<@ip4, 255::8>>, 1, 0, <<@ip4, 255::8>>},
      {<<@ip4, 255::8>>, 0, 0, <<@ip4, 255::8>>},

      # - pad to less/same than current length leaves key untouched
      {<<@ip4, 255::8>>, 1, 7, <<@ip4, 255::8>>},
      {<<@ip4, 255::8>>, 0, 7, <<@ip4, 255::8>>},
      {<<@ip4, 255::8>>, 1, 8, <<@ip4, 255::8>>},
      {<<@ip4, 255::8>>, 0, 8, <<@ip4, 255::8>>},

      # - pad with 1+ bits
      {@ip4, 1, 1, <<@ip4, 1::1>>},
      {<<@ip4, 255::8>>, 0, 15, <<@ip4, 0::7, 255::8>>},
      {<<@ip4, 255::8>>, 1, 15, <<@ip4, 255::8, 255::7>>},
      {<<@ip4, 255::8>>, 1, 9, <<@ip4, 1::1, 255::8>>},

      # ipv6
      {@ip6, 0, 1, <<@ip6, 0::1>>},
      {@ip6, 1, 1, <<@ip6, 1::1>>},
      {@ip6, 0, 128, <<@ip6, 0::128>>},
      {@ip6, 1, 128,
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::16>>}
    ]

    check = fn {key, fill, len, result} -> Key.padl({:ok, key}, fill, len) == {:ok, result} end
    assert Enum.all?(tests, check)
  end

  test "Key.padl bad" do
    tests = [
      # ipv4
      {@ip4, 1, 33, {:error, :epadl}},
      {@ip4, 0, 33, {:error, :epadl}},
      {@ip4, 0, 129, {:error, :epadl}},

      # ipv6
      {@ip6, 1, 129, {:error, :epadl}},
      {@ip6, 0, 129, {:error, :epadl}}
    ]

    check = fn {key, fill, len, error} -> Key.padl({:ok, key}, fill, len) == error end
    assert Enum.all?(tests, check)
  end

  # Key.split

  test "Key.split" do
    tests = [
      {<<@ip4, 255::8, 255::8, 255::8>>, {@ip4, <<255::8, 255::8, 255::8>>}},
      {<<@ip6, 255::8, 255::8, 255::8>>, {@ip6, <<255::8, 255::8, 255::8>>}}
    ]

    # passthrough
    assert Key.split({:error, "reason"}) == {:error, "reason"}

    # test cases
    check = fn {key, result} -> Key.split({:ok, key}) == result end
    assert Enum.all?(tests, check)
  end

  # Key.bits_todigits
  # - supports Key.digits
  test "Key.bits_todigits" do
    tests = [
      {<<255::8>>, 8, [0b11111111]},
      {<<255::8>>, 7, [0b1111111, 0b1000000]},
      {<<255::8>>, 6, [0b111111, 0b110000]},
      {<<255::8>>, 5, [0b11111, 0b11100]},
      {<<255::8>>, 4, [0b1111, 0b1111]},
      {<<255::8>>, 3, [0b111, 0b111, 0b110]},
      {<<255::8>>, 2, [0b11, 0b11, 0b11, 0b11]},
      {<<255::8>>, 1, [0b1, 0b1, 0b1, 0b1, 0b1, 0b1, 0b1, 0b1]}
    ]

    check = fn {bits, chunk, result} ->
      # IO.inspect({bits, chunk, result}, label: "inp")
      # IO.inspect(Key.bits_todigits(bits, chunk), label: "-->")
      Key.bits_todigits(bits, chunk) == result
    end

    assert Enum.all?(tests, check)
  end

  # Key.digits

  test "Key.digits good and bad" do
    tests = [
      # ipv4

      # - zero mask
      {<<@ip4>>, 0, {[0, 0, 0, 0], 0}},
      {<<@ip4>>, 1, {[255, 255, 255, 255], 0}},

      # - partial mask
      {<<@ip4, 255::8>>, 0, {[255, 0, 0, 0], 8}},
      {<<@ip4, 0::1>>, 0, {[0, 0, 0, 0], 1}},

      # - chunks are fit to af chunk size, so 0xb1 is padded to 0xb1111_1111
      {<<@ip4, 1::1>>, 0, {[128, 0, 0, 0], 1}},
      {<<@ip4, 0::24, 1::1>>, 0, {[0, 0, 0, 128], 25}},

      # - full mask
      {<<@ip4, 255::8, 254::8, 253::8, 252::8>>, 0, {[255, 254, 253, 252], 32}},
      {<<@ip4, 0::8, 1::8, 2::8, 3::8>>, 0, {[0, 1, 2, 3], 32}}
    ]

    # test cases
    check = fn {key, fill, result} ->
      # IO.inspect({key, result}, label: "inp")
      # IO.inspect(Key.digits({:ok, key}), label: "-->")
      Key.digits({:ok, key}, fill) == {:ok, result}
    end

    assert Enum.all?(tests, check)

    # passthrough
    assert Key.digits({:error, "reason"}) == {:error, "reason"}

    # defaults to 0's to fill
    assert Key.digits({:ok, <<@ip4>>}) == {:ok, {[0, 0, 0, 0], 0}}
  end
end
