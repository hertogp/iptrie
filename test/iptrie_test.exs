defmodule IptrieTest do
  use ExUnit.Case
  doctest Iptrie

  @ip4 <<0::1>>
  @ip6 <<1::1>>

  # IPv4 setup(good)

  setup do
    # all ones makes mask length checking easier
    ipv4_good = [
      # no mask means full mask
      {"255.255.255.255", <<@ip4, 255::8, 255::8, 255::8, 255::8>>},
      # some long prefixes
      {"255.255.255.255/32", <<@ip4, 255::8, 255::8, 255::8, 255::8>>},
      {"255.255.255.254/31", <<@ip4, 255::8, 255::8, 255::8, 255::7>>},
      {"255.255.255.252/30", <<@ip4, 255::8, 255::8, 255::8, 255::6>>},
      # some inbetween lengths
      {"255.255.224.0/19", <<@ip4, 255::8, 255::8, 255::3>>},
      {"255.255.0.0/16", <<@ip4, 255::8, 255::8>>},
      {"255.254.0.0/15", <<@ip4, 255::8, 255::7>>},
      {"255.128.0.0/9", <<@ip4, 255::8, 255::1>>},
      {"255.0.0.0/8", <<@ip4, 255::8>>},
      {"254.0.0.0/7", <<@ip4, 255::7>>},
      # some short prefixes
      {"224.0.0.0/3", <<@ip4, 255::3>>},
      {"192.0.0.0/2", <<@ip4, 255::2>>},
      {"128.0.0.0/1", <<@ip4, 255::1>>},
      # and the shortest of all
      {"0.0.0.0/0", <<@ip4>>},
      # some other random cases
      {"0.0.0.0/32", <<@ip4, 0::32>>},
      {"1.1.1.1/32", <<@ip4, 1::8, 1::8, 1::8, 1::8>>},
      {"126.127.128.129/32", <<@ip4, 126::8, 127::8, 128::8, 129::8>>},

      # encoding test only: the weird behaviour of :inet.aton
      {"10.10", <<@ip4, 10::8, 0::8, 0::8, 10::8>>},
      {"10", <<@ip4, 0::8, 0::8, 0::8, 10::8>>},
      # hexadecimal numbers allowed
      {"255.0xff.255.0xff", <<@ip4, 255::8, 255::8, 255::8, 255::8>>}
    ]

    {:ok, ipv4_good: ipv4_good}
  end

  # IPv4 setup(bad)

  setup do
    ipv4_bad = [
      # address errors
      {"10.10.10.256", {:error, :eaddress}},
      {"10.10.256.10", {:error, :eaddress}},
      {"10.256.10.10", {:error, :eaddress}},
      {"256.10.10.10", {:error, :eaddress}},
      {"", {:error, :eaddress}},
      {"/24", {:error, :eaddress}},
      {"256.10.10", {:error, :eaddress}},
      {"10.10.10.256/33", {:error, :eaddress}},

      # non-binary prefix errors
      {true, {:error, :eaddress}},
      {'10.10.10.0/24', {:error, :eaddress}},

      # mask errors
      {"10.10.10.10/33", {:error, :emask}},
      {"10.10.10.10/blah", {:error, :emask}}
    ]

    {:ok, ipv4_bad: ipv4_bad}
  end

  # IPv4 tests

  test "IPv4, encoding", context do
    check = fn {pfx, key} -> Iptrie.encode(pfx) == {:ok, key} end
    assert Enum.all?(context[:ipv4_good], check)
  end

  test "IPv4, decoding", context do
    # only test cases where pfx has a /len in it.
    tests =
      Enum.filter(context[:ipv4_good], fn {pfx, _} ->
        String.contains?(pfx, "/")
      end)

    check = fn {pfx, key} -> Iptrie.decode(key) == {:ok, pfx} end
    assert Enum.all?(tests, check)
  end

  test "IPv4, encoding errors", context do
    check = fn {pfx, err} -> Iptrie.encode(pfx) == err end
    assert Enum.all?(context[:ipv4_bad], check)
  end

  # IPv6 setup(good)

  setup do
    tests = [
      {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::16>>},
      {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::16>>},
      {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127",
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::15>>},
      {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc/126",
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::14>>},
      {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8/125",
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16,
         0xFFFF::13>>},
      {"ffff:ffff:ffff:ffff:8000::/65",
       <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::1>>},
      {"ffff:ffff:ffff:ffff::/64", <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16>>},
      {"ffff:ffff:ffff:fffe::/63", <<@ip6, 0xFFFF::16, 0xFFFF::16, 0xFFFF::16, 0xFFFF::15>>},
      {"f000::/4", <<@ip6, 0xF::4>>},
      {"e000::/3", <<@ip6, 0xF::3>>},
      {"c000::/2", <<@ip6, 0xF::2>>},
      {"8000::/1", <<@ip6, 0xF::1>>},
      {"::/0", <<@ip6>>}
    ]

    {:ok, ipv6_good: tests}
  end

  # IPv6 setup(bad)

  setup do
    tests = [
      # address errors
      {"fffG::/0", {:error, :eaddress}},
      {"fffG::/129", {:error, :eaddress}},
      {"blah/64", {:error, :eaddress}},
      {"", {:error, :eaddress}},

      # non-binary prefix errors
      {10, {:error, :eaddress}},
      {true, {:error, :eaddress}},
      {'ff::/64', {:error, :eaddress}},

      # mask errors
      {"::ffff/129", {:error, :emask}},
      {"::ffff/", {:error, :emask}},
      {"::ffff/blah", {:error, :emask}},
      {"::ffff/b", {:error, :emask}},
      {"::ffff/0xb", {:error, :emask}}
    ]

    {:ok, ipv6_bad: tests}
  end

  # IPv6 tests

  test "IPv6, encoding", context do
    check = fn {addr, key} -> assert Iptrie.encode(addr) == {:ok, key} end

    assert Enum.all?(context[:ipv6_good], check)
  end

  test "IPv6, encoding errors", context do
    check = fn {addr, err} -> assert Iptrie.encode(addr) == err end

    assert Enum.all?(context[:ipv6_bad], check)
  end

  test "IPv6, decoding", context do
    # only test cases where pfx has a /len in it.
    tests =
      Enum.filter(context[:ipv6_good], fn {pfx, _} ->
        String.contains?(pfx, "/")
      end)

    check = fn {pfx, key} -> Iptrie.decode(key) == {:ok, pfx} end
    assert Enum.all?(tests, check)
  end
end
