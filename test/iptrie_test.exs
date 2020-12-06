defmodule IptrieTest do
  use ExUnit.Case
  doctest Iptrie, import: true

  setup do
    ex01 = [
      # {pfx, data}, all more or less specifics
      {"1.0.0.0/8", "1.0.0.0/8"},
      {"1.0.0.0/24", "1.0.0.0/24"},
      {"1.0.0.0/16", "1.0.0.0/16"},
      {"1.0.0.0/32", "1.0.0.0/32"}
    ]

    {:ok, ex01: ex01}
  end

  setup do
    ex02 = [
      {"1.0.0.0/8", "1.0.0.0/8"},
      {"1.1.1.64/26", "1.1.1.64/26"},
      {"1.1.1.128/26", "1.1.1.128/26"},
      {"1.1.1.0/24", "1.1.1.0/24"},
      {"1.1.1.0/25", "1.1.1.0/25"}
    ]

    {:ok, ex02: ex02}
  end

  test "ex01 - insertion order does not matter", context do
    t = Iptrie.new(context[:ex01])

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/32"
    assert elem(Iptrie.lookup(t, "1.0.0.1"), 1) == "1.0.0.0/24"
    assert elem(Iptrie.lookup(t, "1.0.1.0"), 1) == "1.0.0.0/16"
    assert elem(Iptrie.lookup(t, "1.1.0.0"), 1) == "1.0.0.0/8"

    # reverse order of insertion and test again
    t = Iptrie.new(Enum.reverse(context[:ex01]))

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/32"
    assert elem(Iptrie.lookup(t, "1.0.0.1"), 1) == "1.0.0.0/24"
    assert elem(Iptrie.lookup(t, "1.0.1.0"), 1) == "1.0.0.0/16"
    assert elem(Iptrie.lookup(t, "1.1.0.0"), 1) == "1.0.0.0/8"

    # shuffle order of insertion and test again
    t = Iptrie.new(Enum.shuffle(context[:ex01]))

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/32"
    assert elem(Iptrie.lookup(t, "1.0.0.1"), 1) == "1.0.0.0/24"
    assert elem(Iptrie.lookup(t, "1.0.1.0"), 1) == "1.0.0.0/16"
    assert elem(Iptrie.lookup(t, "1.1.0.0"), 1) == "1.0.0.0/8"
  end

  test "ex01 - same results with new(list) as set(list)", context do
    # use new with shuffled order of insertion
    t = Iptrie.new(Enum.shuffle(context[:ex01]))

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/32"
    assert elem(Iptrie.lookup(t, "1.0.0.1"), 1) == "1.0.0.0/24"
    assert elem(Iptrie.lookup(t, "1.0.1.0"), 1) == "1.0.0.0/16"
    assert elem(Iptrie.lookup(t, "1.1.0.0"), 1) == "1.0.0.0/8"

    # use set with shuffled order of insertion, expect the same results
    t = Iptrie.new() |> Iptrie.set(Enum.shuffle(context[:ex01]))

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/32"
    assert elem(Iptrie.lookup(t, "1.0.0.1"), 1) == "1.0.0.0/24"
    assert elem(Iptrie.lookup(t, "1.0.1.0"), 1) == "1.0.0.0/16"
    assert elem(Iptrie.lookup(t, "1.1.0.0"), 1) == "1.0.0.0/8"
  end

  test "ex02 - match less specifics in left part of tree", context do
    t = Iptrie.new(context[:ex02])

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/8"
    assert elem(Iptrie.lookup(t, "1.2.0.0"), 1) == "1.0.0.0/8"
    assert elem(Iptrie.lookup(t, "1.255.255.255"), 1) == "1.0.0.0/8"
    assert elem(Iptrie.lookup(t, "1.1.1.65"), 1) == "1.1.1.64/26"
    assert elem(Iptrie.lookup(t, "1.1.1.129"), 1) == "1.1.1.128/26"
    assert elem(Iptrie.lookup(t, "1.1.1.0"), 1) == "1.1.1.0/25"
    assert elem(Iptrie.lookup(t, "1.1.1.193"), 1) == "1.1.1.0/24"

    # just for kicks, reverse order of insertion and test again
    t = Iptrie.new(Enum.reverse(context[:ex02]))

    assert elem(Iptrie.lookup(t, "1.0.0.0"), 1) == "1.0.0.0/8"
    assert elem(Iptrie.lookup(t, "1.2.0.0"), 1) == "1.0.0.0/8"
    assert elem(Iptrie.lookup(t, "1.255.255.255"), 1) == "1.0.0.0/8"
    assert elem(Iptrie.lookup(t, "1.1.1.65"), 1) == "1.1.1.64/26"
    assert elem(Iptrie.lookup(t, "1.1.1.129"), 1) == "1.1.1.128/26"
    assert elem(Iptrie.lookup(t, "1.1.1.0"), 1) == "1.1.1.0/25"
    assert elem(Iptrie.lookup(t, "1.1.1.193"), 1) == "1.1.1.0/24"
  end
end
