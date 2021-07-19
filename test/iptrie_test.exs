defmodule IptrieTest do
  use ExUnit.Case
  doctest Iptrie, import: true
  alias Radix
  import Iptrie

  @bad_pfx [
    "1.1.1.256",
    "dead:beer::",
    "11-22-33-44-55-FG",
    "11-22-33-44-55-66-77-FG",
    42,
    %{}
  ]
  @bad_trees [42, %{}, {0, nil}, {1, nil, nil}, {nil, nil, nil}, [], nil]

  # change this and you'll need to change a lot of assertions
  @test_trie new()
             |> put("1.1.1.0/24", 1)
             |> put("1.1.1.0/25", 2)
             |> put("1.1.1.128/25", 3)
             |> put("acdc:1975::/32", 4)
             |> put("acdc:1976::/32", 5)
             |> put("11-22-33-00-00-00/24", 6)
             |> put("11-22-44-00-00-00/24", 7)
             |> put("11-22-33-44-55-66-00-00/48", 8)
             |> put("11-22-33-44-55-67-00-00/48", 9)

  # Iptrie.new/0
  test "new/0 returns empty Iptrie" do
    assert %Iptrie{} == new()
  end

  test "new/1 returns a populated Iptrie" do
    # IPv4/6 recognized in different representations
    # EUI-48/64 only in binary form
    t =
      new([
        # ipv4
        {"1.1.1.0/24", 1},
        {{{1, 1, 2, 0}, 24}, 2},
        {{1, 2, 3, 4}, 3},
        {%Pfx{bits: <<10, 11, 12>>, maxlen: 32}, 4},
        # ipv6
        {"acdc:1975::/32", 1},
        {{{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32}, 2},
        {{{0xACDC, 0x1976, 0, 0, 0, 0, 0, 1}, 128}, 3},
        {%Pfx{bits: <<0xACDC::16, 0x1977::16>>, maxlen: 128}, 4},
        # eui's
        {"11-22-33-44-55-66/24", 1},
        {"11-22-33-44-55-66-77-88/48", 1}
      ])

    assert 4 == Map.get(t, 32) |> Radix.count()
    assert 4 == Map.get(t, 128) |> Radix.count()
    assert 1 == Map.get(t, 48) |> Radix.count()
    assert 1 == Map.get(t, 64) |> Radix.count()
  end

  test "new/1 raises on invalid arguments" do
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> new([{pfx, 0}]) end)
  end

  # Iptrie.get/2
  test "get/2 uses exact match on correct radix tree" do
    t = @test_trie
    assert get(t, "1.1.1.0/24") == {"1.1.1.0/24", 1}
    assert get(t, "acdc:1976::/32") == {"acdc:1976:0:0:0:0:0:0/32", 5}
    assert get(t, "11-22-33-00-00-00/24") == {"11-22-33-00-00-00/24", 6}
    assert get(t, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 9}
  end

  test "get/2 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> get(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> get(tree, "1.1.1.1") end)
  end

  # Iptrie.put/3
  test "put/3 puts value under key, overriding existing key" do
    t =
      @test_trie
      |> put("1.1.1.0", 100)
      |> put("1.1.1.128/25", 101)
      |> put("acdc:1975:1::/33", 102)
      |> put("11-22-33-00-00-00/24", 103)

    assert 100 == get(t, "1.1.1.0") |> elem(1)
    assert 101 == get(t, "1.1.1.128/25") |> elem(1)
    assert 102 == get(t, "acdc:1975:1::/33") |> elem(1)
    assert 103 == get(t, "11-22-33-00-00-00/24") |> elem(1)
  end

  test "put/3 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> put(t, pfx, 0) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> put(tree, "1.1.1.1", 0) end)
  end

  # Iptrie.put/2
  test "put/2 puts value under key, overriding existing entries" do
    elements = [
      {"1.1.1.0/25", 100},
      {"11-22-33-44-55-67-00-00/48", 101},
      {"2.2.2.2", 102},
      {"11-22-33-44-55-66-77-88", 103}
    ]

    t =
      @test_trie
      |> put(elements)

    for {k, v} <- elements, do: assert({k, v} == get(t, k))
  end

  test "put/2 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> put(t, [{pfx, 0}]) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> put(tree, [{"1.1.1.1", 0}]) end)
  end

  # Iptrie.delete/2
  test "delete/2 deletes using exact match" do
    keys = ["1.1.1.0", "1.1.1.128/25", "acdc:1975::/32", "11-22-33-44-55-67-00-00/48"]
    t = @test_trie |> delete(keys)
    for key <- keys, do: assert(nil == get(t, key))

    assert {"1.1.1.0/24", 1} == get(t, "1.1.1.0/24")
  end

  test "delete/2 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> delete(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> delete(tree, "1.1.1.1") end)
  end

  # Iptrie.fetch/3
  test "fetch/3 fetches exactly or on longest prefix match" do
    t = @test_trie
    assert {:ok, {"1.1.1.0/24", 1}} == fetch(t, "1.1.1.0/24")
    assert {:error, :notfound} == fetch(t, "2.2.2.2")

    # longest prefix match
    assert {:ok, {"1.1.1.0/25", 2}} == fetch(t, "1.1.1.1", match: :lpm)
    assert {:error, :notfound} == fetch(t, "2.2.2.2", match: :lpm)
  end

  test "fetch/3 does not raise on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert({:error, :einval} == fetch(t, pfx))
    for tree <- @bad_trees, do: assert({:error, :bad_trie} == fetch(tree, "1.1.1.1"))
  end

  # Iprie.fetch!/3
  test "fetch!/3 wraps fetch/3 and raises" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> fetch!(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> fetch!(tree, "1.1.1.1") end)

    t = @test_trie
    assert {"1.1.1.0/24", 1} == fetch!(t, "1.1.1.0/24")
    assert_raise KeyError, fn -> fetch!(t, "2.2.2.2") end

    # longest prefix match
    assert {"1.1.1.0/25", 2} == fetch!(t, "1.1.1.1", match: :lpm)
    assert_raise KeyError, fn -> fetch!(t, "2.2.2.2", match: :lpm) end
  end

  # Iptrie.find/2 - simply wraps Iptrie.fetch/3

  # Iptrie.find!/2 - simply wraps Iptrie.fetch!/3

  # Iptrie.filter/2
  test "filter/2 filters based on bits, maxlen and/or value" do
    t = @test_trie
    t1 = filter(t, fn _bits, _maxlen, val -> val in [1, 2, 3, 4] end)
    assert Radix.count(radix(t1, 32)) == 3
    assert Radix.count(radix(t1, 128)) == 1
    assert get(t1, "1.1.1.0/24") == {"1.1.1.0/24", 1}
    assert get(t1, "1.1.1.0/25") == {"1.1.1.0/25", 2}
    assert get(t1, "1.1.1.128/25") == {"1.1.1.128/25", 3}
    assert get(t1, "acdc:1975::/32") == {"acdc:1975:0:0:0:0:0:0/32", 4}
  end

  test "filter/2 raises on invalid Iptries" do
    t = new()
    f = fn _bits, _maxlen, _value -> false end
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> filter(tree, f) end)

    # raises if fun doesn't have arity 3
    assert_raise ArgumentError, fn -> filter(t, fn x -> x end) end
  end

  # Iptrie.keys/1
  test "keys/1 returns all keys in the trie" do
    assert keys(@test_trie) == [
             %Pfx{bits: <<1, 1, 1, 0::size(1)>>, maxlen: 32},
             %Pfx{bits: "\x01\x01\x01", maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 1::size(1)>>, maxlen: 32},
             %Pfx{bits: <<17, 34, 51>>, maxlen: 48},
             %Pfx{bits: <<17, 34, 68>>, maxlen: 48},
             %Pfx{bits: <<17, 34, 51, 68, 85, 102>>, maxlen: 64},
             %Pfx{bits: <<17, 34, 51, 68, 85, 103>>, maxlen: 64},
             %Pfx{bits: <<172, 220, 25, 117>>, maxlen: 128},
             %Pfx{bits: <<172, 220, 25, 118>>, maxlen: 128}
           ]
  end

  test "keys/1 raises on invalid Iptries" do
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> keys(tree) end)
  end

  # Iptrie.values/1
  test "values/1 returns all values of all radix trees" do
    assert values(@test_trie) |> Enum.sort() == [1, 2, 3, 4, 5, 6, 7, 8, 9]
  end

  test "values/1 raises on invalid Iptries" do
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> values(tree) end)
  end

  # Iptrie.lookup/2
  test "lookup/2 uses longest prefix matching" do
    t = @test_trie
    assert lookup(t, "1.1.1.1") == {"1.1.1.0/25", 2}
    assert lookup(t, "acdc:1976::1") == {"acdc:1976:0:0:0:0:0:0/32", 5}
    assert lookup(t, "11-22-33-44-55-66") == {"11-22-33-00-00-00/24", 6}
    assert lookup(t, "11-22-33-44-55-67-01-02") == {"11-22-33-44-55-67-00-00/48", 9}
  end

  test "lookup/2 raises on invalid input" do
    t = @test_trie
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> lookup(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> lookup(tree, "1.1.1.1") end)
  end

  # Iptrie.more/2
  test "more/2 gets all more specifics from the trie" do
    t = @test_trie

    assert more(t, "1.1.1.0/24") == [
             {"1.1.1.0/25", 2},
             {"1.1.1.0/24", 1},
             {"1.1.1.128/25", 3}
           ]

    assert more(t, "11-22-33-44-55-00-00-00/40") == [
             {"11-22-33-44-55-67-00-00/48", 9},
             {"11-22-33-44-55-66-00-00/48", 8}
           ]
  end

  test "more/2 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> more(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> more(tree, "0.0.0.0/0") end)
  end

  # Iptrie.less/2

  test "less/2 returns all less specifics" do
    t = @test_trie

    assert less(t, "1.1.1.1") == [
             {"1.1.1.0/25", 2},
             {"1.1.1.0/24", 1}
           ]

    assert less(t, "1.1.1.255") == [
             {"1.1.1.128/25", 3},
             {"1.1.1.0/24", 1}
           ]
  end

  test "less/2 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> less(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> less(tree, "0.0.0.0/0") end)
  end

  # Iptrie.update/3
  test "update/3 uses longest prefix match to update" do
    t = @test_trie
    fun = fn x -> x + 100 end

    t1 =
      update(t, "1.1.1.255", fun)
      |> update("11-22-33-44-55-67-99-99", fun)

    assert get(t1, "1.1.1.128/25") == {"1.1.1.128/25", 103}
    assert get(t1, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 109}
  end

  test "update/3 does not add if key not found" do
    t = @test_trie
    t1 = update(t, "2.2.2.2", fn x -> x + 1 end)
    assert t == t1
  end

  test "update/3 raises on invalid input" do
    t = new()
    f = fn x -> x end
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> update(t, pfx, f) end)

    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> update(tree, "0.0.0.0/0", f) end)

    # bad arity
    assert_raise ArgumentError, fn -> update(t, "0.0.0.0/0", fn x, y -> x + y end) end
  end

  # Iptrie.update/4
  test "update/4 uses longest prefix match to update" do
    t = @test_trie
    fun = fn x -> x + 100 end
    default = 0

    t1 =
      update(t, "1.1.1.255", default, fun)
      |> update("11-22-33-44-55-67-99-99", default, fun)

    assert get(t1, "1.1.1.128/25") == {"1.1.1.128/25", 103}
    assert get(t1, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 109}
  end

  test "update/4 inserts default value if if key not found" do
    t = @test_trie
    t1 = update(t, "2.2.2.2", 0, fn x -> x + 1 end)
    assert get(t1, "2.2.2.2") == {"2.2.2.2", 0}
  end

  test "update/4 raises on invalid input" do
    t = new()
    f = fn x -> x end
    default = nil

    for pfx <- @bad_pfx,
        do: assert_raise(ArgumentError, fn -> update(t, pfx, default, f) end)

    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> update(tree, "0.0.0.0/0", default, f) end)

    # bad arity
    assert_raise ArgumentError, fn -> update(t, "0.0.0.0/0", default, fn x, y -> x + y end) end
  end

  # Iptrie.to_list/1
  test "to_list/1 returns list across all radix trees and their entries" do
    l = to_list(@test_trie)
    assert length(l) == 9
    assert Enum.member?(l, {%Pfx{bits: <<1, 1, 1, 1::1>>, maxlen: 32}, 3})
    assert Enum.member?(l, {%Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}, 5})
    assert Enum.member?(l, {%Pfx{bits: <<0x11, 0x22, 0x33>>, maxlen: 48}, 6})
    assert Enum.member?(l, {%Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x67>>, maxlen: 64}, 9})
  end

  test "to_list/1 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> to_list(tree) end)
  end

  test "to_list/2 returns list of one or more radix trees" do
    l = to_list(@test_trie, 32)
    Enum.all?(l, fn {pfx, _} -> pfx.maxlen == 32 end)

    l = to_list(@test_trie, [48, 64])
    Enum.all?(l, fn {pfx, _} -> pfx.maxlen in [48, 64] end)
  end

  test "to_list/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> to_list(tree, 32) end)

    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> to_list(tree, [128]) end)

    # bad args
    assert_raise ArgumentError, fn -> to_list(@test_trie, {32}) end
    assert_raise ArgumentError, fn -> to_list(@test_trie, -32) end
  end

  # Iptrie.reduce/3
  test "reduce/3 runs across all radix trees" do
    t = @test_trie
    add = fn _k, v, acc -> acc + v end
    assert reduce(t, 0, add) == 45

    assert reduce(new(), 0, add) == 0
  end

  test "reduce/3 raises on invalid input" do
    add = fn _k, v, acc -> acc + v end

    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> reduce(tree, 0, add) end)

    # bad fun
    assert_raise ArgumentError, fn -> reduce(new(), 0, fn x -> x end) end
  end

  # Iptrie.reduce/4
  test "reduce/4 runs across one or more radix trees" do
    t = @test_trie
    add = fn _k, v, acc -> acc + v end
    assert reduce(t, 32, 0, add) == 6
    assert reduce(t, 128, 0, add) == 9
    assert reduce(t, 48, 0, add) == 13
    assert reduce(t, 64, 0, add) == 17

    # multiple radix trees
    assert reduce(t, [32, 128], 0, add) == 15
    assert reduce(t, [48, 64], 0, add) == 30
    assert reduce(t, [32, 48, 64, 128], 0, add) == 45

    # unknown types are handled
    assert reduce(t, 3, 0, add) == 0
    assert reduce(t, [3, 32, 48, 64, 128], 0, add) == 45
  end

  test "reduce/4 raises on invalid input" do
    add = fn _k, v, acc -> acc + v end

    # bad_trie
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> reduce(tree, 32, 0, add) end)

    # bad fun
    assert_raise ArgumentError, fn -> reduce(new(), 32, 0, fn x -> x end) end
  end

  # Iptrie.radix/2
  test "radix/2 returns an existing radix tree or an empty one" do
    alias Radix
    t = @test_trie
    r = radix(t, 32)
    assert Radix.get(r, <<1, 1, 1>>) == {<<1, 1, 1>>, 1}
    r = radix(t, 48)
    assert Radix.get(r, <<0x11, 0x22, 0x33>>) == {<<0x11, 0x22, 0x33>>, 6}
    r = radix(t, 16)
    assert Radix.empty?(r)
  end

  test "radix/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> radix(tree, 0) end)

    # bad types
    assert_raise ArgumentError, fn -> radix(new(), -1) end
    assert_raise ArgumentError, fn -> radix(new(), 32.0) end
  end

  # Iptrie.types/1
  test "types/1 returns all types from an Iptrie" do
    assert types(@test_trie) |> Enum.sort() == [32, 48, 64, 128]
  end

  test "types/1 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> types(tree) end)
  end

  # Iptrie.has_type?/2
  test "has_type?/2 syas yay or nay" do
    t = @test_trie

    for type <- types(t),
        do: assert(has_type?(t, type))

    refute has_type?(t, 0)
  end

  test "has_type?/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> has_type?(tree, 0) end)

    assert_raise ArgumentError, fn -> has_type?(new(), 32.0) end
    assert_raise ArgumentError, fn -> has_type?(new(), -32) end
  end
end
