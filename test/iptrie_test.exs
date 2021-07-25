defmodule IptrieTest do
  use ExUnit.Case
  doctest Iptrie, import: true
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

  # Iptrie.count/1
  test "count/1 returns total count of entries in Iptrie" do
    assert count(@test_trie) == 9
  end

  test "count/1 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> count(tree) end)
  end

  # Iptrie.count/2
  test "count/2 returns count for given type" do
    assert count(@test_trie, 32) == 3
    assert count(@test_trie, 48) == 2
    assert count(@test_trie, 64) == 2
    assert count(@test_trie, 128) == 2
    # no type -> 0
    assert count(@test_trie, 11) == 0
  end

  test "count/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> count(tree, 32) end)

    assert_raise ArgumentError, fn -> count(@test_trie, 1.0) end
    assert_raise ArgumentError, fn -> count(@test_trie, -32) end
  end

  # Iptrie.delete/2
  test "delete/2 deletes using exact match" do
    keys = ["1.1.1.0", "1.1.1.128/25", "acdc:1975::/32", "11-22-33-44-55-67-00-00/48"]
    t = @test_trie
    t = Enum.reduce(keys, t, fn pfx, acc -> delete(acc, pfx) end)
    for key <- keys, do: assert(nil == get(t, key))

    assert {"1.1.1.0/24", 1} == get(t, "1.1.1.0/24")
  end

  test "delete/2 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> delete(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> delete(tree, "1.1.1.1") end)
  end

  # Iptrie.drop/2
  test "drop/2 removes pfx,value-pairs and returns a new tree" do
    t = @test_trie

    t2 = drop(t, ["1.1.1.0/24", "1.1.1.128/25", "11-22-33-44-55-67-00-00/48"])
    assert get(t2, "1.1.1.0/24") == nil
    assert get(t2, "1.1.1.128/25") == nil
    assert get(t2, "11-22-33-44-55-67-00-00/48") == nil

    # ignores non-existing prefixesdefault value for prefix not found is nil
    assert t == drop(t, ["2.2.2.2"])

    # doesn't choke on empty list
    assert t == drop(t, [])
  end

  test "drop/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> drop(tree, ["1.1.1.1"]) end)

    t = new()

    for pfx <- @bad_pfx,
        do: assert_raise(ArgumentError, fn -> drop(t, [pfx]) end)

    # also complaines when arg is not a list
    assert_raise ArgumentError, fn -> drop(t, "1.1.1.1") end
  end

  # Iptrie.empty/1
  test "empty/1 says if an Iptrie is empty or not" do
    assert empty?(@test_trie) == false
    assert empty?(new()) == true
  end

  test "empty/1 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> empty?(tree) end)
  end

  # Iptrie.empty/2
  test "empty/2 says if a radix tree is empty or not" do
    assert empty?(@test_trie, 32) == false
    assert empty?(@test_trie, 48) == false
    assert empty?(@test_trie, 64) == false
    assert empty?(@test_trie, 128) == false
    # no type -> is empty
    assert empty?(@test_trie, 11) == true
  end

  test "empty/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> empty?(tree, 32) end)

    assert_raise ArgumentError, fn -> empty?(@test_trie, 1.0) end
    assert_raise ArgumentError, fn -> empty?(@test_trie, -32) end
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

  # Iptrie.fetch!/3
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

  # Iptrie.filter/2
  test "filter/2 filters based on bits, maxlen and/or value" do
    t = @test_trie
    t1 = filter(t, fn _pfx, val -> val in [1, 2, 3, 4] end)
    assert Radix.count(radix(t1, 32)) == 3
    assert Radix.count(radix(t1, 128)) == 1
    assert get(t1, "1.1.1.0/24") == {"1.1.1.0/24", 1}
    assert get(t1, "1.1.1.0/25") == {"1.1.1.0/25", 2}
    assert get(t1, "1.1.1.128/25") == {"1.1.1.128/25", 3}
    assert get(t1, "acdc:1975::/32") == {"acdc:1975:0:0:0:0:0:0/32", 4}
  end

  test "filter/2 raises on invalid Iptries" do
    t = new()
    f = fn _pfx, _value -> false end
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> filter(tree, f) end)

    # raises if fun doesn't have arity 2
    assert_raise ArgumentError, fn -> filter(t, fn x -> x end) end
  end

  # Iptrie.find/2 - simply wraps Iptrie.fetch/3
  test "find/2 findes exactly or on longest prefix match" do
    t = @test_trie
    assert {:ok, {"1.1.1.0/24", 1}} == find(t, "1.1.1.0/24")
    assert {:ok, {"1.1.1.0/25", 2}} == find(t, "1.1.1.1")
    assert {:error, :notfound} == find(t, "2.2.2.2")
  end

  test "find/2 does not raise on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert({:error, :einval} == find(t, pfx))
    for tree <- @bad_trees, do: assert({:error, :bad_trie} == find(tree, "1.1.1.1"))
  end

  # Iptrie.find!/2 - simply wraps Iptrie.fetch!/3
  test "find!/2 wraps fetch/3 and raises" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> find!(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> find!(tree, "1.1.1.1") end)

    t = @test_trie
    assert {"1.1.1.0/24", 1} == find!(t, "1.1.1.0/24")
    assert_raise KeyError, fn -> find!(t, "2.2.2.2") end

    # longest prefix match
    assert {"1.1.1.0/25", 2} == find!(t, "1.1.1.1")
    assert_raise KeyError, fn -> find!(t, "2.2.2.2") end
  end

  # Iptrie.get/3
  test "get/3 uses exact match on correct radix tree" do
    t = @test_trie
    assert get(t, "1.1.1.0/24") == {"1.1.1.0/24", 1}
    assert get(t, "acdc:1976::/32") == {"acdc:1976:0:0:0:0:0:0/32", 5}
    assert get(t, "11-22-33-00-00-00/24") == {"11-22-33-00-00-00/24", 6}
    assert get(t, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 9}

    # in case of no match, returns default if provided, nil otherwise
    assert get(t, "2.2.2.2") == nil
    assert get(t, "2.2.2.2", :notfound) == :notfound
  end

  test "get/3 raises on invalid input" do
    t = new()
    for pfx <- @bad_pfx, do: assert_raise(ArgumentError, fn -> get(t, pfx) end)
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> get(tree, "1.1.1.1") end)
  end

  # Iptrie.has_prefix?/3
  test "has_prefix/3 says if an Iptrie has a prefix or not" do
    assert has_prefix?(@test_trie, "1.1.1.0/24") == true
    assert has_prefix?(@test_trie, "acdc:1976::/32") == true
    assert has_prefix?(@test_trie, "1.1.1.0") == false
    assert has_prefix?(@test_trie, "1.1.1.0", match: :lpm) == true
  end

  test "has_prefix/3 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> has_prefix?(tree, "1.1.1.1") end)

    # bad prefix
    t = new()

    for pfx <- @bad_pfx,
        do: assert_raise(ArgumentError, fn -> has_prefix?(t, pfx) end)
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

  # Iptrie.keys/2
  test "keys/2 returns all keys for given type of radix tree" do
    assert keys(@test_trie, 32) == [
             %Pfx{bits: <<1, 1, 1, 0::size(1)>>, maxlen: 32},
             %Pfx{bits: "\x01\x01\x01", maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 1::size(1)>>, maxlen: 32}
           ]
  end

  test "keys/2 raises on invalid Iptries" do
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> keys(tree, 32) end)
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

  # Iptrie.merge/2
  test "merge/2 merges two tries into one" do
    other_trie =
      new([
        {"1.1.1.0/24", 0},
        {"2.2.2.0/24", 10},
        {"acdc:1977::/32", 11},
        {"11-22-33-55-00-00/32", 12},
        {"11-22-33-44-55-68-00-00/54", 13}
      ])

    t = merge(@test_trie, other_trie)
    assert count(t) == 13
    assert count(t, 32) == 4
    assert count(t, 48) == 3
    assert count(t, 64) == 3
    assert count(t, 128) == 3

    # merge overwrites entries in first trie
    assert get(t, "1.1.1.0/24") == {"1.1.1.0/24", 0}

    # check t got the other_trie's prefix,value entries
    assert get(t, "2.2.2.0/24") == {"2.2.2.0/24", 10}
    assert get(t, "acdc:1977::/32") == {"acdc:1977:0:0:0:0:0:0/32", 11}
  end

  test "merge/2 raises on invalid input" do
    good = new()

    for bad <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> merge(bad, good) end)

    for bad <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> merge(good, bad) end)
  end

  test "merge/3 merges two tries into one with conflict resolution" do
    keep1 = fn _k, v1, _v2 -> v1 end

    other_trie =
      new([
        {"1.1.1.0/24", 0},
        {"2.2.2.0/24", 10},
        {"acdc:1977::/32", 11},
        {"11-22-33-55-00-00/32", 12},
        {"11-22-33-44-55-68-00-00/54", 13}
      ])

    t = merge(@test_trie, other_trie, keep1)
    assert count(t) == 13
    assert count(t, 32) == 4
    assert count(t, 48) == 3
    assert count(t, 64) == 3
    assert count(t, 128) == 3

    # conflicts preserve value in the first trie (@test_trie)
    assert get(t, "1.1.1.0/24") == {"1.1.1.0/24", 1}

    # check t got the other_trie's prefix,value entries
    assert get(t, "2.2.2.0/24") == {"2.2.2.0/24", 10}
    assert get(t, "acdc:1977::/32") == {"acdc:1977:0:0:0:0:0:0/32", 11}

    # an empty trie is not a problem
    assert @test_trie == merge(new(), @test_trie, keep1)
    assert @test_trie == merge(@test_trie, new(), keep1)
  end

  test "merge/3 raises on invalid input" do
    good = new()
    keep1 = fn _k, v1, _v2 -> v1 end

    for bad <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> merge(bad, good, keep1) end)

    for bad <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> merge(good, bad, keep1) end)

    assert_raise ArgumentError, fn -> merge(good, good, fn x -> x end) end
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

  # Iptrie.new/0
  test "new/0 returns empty Iptrie" do
    assert %Iptrie{} == new()
  end

  test "new/1 returns a populated Iptrie" do
    # ipv4/6 recognized in different representations
    # eui-48/64 only in binary form
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

  # Iptrie.pop/2
  test "pop/2 removes pfx,v-pair and returns it with a new tree" do
    t = @test_trie

    {{pfx, val}, t2} = pop(t, "1.1.1.0/24")
    assert {"1.1.1.0/24", 1} == {pfx, val}
    assert get(t2, "1.1.1.0/24") == nil

    # default value for prefix not found is nil
    {{pfx, val}, t2} = pop(t, "1.1.1.1")
    assert {"1.1.1.1", nil} == {pfx, val}
    assert t2 == t

    # specify default value in case of no match
    {{pfx, val}, t2} = pop(t, "1.1.1.1", default: :notfound)
    assert {"1.1.1.1", :notfound} == {pfx, val}
    assert t2 == t

    # use lpm to pop lpm match
    {{pfx, val}, t2} = pop(t, "1.1.1.1", match: :lpm)
    assert {"1.1.1.0/25", 2} == {pfx, val}
    assert get(t2, "1.1.1.0/25") == nil
  end

  test "pop/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> pop(tree, "1.1.1.1") end)

    t = new()

    for pfx <- @bad_pfx,
        do: assert_raise(ArgumentError, fn -> pop(t, pfx) end)
  end

  # Iptrie.prune/3
  test "prune/3 validates input" do
    goodfun = fn _ -> {:ok, 0} end
    badfun = fn -> {:ok, 0} end

    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> prune(tree, goodfun) end)

    assert_raise ArgumentError, fn -> prune(@test_trie, badfun) end
  end

  test "prune/3 combines neighboring prefixes" do
    combine = fn _ -> {:ok, 0} end
    elements = Pfx.partition("1.1.1.0/24", 32) |> Enum.with_index()
    ipt = new(elements)
    assert count(ipt) == 256
    # one pass
    ipt2 = prune(ipt, combine)
    assert count(ipt2) == 128
    assert has_prefix?(ipt2, "1.1.1.0/31")
    ipt3 = prune(ipt, combine, recurse: true)
    assert count(ipt3) == 1
    assert has_prefix?(ipt3, "1.1.1.0/24")
  end

  test "prune/3 combines a full set of prefixes to empty prefix for given type" do
    combine = fn
      {_p0, _p1, v1, _p2, v2} -> {:ok, v1 + v2}
      {_p0, v0, _p1, v1, _p2, v2} -> {:ok, v0 + v1 + v2}
    end

    ipt = new(for x <- 0..255, do: {Pfx.new(<<x>>, 8), x})
    assert count(ipt) == 256
    ipt2 = prune(ipt, combine, recurse: true)
    assert count(ipt2) == 1
    assert get(ipt2, Pfx.new(<<>>, 8)) == {%Pfx{bits: <<>>, maxlen: 8}, 32640}
    assert Enum.sum(0..255) == 32640
  end

  test "prune/3 prunes across all radix trees" do
    combine = fn
      {_p0, _p1, v1, _p2, v2} -> {:ok, v1 + v2}
      {_p0, v0, _p1, v1, _p2, v2} -> {:ok, v0 + v1 + v2}
    end

    ipt = new([{"1.1.1.0/31", 1}, {"1.1.1.2/31", 2}, {"acdc::0", 30}, {"acdc::1", 40}])
    assert count(ipt) == 4
    assert count(ipt, 32) == 2
    assert count(ipt, 128) == 2

    ipt2 = prune(ipt, combine, recurse: true)
    assert count(ipt2) == 2
    assert get(ipt2, "1.1.1.0/30") == {"1.1.1.0/30", 3}
    assert get(ipt2, "acdc::0/127") == {"acdc:0:0:0:0:0:0:0/127", 70}
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

  # Iptrie.radix/2
  test "radix/2 returns an existing radix tree or an empty one" do
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
  test "reduce/4 runs across one radix trees" do
    t = @test_trie
    add = fn _k, v, acc -> acc + v end
    assert reduce(t, 32, 0, add) == 6
    assert reduce(t, 128, 0, add) == 9
    assert reduce(t, 48, 0, add) == 13
    assert reduce(t, 64, 0, add) == 17

    # unknown types are handled
    assert reduce(t, 3, 0, add) == 0
  end

  test "reduce/4 raises on invalid input" do
    add = fn _k, v, acc -> acc + v end

    # bad_trie
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> reduce(tree, 32, 0, add) end)

    # bad fun
    assert_raise ArgumentError, fn -> reduce(new(), 32, 0, fn x -> x end) end
  end

  # Iptrie.split/3
  test "split/3 splits a trie using a list of prefixes" do
    t = @test_trie

    {t2, t3} = split(t, ["1.1.1.0/24", "1.1.1.128/25", "11-22-33-44-55-67-00-00/48"])
    assert count(t2) == 3
    assert count(t3) == 6
    assert get(t2, "1.1.1.0/24") == {"1.1.1.0/24", 1}
    assert get(t2, "1.1.1.128/25") == {"1.1.1.128/25", 3}
    assert get(t2, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 9}

    # ignores non-existing prefixesdefault value for prefix not found is nil
    {t2, t3} = split(t, ["2.2.2.2"])
    assert empty?(t2)
    assert count(t3) == 9

    # doesn't choke on empty list
    {t2, t3} = split(t, [])
    assert empty?(t2)
    assert count(t3) == 9

    # can use lpm
    {t2, t3} = split(t, ["1.1.1.1", "1.1.1.161", "11-22-33-44-55-67-11-22"], match: :lpm)
    assert count(t2) == 3
    assert count(t3) == 6
    assert get(t2, "1.1.1.0/25") == {"1.1.1.0/25", 2}
    assert get(t2, "1.1.1.128/25") == {"1.1.1.128/25", 3}
    assert get(t2, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 9}
  end

  test "split/3 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> split(tree, ["1.1.1.1"]) end)

    t = new()

    for pfx <- @bad_pfx,
        do: assert_raise(ArgumentError, fn -> split(t, [pfx]) end)

    # also complaines when arg is not a list
    assert_raise ArgumentError, fn -> split(t, "1.1.1.1") end
  end

  # Iptrie.take/3
  test "take/3 returns a new trie with only given prefixes" do
    t = @test_trie

    t2 = take(t, ["1.1.1.0/24", "1.1.1.128/25", "11-22-33-44-55-67-00-00/48"])
    assert get(t2, "1.1.1.0/24") == {"1.1.1.0/24", 1}
    assert get(t2, "1.1.1.128/25") == {"1.1.1.128/25", 3}
    assert get(t2, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 9}

    # ignores non-existing prefixesdefault value for prefix not found is nil
    assert take(t, ["2.2.2.2"]) |> empty?()

    # doesn't choke on empty list
    assert take(t, []) |> empty?()

    # can use lpm match
    t2 = take(t, ["1.1.1.1", "1.1.1.129", "11-22-33-44-55-67-88-99"], match: :lpm)
    assert get(t2, "1.1.1.0/25") == {"1.1.1.0/25", 2}
    assert get(t2, "1.1.1.128/25") == {"1.1.1.128/25", 3}
    assert get(t2, "11-22-33-44-55-67-00-00/48") == {"11-22-33-44-55-67-00-00/48", 9}
  end

  test "take/3 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> take(tree, ["1.1.1.1"]) end)

    t = new()

    for pfx <- @bad_pfx,
        do: assert_raise(ArgumentError, fn -> take(t, [pfx]) end)

    # also complaines when arg is not a list
    assert_raise ArgumentError, fn -> take(t, "1.1.1.1") end
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

  test "to_list/2 returns list prefixes of a radix tree of given type" do
    l = to_list(@test_trie, 32)
    Enum.all?(l, fn {pfx, _} -> pfx.maxlen == 32 end)

    assert to_list(@test_trie, 13) == []
  end

  test "to_list/2 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> to_list(tree, 32) end)

    # bad type's
    assert_raise ArgumentError, fn -> to_list(@test_trie, {32}) end
    assert_raise ArgumentError, fn -> to_list(@test_trie, -32) end
  end

  # Iptrie.types/1
  test "types/1 returns all types from an Iptrie" do
    assert types(@test_trie) |> Enum.sort() == [32, 48, 64, 128]
  end

  test "types/1 raises on invalid input" do
    for tree <- @bad_trees,
        do: assert_raise(ArgumentError, fn -> types(tree) end)
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

  # Iptrie.values/1
  test "values/1 returns all values of all radix trees" do
    assert values(@test_trie) |> Enum.sort() == [1, 2, 3, 4, 5, 6, 7, 8, 9]
  end

  test "values/1 raises on invalid Iptries" do
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> values(tree) end)
  end

  # Iptrie.values/2
  test "values/2 returns all values for a radix trees of given type" do
    assert values(@test_trie, 32) |> Enum.sort() == [1, 2, 3]
    assert values(@test_trie, 48) |> Enum.sort() == [6, 7]
    assert values(@test_trie, 64) |> Enum.sort() == [8, 9]
    assert values(@test_trie, 128) |> Enum.sort() == [4, 5]
    assert values(@test_trie, 15) == []
  end

  test "values/2 raises on invalid input" do
    for tree <- @bad_trees, do: assert_raise(ArgumentError, fn -> values(tree, 32) end)

    assert_raise ArgumentError, fn -> values(@test_trie, -1) end
    assert_raise ArgumentError, fn -> values(@test_trie, [32]) end
  end
end
