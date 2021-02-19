defmodule RadixTest do
  use ExUnit.Case
  doctest Radix, import: true

  import Radix

  # Takes a looong time, when set to 255
  @max 25
  @key_val8 (for x <- 0..@max do
               {<<x>>, <<x>>}
             end)
  @key_val16 (for x <- 0..@max, y <- 0..@max do
                {<<x, y>>, <<x, y>>}
              end)

  @key_vals @key_val8 ++ @key_val16

  @tree new(@key_vals)

  def shorter(key) do
    l = bit_size(key) - 1
    <<key::bitstring-size(l)>>
  end

  def longer(key, bit \\ 0) do
    <<key::bitstring, bit::1>>
  end

  # Radix.new/0
  test "new/0" do
    assert {0, nil, nil} = new()
  end

  # Radix.new/1
  test "new/1" do
    # bit 0 is 0 for both entries -> both go into left subtree
    # bit 7 is the first different bit -> new subtree
    t = new([{<<0>>, 0}, {<<1>>, 1}])
    assert t == {0, {7, [{<<0>>, 0}], [{<<1>>, 1}]}, nil}

    # bit 0 is different for both entries
    t = new([{<<0>>, 0}, {<<128>>, 1}])
    assert t == {0, [{<<0>>, 0}], [{<<128>>, 1}]}

    # order of k,v's does not matter
    assert @tree == new(Enum.shuffle(@key_vals))
    assert @tree == new(Enum.reverse(@key_vals))
  end

  # Radix.get/2
  test "get/2" do
    # get {k,v} pair by exact match
    t = new([{<<0>>, 0}, {<<128>>, 1}])
    assert {<<0>>, 0} == get(t, <<0>>)
    assert {<<128>>, 1} == get(t, <<128>>)

    assert nil == get(t, <<0::7>>)
    assert nil == get(t, <<0::9>>)
    assert nil == get(t, <<>>)

    # check some typical key,value pairs, more tests in set/1
    assert {<<0>>, <<0>>} = get(@tree, <<0>>)
    assert {<<@max>>, <<@max>>} = get(@tree, <<@max>>)
    assert {<<0, 0>>, <<0, 0>>} = get(@tree, <<0, 0>>)
    assert {<<@max, @max>>, <<@max, @max>>} = get(@tree, <<@max, @max>>)
  end

  # Radix.set
  test "set/2" do
    # check all key,value pairs
    check = fn {k, v}, acc -> acc and get(@tree, k) == {k, v} end
    assert Enum.reduce(@key_vals, true, check)

    # take off 1 bit from key
    check = fn {k, _v}, acc -> acc and get(@tree, shorter(k)) == nil end
    assert Enum.reduce(@key_vals, true, check)

    # add a 0-bit to key
    check = fn {k, _v}, acc -> acc and get(@tree, longer(k)) == nil end
    assert Enum.reduce(@key_vals, true, check)
  end

  test "set/3" do
    # different kind of test from set/2 since that basically uses set/3
    t = new()
    t = set(t, "*", "Douglas")
    t = set(t, "**", "Adams")
    assert t == {0, {10, [{"*", "Douglas"}], [{"**", "Adams"}]}, nil}
  end

  # Radix.del
  test "del/2" do
    t = @tree

    # check k,v exists, delete it, then check for nil
    check = fn {k, v}, acc ->
      acc = acc and get(t, k) == {k, v}
      t = del(t, k)
      acc and get(t, k) == nil
    end

    # delete individual {k,v}'s
    assert Enum.reduce(@key_vals, true, check)

    # t is empty after deleting all {k,v}'s
    assert {0, nil, nil} == Enum.reduce(@key_vals, t, fn {k, _}, t -> del(t, k) end)
  end

  # Radix.lpm
  test "lpm/2" do
    assert {<<0>>, <<0>>} == lpm(@tree, <<0>>)

    # search key is one 0-bit longer than keys in the tree
    check = fn {k, v}, acc -> acc and lpm(@tree, longer(k)) == {k, v} end
    assert Enum.reduce(@key_vals, true, check)

    # search key is one 1-bit longer than keys in the tree
    check = fn {k, v}, acc -> acc and lpm(@tree, longer(k, 1)) == {k, v} end
    assert Enum.reduce(@key_vals, true, check)
  end

  # Radix.apm
  test "apm/2" do
    # find all keys that are a prefix to the search key
    assert [{<<0>>, <<0>>}] == apm(@tree, <<0>>)
    assert [{<<0, 0>>, <<0, 0>>}, {<<0>>, <<0>>}] == apm(@tree, <<0, 0>>)

    for x <- 0..@max, y <- 0..@max do
      assert [{<<x>>, <<x>>}] == apm(@tree, <<x>>)
      assert [{<<x, y>>, <<x, y>>}, {<<x>>, <<x>>}] = apm(@tree, <<x, y>>)
    end
  end

  # Radix.rpm
  test "rpm/2" do
    for x <- 0..@max do
      # find all keys that have search key as a prefix
      result =
        for y <- 0..@max do
          {<<x, y>>, <<x, y>>}
        end

      result = [{<<x>>, <<x>>} | result]
      assert Enum.sort(result) == Enum.sort(rpm(@tree, <<x>>))
    end
  end

  # Radix.to_list
  test "to_list/1" do
    assert Enum.sort(@key_vals) == Enum.sort(to_list(@tree))
  end

  # Radix.exec
  test "exec/3" do
    keys =
      @key_vals
      |> Enum.map(fn {k, _} -> k end)
      |> Enum.sort()

    vals =
      @key_vals
      |> Enum.map(fn {_, v} -> v end)
      |> Enum.sort()

    # turn tree into list of keys
    assert keys == Enum.sort(exec(@tree, fn {k, _}, acc -> [k | acc] end, []))

    # turn tree into list of values
    assert vals == Enum.sort(exec(@tree, fn {_, v}, acc -> [v | acc] end, []))

    # turn tree into map
    mapped = exec(@tree, fn {k, v}, acc -> Map.put(acc, k, v) end, %{})
    # check all k's map to their v
    assert Enum.reduce(@key_vals, true, fn {k, v}, acc -> acc and Map.get(mapped, k) == v end)
  end

  # Radix.traverse
  test "traverse/4" do
    t =
      new([
        {<<1>>, "1"},
        {<<2>>, "2"},
        {<<3>>, "3"}
      ])

    # t = {0, {6, [{<<1>>, "1"}],
    #             {7, [{<<2>>, "2"}],
    #                 [{<<3>>, "3"}]}
    #         },
    #         nil}

    f = fn
      acc, {bit, _left, _right} -> [bit | acc]
      acc, nil -> [nil | acc]
      acc, leaf -> Enum.map(leaf, fn {_k, v} -> v end) ++ acc
    end

    # left, bit, right
    inorder = [nil, 0, "3", 7, "2", 6, "1"]
    assert inorder == traverse(t, f, [])
    assert inorder == traverse(t, f, [], :inorder)

    # bit, left, right
    preorder = [nil, "3", "2", 7, "1", 6, 0]
    assert preorder == traverse(t, f, [], :preorder)

    # left, right, bit
    postorder = [0, nil, 6, 7, "3", "2", "1"]
    assert postorder == traverse(t, f, [], :postorder)
  end
end
