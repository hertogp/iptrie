defmodule Iptrie do
  @moduledoc """
  `Iptrie` Ip lookup table using longest prefix match.

  """
  alias Iptrie.Key
  alias Iptrie.Dot

  @empty {0, nil, nil}

  # Tree
  # - node {bit >= 0, l, r}, where l and/or r might be nil
  # - leaf {-1, [{k,v}, ..]}

  # HELPERS

  def ascii(key), do: Iptrie.Key.to_ascii(key) |> Iptrie.Key.ok()

  # get key's position in the tree: {bitpos, match-type}
  def tree_pos(bst, key) do
    case get(bst, key) do
      nil -> {bit_size(key) - 1, :nomatch}
      leaf -> {bitdiff(leaf, key), kvmatch(leaf, key)}
    end
  end

  def bitdiff([{k, _v} | _leaf], key), do: Key.diffbit(k, key)

  # match type for key relative to a leaf's keys (:nomatch, :equal, :more or :less)
  # def kvmatch([], _key), do: :nomatch

  # def kvmatch([{k, _} | tail], key) do
  #   case Key.match(key, k) do
  #     :nomatch -> kvmatch(tail, key)
  #     result -> result
  #   end
  # end

  def kvmatch([], _key), do: :split

  def kvmatch(kv, key) do
    matches = IO.inspect(Enum.map(kv, fn {k, _v} -> Key.match(key, k) end), label: "matches")

    cond do
      :equal in matches -> :update
      :more in matches -> :add
      :less in matches -> :add
      :supernet in matches -> :split
      :subnet in matches -> :split
      :nomatch in matches -> :split
    end
  end

  # API
  # TODO:
  # - returning {:error, reason} feels wrong for tree operations ...
  # - adding supernets *after* more specifics -> yields wrong lookups when
  #   subnets in the upper half of the supernet exist(ed) in the tree.

  @spec new :: {0, nil, nil}
  def new, do: @empty

  # run down the tree and return leaf (might be nil) based on key-path
  def get(nil, _key), do: nil

  def get({-1, leaf}, _key), do: leaf

  def get({bit, l, r}, key) do
    case(Key.bit(key, bit)) do
      0 -> get(l, key)
      1 -> get(r, key)
    end
  end

  # PUT:
  # insert/update a {key,value}-pair into the tree
  # - {pos, type}, type = :equal, :more, :less, :nomatch

  # ran into an empty leaf, so take it
  def put(nil, _treepos, key, val), do: newleaf({key, val})

  # follow treepath, insert somewhere left or right
  def put({bit, l, r}, {pos, type}, key, val) when pos > bit do
    case Key.bit(key, bit) do
      0 -> {bit, put(l, {pos, type}, key, val), r}
      1 -> {bit, l, put(r, {pos, type}, key, val)}
    end
  end

  # we ran into a non-empty leaf.
  # - split if there was :nomatch or key is a :supernet or :subnet
  # - update leaf if key :equal (leaf has key)
  # - add to leaf if :more or :less specific (same network address)
  def put({-1, leaf}, {pos, type}, key, val) do
    IO.inspect("pos: #{pos}, type: #{type}", label: "LEAF")

    case type do
      :split ->
        # split tree, new key decides if it goes left or right
        case Key.bit(key, pos) do
          0 -> {pos, newleaf({key, val}), {-1, leaf}}
          1 -> {pos, {-1, leaf}, newleaf({key, val})}
        end

      :add ->
        newleaf([{key, val} | leaf])

      :update ->
        {-1, Enum.map(leaf, fn {k, v} -> if k == key, do: {k, val}, else: {k, v} end)}

        # ====#
        # :nomatch ->
        #   # split tree, new key decides if it goes left or right
        #   case Key.bit(key, pos) do
        #     0 -> {pos, newleaf({key, val}), {-1, leaf}}
        #     1 -> {pos, {-1, leaf}, newleaf({key, val})}
        #   end

        # :equal ->
        #   # update the existing key's value in leaf
        #   {-1, Enum.map(leaf, fn {k, v} -> if k == key, do: {k, val}, else: {k, v} end)}

        # :less ->
        #   # less specific, same network address
        #   # {-1, Enum.sort([{key, val} | leaf], {:desc, Iptrie.Key})}
        #   newleaf([{key, val} | leaf])

        # :more ->
        #   # more specific, same network address
        #   newleaf([{key, val} | leaf])

        # :subnet ->
        #   # split tree, new key decides if it goes left or right
        #   case Key.bit(key, pos) do
        #     # 0 -> {pos, {-1, [{key, val}]}, {-1, leaf}}
        #     # 1 -> {pos, {-1, leaf}, {-1, [{key, val}]}}
        #     0 -> {pos, newleaf({key, val}), {-1, leaf}}
        #     1 -> {pos, {-1, leaf}, newleaf({key, val})}
        #   end

        # :supernet ->
        #   # split tree, new key decides if it goes left or right
        #   case Key.bit(key, pos) do
        #     # 0 -> {pos, {-1, [{key, val}]}, {-1, leaf}}
        #     # 1 -> {pos, {-1, leaf}, {-1, [{key, val}]}}
        #     0 -> {pos, newleaf({key, val}), {-1, leaf}}
        #     1 -> {pos, {-1, leaf}, newleaf({key, val})}
        #   end
    end
  end

  # pos >= bit and bit != 1, so at internal node
  # :nomatch means split the tree
  # :equal, :less, :more, :subnet, :supernet  means continue towards leaf
  def put({bit, l, r}, {pos, type}, key, val) do
    IO.inspect("bit #{bit}, pos: #{pos}, type: #{type}", label: "NODE")

    case type do
      :split ->
        # split the tree, the new key decides new left or right leaf
        case Key.bit(key, pos) do
          0 -> {pos, newleaf({key, val}), {bit, l, r}}
          1 -> {pos, {bit, l, r}, newleaf({key, val})}
        end

      _ ->
        # otherwise -> continue path towards leaf
        put({bit, l, r}, {bit + 1, type}, key, val)

        # ==#
        # :nomatch ->
        #   # split the tree, the new key decides new left or right leaf
        #   case Key.bit(key, pos) do
        #     0 -> {pos, newleaf({key, val}), {bit, l, r}}
        #     1 -> {pos, {bit, l, r}, newleaf({key, val})}
        #   end

        # _ ->
        #   # otherwise -> continue path towards leaf
        #   put({bit, l, r}, {bit + 1, type}, key, val)
    end
  end

  # create new leaf
  def newleaf(nil), do: {-1, nil}
  def newleaf([]), do: {-1, nil}
  def newleaf({k, v}), do: {-1, [{k, v}]}
  def newleaf(l) when is_list(l), do: {-1, Enum.sort(l, {:desc, Iptrie.Key})}

  def to_list(bst), do: to_list(bst, [])
  defp to_list({_bit, l, r}, acc), do: to_list(l, acc) ++ to_list(r, [])
  defp to_list({-1, leaf}, acc), do: leaf ++ acc
  defp to_list(nil, acc), do: acc

  def add(bst, key, val) do
    case Key.to_key(key) do
      {:ok, key} -> put(bst, tree_pos(bst, key), key, val)
      {:error, reason} -> {:error, reason}
    end
  end

  def lookup(bst, key) do
    case Key.to_key(key) do
      {:ok, key} -> lpm(bst, key)
      {:error, reason} -> {:error, reason}
    end
  end

  # key satisfies k if it is equal to or more specific than k or lies in k
  def satisfies?(key, k) do
    case Key.match(key, k) do
      :equal -> true
      :more -> true
      :subnet -> true
      _ -> false
    end
  end

  # get the longest prefix match for binary key
  def lpm({_, _, _} = tree, key) do
    case get(tree, key) do
      nil -> nil
      leaf -> Enum.find(leaf, nil, fn {k, _} -> satisfies?(key, k) end)
    end
  end

  def dot(bst, fname) do
    File.write(fname, Dot.dotify(bst))
    bst
  end

  # TRAVERSALs

  @doc """
  Traverse the tree in `order`, one of (:inorder, :preorder, :postorder), and
  run function f on each node.  Function f should have the signatures:
    f :: (acc, {bit, l, r}) -> acc
    f :: (acc, {-1, leaf}) -> acc
    f :: (acc, nil) -> acc

  """
  def traverse(acc, f, node, order \\ :inorder)

  def traverse(acc, fun, {bit, l, r}, order) do
    case order do
      :inorder ->
        acc
        |> traverse(fun, l, order)
        |> fun.({bit, l, r})
        |> traverse(fun, r, order)

      :preorder ->
        acc
        |> fun.({bit, l, r})
        |> traverse(fun, l, order)
        |> traverse(fun, r, order)

      :postorder ->
        acc
        |> traverse(fun, l, order)
        |> traverse(fun, r, order)
        |> fun.({bit, l, r})
    end
  end

  def traverse(acc, fun, nil, _order), do: fun.(acc, nil)
  def traverse(acc, fun, {-1, leaf}, _order), do: fun.(acc, leaf)
end
