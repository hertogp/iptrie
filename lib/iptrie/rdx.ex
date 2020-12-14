defmodule Iptrie.RdxError do
  defexception [:id, :detail]

  @typedoc """
  An RdxError exception struct for signalling errors.
  """
  @type t :: %__MODULE__{id: atom, detail: String.t()}

  @spec new(atom, String.t()) :: t()
  def new(id, detail),
    do: %__MODULE__{id: id, detail: detail}

  @spec message(t()) :: String.t()
  def message(t), do: format(t.id, t.detail)

  defp format(:eaddress, address),
    do: "Bad address #{address}"

  defp format(:emask, detail),
    do: "Bad mask #{detail}"

  defp format(:multi, {v1, v2}),
    do: "Multiple reasons #{v1} -&- #{v2}"

  defp format(unknown, detail),
    do: "Bad ultra: #{inspect({unknown, detail})}"
end

defmodule Iptrie.Rdx do
  # TODO:
  # - hide functions internal to the Rdx module
  #   eg _get, _kvnew, _tree_pos
  # - rename match to something like: _leaf_action (and make it private)
  # - `all` -> returns all matches
  # - `shortest` -> returns shortest prefix match
  # - `shorter` -> all shorter matches (supernets) with option :inclusive
  # - `longer` -> all longer matches (subnets) with option :inclusive
  # - `get` -> get an exact match
  # - `set` -> set an entry (based on exact match)
  # - `exec` -> new name for traverse, runs func on nodes
  # - `visit` -> same but inside a prefix
  # - pairs -> yield key-pairs that differ only in their last bit
  #
  # - maybe split up traverse into specific order traversal functions, e.g.
  #   :inorder -> inorder(tree, ..) etc ...
  # - improve consistency in function and variable names
  #   - _get to get a leaf
  #   - get to 
  # - ipt is the tree
  # - leaf is the leaf node
  # - kvs is the list of k,v-pairs
  #
  #
  @moduledoc """
  A path-compressed Patricia trie with one-way branching removed.

  The radix tree (`r=2`)  has 2 types of nodes:
  - *internal* `{bit, left, right}`, where `bit` >= 0
  - *leaf*     `{-1, [{key,value} ..]}`

  where:
  - `bit` is the bit position to check in a key
  - `left` contains a subtree with keys whose `bit` is 0
  - `right` contains a subtree with keys whose `bit` is 1
  - `key` is a bitstring used to index into the tree
  - `value` can be anything

  The keys stored below any given `internal` node or in a `leaf` node, all
  agree on the bits checked to arrive at that particular node.
  Path-compression means not all bits in a key are checked on the way down,
  only those that differentiate between keys stored below the current
  `internal` node.  So a final match is needed to ensure a correct match.

  A `leaf` stores key,value-pairs in a list sorted in descending order of
  key-length and all keys in a leaf have the shortest key as a common prefix.
  This is how one-way branching is removed.

  Normally, the keys are bitstrings created from Ip prefixes but any bitstring,
  including binaries, can be used as keys.

  ## Examples

      iex> t = new()
      ...>     |> set({<<1::8, 1::8, 1::8>>, "1.1.1.0/24"})
      ...>     |> set({<<1::8, 1::8, 1::8, 0::6>>, "1.1.1.0/30"})
      iex>
      iex> lpm(t, <<1::8, 1::8, 1::8, 255::8>>)
      {<<1::8, 1::8, 1::8>>, "1.1.1.0/24"}
      iex>
      iex> lpm(t, <<1::8, 1::8, 1::8, 3::8>>)
      {<<1::8, 1::8, 1::8, 0::6>>, "1.1.1.0/30"}

  Regular binaries work too:

      iex> t = new([{"hallo", 5}, {"hallooo", 7}])
      iex> lpm(t, "halloo")
      {"hallo", 5}
      iex>
      iex> lpm(t, "hallooooooo")
      {"hallooo", 7}
      iex>
      iex> lpm(t, "goodbye")
      nil

  """

  alias Iptrie.RdxError

  @empty {0, nil, nil}

  # Helpers

  # - run down the tree and return the kvs of a leaf (might be nil) based on key-path
  defp get_leaf(nil, _key), do: nil

  defp get_leaf({-1, kvs}, _key), do: kvs

  defp get_leaf({bit, l, r}, key) do
    case(bit(key, bit)) do
      0 -> get_leaf(l, key)
      1 -> get_leaf(r, key)
    end
  end

  # put inserts/updates a insert/update a {key,value}-pair into the tree using
  # {pos, type}, where type denotes the type of action to take:split, :add or
  # :update

  # ran into an empty leaf, so take it
  defp put(nil, _treepos, key, val), do: kvnew({key, val})

  # follow path, insert somewhere in the left/right subtree
  defp put({bit, l, r}, {pos, type}, key, val) when pos > bit do
    case bit(key, bit) do
      0 -> {bit, put(l, {pos, type}, key, val), r}
      1 -> {bit, l, put(r, {pos, type}, key, val)}
    end
  end

  # ran into a non-empty leaf.
  defp put({-1, leaf}, {pos, type}, key, val) do
    case type do
      :split ->
        # split tree, new key decides if it goes left or right
        case bit(key, pos) do
          0 -> {pos, kvnew({key, val}), {-1, leaf}}
          1 -> {pos, {-1, leaf}, kvnew({key, val})}
        end

      :add ->
        kvnew([{key, val} | leaf])

      :update ->
        {-1, Enum.map(leaf, fn {k, v} -> if k == key, do: {k, val}, else: {k, v} end)}
    end
  end

  # pos <= bit and bit != -1, so at internal node
  # :nomatch means split the tree
  # :equal, :less, :more, :subnet, :supernet  means continue towards leaf
  defp put({bit, l, r}, {pos, type}, key, val) do
    case type do
      :split ->
        # split the tree, the new key decides new left or right leaf
        case bit(key, pos) do
          0 -> {pos, kvnew({key, val}), {bit, l, r}}
          1 -> {pos, {bit, l, r}, kvnew({key, val})}
        end

      _ ->
        # otherwise -> continue path towards leaf
        put({bit, l, r}, {bit + 1, type}, key, val)
    end
  end

  # compare two {k,v}-pairs based on their keys
  # def compare({k1, _v1}, {k2, _v2}), do: compare(k1, k2)

  # # compare two keys directly
  # def compare(key1, key2) do
  #   cond do
  #     key1 == key2 -> :eq
  #     bit_size(key1) < bit_size(key2) -> :lt
  #     bit_size(key1) > bit_size(key2) -> :gt
  #     key1 < key2 -> :lt
  #     true -> :gt
  #   end
  # end

  # bit
  # - extract the value of a bit in a key
  # - bits beyond the key-length are considered `0`
  defp bit(key, pos) when pos > bit_size(key) - 1, do: 0

  defp bit(key, pos) do
    <<_::size(pos), bit::1, _::bitstring>> = key
    bit
  end

  # diffbit
  # - find the first bit where two keys differ
  # - for two equal keys, the last bit position is returned.
  # - returns the last bitpos if one key is a shorter prefix of the other
  #   in which case they both should belong to the same leaf.
  # The bit position is used to determine where a k,v-pair is stored in the tree

  # for a k,v-list of a leaf, we only need to check the first/longest key
  defp diffbit([{k, _v} | _leaf], key), do: diffbit(0, k, key)

  defp diffbit(k, key), do: diffbit(0, k, key)

  # guards stop the recursion when longest key is exhausted
  defp diffbit(pos, k, key) when pos < bit_size(k) or pos < bit_size(key) do
    case bit(key, pos) == bit(k, pos) do
      true -> diffbit(pos + 1, k, key)
      false -> pos
    end
  end

  # keep pos if outside both keys
  defp diffbit(pos, _key1, _key2), do: pos

  # get key's position in the tree: {bitpos, match-type}
  defp tree_pos(bst, key) do
    case get_leaf(bst, key) do
      nil ->
        {bit_size(key) - 1, :nomatch}

      leaf ->
        {diffbit(leaf, key), kvmatch(leaf, key)}
    end
  end

  # kvmatch
  # - match a candidate key against the keys of a leaf, yields one of:
  # :update if the candidate key is already present in the leaf
  # :add    if the candidate shares the leaf's common prefix
  # :split  if the candidate does not share the leaf's common prefix
  # - note we run through the entire list in order to detect k1==k2
  # - TODO: we can cut short when the leaf's key is shorter than the new key
  #   1/30, 1/24, 1/16, 1/8: when checking for 1/25 and we see 1/24 we know
  #   the 1/25 key can be added and there's no point in checking further.
  defp kvmatch([], _k2), do: :add

  defp kvmatch([{k1, _v} | _], k2) when k1 == k2, do: :update

  defp kvmatch([{k1, _v} | tail], k2) do
    # expands the smallest key to match size of larget key
    # when that matches one key is a prefix of the other key
    pad1 = max(0, bit_size(k2) - bit_size(k1))
    pad2 = max(0, bit_size(k1) - bit_size(k2))

    case <<k1::bitstring, 0::size(pad1)>> == <<k2::bitstring, 0::size(pad2)>> do
      true -> kvmatch(tail, k2)
      false -> :split
    end
  end

  # create new k,v-pair list for a leaf
  # TODO: should return only the list, not the leaf
  # `-> refactor calls to this function
  defp kvnew({k, v}), do: {-1, [{k, v}]}
  defp kvnew(l) when is_list(l), do: {-1, Enum.sort(l, &kvsort/2)}

  # kvget
  # - get first k,v-pair of a leaf where `k` is a prefix of `key`
  # - list is sorted on key-length in descending order -> gets the longest match
  defp kvget([], _key), do: nil
  defp kvget([{k, _v} | tail], key) when bit_size(k) > bit_size(key), do: kvget(tail, key)
  defp kvget([{k, v} | _tail], key) when k == key, do: {k, v}

  defp kvget([{k, v} | tail], key) do
    len = bit_size(k)
    <<key::bitstring-size(len), _::bitstring>> = key

    case k == key do
      true -> {k, v}
      false -> kvget(tail, key)
    end
  end

  # helper to sort leaf k,v-pairs on bit_size(k) in descending order
  defp kvsort({k1, _v1}, {k2, _v2}) do
    cond do
      k1 == k2 -> true
      bit_size(k1) < bit_size(k2) -> false
      true -> true
    end
  end

  # API

  @spec new :: {0, nil, nil}
  def new, do: @empty

  def new(kvs) when is_list(kvs) do
    Enum.reduce(kvs, @empty, fn kv, t -> set(t, kv) end)
  end

  @doc """
  Update or insert key-value pair(s) in the iptrie, using an *exact* match.

  ## Example

      iex> elements = [{<<0::1, 1::8, 1::8>>, "1.1.0.0/16"}, {<<0::1, 1::8, 1::8, 1::8, 1::8>>, "x.x.x.x"}]
      iex> ipt = new() |> set(elements)
      {0,
        {24, {-1, [{<<0::1, 1::8, 1::8>>, "1.1.0.0/16"}]},
             {-1, [{<<0::1, 1::8, 1::8, 1::8, 1::8>>, "x.x.x.x"}]}},
        nil
      }
      iex> # fix the x's
      iex> ipt = set(ipt, {<<0::1, 1::8, 1::8, 1::8, 1::8>>, "1.1.1.1"})
      iex> ipt
      {0,
        {24, {-1, [{<<0::1, 1::8, 1::8>>, "1.1.0.0/16"}]},
             {-1, [{<<0::1, 1::8, 1::8, 1::8, 1::8>>, "1.1.1.1"}]}},
        nil
      }

  """
  def set(tree, element_or_elements)
  def set(tree, {key, val}), do: put(tree, tree_pos(tree, key), key, val)

  # for convenience: add a list of [{k,v},...] to a tree
  def set(tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn elm, t -> set(t, elm) end)
  end

  def to_list(bst), do: to_list(bst, [])
  defp to_list({_bit, l, r}, acc), do: to_list(l, acc) ++ to_list(r, [])
  defp to_list({-1, leaf}, acc), do: leaf ++ acc
  defp to_list(nil, acc), do: acc

  # get the longest prefix match for binary key
  # - follow tree path using key and get longest match from the leaf found
  # - more specific is to the right, less specific is to the left.  So:
  #   - when left won't provide a match, the right never will either
  #   - however, if the right won't match, the left might still match
  def lpm(x) when is_exception(x), do: x

  def lpm(nil, _key), do: nil

  def lpm({b, l, r}, key) do
    case bit(key, b) do
      0 ->
        lpm(l, key)

      1 ->
        case lpm(r, key) do
          nil -> lpm(l, key)
          x -> x
        end
    end
  end

  def lpm({-1, kvs}, key), do: kvget(kvs, key)

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

  @compile {:inline, error: 2}
  defp error(id, detail),
    do: RdxError.new(id, detail)
end
