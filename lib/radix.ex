defmodule RadixError do
  defexception [:id, :detail]

  @typedoc """
  An RadixError exception struct for signalling errors.
  """
  @type t :: %__MODULE__{id: atom, detail: any()}

  @spec new(atom, any()) :: t()
  def new(id, detail),
    do: %__MODULE__{id: id, detail: detail}

  @spec message(t()) :: String.t()
  def message(x) when is_tuple(x.detail) do
    x.detail
    |> Tuple.to_list()
    |> Enum.map(fn x -> "#{inspect(x)}" end)
    |> Enum.join(", ")
    |> (&"#{x.id}: args (#{&1})").()
  end

  def message(x), do: "#{x.id}: #{inspect(x.detail)}"
end

defmodule Radix do
  @moduledoc """
  A path-compressed Patricia trie with one-way branching removed.

  The radix tree (with `r=2`)  has 2 types of nodes:
  - *internal* `{bit, left, right}`, where `bit` >= 0
  - *leaf*     `[{key,value} ..]`

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
      ...>     |> set(<<1, 1, 1>>, "1.1.1.0/24")
      ...>     |> set(<<1, 1, 1, 0::6>>, "1.1.1.0/30")
      iex>
      iex> lpm(t, <<1, 1, 1, 255>>)
      {<<1, 1, 1>>, "1.1.1.0/24"}
      iex>
      iex> lpm(t, <<1, 1, 1, 3>>)
      {<<1, 1, 1, 0::6>>, "1.1.1.0/30"}

  Regular binaries work too:

      iex> t = new([{"hello", "Sir"}, {"hellooo", "there"}])
      iex> lpm(t, "helloo")
      {"hello", "Sir"}
      iex>
      iex> lpm(t, "hellooooooo")
      {"hellooo", "there"}
      iex>
      iex> lpm(t, "hello!")
      {"hello", "Sir"}
      iex>
      iex> lpm(t, "goodbye")
      nil

  """

  alias RadixError

  @empty {0, nil, nil}

  # Helpers

  @compile {:inline, error: 2}
  defp error(id, detail),
    do: RadixError.new(id, detail)

  # bit
  # - extract the value of a bit in a key
  # - bits beyond the key-length are considered `0`
  defp bit(key, pos) when pos > bit_size(key) - 1, do: 0

  defp bit(key, pos) do
    <<_::size(pos), bit::1, _::bitstring>> = key
    bit
  end

  # follow key-path and return a leaf (which might be nil)
  # - inlining bit check doesn't really speed things up
  defp leaf({bit, l, r}, key) do
    case(bit(key, bit)) do
      0 -> leaf(l, key)
      1 -> leaf(r, key)
    end
  end

  defp leaf(leaf, _key), do: leaf

  # action to take given a new, candidate key and a leaf:
  #  :take   if the leaf is nil and thus free
  #  :update if the candidate key is already present in the leaf
  #  :add    if the candidate shares the leaf's common prefix
  #  :split  if the candidate does not share the leaf's common prefix
  defp action(nil, _key), do: :take

  defp action([{k, _v} | _tail] = leaf, key) do
    pad1 = max(0, bit_size(key) - bit_size(k))
    pad2 = max(0, bit_size(k) - bit_size(key))

    case <<k::bitstring, 0::size(pad1)>> == <<key::bitstring, 0::size(pad2)>> do
      false -> :split
      true -> if List.keyfind(leaf, key, 0) == nil, do: :add, else: :update
    end
  end

  # Say whether `k` is a prefix of `key`
  defp is_prefix?(k, key) when bit_size(k) > bit_size(key), do: false

  defp is_prefix?(k, key) do
    len = bit_size(k)
    <<key::bitstring-size(len), _::bitstring>> = key
    k == key
  end

  # Tree modifications

  # put
  # - inserts/updates a {key,value}-pair into the tree
  # - pos is maximum depth to travel down the tree

  # max depth exceeded, so split the tree here
  defp put({bit, _l, _r} = node, pos, key, val) when pos < bit do
    case bit(key, pos) do
      0 -> {pos, [{key, val}], node}
      1 -> {pos, node, [{key, val}]}
    end
  end

  # insert somewhere in the left/right subtree
  defp put({bit, l, r}, pos, key, val) do
    case bit(key, bit) do
      0 -> {bit, put(l, pos, key, val), r}
      1 -> {bit, l, put(r, pos, key, val)}
    end
  end

  # ran into a leaf
  defp put(leaf, pos, key, val) do
    case action(leaf, key) do
      :take ->
        [{key, val}]

      :split ->
        # split tree, new key decides if it goes left or right
        case bit(key, pos) do
          0 -> {pos, [{key, val}], leaf}
          1 -> {pos, leaf, [{key, val}]}
        end

      :add ->
        [{key, val} | leaf] |> List.keysort(0) |> Enum.reverse()

      :update ->
        List.keyreplace(leaf, key, 0, {key, val})
    end
  end

  # differ
  # - find the first bit where two keys differ
  # - for two equal keys, the last bit position is returned.
  # - returns the last bitpos if one key is a shorter prefix of the other
  #   in which case they both should belong to the same leaf.
  # the bit position is used to determine where a k,v-pair is stored in the tree

  # a leaf, only need to check the first/longest key
  defp differ([{k, _v} | _leaf], key), do: differ(0, k, key)

  defp differ(k, key), do: differ(0, k, key)

  # stop recursion once longest key is exhausted
  defp differ(pos, k, key) when pos < bit_size(k) or pos < bit_size(key) do
    case bit(key, pos) == bit(k, pos) do
      true -> differ(pos + 1, k, key)
      false -> pos
    end
  end

  # keep pos if outside both keys
  defp differ(pos, _key1, _key2), do: pos

  # get key's position in the tree: {bitpos, match-type}
  defp position(bst, key) do
    case leaf(bst, key) do
      nil -> bit_size(key) - 1
      leaf -> differ(leaf, key)
    end
  end

  # API

  @doc """
  Return a new Iptrie.

  Optionally, a list of `{key,value}`-pairs can be passed in for initialization,
  where `key` is a bitstring.

  ## Examples

      iex> new()
      {0, nil, nil}

      iex> elements = [{<<1, 1>>, 16}, {<<1, 1, 1, 1>>, 32}, {<<1, 1, 0>>, 24}]
      iex> new(elements)
      {0,
        {23, [{<<1, 1, 0>>, 24}, {<<1, 1>>, 16}],
             [{<<1, 1, 1, 1>>, 32}]},
        nil
      }
  """
  @spec new :: {0, nil, nil}
  def new, do: @empty

  def new(kvs) when is_list(kvs) do
    Enum.reduce(kvs, @empty, fn {k, v}, t -> set(t, k, v) end)
  end

  @doc """
  Get a {k,v}-pair for search key, using an *exact* match, or return nil.

  ## Example

      iex> elements = [{<<1, 1>>, 16}, {<<1, 1, 1>>, 24}, {<<1, 1, 1, 1>>, 32}]
      iex> ipt = new(elements)
      iex> get(ipt, <<1, 1, 1>>)
      {<<1, 1, 1>>, 24}
      iex> get(ipt, <<1, 1>>)
      {<<1, 1>>, 16}
      iex> get(ipt, <<1, 1, 0::1>>)
      nil

  """
  @spec get(any, bitstring()) :: {bitstring(), term} | nil
  def get(t, key) do
    case leaf(t, key) do
      nil -> nil
      leaf -> List.keyfind(leaf, key, 0)
    end
  end

  @doc """
  Update or insert key-value pair(s) in the iptrie, using an *exact* match.

  ## Example

      iex> elements = [{<<1, 1>>, "1.1.0.0/16"}, {<<1, 1, 1, 1>>, "x.x.x.x"}]
      iex> ipt = new(elements)
      iex> # fix the x's
      iex> ipt = set(ipt, <<1, 1, 1, 1>>, "1.1.1.1")
      iex> ipt
      {0,
        {23, [{<<1, 1>>, "1.1.0.0/16"}],
             [{<<1, 1, 1, 1>>, "1.1.1.1"}]},
        nil
      }

  """
  def set(tree, key, val), do: put(tree, position(tree, key), key, val)

  # for convenience: add a list of [{k,v},...] to a tree
  def set(tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn {k, v}, t -> set(t, k, v) end)
  end

  @doc """
  Delete a `{key, value}`-pair for given `key`.

  Uses an exact match.

  ## Examples

      iex> elms = [{<<1,1>>, 16}, {<<1,1,0>>, 24}, {<<1,1,1,1>>, 32}]
      iex> t = new(elms)
      iex> t
      {0, {23, [{<<1, 1, 0>>, 24}, {<<1, 1>>, 16}],
               [{<<1, 1, 1, 1>>, 32}]
           },
        nil}
      iex>
      iex> del(t, <<1, 1, 0>>)
      {0, {23, [{<<1, 1>>, 16}],
               [{<<1, 1, 1, 1>>, 32}]
           },
        nil}
      iex>
      iex> del(t, <<1, 1, 0>>) |> del(<<1, 1>>)
      {0, [{<<1, 1, 1, 1>>, 32}],
          nil}
      iex>
      iex> del(t, <<1, 1, 0>>) |> del(<<1, 1>>) |> del(<<1, 1, 1, 1>>)
      {0, nil, nil}


  """
  def del(tree, keys) when is_list(keys),
    do: Enum.reduce(keys, tree, fn k, t -> del(t, k) end)

  def del({bit, l, r}, key) do
    case bit(key, bit) do
      0 -> del({bit, del(l, key), r})
      1 -> del({bit, l, del(r, key)})
    end
  end

  # key wasn't in the tree
  def del(nil, _key), do: nil

  # key leads to leaf
  def del(leaf, key) do
    case List.keydelete(leaf, key, 0) do
      [] -> nil
      leaf -> leaf
    end
  end

  # always keep the root, eliminate empty nodes and promote half-empty nodes
  defp del({0, l, r}), do: {0, l, r}
  defp del({_, nil, nil}), do: nil
  defp del({_, l, nil}), do: l
  defp del({_, nil, r}), do: r
  defp del({bit, l, r}), do: {bit, l, r}

  # get the longest prefix match for binary key
  # - follow tree path using key and get longest match from the leaf found
  # - more specific is to the right, less specific is to the left.  So:
  #   - when left won't provide a match, the right never will either
  #   - however, if the right won't match, the left might still match
  @doc """
  Longest prefix match for given key, returns either nil of {k,v}-pair.


  ## Example

      iex> elms = [{<<1, 1>>, 16}, {<<1, 1, 0>>, 24}, {<<1, 1, 0, 0::1>>, 25}]
      iex> t = new(elms)
      iex> lpm(t, <<1, 1, 0, 127>>)
      {<<1, 1, 0, 0::1>>, 25}
      iex> lpm(t, <<1, 1, 0, 128>>)
      {<<1, 1, 0>>, 24}
      iex> lpm(t, <<1, 1, 1, 1>>)
      {<<1, 1>>, 16}

  """
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

  def lpm(nil, _key), do: nil
  def lpm(leaf, key), do: Enum.find(leaf, fn {k, _} -> is_prefix?(k, key) end)
  # def lpm(leaf, key), do: llpm(leaf, key)

  @doc """
  Return all prefix matches for given key.

  ## Example

      iex> elms = [{<<1, 1>>, 16}, {<<1, 1, 0>>, 24}, {<<1, 1, 0, 0>>, 32}, {<<1, 1, 1, 1>>, 32}]
      iex> t = new(elms)
      iex> apm(t, <<1, 1, 1, 1>>)
      [{<<1, 1, 1, 1>>, 32}, {<<1, 1>>, 16}]
      iex>
      iex> apm(t, <<1, 1, 0>>)
      [{<<1, 1, 0>>, 24}, {<<1, 1>>, 16}]

  """
  def apm({b, l, r}, key) do
    case bit(key, b) do
      0 -> apm(l, key)
      1 -> apm(r, key) ++ apm(l, key)
    end
  end

  def apm(nil, _), do: []
  def apm(leaf, key), do: Enum.filter(leaf, fn {k, _} -> is_prefix?(k, key) end)

  @doc """
  Return all reversed prefix matches.

  This returns all `{k,v}`-pairs where search `key` is a prefix of `k`

  ## Example

      iex> elms = [{<<1, 1>>, 16}, {<<1, 1, 0>>, 24}, {<<1, 1, 0, 0>>, 32}, {<<1, 1, 1, 1>>, 32}]
      iex> t = new(elms)
      iex> rpm(t, <<1, 1, 0>>)
      [{<<1, 1, 0, 0>>, 32}, {<<1, 1, 0>>, 24}]
      iex>
      iex> rpm(t, <<1, 1, 1>>)
      [{<<1, 1, 1, 1>>, 32}]
      iex>
      iex> rpm(t, <<2>>)
      []
  """
  def rpm({b, l, r}, key) when bit_size(key) < b do
    rpm(r, key) ++ rpm(l, key)
  end

  def rpm({b, l, r}, key) do
    case bit(key, b) do
      0 -> rpm(l, key)
      1 -> rpm(r, key) ++ rpm(l, key)
    end
  end

  def rpm(nil, _), do: []
  def rpm(leaf, key), do: Enum.filter(leaf, fn {k, _} -> is_prefix?(key, k) end)
  # TRAVERSALs

  def to_list(bst), do: to_list(bst, [])
  defp to_list(nil, acc), do: acc
  defp to_list({_bit, l, r}, acc), do: to_list(l, acc) ++ to_list(r, [])
  defp to_list(leaf, acc), do: leaf ++ acc

  @doc """
  Traverse the tree in `order`, one of (`:inorder`, `:preorder` or
  `:postorder`), and run function f on each node.  Function f should have the
  signatures:

  -  `(acc, {bit, l, r}) :: acc`
  -  `(acc, {-1, leaf}) :: acc`
  -  `(acc, nil) :: acc`

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

  # def traverse(acc, fun, nil, _order), do: fun.(acc, nil)
  def traverse(acc, fun, leaf, _order), do: fun.(acc, leaf)
end
