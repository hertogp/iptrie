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

# defmodule Radix.Leaf do
#   @type t :: list({bitstring, term})
# end

# defmodule Radix.Node do
#   @type t :: {non_neg_integer, t | Radix.Leaf.t() | nil, t | Radix.Leaf.t() | nil}
# end

defmodule Radix do
  @moduledoc """
  A path-compressed Patricia trie with one-way branching removed.

  The radix tree (whose r is 2)  has 2 types of nodes:
  - *internal* `{bit, left, right}`, where `bit` >= 0
  - *leaf*     `[{key,value} ..]`

  where:
  - `bit` is the bit position to check in a key
  - `left` contains a subtree with keys whose `bit` is 0
  - `right` contains a subtree with keys whose `bit` is 1
  - `key` is a bitstring
  - `value` can be anything

  The keys stored below any given `internal` node or in a `leaf` node, all
  agree on the bits checked to arrive at that particular node.
  Path-compression means not all bits in a key are checked while traversing
  the tree, only those that differentiate between keys stored below the current
  `internal` node.  So a final match is needed to ensure a correct match.

  A `leaf` stores key,value-pairs in a list sorted in descending order of
  key-length and all keys in a leaf have the other, shorter keys as their
  prefix.

  Normally, the keys are bitstrings created from ip prefixes but any bitstring,
  including binaries, can be used as keys.

  ## Examples

      iex> t = new()
      ...>     |> set(<<1, 1, 1>>, "1.1.1.0/24")
      ...>     |> set(<<1, 1, 1, 0::6>>, "1.1.1.0/30")
      iex>
      iex> lpm(t, <<1, 1, 1, 255>>)
      {<<1, 1, 1>>, "1.1.1.0/24"}
      #
      iex> lpm(t, <<1, 1, 1, 3>>)
      {<<1, 1, 1, 0::6>>, "1.1.1.0/30"}

  Regular binaries work too:

      iex> t = new([{"hello", "Sir"}, {"hellooo", "there"}])
      iex> lpm(t, "helloo")
      {"hello", "Sir"}
      #
      iex> lpm(t, "hellooooooo")
      {"hellooo", "there"}
      #
      iex> lpm(t, "hello!")
      {"hello", "Sir"}
      #
      iex> lpm(t, "goodbye")
      nil

  """

  alias RadixError

  @typedoc """
  A user supplied accumulator.

  """
  @type acc :: any()

  @typedoc """
  The maximum depth to travel the `t:tree/0` before inserting a new key.

  """
  @type bitpos :: non_neg_integer()

  @typedoc """
  Any value to be stored in the radix tree.

  """
  @type value :: any()

  @typedoc """
  A key to index into the radix tree.

  """
  @type key :: bitstring()

  @typedoc """
  Key,value-pair as stored in the tree.

  """
  @type keyval :: {key(), value()}

  @typedoc """
  A radix leaf node.

  """
  @type leaf :: list(keyval) | nil

  @typedoc """
  A radix tree node.

  """
  @type tree :: {non_neg_integer, tree | leaf, tree | leaf}

  @empty {0, nil, nil}

  # Helpers

  @compile {:inline, error: 2}
  defp error(id, detail),
    do: RadixError.new(id, detail)

  # bit
  # - extract the value of a bit in a key
  # - bits beyond the key-length are considered `0`
  @spec bit(key, bitpos) :: 0 | 1
  defp bit(key, pos) when pos > bit_size(key) - 1, do: 0

  defp bit(key, pos) do
    <<_::size(pos), bit::1, _::bitstring>> = key
    bit
  end

  # follow key-path and return a leaf (which might be nil)
  # - inlining bit check doesn't really speed things up
  @spec leaf(tree | leaf, key) :: leaf
  defp leaf({bit, l, r}, key) do
    case(bit(key, bit)) do
      0 -> leaf(l, key)
      1 -> leaf(r, key)
    end
  end

  defp leaf(leaf, _key), do: leaf

  # action to take given a new, candidate key and a leaf
  #  :take   if the leaf is nil and thus free
  #  :update if the candidate key is already present in the leaf
  #  :add    if the candidate shares the leaf's common prefix
  #  :split  if the candidate does not share the leaf's common prefix
  @spec action(leaf, key) :: :take | :update | :add | :split
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
  @spec is_prefix?(key, key) :: boolean
  defp is_prefix?(k, key) when bit_size(k) > bit_size(key), do: false

  defp is_prefix?(k, key) do
    len = bit_size(k)
    <<key::bitstring-size(len), _::bitstring>> = key
    k == key
  end

  # Tree modifications

  # put
  # - inserts/updates a {key,value}-pair into the tree
  # - pos is maximum depth to travel down the tree before splitting

  # max depth exceeded, so split the tree here
  @spec put(tree | leaf, bitpos, key, value) :: tree | leaf
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
  @spec differ(leaf, key) :: bitpos
  defp differ([{k, _v} | _tail], key),
    do: diffkey(k, key, 0)

  # stop recursion once longest key is exhausted
  @spec diffkey(key, key, bitpos) :: bitpos
  defp diffkey(k, key, pos) when pos < bit_size(k) or pos < bit_size(key) do
    case bit(key, pos) == bit(k, pos) do
      true -> diffkey(k, key, pos + 1)
      false -> pos
    end
  end

  # keep pos if outside both keys
  defp diffkey(_key1, _key2, pos), do: pos

  # get key's position in the tree: {bitpos, match-type}
  @spec position(tree, key) :: bitpos
  defp position(tree, key) do
    case leaf(tree, key) do
      nil -> bit_size(key) - 1
      leaf -> differ(leaf, key)
    end
  end

  # API

  @doc """
  Return a new, empty radix tree.

  ## Example

      iex> new()
      {0, nil, nil}

  """
  @spec new :: tree
  def new, do: @empty

  @doc """
  Return a new radix tree, initialized using given list of `{k, v}`-pairs.

  ## Example

      iex> elements = [{<<1, 1>>, 16}, {<<1, 1, 1, 1>>, 32}, {<<1, 1, 0>>, 24}]
      iex> new(elements)
      {0,
        {23, [{<<1, 1, 0>>, 24}, {<<1, 1>>, 16}],
             [{<<1, 1, 1, 1>>, 32}]},
        nil
      }
  """
  @spec new(list(keyval)) :: tree
  def new(elements) when is_list(elements) do
    Enum.reduce(elements, @empty, fn {k, v}, t -> set(t, k, v) end)
  end

  @doc """
  Get the {k, v}-pair where `k` is equal to *key*.

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
  @spec get(tree, key) :: keyval | nil
  def get(t, key) do
    case leaf(t, key) do
      nil -> nil
      leaf -> List.keyfind(leaf, key, 0)
    end
  end

  @doc """
  Store `{k, v}`-pairs in the radix tree, any existing `k`'s will have their `v` replaced.

  ## Example

      iex> elements = [{<<1, 1>>, "1.1.0.0/16"}, {<<1, 1, 1, 1>>, "x/y"}]
      iex> new() |> set(elements)
      {0,
        {23, [{<<1, 1>>, "1.1.0.0/16"}],
             [{<<1, 1, 1, 1>>, "x/y"}]},
        nil
      }

  """
  @spec set(tree, list(keyval)) :: tree
  def set(tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn {k, v}, t -> set(t, k, v) end)
  end

  @doc """
  Store a `{k, v}`-pair in the radix tree, an existing `k` will have its `v` replaced.

  ## Example

      iex> elements = [{<<1, 1>>, "1.1.0.0/16"}, {<<1, 1, 1, 1>>, "x.x.x.x"}]
      iex> new(elements) |> set(<<1, 1, 1, 1>>, "1.1.1.1")
      {0,
        {23, [{<<1, 1>>, "1.1.0.0/16"}],
             [{<<1, 1, 1, 1>>, "1.1.1.1"}]},
        nil
      }

  """
  @spec set(tree, key, value) :: tree
  def set(tree, key, value), do: put(tree, position(tree, key), key, value)

  @doc """
  Delete the `{k, v}`-pair where `k` is equal to *key*.

  ## Example

      iex> elms = [{<<1,1>>, 16}, {<<1,1,0>>, 24}, {<<1,1,1,1>>, 32}]
      iex> t = new(elms)
      iex> t
      {0, {23, [{<<1, 1, 0>>, 24}, {<<1, 1>>, 16}],
               [{<<1, 1, 1, 1>>, 32}]
           },
        nil}
      #
      iex> del(t, <<1, 1, 0>>)
      {0, {23, [{<<1, 1>>, 16}],
               [{<<1, 1, 1, 1>>, 32}]
           },
        nil}


  """
  @spec del(tree | leaf, list(key) | key) :: tree
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
  Get the `{k,v}`-pair where `k` is the longest possible prefix of *key*.


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
  @spec lpm(tree | leaf, key) :: keyval | nil
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

  @doc """
  Get all `{k,v}`-pairs where `k` is a prefix of *key*.

  ## Example

      iex> elms = [{<<1, 1>>, 16}, {<<1, 1, 0>>, 24}, {<<1, 1, 0, 0>>, 32}, {<<1, 1, 1, 1>>, 32}]
      iex> t = new(elms)
      iex> apm(t, <<1, 1, 1, 1>>)
      [{<<1, 1, 1, 1>>, 32}, {<<1, 1>>, 16}]
      iex>
      iex> apm(t, <<1, 1, 0>>)
      [{<<1, 1, 0>>, 24}, {<<1, 1>>, 16}]

  """
  @spec apm(tree | leaf, key) :: list(keyval)
  def apm({b, l, r}, key) do
    case bit(key, b) do
      0 -> apm(l, key)
      1 -> apm(r, key) ++ apm(l, key)
    end
  end

  def apm(nil, _), do: []
  def apm(leaf, key), do: Enum.filter(leaf, fn {k, _} -> is_prefix?(k, key) end)

  @doc """
  Get all `{k,v}`-pairs where *key* is a prefix of `k`.

  ## Example

      iex> elements = [
      ...>  {<<1, 1>>, 16},
      ...>  {<<1, 1, 0>>, 24},
      ...>  {<<1, 1, 0, 0>>, 32},
      ...>  {<<1, 1, 1, 1>>, 32}
      ...> ]
      iex> t = new(elements)
      iex> rpm(t, <<1, 1, 0>>)
      [{<<1, 1, 0, 0>>, 32}, {<<1, 1, 0>>, 24}]
      #
      iex> rpm(t, <<1, 1, 1>>)
      [{<<1, 1, 1, 1>>, 32}]
      #
      iex> rpm(t, <<2>>)
      []
  """
  @spec rpm(tree | leaf, key) :: list(keyval)
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

  @doc """
  Return all `{k,v}`-pairs as a flat list, using inorder traversal.

  ## Example

      iex> elements = [
      ...>  {<<1, 1>>, 16},
      ...>  {<<1, 1, 0>>, 24},
      ...>  {<<1, 1, 0, 0>>, 32},
      ...>  {<<1, 1, 1, 1>>, 32}
      ...> ]
      iex> new(elements) |> to_list()
      [
        {<<1, 1, 0, 0>>, 32},
        {<<1, 1, 0>>, 24},
        {<<1, 1>>, 16},
        {<<1, 1, 1, 1>>, 32},
      ]


  """
  @spec to_list(tree) :: list(keyval)
  def to_list(tree), do: to_list(tree, [])

  defp to_list(nil, acc), do: acc
  defp to_list({_bit, l, r}, acc), do: to_list(l, acc) ++ to_list(r, [])
  defp to_list(leaf, acc), do: leaf ++ acc

  @doc """
  Execute a user supplied function on all `{k,v}`-pairs in the tree.

  # Example

      iex> t = new([
      ...>  {<<1, 1>>, "1.1"},
      ...>  {<<1, 1, 0>>, "1.1.0"},
      ...>  {<<1, 1, 0, 0>>, "1.1.0.0"},
      ...>  {<<1, 1, 1, 1>>, "1.1.1.1"}
      ...>  ])
      iex>
      iex> f = fn _key, value, acc -> [value] ++ acc end
      iex>
      iex> exec(t, f, [])
      ["1.1.1.1", "1.1", "1.1.0", "1.1.0.0"]

  """
  @spec exec(tree, (acc, key, value -> acc), acc) :: acc
  def exec(tree, fun, acc)
  def exec(nil, _f, acc), do: acc
  def exec([], _f, acc), do: acc
  def exec({_, l, r}, fun, acc), do: exec(r, fun, exec(l, fun, acc))
  def exec([{k, v} | tail], fun, acc), do: exec(tail, fun, fun.(k, v, acc))

  @doc """
  Traverse the tree in `:inorder`, `:preorder` or `:postorder`, and call *fun*
  on each radix tree node.

  *fun* should have the signatures:
  -  (`t:acc/0`, `t:tree/0`) -> `t:acc/0`
  -  (`t:acc/0`, `t:leaf/0`) -> `t:acc/0`

  and where *leaf* might be nil.

  ## Example

      iex> t = new([
      ...>  {<<1, 1>>, "1.1"},
      ...>  {<<1, 1, 0>>, "1.1.0"},
      ...>  {<<1, 1, 0, 0>>, "1.1.0.0"},
      ...>  {<<1, 1, 1, 1>>, "1.1.1.1"}
      ...>  ])
      iex>
      iex> f = fn
      ...>   (acc, {_bit, _left, _right}) -> acc
      ...>   (acc, nil) -> acc
      ...>   (acc, leaf) -> Enum.map(leaf, fn {_k, v} -> v end) ++ acc
      ...> end
      iex>
      iex> traverse([], f, t, :inorder)
      ["1.1.1.1", "1.1.0.0", "1.1.0", "1.1"]

  """
  @spec traverse(acc, (acc, tree | leaf -> acc), tree | leaf, atom) :: acc
  def traverse(acc, fun, tree, order \\ :inorder)

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

  def traverse(acc, fun, leaf, _order), do: fun.(acc, leaf)
end
