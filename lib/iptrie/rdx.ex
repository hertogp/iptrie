defmodule Iptrie.RdxError do
  defexception [:id, :detail]

  @type t :: %__MODULE__{id: Atom.t(), detail: String.t()}

  def new(id, detail),
    do: %__MODULE__{id: id, detail: detail}

  def message(x), do: format(x.id, x.detail)

  def format(:eaddress, address),
    do: "Bad address #{address}"

  def format(:emask, detail),
    do: "Bad mask #{detail}"

  def format(:multi, {v1, v2}),
    do: "Multiple reasons #{v1} -&- #{v2}"

  def format(unknown, detail),
    do: "Bad ultra: #{inspect({unknown, detail})}"
end

defmodule Iptrie.Rdx do
  # TODO:
  # - all API-functions should yield either an :ok or an :error tuple
  #   alternative: yield a value or :error-tuple
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
  `Iptrie.Rdx` provides a path-compressed Patricia trie with one-way branching removed.

  The radix tree has 2 types of nodes:
  - *internal* `{bit, left, right}`, where `bit` >= 0
  - *leaf*     `{-1, [{key,value} ..]}`

  where:
  - `bit` is the bit position to check in a key
  - `left` contains a subtree with keys whose `bit` is 0
  - `right` contains a subtree with keys whose `bit` is 1
  - `key` is a bitstring used to index into the tree
  - `value` can be anything

  The keys stored below any given internal node, or stored at a leaf, all
  agree on the bits checked to arrive at that particular node.  A leaf stores
  key,value-pairs in descending order of key-length and all keys in a leaf have
  the shortest key as a common prefix.

  Normally, the keys are bitstrings created from Ip prefixes, but they need not
  be.  The `Iptrie` module Uses `Iptrie.Pfx` to convert prefixes to/from keys.

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

  Keys donot have to be bitstrings, binaries work too:

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
  def get(nil, _key), do: nil

  def get({-1, kvs}, _key), do: kvs

  def get({bit, l, r}, key) do
    case(bit(key, bit)) do
      0 -> get(l, key)
      1 -> get(r, key)
    end
  end

  # put inserts/updates a insert/update a {key,value}-pair into the tree using
  # {pos, type}, where type denotes the type of action to take:split, :add or
  # :update

  # ran into an empty leaf, so take it
  def put(nil, _treepos, key, val), do: kvnew({key, val})

  # follow path, insert somewhere in the left/right subtree
  def put({bit, l, r}, {pos, type}, key, val) when pos > bit do
    case bit(key, bit) do
      0 -> {bit, put(l, {pos, type}, key, val), r}
      1 -> {bit, l, put(r, {pos, type}, key, val)}
    end
  end

  # ran into a non-empty leaf.
  def put({-1, leaf}, {pos, type}, key, val) do
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
  def put({bit, l, r}, {pos, type}, key, val) do
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

  @doc """
  Compare two keys and return one of `:eq`, `:lt` or `:gt`.

  Used to sort a list of {k,v}-pairs in descending key-length order.
  """

  # compare two {k,v}-pairs based on their keys
  def compare({k1, _v1}, {k2, _v2}), do: compare(k1, k2)

  # compare two keys directly
  def compare(key1, key2) do
    cond do
      key1 == key2 -> :eq
      bit_size(key1) < bit_size(key2) -> :lt
      bit_size(key1) > bit_size(key2) -> :gt
      key1 < key2 -> :lt
      true -> :gt
    end
  end

  @doc """
  Get the value of a bit in a given key.

  Bits beyond the length of the key are considered to be 0.

  """
  def bit(key, pos) when pos > bit_size(key) - 1, do: 0

  def bit(key, pos) do
    <<_::size(pos), bit::1, _::bitstring>> = key
    bit
  end

  @doc """
  Find the first bit where two keys differ

  For two equal keys, the last bit position is returned.
  In case one key is a shorter prefix of the other, the last bit position of
  the longest key is returned.
  """
  # easily get diffbit for k,v-pair and a given key.
  def diffbit([{k, _v} | _leaf], key), do: diffbit(0, k, key)

  def diffbit(k, key), do: diffbit(0, k, key)

  # guards stop the recursion when longest key is exhausted
  def diffbit(pos, k, key) when pos < bit_size(k) or pos < bit_size(key) do
    case bit(key, pos) == bit(k, pos) do
      true -> diffbit(pos + 1, k, key)
      false -> pos
    end
  end

  # keep pos if outside both keys
  def diffbit(pos, _key1, _key2), do: pos

  @doc """
  Match a candidate key to the keys of a leaf.  If the candidate does not share
  a common prefix with the longest key in the leaf, a new leaf must be created.
  Otherwise, if the key is nog yet present it can be added or the leaf updated
  if the candidate already exists in the leaf.
  """
  def match([], _k2), do: :add

  def match([{k1, _v} | _], k2) when k1 == k2, do: :update

  def match([{k1, _v} | tail], k2) do
    pad1 = max(0, bit_size(k2) - bit_size(k1))
    pad2 = max(0, bit_size(k1) - bit_size(k2))

    case <<k1::bitstring, 0::size(pad1)>> == <<k2::bitstring, 0::size(pad2)>> do
      true -> match(tail, k2)
      false -> :split
    end
  end

  # get key's position in the tree: {bitpos, match-type}
  def tree_pos(bst, key) do
    case get(bst, key) do
      nil ->
        {bit_size(key) - 1, :nomatch}

      leaf ->
        {diffbit(leaf, key), match(leaf, key)}
    end
  end

  def kvnew({k, v}), do: {-1, [{k, v}]}
  def kvnew(l) when is_list(l), do: {-1, Enum.sort(l, {:desc, Iptrie.Rdx})}

  @doc """
  Get the first k,v-pair that matches as a prefix of `key` from a list of
  k,v-pairs.

  If the list is sorted on key-length in descending order, the longest match
  will be returned.

      iex> kv_list = [{"11000", 5}, {"110", 3}]
      iex>
      iex> kvget(kv_list, "1100")
      ...> {"110", 3}
      iex>
      iex> kvget(kv_list, "110000000")
      ...> {"11000", 5}
  """
  def kvget([], _key), do: nil
  def kvget([{k, _v} | tail], key) when bit_size(k) > bit_size(key), do: kvget(tail, key)
  def kvget([{k, v} | _tail], key) when k == key, do: {k, v}

  def kvget([{k, v} | tail], key) do
    len = bit_size(k)
    <<key::bitstring-size(len), _::bitstring>> = key

    case k == key do
      true -> {k, v}
      false -> kvget(tail, key)
    end
  end

  # API

  @spec new :: {0, nil, nil}
  def new, do: @empty

  def new(kvs) when is_list(kvs) do
    Enum.reduce(kvs, @empty, fn kv, t -> set(t, kv) end)
  end

  @doc """
  Update or insert key-value pair(s) in the iptrie.

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
