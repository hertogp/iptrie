alias Iptrie
alias Pfx
alias Radix

# Compare Iptrie.minimize/2  with Iptrie.new/2
# % mix run benchmarks/iptrie_minimize.exs

defmodule Alt do
  # minimal trie by sorting input on prefix length (descending)
  # and do conditional insert in the trie.
  def new(elements, fun) when is_function(fun, 2) do
    p = fn
      {_p0, _p1, v1, _p2, v2} -> fun.(v1, v2)
      {_p0, _v0, _p1, v1, _p2, v2} -> fun.(v1, v2)
    end

    elements
    |> Enum.sort_by(fn {k, _} -> k end, {:desc, Pfx})
    |> Enum.reduce(Iptrie.new(), fn {pfx, val}, acc ->
      with {k, v} <- Iptrie.lookup(acc, pfx),
           {:ok, retval} <- fun.(v, val) do
        Iptrie.put(acc, k, retval)
      else
        nil -> Iptrie.put(acc, pfx, val)
      end
    end)
    |> Iptrie.prune(p, recurse: true)
  end
end

defmodule Walk do
  # minimize a trie by walking the radix tree and dropping
  # more specifics in a leaf by value.
  # internal node
  def walkp(acc, fun, {_bit, l, r}) do
    acc
    |> walkp(fun, l)
    |> walkp(fun, r)
  end

  def walkp(acc, fun, [{_, _} | _] = leaf) do
    fun.(acc, leaf)
  end

  def walkp(acc, _fun, nil),
    do: acc

  def walkp(_acc, _fun, badnode),
    do: raise("bad node, got #{inspect(badnode, limit: 3)}")

  def mini(trie) do
    p = fn
      {_p0, _p1, v1, _p2, v2} -> if v1 == v2, do: {:ok, v1}
      {_p0, _v0, _p1, v1, _p2, v2} -> if v1 == v2, do: {:ok, v1}
    end

    f = fn acc, leaf ->
      leaf
      |> Enum.reverse()
      |> Enum.reduce(acc, fn {k, v}, acc ->
        with {_, v2} <- Radix.lookup(acc, k) do
          if v == v2,
            do: acc,
            else: Radix.put(acc, k, v)
        else
          nil -> Radix.put(acc, k, v)
        end
      end)
    end

    trie
    |> Iptrie.types()
    |> Enum.reduce(Iptrie.new(), fn type, acc ->
      trie
      |> Iptrie.radix(type)
      |> then(fn radix -> walkp(Radix.new(), f, radix) end)
      |> then(fn radix -> Map.put(acc, type, radix) end)
    end)
    |> Iptrie.prune(p, recurse: true)
  end

  def minimize(trie) do
    f = fn
      trie, {_, _, _} ->
        trie

      trie, leaf ->
        leaf
        |> Enum.reverse()
        |> Enum.uniq_by(fn {_, v} -> v end)
        |> Enum.reduce(trie, fn {k, v}, acc ->
          with {_, v2} <- Radix.lookup(acc, k) do
            if v == v2,
              do: acc,
              else: Radix.put(acc, k, v)
          else
            nil -> Radix.put(acc, k, v)
          end
        end)
    end

    p = fn
      {_p0, _p1, v1, _p2, v2} -> if v1 == v2, do: {:ok, v1}
      {_p0, _v0, _p1, v1, _p2, v2} -> if v1 == v2, do: {:ok, v1}
    end

    trie
    |> Iptrie.types()
    |> Enum.reduce(Iptrie.new(), fn type, acc ->
      trie
      |> Iptrie.radix(type)
      |> Radix.walk(Radix.new(), f)
      |> then(fn radix -> Map.put(acc, type, radix) end)
    end)
    |> Iptrie.prune(p, recurse: true)
  end
end

# defmodule Original do
#   @spec minimize(t, function) :: t
#   def minimize(trie, fun) when is_function(fun, 2) do
#     do_prune = fn
#       {_p0, _p1, v1, _p2, v2} -> fun.(v1, v2)
#       {_p0, _v0, _p1, _v1, _p2, _v2} -> nil
#     end
#
#     trie
#     |> prune(do_prune, recurse: true)
#     |> to_list()
#     |> Enum.sort_by(fn {k, _} -> k end, {:desc, Pfx})
#     |> Enum.reduce(new(), fn {pfx, val}, acc ->
#       with {k, v} <- lookup(acc, pfx),
#            {:ok, retval} <- fun.(v, val) do
#         put(acc, k, retval)
#       else
#         nil -> put(acc, pfx, val)
#       end
#     end)
#   end
#
#   def minimize(_trie, fun),
#     do: raise(arg_err(:bad_fun, {fun, 2}))
#
#   def minimize(trie, _fun),
#     do: raise(arg_err(:bad_trie, trie))
# end

# original_count: 131056
# ets_size: 3079179
# heap_size: 1636920
# min: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# heap_size: 20
# new: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# ets_size: 20
# pfx: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# ets_size: 20
# walk: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# ets_size: 20
# walk2: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# ets_size: 20
# Operating System: Linux
# CPU Information: Intel(R) Core(TM) i3-4010U CPU @ 1.70GHz
# Number of Available Cores: 4
# Available memory: 7.69 GB
# Elixir 1.14.2
# Erlang 25.1.2
#
# Benchmark suite executing with the following configuration:
# warmup: 2 s
# time: 5 s
# memory time: 0 ns
# parallel: 1
# inputs: none specified
# Estimated total run time: 42 s
#
# Benchmarking alt_new...
# Benchmarking ipt_min...
# Benchmarking pfx_min...
# Benchmarking pfx_red...
# Benchmarking wlk_min...
# Benchmarking wlk_mini...
#
# Name               ips        average  deviation         median         99th %
# wlk_mini          0.29         3.47 s     ±2.53%         3.47 s         3.53 s
# wlk_min           0.28         3.56 s     ±2.89%         3.56 s         3.64 s
# ipt_min           0.27         3.67 s     ±0.30%         3.67 s         3.68 s
# alt_new          0.128         7.81 s     ±0.00%         7.81 s         7.81 s
# pfx_red         0.0827        12.09 s     ±0.00%        12.09 s        12.09 s
# pfx_min         0.0819        12.20 s     ±0.00%        12.20 s        12.20 s
#
# Comparison:
# wlk_mini          0.29
# wlk_min           0.28 - 1.03x slower +0.0983 s
# ipt_min           0.27 - 1.06x slower +0.20 s
# alt_new          0.128 - 2.25x slower +4.34 s
# pfx_red         0.0827 - 3.49x slower +8.63 s
# pfx_min         0.0819 - 3.52x slower +8.74 s

# Conclusion:
# Not using Enum.uniq_by to remove more specifics before conditionally
# reinserting them in the radix tree, does not seem to gain speed, while
# allowing correct summarization of statistic values.

max = 255
keys = for x <- 0..max, y <- 0..max, z <- 20..32, do: Pfx.new("1.1.#{x}.#{y}/#{z}")
keyvalues = for k <- keys, do: {k, true}

ipt = Iptrie.new(keyvalues)

f = fn _, _ -> {:ok, true} end

# check validity of results
IO.inspect(Iptrie.count(ipt), label: :original_count)
IO.inspect(:erlang.external_size(ipt), label: :ets_size)
IO.inspect(:erts_debug.size(ipt), label: :heap_size)

ipt
|> Iptrie.minimize(f)
|> IO.inspect(label: :min)
|> then(fn t -> IO.inspect(:erts_debug.size(t), label: :heap_size) end)

keyvalues
|> Alt.new(f)
|> IO.inspect(label: :new)
|> then(fn t -> IO.inspect(:erts_debug.size(t), label: :ets_size) end)

keys
|> Pfx.minimize()
|> Enum.map(fn k -> {k, true} end)
|> Iptrie.new()
|> IO.inspect(label: :pfx)
|> then(fn t -> IO.inspect(:erts_debug.size(t), label: :ets_size) end)

ipt
|> Walk.minimize()
|> IO.inspect(label: :walk)
|> then(fn t -> IO.inspect(:erts_debug.size(t), label: :ets_size) end)

ipt
|> Walk.mini()
|> IO.inspect(label: :walk2)
|> then(fn t -> IO.inspect(:erts_debug.size(t), label: :ets_size) end)

Benchee.run(%{
  "alt_new" => fn -> Alt.new(keyvalues, f) end,
  "ipt_min" => fn -> Iptrie.new(keyvalues) |> Iptrie.minimize(f) end,
  "pfx_min" => fn -> Pfx.minimize(keys) |> Enum.map(fn k -> {k, true} end) |> Iptrie.new() end,
  "pfx_red" => fn ->
    Pfx.minimize(keys) |> Enum.reduce(Iptrie.new(), fn k, acc -> Iptrie.put(acc, k, true) end)
  end,
  "wlk_min" => fn -> Iptrie.new(keyvalues) |> Walk.minimize() end,
  "wlk_mini" => fn -> Iptrie.new(keyvalues) |> Walk.mini() end
})
