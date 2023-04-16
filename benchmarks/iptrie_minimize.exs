alias Iptrie
alias Pfx
alias Radix

# Compare Iptrie.minimize/2  with Iptrie.new/2
# % mix run benchmarks/iptrie_minimize.exs

defmodule Alt do
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

# min: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# new: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
# pfx: %{32 => {0, [{<<1, 1>>, true}], nil}, :__struct__ => Iptrie}
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
# Estimated total run time: 21 s
#
# Benchmarking ipt_min...
# Benchmarking ipt_new...
# Benchmarking pfx_min...
#
# Name              ips        average  deviation         median         99th %
# ipt_min          0.53         1.89 s     ±1.97%         1.87 s         1.93 s
# ipt_new          0.25         4.06 s     ±3.45%         4.06 s         4.15 s
# pfx_min         0.167         5.97 s     ±0.00%         5.97 s         5.97 s
#
# Comparison:
# ipt_min          0.53
# ipt_new          0.25 - 2.15x slower +2.17 s
# pfx_min         0.167 - 3.17x slower +4.09 s

# Conclusion:
# Iptrie.new/2 is ~2 times slower than Iptrie.new/1 |> Iptrie.minimize/1
# `-> so add minimize/2 and not new/2

keys = for x <- 0..255, y <- 0..255, z <- 24..30, do: Pfx.new("1.1.#{x}.#{y}/#{z}")
keyvalues = for k <- keys, do: {k, true}

ipt = Iptrie.new(keyvalues)

f = fn _, _ -> {:ok, true} end

ipt
|> Iptrie.minimize(f)
|> IO.inspect(label: :min)

keyvalues
|> Alt.new(f)
|> IO.inspect(label: :new)

keys
|> Pfx.minimize()
|> Enum.map(fn k -> {k, true} end)
|> Iptrie.new()
|> IO.inspect(label: :pfx)

Benchee.run(%{
  "alt_new" => fn -> Alt.new(keyvalues, f) end,
  "ipt_min" => fn -> Iptrie.new(keyvalues) |> Iptrie.minimize(f) end,
  "pfx_min" => fn -> Pfx.minimize(keys) |> Enum.map(fn k -> {k, true} end) |> Iptrie.new() end
})
