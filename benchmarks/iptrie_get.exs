alias Iptrie
alias Pfx
alias Radix

# Compare Iptrie.get vs Radix.get vs Map.get
# % mix run benchmarks/iptrie_get.exs

# Name              ips        average  deviation         median         99th %
# map_get       18.34 M       54.53 ns ±85299.67%           0 ns           0 ns
# rdx_get        5.86 M      170.53 ns ±35812.22%           0 ns         645 ns
# ipt_get        3.41 M      292.92 ns ±15328.43%         142 ns        1443 ns

# Comparison: 
# map_get       18.34 M
# rdx_get        5.86 M - 3.13x slower +116.00 ns
# ipt_get        3.41 M - 5.37x slower +238.39 ns

# On a good day ..., but seems impossible since ipt_get uses rdx_get
# Name              ips        average  deviation         median         99th %
# map_get       19.79 M       50.53 ns ±90992.89%           0 ns           0 ns
# ipt_get        7.15 M      139.93 ns ±32375.58%           0 ns         780 ns
# rdx_get        7.00 M      142.82 ns ±30188.20%           0 ns         193 ns

# Comparison: 
# map_get       19.79 M
# ipt_get        7.15 M - 2.77x slower +89.40 ns
# rdx_get        7.00 M - 2.83x slower +92.29 ns

keyvalues = for x <- 0..255, y <- 0..255, do: {Pfx.new(<<x, y>>, 16), <<x, y>>}

ipt = Iptrie.new(keyvalues)
rdx = Iptrie.radix(ipt, 16)
map = Enum.reduce(keyvalues, %{}, fn {k, v}, acc -> Map.put(acc, k.bits, {k.bits, v}) end)

x = :rand.uniform(255)
y = :rand.uniform(255)
pfx = Pfx.new(<<x, y>>, 16)
IO.inspect(Radix.get(rdx, pfx.bits), label: :radix_get)
IO.inspect(Iptrie.get(ipt, pfx), label: :iptrie_get)
IO.inspect(Map.get(map, pfx.bits), label: :map_get)

Benchee.run(%{
  "ipt_get" => fn -> Iptrie.get(ipt, pfx) end,
  "rdx_get" => fn -> Radix.get(rdx, pfx.bits) end,
  "map_get" => fn -> Map.get(map, pfx.bits) end
})
