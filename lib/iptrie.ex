defmodule Iptrie do
  @external_resource "README.md"

  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)

  require Pfx
  alias Radix

  defstruct []

  @typedoc """
  An Iptrie struct that contains a `Radix` tree per `maxlen` used.

  See `t:Pfx.t/0` and `t:Radix.tree/0`.

  """
  @type t :: %__MODULE__{}

  @type prefix :: Pfx.prefix()

  # Helpers
  defp marshall(pfx, x) when Pfx.is_pfx(pfx) do
    width = if pfx.maxlen == 128, do: 16, else: 8

    cond do
      is_binary(x) -> "#{pfx}"
      is_tuple(x) and tuple_size(x) == 2 -> Pfx.digits(pfx, width)
      is_tuple(x) -> Pfx.digits(pfx, width) |> elem(0)
      true -> pfx
    end
  end

  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      %Iptrie{}


  """
  @spec new() :: t()
  def new,
    do: %__MODULE__{}

  @doc """
  Create a new `t:Iptrie/0` populated via a list of {`t:Pfx.t/0`, `any`}-pairs.

  ## Example

      iex> ipt = Iptrie.new([{"1.1.1.0/24", "net1"}, {"acdc:1975::/32", "TNT"}])
      iex> Map.get(ipt, 32)
      {0, [{<<1, 1, 1>>, "net1"}], nil}
      iex> Map.get(ipt, 128)
      {0, nil, [{<<172, 220, 25, 117>>, "TNT"}]}

  """
  @spec new(list({prefix(), any})) :: t
  def new(elements) when is_list(elements),
    do: Enum.reduce(elements, new(), fn {prefix, value}, trie -> put(trie, prefix, value) end)

  @doc """
  Return the {key,val}-pair where key is an exact match for given `prefix`,
  or a list of pairs for a list of prefixes.

  ## Examples

      iex> ipt = new([{"1.1.1.0/30", "A"}, {"1.1.1.0/31", "B"}, {"1.1.1.0", "C"}])
      iex> get(ipt, "1.1.1.0/31")
      {"1.1.1.0/31", "B"}
      iex>
      iex> get(ipt, {{1, 1, 1, 0}, 30})
      {{{1, 1, 1, 0}, 30}, "A"}


  """
  @spec get(t, prefix() | list(prefix())) :: {prefix(), any} | nil | list({prefix(), any} | nil)
  def get(%__MODULE__{} = trie, prefixes) when is_list(prefixes) do
    Enum.map(prefixes, fn prefix -> get(trie, prefix) end)
  end

  def get(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.get(tree, pfx.bits) do
        nil -> nil
        {bits, value} -> {marshall(%{pfx | bits: bits}, prefix), value}
      end
    rescue
      ArgumentError -> nil
    end
  end

  @doc """
  Enter a single {prefix,value}-pair into an iptrie.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.  Any errors are silently ignored as the tree is always returned.

  ## Examples

  """
  @spec put(t, list({prefix(), any})) :: t
  def put(%__MODULE__{} = trie, elements) when is_list(elements) do
    Enum.reduce(elements, trie, fn {k, v}, t -> put(t, k, v) end)
  end

  @spec put(t, prefix(), any) :: t
  def put(%__MODULE__{} = trie, prefix, value) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()
      Map.put(trie, pfx.maxlen, Radix.put(tree, pfx.bits, value))
    rescue
      ArgumentError -> trie
    end
  end

  @doc """
  Return the `t:prefix.t/0`,value--pair, whose key represents the longest possible
  prefix for the given search *prefix* or `nil` if nothing matched.

  Silently ignores any errors when encoding given *prefix* by returning nil.

  ## Example

  """
  @spec lookup(t(), prefix()) :: {prefix(), any} | nil
  def lookup(%__MODULE__{} = trie, prefix) do
    try do
      pfx = Pfx.new(prefix)
      tree = Map.get(trie, pfx.maxlen) || Radix.new()

      case Radix.lookup(tree, pfx.bits) do
        nil -> nil
        {bits, value} -> {marshall(%{pfx | bits: bits}, prefix), value}
      end
    rescue
      ArgumentError -> nil
    end
  end
end
