defmodule Iptrie do
  @moduledoc """
  A Key,Value-store for IPv4 and IPv6 networks or addresses with longest prefix matching.

  """
  alias Pfx
  alias Radix

  defstruct root: %{}

  @typedoc """
  An Iptrie struct whose root is a `Radix` tree.

  See `t:Radix.tree/0`.

  """
  @type t :: %__MODULE__{root: map()}

  @doc """
  Create an new, empty Iptrie.

  ## Example

      iex> Iptrie.new()
      %Iptrie{root: %{}}

  """
  @spec new() :: t()
  def new,
    do: %__MODULE__{root: %{}}

  @doc """
  Return the {key,val}-pair where key is an exact match for given *prefix*,
  or a list of pairs for a list of prefixes.

  ## Examples

      iex> tree = new([{"1.1.1.0/30", "A"}, {"1.1.1.0/31", "B"}, {"1.1.1.0", "C"}])
      iex> get(tree, "1.1.1.0/31")
      {<<0::1, 1, 1, 1, 0::7>>, "B"}

  """
  def get(%__MODULE__{} = tree, prefixes) when is_list(prefixes) do
    Enum.map(prefixes, fn x -> get(tree, x) end)
  end

  def get(%__MODULE__{} = tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> x
      x -> Radix.get(tree.root, key(x))
    end
  end

  @doc """
  Enter a single {prefix,value}-pair into an iptrie.

  This always uses an exact match for *prefix*, updating its *value* if it
  exists.  Any errors are silently ignored as the tree is always returned.

  ## Examples

  """
  def put(%__MODULE__{} = tree, elements) when is_list(elements) do
    Enum.reduce(elements, tree, fn kv, t -> set(t, kv) end)
  end

  def set(%__MODULE__{} = tree, {prefix, value}) do
    case encode(prefix) do
      x when is_exception(x) -> tree
      x -> %{tree | root: Radix.set(tree.root, key(x), value)}
    end
  end

  @doc """
  Return the `t:keyval/0`-pair, whose key represents the longest possible
  prefix for the given search *prefix* or `nil` if nothing matched.

  Silently ignores any errors when encoding given *prefix* by returning nil.

  ## Example

  """
  @spec lookup(t(), prefix()) :: term
  def lookup(%__MODULE__{} = tree, prefix) do
    case encode(prefix) do
      x when is_exception(x) -> nil
      x -> Radix.lpm(tree.root, key(x))
    end
  end

  def lookup(_, _), do: nil
end
