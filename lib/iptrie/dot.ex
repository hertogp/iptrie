defmodule Iptrie.Dot do
  @moduledoc """
  Functions to save an Iptrie as a simple graphviz dot file.

  """

  alias Radix
  alias Iptrie

  @color %{
    root: "orange",
    node: "yellow",
    leaf: "green"
  }

  # Helpers

  defp decode(key) do
    key
    |> Iptrie.rdx_key_tostr()
  end

  # TODO:
  # - add toplevel opts as keyword list
  # - parameterize the graph options that are now hardcoded, like colors
  # - optionally graph payload instead of key's, perhaps via callback that
  #   takes a k,v-pair and produces a (short) string?

  # DUMP
  # The accumulator holds [ids, nodes, verts]
  # The radix tree is traversed in post-order, so left/right children are
  # processed before the internal node itself.
  # A leaf:
  # - adds a node to nodes (id = length of nodes)
  # - adds the node's id to ids
  # A node:
  # - adds node to nodes (id = length of nodes) -- if non-nil
  # - ads id or nil to ids
  # - adds self-id -> child-id to verts

  defp dump([ids, nodes, verts], {pos, _l, _r}) do
    id = length(nodes)
    [rid, lid | rest] = ids
    bgcolor = if pos == 0, do: @color[:root], else: @color[:node]

    node = """
    N#{id} [label=<
      <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
        <TR><TD PORT="N#{id}" COLSPAN="2" BGCOLOR="#{bgcolor}">bit #{pos}</TD></TR>
        <TR><TD PORT=\"L\">0</TD><TD PORT=\"R\">1</TD></TR>
      </TABLE>
    >, shape="plaintext"];
    """

    nodes = [node | nodes]
    verts = if lid != nil, do: ["N#{id}:L -> N#{lid};\n" | verts], else: verts
    verts = if rid != nil, do: ["N#{id}:R -> N#{rid};\n" | verts], else: verts

    [[id | rest], nodes, verts]
  end

  defp dump([ids, nodes, verts], nil), do: [[nil | ids], nodes, verts]

  defp dump([ids, nodes, verts], leaf) do
    id = length(nodes)

    body =
      leaf
      |> Enum.map(fn {key, _v} -> decode(key) end)
      |> Enum.map(fn x -> "  <TR><TD>#{x}</TD></TR>" end)
      |> Enum.join("\n  ")

    node = """
    N#{id} [label=<
      <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
        <TR><TD PORT="N#{id}" BGCOLOR="#{@color[:leaf]}">LEAF</TD></TR>
      #{body}
      </TABLE>
      >, shape="plaintext"];
    """

    [[id | ids], [node | nodes], verts]
  end

  # TODO:
  #  add opts to color specific key(s) differently
  #  - perhaps an Iptrie with properties for drawing and using lpm match
  def dotify(tree, title) do
    [_ids, nodes, verts] =
      Radix.traverse(tree, fn n, x -> dump(n, x) end, [[], [], []], :postorder)

    """
    digraph G {

      labelloc="t";
      label="#{title}";
      rankdir="TB";
      ranksep="0.5 equally";

      #{Enum.join(nodes)}

      #{Enum.join(verts)}
    }
    """
  end

  def write(bst, fname, title \\ "Iptrie") do
    File.write(fname, dotify(bst.root, title))
  end
end
