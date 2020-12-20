defmodule PrefixError do
  defexception [:id, :detail]

  @typedoc """
  An exception struct with members *id* and *detail*.

  Used by Prefix and its domain specific submodules to report errors
  encountered during encoding/decoding/formatting prefixes.

  """
  @type t :: %__MODULE__{id: atom(), detail: String.t()}

  @doc """
  Create an PrefixError struct.

  ## Example
      iex> PrefixError.new(:eaddress, "1.1.1.256")
      %PrefixError{id: :eaddress, detail: "1.1.1.256"}

  """
  @spec new(atom(), String.t()) :: t()
  def new(id, detail),
    do: %__MODULE__{id: id, detail: detail}

  @doc """
  Format an PrefixError as a string suitable for human consumption.

  ## Example
      iex> PrefixError.new(:eargument, "what's this?") |> PrefixError.message()
      "Bad argument (what's this?)"

  """
  @spec message(t()) :: String.t()
  def message(x), do: format(x.id, x.detail)

  # used by submodules, signals error in domain construct
  defp format(:eaddress, detail),
    do: "Bad address (#{detail})"

  # used by submodules, signals error in domain construct
  defp format(:emask, detail),
    do: "Bad mask (#{detail})"

  # illegal prefix length
  defp format(:elength, detail),
    do: "Bad length (#{detail})"

  defp format(:eargument, detail),
    do: "Bad argument (#{detail})"

  defp format(:ecompare, detail),
    do: "Cannot compare (#{detail})"

  # catch all other error id's
  defp format(id, detail),
    do: "#{id}: #{detail}"
end

defmodule Prefix do
  use Bitwise
  alias PrefixError

  @moduledoc ~S"""
  Prefixes represent a series of bitstrings.

  A prefix is defined by zero or more bits & a maximum length, and is
  internally represented by a struct.

      # creating a prefix
      iex> new(<<10, 10, 10>>, 32)
      %Prefix{bits: <<10, 10, 10>>, maxlen: 32}           # IPv4

      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      %Prefix{bits: <<172, 220, 25, 118>>, maxlen: 128}   # IPv6

      iex> new(<<0xc0, 0x3f, 0xd5>>, 48)
      %Prefix{bits: <<192, 63, 213>>, maxlen: 48}         # MAC OUI


  The module contains generic functions to validate, create, modify, sort,
  enumerate, format or index into prefixes, usually without any form of
  interpretation.  Submodules that parse domain specific constructs into a
  prefix can use these to provide additional functions that reflect their
  domain's meaning of prefixes.

  In general, Prefix functions either return some value or a PrefixError in
  case of any errors.  These exceptions are also passed through if given where
  a prefix was expected.

  Additionally, a `Prefix.to_numbers/2` decodes a prefix to a `{digits, len}`
  format.  The *missing* bits are filled in as `0`'s before turning the bits
  into numbers using a specified *width* and the length is the actual length of
  the original bitstring.

      # prefix as numbers
      iex> new(<<10,10,10>>, 32) |> to_numbers(8)
      {{10, 10, 10, 0}, 24}

      iex> new(<<0xacdc::16, 0x1976::16>>, 128) |> to_numbers(16)
      {{44252, 6518, 0, 0, 0, 0, 0, 0}, 32}

  A prefix is also enumerable:

      iex> pfx = new(<<10,10,10,0::6>>, 32)
      iex> for ip <- pfx do ip end
      [
        %Prefix{bits: <<10, 10, 10, 0>>, maxlen: 32},
        %Prefix{bits: <<10, 10, 10, 1>>, maxlen: 32},
        %Prefix{bits: <<10, 10, 10, 2>>, maxlen: 32},
        %Prefix{bits: <<10, 10, 10, 3>>, maxlen: 32}
      ]

  Note that enumeration yields a list of full-length prefixes as the missing
  bits are filled in during the enumeration.  This could be used for something
  like:

      iex> for ip <- new(<<10,10,10,0::6>>, 32) do
      ...>   elem(to_numbers(ip, 8), 0)
      ...> end
      [ {10, 10, 10, 0},
        {10, 10, 10, 1},
        {10, 10, 10, 2},
        {10, 10, 10, 3}
      ]

  Prefix also implements the `String.Chars` protocol, using the format function
  to provide some sane defaults for prefix's of *maxlen* 32, 48 and 128
  respectively.  Other sizes fallback to a generic dotted notation of 8-bit
  numbers.

      iex> "#{new(<<10, 11, 12>>, 32)}"
      "10.11.12.0/24"

      iex> "#{new(<<10, 11, 12, 14>>, 32)}"
      "10.11.12.14"

      iex> "#{new(<<0xACDC::16, 0x1976::16>>, 128)}"
      "ACDC:1976:0:0:0:0:0:0/32"

      iex> "#{new(<<0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6>>, 48)}"
      "A1:B2:C3:D4:E5:F6"

  So the list comprehension earlier, could also read:

      iex> for ip <- new(<<10, 10, 10, 0::6>>, 32) do "#{ip}" end
      [
        "10.10.10.0",
        "10.10.10.1",
        "10.10.10.2",
        "10.10.10.3"
      ]
  """

  @enforce_keys [:bits, :maxlen]
  defstruct bits: nil, maxlen: nil

  @typedoc """
  A prefix struct with *bits* and a *maxlen*.

  """
  @type t :: %__MODULE__{bits: <<_::_*1>>, maxlen: non_neg_integer}
  # @type t(bits, length) :: %__MODULE__{bits: bits, maxlen: length}

  # Guards

  @doc """
  Guard that ensures *bits* is a bitstring and *maxlen* a non-neg-integer.

  """
  defguard types?(bits, maxlen) when is_bitstring(bits) and is_integer(maxlen) and maxlen >= 0

  @doc """
  Guard that *prefix* is actually a `t:Prefix.t/0` struct.

  """
  defguard prefix?(prefix) when prefix.__struct__ == __MODULE__

  @doc """
  Guard that given *prefix* is actually valid.
  - it is a `t:Prefix.t/0` struct
  - the length of its *bits* <= *maxlen*

  """
  defguard valid?(prefix) when prefix?(prefix) and bit_size(prefix.bits) <= prefix.maxlen

  @doc """
  Guard that both prefixes are valid and comparable.
  - must both be valid prefixes
  - must both have the same *maxlen*

  """
  defguard valid?(px, py) when valid?(px) and valid?(py) and px.maxlen == py.maxlen

  # Helpers

  # optionally drops some lsb's
  defp truncate(bits, max) do
    if bit_size(bits) > max do
      <<part::bitstring-size(max), _::bitstring>> = bits
      part
    else
      bits
    end
  end

  # maybe reverse a list
  defp maybe_reverse(l, true), do: Enum.reverse(l)
  defp maybe_reverse(l, _), do: l

  # maybe pad the bitstring
  defp maybe_padding(pfx, max, true), do: padright(pfx, max)
  defp maybe_padding(pfx, _, _), do: pfx

  # Creation

  @doc """
  Creates a new prefix.

  A prefix can be created from a bitstring and a maximum length, truncating the
  bitstring when needed or from an existing prefix and a new maxlen, again
  truncating the bits when needed.

  ## Examples

      iex> new(<<10, 10>>, 32)
      %Prefix{maxlen: 32, bits: <<10, 10>>}

      iex> new(<<10::8, 10::8>>, 8)
      %Prefix{maxlen: 8, bits: <<10::8>>}

      # changing maxlen changes the prefix' meaning
      iex> new(<<10::8, 10::8>>, 32) |> new(128)
      %Prefix{maxlen: 128, bits: <<10::8, 10::8>>}

  """
  @spec new(t | bitstring, non_neg_integer) :: t
  def new(bits, maxlen) when types?(bits, maxlen),
    do: %__MODULE__{bits: truncate(bits, maxlen), maxlen: maxlen}

  def new(pfx, maxlen) when valid?(pfx),
    do: new(pfx.bits, maxlen)

  def new(x, _maxlen) when is_exception(x),
    do: x

  def new(_bits, maxlen) when maxlen < 0 or not is_integer(maxlen),
    do: PrefixError.new(:elength, "#{maxlen}")

  # Padding

  @doc """
  Prepend bits to a prefix to achieve a desired  length.

  By default, `0`-bits are used, unless *fill* is a negative number.

  If the length specified by *nbits* is shorter than the prefix' current
  length, the prefix is returned unchanged but it is an error to try to pad
  beyond the prefix' maximum length.

  ## Examples

      iex> new(<<10::8, 11::8>>, 32) |> padleft(17)
      %Prefix{bits: <<0::1, 10::8, 11::8>>, maxlen: 32}

      iex> new(<<0::8>>, 32) |> padleft(32, -1)
      %Prefix{bits: <<255::8, 255::8, 255::8, 0::8>>, maxlen: 32}

  """
  @spec padleft(t(), non_neg_integer, integer) :: bitstring
  def padleft(prefix, nbits, fill \\ 0)

  def padleft(x, _nbits, _fill) when is_exception(x), do: x

  def padleft(prefix, nbits, fill)
      when bit_size(prefix.bits) < nbits and nbits <= prefix.maxlen do
    bit = if fill < 0, do: -1, else: 0
    pad = nbits - bit_size(prefix.bits)
    %Prefix{prefix | bits: <<bit::size(pad), prefix.bits::bitstring>>}
  end

  def padleft(prefix, nbits, _fill) when nbits > prefix.maxlen,
    do: PrefixError.new(:elength, "#{nbits} > #{prefix.maxlen}")

  def padleft(prefix, _nbits, _fill), do: prefix

  @doc """
  Append bits to a prefix to achieve a desired length.

  By default, `0`-bits are used, unless fill is a negative number.

  If the length specified by *nbits* is shorter than the prefix' current
  length, the prefix is returned unchanged but it is an error to try to pad
  beyond the prefix' maximum length.


  ## Examples

      iex> new(<<10::8, 10::8>>, 32) |> padright(25)
      %Prefix{bits: <<10::8, 10::8, 0::8, 0::1>>, maxlen: 32}

      iex> new(<<>>, 32) |> padright(24, -1) |> padright(32)
      %Prefix{bits: <<255::8, 255::8, 255::8, 0::8>>, maxlen: 32}

  """
  @spec padright(t(), non_neg_integer, integer) :: t()
  def padright(prefix, nbits, fill \\ 0)

  def padright(x, _nbits, _fill) when is_exception(x), do: x

  def padright(prefix, nbits, fill)
      when bit_size(prefix.bits) < nbits and nbits <= prefix.maxlen do
    bit = if fill < 0, do: -1, else: 0
    pad = nbits - bit_size(prefix.bits)
    %Prefix{prefix | bits: <<prefix.bits::bitstring, bit::size(pad)>>}
  end

  def padright(prefix, nbits, _fill) when nbits > prefix.maxlen,
    do: PrefixError.new(:elength, "#{nbits} > #{prefix.maxlen}")

  def padright(prefix, _nbits, _fill), do: prefix

  # Numbers

  @doc """
  Turn a prefix into a list of fields of a given *width*.

  If the actual number of prefix bits are not a multiple of *width*, the last
  field will have a shorter width.

  ## Examples

      iex> new(<<10::8, 10::8, 10::8, 0::1>>, 32)
      ...> |> fields(8)
      [{10, 8}, {10, 8}, {10, 8}, {0, 1}]

      iex> new(<<0xacdc::16>>, 128)
      ...> |> fields(4)
      [{10, 4}, {12, 4}, {13, 4}, {12, 4}]

  """
  @spec fields(t, non_neg_integer) :: list({non_neg_integer, non_neg_integer})
  def fields(prefix, width) when prefix?(prefix),
    do: fields([], prefix.bits, width)

  def fields(x, _width) when is_exception(x), do: x

  defp fields(acc, <<>>, _width), do: Enum.reverse(acc)

  defp fields(acc, bits, width) when bit_size(bits) >= width do
    <<num::size(width), rest::bitstring>> = bits
    fields([{num, width} | acc], rest, width)
  end

  defp fields(acc, bits, width) when bit_size(bits) < width do
    w = bit_size(bits)
    <<num::size(w)>> = bits
    fields([{num, w} | acc], "", width)
  end

  @doc """
  Turn a prefix in a `{digits, len}` format.

  The prefix is padded to its maximum length using `0`'s and the resulting
  bits are grouped into numbers, each *width*-bits wide.  Note: works best if
  prefix' *maxlen* is a multiple of the *width* used.

  ## Examples

      iex> new(<<10::8, 11::8, 12::8>>, 32) |> to_numbers(8)
      {{10, 11, 12, 0}, 24}

      iex> new(<<10, 11, 12, 1::1>>, 32) |> to_numbers(8)
      {{10, 11, 12, 128}, 25}

      iex> new(<<0xacdc::16, 1976::16>>, 128) |> to_numbers(16)
      {{44252, 1976, 0, 0, 0, 0, 0, 0}, 32}

  """
  @spec to_numbers(t, non_neg_integer) :: {tuple, non_neg_integer}
  def to_numbers(prefix, width) when valid?(prefix) and width > 0 do
    prefix
    |> padright(prefix.maxlen)
    |> fields(width)
    |> Enum.map(fn x -> elem(x, 0) end)
    |> List.to_tuple()
    |> (&{&1, bit_size(prefix.bits)}).()
  end

  def to_numbers(x, _width) when is_exception(x), do: x
  def to_numbers(_, w), do: PrefixError.new(:eargument, "illegal width #{w}")

  @doc """
  The size of a prefix is determined by its *missing* bits.

  size(p) == 2^(p.maxlen - bit_size(p.bits))

  ## Examples

      iex> new(<<10, 10, 10>>, 32) |> size()
      256

      iex> new(<<10, 10, 10, 10>>, 32) |> size()
      1
  """
  @spec size(t) :: non_neg_integer
  def size(prefix) when valid?(prefix),
    do: :math.pow(2, prefix.maxlen - bit_size(prefix.bits)) |> trunc

  @doc """
  Given an *offset*, index into the series of bitstrings represented by *prefix*.

  Note that it is an error to index beyond the prefix' limits.

  ## Examples

      iex> new(<<10, 10, 10>>, 32) |> index(128)
      %Prefix{bits: <<10, 10, 10, 128>>, maxlen: 32}

      iex> new(<<10, 10, 10>>, 32) |> index(256)
      %PrefixError{detail: "256", id: :eindex}

  """
  @spec index(t, non_neg_integer) :: t
  def index(prefix, offset) when valid?(prefix) do
    width = prefix.maxlen - bit_size(prefix.bits)
    index(prefix, offset, width, size(prefix))
  end

  def index(x, _offset) when is_exception(x), do: x

  defp index(pfx, offset, width, max) when offset < max,
    do: %Prefix{pfx | bits: <<pfx.bits::bits, offset::size(width)>>}

  defp index(_, offset, _, _),
    do: PrefixError.new(:eindex, "#{offset}")

  # Format

  @doc ~S"""
  Generic formatter to turn a *prefix* into a string, with several keyword options
  - `:width`, field width (default 8)
  - `:base`, howto turn a field into a string (default 10)
  - `:unit`, how many fields go into 1 section (default 1)
  - `:ssep`, howto join the sections together (default ".")
  - `:lsep`, howto join a mask if required (default "/")
  - `:mask`, whether to add a mask (default false)
  - `:reverse`, whether to reverse fields before grouping/joining (default false)
  - `:padding`, whether to pad out the prefix' bits (default true)

  The defaults are geared towards IPv4 prefixes, but the options should be able
  to accomodate other domains as well.  Note the length of the original prefix
  *bits* is never added when its bitsize is equal to its maximum size *maxlen*.

  ## Examples

      iex> new(<<10, 11, 12>>, 32) |> format()
      "10.11.12.0/24"

      # mask not appended as its redundant for a full-sized prefix
      iex> new(<<10, 11, 12, 128>>, 32) |> format()
      "10.11.12.128"

      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 16, base: 16, ssep: ":")
      "ACDC:1976:0:0:0:0:0:0/32"

      # similar, but grouping 4 fields, each of which are 4 bits wide
      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 4, base: 16, unit: 4, ssep: ":")
      "ACDC:1976:0000:0000:0000:0000:0000:0000/32"

      # this time, omit the acutal prefix length
      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 16, base: 16, ssep: ":", mask: false)
      "ACDC:1976:0:0:0:0:0:0"

      # PTR for IPv6 using the nibble format:
      # - dot-separated reversal of all hex digits in the expanded address
      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 4, base: 16, mask: false, reverse: true)
      ...> |> String.downcase()
      ...> |> (&"#{&1}.ip6.arpa.").()
      "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.7.9.1.c.d.c.a.ip6.arpa."

      # turn off padding to get reverse zone ptr record
      iex> new(<<10, 11, 12>>, 32)
      ...> |> format(padding: false, reverse: true, mask: false)
      ...> |> (&"#{&1}.in-addr.arpa.").()
      "12.11.10.in-addr.arpa."


  """
  @spec format(t, list) :: String.t()
  def format(prefix, opts \\ [])

  def format(prefix, opts) when valid?(prefix) do
    width = Keyword.get(opts, :width, 8)
    base = Keyword.get(opts, :base, 10)
    ssep = Keyword.get(opts, :ssep, ".")
    lsep = Keyword.get(opts, :lsep, "/")
    unit = Keyword.get(opts, :unit, 1)
    mask = Keyword.get(opts, :mask, true)
    reverse = Keyword.get(opts, :reverse, false)
    padding = Keyword.get(opts, :padding, true)

    bitstr =
      prefix
      |> maybe_padding(prefix.maxlen, padding)
      |> fields(width)
      |> Enum.map(fn {n, _w} -> Integer.to_string(n, base) end)
      |> maybe_reverse(reverse)
      |> Enum.chunk_every(unit)
      |> Enum.join(ssep)

    if mask and bit_size(prefix.bits) < prefix.maxlen do
      "#{bitstr}#{lsep}#{bit_size(prefix.bits)}"
    else
      bitstr
    end
  end

  def format(x, _opts) when is_exception(x), do: x
  def format(x, _), do: PrefixError.new(:einvalid, "#{x}")
  # Sorting

  @doc """
  Compare function for sorting.

  - `:eq` prefix1 is equal to prefix2
  - `:lt` prefix1 has more bits *or* lies to the left of prefix2
  - `:gt` prefix1 has less bits *or* lies to the right of prefix2

  The prefixes must have the same *maxlen* and are first compared by size
  (i.e. a *shorter* prefix is considered *larger*), and second on their
  bitstring value.

  ## Examples

      iex> compare(new(<<10::8>>, 32), new(<<11::8>>, 32))
      :lt

      iex> compare(new(<<11::8>>, 32), new(<<10::8>>, 32))
      :gt

      iex> compare(new(<<10::8>>, 32), new(<<10::8>>, 32))
      :eq

      iex> compare(new(<<10::8>>, 32), new(<<10::8>>, 128))
      %PrefixError{id: :eargument, detail: "A00:0:0:0:0:0:0:0/8"}

      # sort on prefix size, longest prefix comes first
      iex> l = [new(<<10>>, 32), new(<<10,10,10>>, 32), new(<<10,10>>, 32)]
      iex> Enum.sort(l, Prefix)
      [ %Prefix{bits: <<10,10,10>>, maxlen: 32},
        %Prefix{bits: <<10,10>>, maxlen: 32},
        %Prefix{bits: <<10>>, maxlen: 32}
      ]

      # sort on bitvalues, since all have the same length
      iex> l = [new(<<11>>, 128), new(<<12>>, 128), new(<<10>>, 128)]
      iex> Enum.sort(l, Prefix)
      [ %Prefix{bits: <<10>>, maxlen: 128},
        %Prefix{bits: <<11>>, maxlen: 128},
        %Prefix{bits: <<12>>, maxlen: 128}
      ]
  """

  @spec compare(t, t) :: :eq | :lt | :gt | PrefixError.t()
  def compare(prefix1, prefix2) when valid?(prefix1, prefix2),
    do: comparep(prefix1.bits, prefix2.bits)

  def compare(x, _) when is_exception(x), do: x
  def compare(_, y) when is_exception(y), do: y
  def compare(x, y) when valid?(x), do: PrefixError.new(:eargument, "#{y}")
  def compare(x, _), do: PrefixError.new(:eargument, "#{x}")

  defp comparep(x, y) when bit_size(x) > bit_size(y), do: :lt
  defp comparep(x, y) when bit_size(x) < bit_size(y), do: :gt
  defp comparep(x, y) when x < y, do: :lt
  defp comparep(x, y) when x > y, do: :gt
  defp comparep(x, y) when x == y, do: :eq

  # Contrast two prefixes.
  # - `:default` prefix1 matches prefix2, because of one or both have zero bits
  # - `:equal` prefix1 is equal to prefix2
  # - `:more` prefix1 is a more specific version of prefix2
  # - `:less` prefix1 is a less specific version of prefix2
  # - `:left` prefix1 is left-adjacent to prefix2
  # - `:right` prefix1 is right-adjacent to prefix2
  # - `:subnet` prefix1 is a subnet of prefix2
  # - `:supernet` prefix1 is a supernet of prefix2
  # - `:disjoint` prefix1 has no match with prefix2.
  #
  # @spec contrast(t, t) :: atom
  # def contrast(x, y) when valid?(x, y), do: contrastp(x.bits, y.bits)
  # def contrast(x, _) when is_exception(x), do: x
  # def contrast(_, y) when is_exception(y), do: y
  # def contrast(x, y) when valid?(x), do: PrefixError.new(:eargument, "#{y}")
  # def contrast(x, _), do: PrefixError.new(:eargument, "#{x}")

  # defp contrastp(x, y) when x == y, do: :equal
  # defp contrastp(x, y) 
end

defimpl String.Chars, for: Prefix do
  def to_string(prefix) do
    # bitstr =
    #   prefix
    #   |> Prefix.fields(8)
    #   |> Enum.map(fn {num, width} -> "#{num}::#{width}" end)
    #   |> Enum.join(", ")

    # "%Prefix{bits: <<#{bitstr}>>, maxlen: #{prefix.maxlen}}"

    case prefix.maxlen do
      32 -> Prefix.format(prefix)
      48 -> Prefix.format(prefix, base: 16, ssep: ":")
      128 -> Prefix.format(prefix, base: 16, width: 16, ssep: ":")
      _ -> Prefix.format(prefix)
    end
  end
end

defimpl Enumerable, for: Prefix do
  require Prefix

  def count(prefix),
    do: {:ok, trunc(:math.pow(2, prefix.maxlen - bit_size(prefix.bits)))}

  def member?(x, y) when Prefix.valid?(x, y) do
    memberp?(x.bits, y.bits)
  end

  def member?(_, _),
    do: {:ok, false}

  defp memberp?(x, y) when bit_size(x) > bit_size(y),
    do: {:ok, false}

  defp memberp?(x, y) do
    len = bit_size(x)
    <<ypart::bitstring-size(len), _::bitstring>> = y
    {:ok, x == ypart}
  end

  def slice(prefix) do
    {:ok, size} = count(prefix)
    {:ok, size, &slicep(&1, &2)}
  end

  defp slicep(pfx, n) when n < 1,
    do: [Prefix.index(pfx, n)]

  defp slicep(pfx, n),
    do: slicep(pfx, n - 1) ++ [Prefix.index(pfx, n)]

  def reduce(pfx, acc, fun) do
    reduce(pfx, acc, fun, _idx = 0, _max = Prefix.size(pfx))
  end

  defp reduce(_pfx, {:halt, acc}, _fun, _idx, _max),
    do: {:halted, acc}

  defp reduce(pfx, {:suspend, acc}, fun, idx, max),
    do: {:suspended, acc, &reduce(pfx, &1, fun, idx, max)}

  defp reduce(pfx, {:cont, acc}, fun, idx, max) when idx < max do
    reduce(pfx, fun.(Prefix.index(pfx, idx), acc), fun, idx + 1, max)
  end

  defp reduce(_, {:cont, acc}, _fun, _idx, _max),
    do: {:done, acc}
end
