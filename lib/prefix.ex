defmodule PrefixError do
  defexception [:id, :detail]

  @typedoc """
  An exception struct with members `id` and `detail`.

  Used by Prefix and its domain specific submodules to report errors
  encountered during encoding/decoding/formatting prefixes.

  """
  @type t :: %__MODULE__{id: atom(), detail: String.t()}

  @doc """
  Create a PrefixError struct.

  ## Example

      iex> new(:func_x, "1.1.1.256")
      %PrefixError{id: :func_x, detail: "1.1.1.256"}

  """
  @spec new(atom(), any()) :: t()
  def new(id, detail),
    do: %__MODULE__{id: id, detail: detail}

  @doc ~S"""
  Stringify the exception.

  ## Example
      iex> new(:efunc_x, {"arg1", "arg2"}) |> message()
      "efunc_x: args (\"arg1\", \"arg2\")"

  """
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

  Additionally, a `Prefix.digits/2` decodes a prefix to a `{digits, len}`
  format.  The *missing* bits are filled in as `0`'s before turning the bits
  into numbers using a specified *width* and the length is the actual length of
  the original bitstring.

      # prefix as numbers
      iex> new(<<10,10,10>>, 32) |> digits(8)
      {{10, 10, 10, 0}, 24}

      iex> new(<<0xacdc::16, 0x1976::16>>, 128) |> digits(16)
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
      ...>   elem(digits(ip, 8), 0)
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
  A prefix struct with members `bits` and `maxlen`.

  """
  @type t :: %__MODULE__{bits: <<_::_*1>>, maxlen: pos_integer}

  # Behaviour

  @callback encode(term) :: t
  @callback decode(t) :: term

  # Guards

  @doc """
  Guard that ensures *bits* is a bitstring and *maxlen* a non-neg-integer.

  """
  defguard types?(bits, maxlen) when is_bitstring(bits) and is_integer(maxlen) and maxlen >= 0

  @doc """
  Guard that ensures a given *prefix* is actually valid.
  - it is a `t:Prefix.t/0` struct
  - the length of its *bits* <= *maxlen*

  """
  defguard valid?(prefix)
           when prefix.__struct__ == __MODULE__ and
                  bit_size(prefix.bits) <= prefix.maxlen

  @doc """
  Guard that ensures both prefixes are valid and comparable.
  - must both be valid prefixes
  - must both have the same *maxlen*

  """
  defguard valid?(px, py)
           when valid?(px) and valid?(py) and px.maxlen == py.maxlen

  @doc """
  Guard that ensures *pfx* has *width*-bits to spare.

  """
  defguard width?(prefix, width)
           when valid?(prefix) and width in 0..(prefix.maxlen - bit_size(prefix.bits))

  @doc """
  Guard that ensures a proposed new *size* is valid for given *prefix*.

  """
  defguard size?(prefix, size)
           when valid?(prefix) and size in 0..prefix.maxlen

  # Helpers

  @compile inline: [error: 2]
  defp error(id, detail), do: PrefixError.new(id, detail)

  # optionally drops some lsb's
  defp truncate(bits, max) do
    if bit_size(bits) > max do
      <<part::bitstring-size(max), _::bitstring>> = bits
      part
    else
      bits
    end
  end

  # maybe reverse a list during a pipeline
  defp maybe_reverse(l, true), do: Enum.reverse(l)
  defp maybe_reverse(l, _), do: l

  # maybe pad the bitstring during a pipeline
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

      iex> new(<<10, 10>>, 8)
      %Prefix{maxlen: 8, bits: <<10>>}

      # changing maxlen changes the prefix' meaning
      iex> new(<<10, 10>>, 32) |> new(128)
      %Prefix{maxlen: 128, bits: <<10, 10>>}

  """
  @spec new(t | bitstring, non_neg_integer) :: t
  def new(bits, maxlen) when types?(bits, maxlen),
    do: %__MODULE__{bits: truncate(bits, maxlen), maxlen: maxlen}

  def new(pfx, maxlen) when valid?(pfx),
    do: new(pfx.bits, maxlen)

  def new(x, _) when is_exception(x), do: x
  def new(x, m), do: error(:new, {x, m})

  # Padding/Truncating
  # resize(prefix, max, fill \\0, side \\ :left)

  @doc """
  Prepend bits to a prefix to achieve a desired  length.

  By default, `0`-bits are used, unless *fill* is `1` in which case `1`-bits
  are used.

  Note: when "prepending" to a shorter length, bits are actually removed.

  ## Examples

      iex> new(<<10, 11>>, 32) |> padleft(17)
      %Prefix{bits: <<0::1, 10, 11>>, maxlen: 32}

      iex> new(<<0>>, 32) |> padleft(32, 1)
      %Prefix{bits: <<255, 255, 255, 0>>, maxlen: 32}

  """
  @spec padleft(t, pos_integer, 0..1) :: t
  def padleft(prefix, size, fill \\ 0)

  def padleft(prefix, size, fill) when size?(prefix, size) do
    pad = size - bit_size(prefix.bits)
    fill = if fill == 0, do: 0, else: -1

    case pad > 0 do
      true -> %{prefix | bits: <<fill::size(pad), prefix.bits::bitstring>>}
      false -> %{prefix | bits: <<prefix.bits::bitstring-size(size)>>}
    end
  end

  def padleft(x, _, _) when is_exception(x), do: x
  def padleft(x, s, f), do: error(:padleft, {x, s, f})

  @doc """
  Append bits to a prefix to achieve a desired length.

  By default, `0`-bits are used, unless fill is a negative number.

  Note: when "appending" to a shorter length, bits are actually removed.

  ## Examples

      iex> new(<<10, 10>>, 32) |> padright(25)
      %Prefix{bits: <<10, 10, 0, 0::1>>, maxlen: 32}

      iex> new(<<>>, 32) |> padright(24, 1) |> padright(32)
      %Prefix{bits: <<255, 255, 255, 0>>, maxlen: 32}

  """
  @spec padright(t, pos_integer, 0..1) :: t
  def padright(prefix, size, fill \\ 0)

  def padright(prefix, size, fill) when size?(prefix, size) do
    pad = size - bit_size(prefix.bits)
    fill = if fill == 0, do: 0, else: -1

    case pad > 0 do
      true -> %{prefix | bits: <<prefix.bits::bitstring, fill::size(pad)>>}
      false -> %{prefix | bits: <<prefix.bits::bitstring-size(size)>>}
    end
  end

  def padright(x, _, _) when is_exception(x), do: x
  def padright(x, s, f), do: error(:padright, {x, s, f})

  @doc """
  Split a *prefix* into a list of smaller pieces, each *newlen* bits long.

  Turn a prefix into a list of subsequent smaller prefixes.  *newlen* must be
  larger than or equal to the prefix' current bit length, else it is considered
  an error.

  ## Examples

      # break out the /26's in a /24
      iex> new(<<10, 11, 12>>, 32)|> split(26)
      [
        %Prefix{bits: <<10, 11, 12, 0::size(2)>>, maxlen: 32},
        %Prefix{bits: <<10, 11, 12, 1::size(2)>>, maxlen: 32},
        %Prefix{bits: <<10, 11, 12, 2::size(2)>>, maxlen: 32},
        %Prefix{bits: <<10, 11, 12, 3::size(2)>>, maxlen: 32}
      ]

  """
  @spec split(t, non_neg_integer) :: list(t)
  def split(prefix, newlen) when size?(prefix, newlen),
    do: splitp([prefix], _curlen = bit_size(prefix.bits), newlen)

  def split(x, _) when is_exception(x), do: x
  def split(x, l), do: error(:split, {x, l})

  defp splitp([pfx], curlen, newlen) when newlen < curlen,
    do: error(:split, {pfx, curlen, newlen})

  defp splitp(acc, curlen, newlen) when curlen == newlen,
    do: Enum.sort(acc, Prefix)

  defp splitp(acc, curlen, newlen) do
    acc0 = acc |> Enum.map(fn p -> padright(p, bit_size(p.bits) + 1) end)
    acc1 = acc |> Enum.map(fn p -> padright(p, bit_size(p.bits) + 1, 1) end)
    splitp(acc0 ++ acc1, curlen + 1, newlen)
  end

  # Numbers

  @doc """
  Turn a prefix into a list of `{number, width}`-fields.

  If the actual number of prefix bits are not a multiple of *width*, the last
  field will have a shorter width.

  ## Examples

      iex> new(<<10, 11, 12, 0::1>>, 32)
      ...> |> fields(8)
      [{10, 8}, {11, 8}, {12, 8}, {0, 1}]

      iex> new(<<0xacdc::16>>, 128)
      ...> |> fields(4)
      [{10, 4}, {12, 4}, {13, 4}, {12, 4}]

      iex> new(<<10, 11, 12>>, 32)
      ...> |> fields(1)
      ...> |> Enum.map(fn {x, _y} -> x end)
      ...> |> Enum.join("")
      "000010100000101100001100"

  """
  @spec fields(t, non_neg_integer) :: list({non_neg_integer, non_neg_integer})
  def fields(prefix, width) when valid?(prefix),
    do: fields([], prefix.bits, width)

  def fields(x, _) when is_exception(x), do: x
  def fields(x, w), do: error(:fields, {x, w})

  defp fields(acc, <<>>, _width), do: Enum.reverse(acc)

  defp fields(acc, bits, width) when bit_size(bits) >= width do
    <<num::size(width), rest::bitstring>> = bits
    fields([{num, width} | acc], rest, width)
  end

  defp fields(acc, bits, width) do
    w = bit_size(bits)
    <<num::size(w)>> = bits
    fields([{num, w} | acc], "", width)
  end

  @doc """
  Transform a *prefix* into a `{digits, len}` format.

  The *prefix* is padded to its maximum length using `0`'s and the resulting
  bits are grouped into numbers, each *width*-bits wide.  The resulting *len*
  preserves the original bitstring length.  Note: works best if prefix'
  *maxlen* is a multiple of the *width* used, otherwise *maxlen* cannot be
  inferred from this format in combination with *width*.

  ## Examples

      iex> new(<<10, 11, 12>>, 32) |> digits(8)
      {{10, 11, 12, 0}, 24}

      iex> new(<<0x12, 0x34, 0x56>>, 32) |> digits(4)
      {{1, 2, 3, 4, 5, 6, 0, 0}, 24}

      iex> new(<<10, 11, 12, 1::1>>, 32) |> digits(8)
      {{10, 11, 12, 128}, 25}

      iex> new(<<0xacdc::16, 1976::16>>, 128) |> digits(16)
      {{44252, 1976, 0, 0, 0, 0, 0, 0}, 32}

      iex> new(<<255>>, 32)
      ...> |> digits(1)
      ...> |> elem(0)
      ...> |> Tuple.to_list()
      ...> |> Enum.join("")
      "11111111000000000000000000000000"

  """
  @spec digits(t, pos_integer) :: {tuple(), pos_integer}
  def digits(prefix, width) when valid?(prefix) and width > 0 do
    prefix
    |> padright(prefix.maxlen)
    |> fields(width)
    |> Enum.map(fn x -> elem(x, 0) end)
    |> List.to_tuple()
    |> (&{&1, bit_size(prefix.bits)}).()
  end

  def digits(x, _) when is_exception(x), do: x
  def digits(x, w), do: error(:digits, {x, w})

  @doc """
  Return the prefix represented by the *digits*, actual *length* and a given
  field *width*.

  Each number/digit in *digits* is turned into a number of *width* bits wide
  and the resulting prefix's *maxlen* is inferred from the number of digits
  given and their *width*.

  Note: if a *digit* does not fit in *width*-bits, only the *width*-least
  significant bits are preserved.

  ## Examples

      iex> undigits({{10, 11, 12, 0}, 24}, 8)
      %Prefix{bits: <<10, 11, 12>>, maxlen: 32}

      iex> undigits({{10, 11, 12, 0}, 24}, 8) |> digits(8)
      {{10, 11, 12, 0}, 24}

      iex> undigits({{-1, -1, 0, 0}, 32}, 8) |> format()
      "255.255.0.0"

  """
  @spec undigits({tuple(), pos_integer}, pos_integer) :: t
  def undigits({digits, length}, width)
      when tuple_size(digits) > 0 and length >= 0 and width >= 0 do
    try do
      bits =
        digits
        |> Tuple.to_list()
        |> Enum.map(fn x -> <<x::size(width)>> end)
        |> Enum.reduce(fn x, acc -> <<acc::bitstring, x::bitstring>> end)
        |> truncate(length)

      Prefix.new(bits, tuple_size(digits) * width)
    rescue
      # in case digits-tuple contains non-integers
      _ ->
        error(:undigits, {{digits, length}, width})
    end
  end

  def undigits(x, _) when is_exception(x), do: x
  def undigits(d, l), do: error(:undigits, {d, l})

  @doc """
  Increase or decrease a *prefix* with given *offset*.

  Increases or decreases the number represented by the *prefix* bits.  This
  basically calculates the *nth* next or previous prefix given the offset.

  Note that the length of *prefix.bits* will not change.

  ## Examples

      iex> new(<<10, 11>>, 32) |> offset(1)
      %Prefix{bits: <<10, 12>>, maxlen: 32}

      iex> new(<<10, 11, 0>>, 32) |> offset(1)
      %Prefix{bits: <<10, 11, 1>>, maxlen: 32}

      iex> new(<<10, 11, 0>>, 32) |> offset(255)
      %Prefix{bits: <<10, 11, 255>>, maxlen: 32}

      iex> new(<<10, 11, 0>>, 32) |> offset(256)
      %Prefix{bits: <<10, 12, 0>>, maxlen: 32}

      # wraps around address boundaries
      iex> new(<<0, 0, 0, 0>>, 32) |> offset(-1)
      %Prefix{bits: <<255, 255, 255, 255>>, maxlen: 32}

      # zero bit-length stays zero bit-length
      iex> new(<<>>, 32) |> offset(1)
      %Prefix{bits: <<>>, maxlen: 32}

  """
  @spec offset(t, integer) :: t
  def offset(prefix, offset) when valid?(prefix) do
    len = bit_size(prefix.bits)
    <<n::size(len)>> = prefix.bits
    n = n + offset
    %{prefix | bits: <<n::size(len)>>}
  end

  def offset(x, _) when is_exception(x), do: x
  def offset(x, o), do: error(:offset, {x, o})

  @doc """
  The 'size' of a prefix as determined by its *missing* bits.

  size(prefix) == 2^(prefix.maxlen - bit_size(prefix.bits))

  ## Examples

      iex> new(<<10, 10, 10>>, 32) |> size()
      256

      iex> new(<<10, 10, 10, 10>>, 32) |> size()
      1
  """
  @spec size(t) :: non_neg_integer
  def size(prefix) when valid?(prefix),
    do: :math.pow(2, prefix.maxlen - bit_size(prefix.bits)) |> trunc

  def size(x) when is_exception(x), do: x
  def size(x), do: error(:size, x)

  @doc """
  Return the *nth*-member given a *prefix*, a (zero-based) *index* and an
  optional bit-*width* for the *index*.

  A prefix represents a range of (possibly longer) prefixes which can be
  seen as *members* of the prefix.  So a prefix of `n`-bits long represents:
  - 1 prefix of `n+0`-bits long (i.e. itself),
  - 2 prefixes of `n+1`-bits long,
  - 4 prefixes of `n+2`-bits long
  - ..
  - 2^w prefixes of `n+w`-bits long

  where `n+w` <= *prefix.maxlen*.

  Not specifying a *width* assumes the maximum width available.  If a *width*
  is specified, the *nth*-offset is added to the prefix as a number
  *width*-bits wide.  This wraps around since `<<16::4>>` comes out as
  `<<0::4>>`.

  It is considered an error to specify a *width* greater than the amount of
  bits the *prefix* actually has to spare, given its *prefix.bits*-length and its
  *prefix.maxlen*.

  ## Examples

      iex> new(<<10, 10, 10>>, 32) |> member(0)
      %Prefix{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> new(<<10, 10, 10>>, 32) |> member(255)
      %Prefix{bits: <<10, 10, 10, 255>>, maxlen: 32}

      # wraps around
      iex> new(<<10, 10, 10>>, 32) |> member(256)
      %Prefix{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> new(<<10, 10, 10>>, 32) |> member(-1)
      %Prefix{bits: <<10, 10, 10, 255>>, maxlen: 32}

      # a full prefix always returns itself
      iex> new(<<10, 10, 10, 10>>, 32) |> member(0)
      %Prefix{bits: <<10, 10, 10, 10>>, maxlen: 32}
      iex> new(<<10, 10, 10, 10>>, 32) |> member(1)
      %Prefix{bits: <<10, 10, 10, 10>>, maxlen: 32}
      iex> new(<<10, 10, 10, 10>>, 32) |> member(-1)
      %Prefix{bits: <<10, 10, 10, 10>>, maxlen: 32}


      # get the first sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(0, 2)
      %Prefix{bits: <<10, 10, 10, 0::2>>, maxlen: 32}

      # get the second sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(1, 2)
      %Prefix{bits: <<10, 10, 10, 1::2>>, maxlen: 32}

      # get the third sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(2, 2)
      %Prefix{bits: <<10, 10, 10, 2::2>>, maxlen: 32}

  """
  @spec member(t, integer) :: t
  def member(prefix, nth) when valid?(prefix),
    do: member(prefix, nth, prefix.maxlen - bit_size(prefix.bits))

  def member(x, _nth) when is_exception(x), do: x

  @spec member(t, integer, pos_integer) :: t
  def member(pfx, nth, width) when valid?(pfx) and width?(pfx, width),
    do: %{pfx | bits: <<pfx.bits::bits, nth::size(width)>>}

  def member(x, _, _) when is_exception(x), do: x
  def member(x, n, w), do: error(:member, {x, n, w})

  # Format

  @doc ~S"""
  Generic formatter to turn a *prefix* into a string, using several options:
  - `:width`, field width (default 8)
  - `:base`, howto turn a field into a string (default 10, use 16 for hex numbers)
  - `:unit`, how many fields go into 1 section (default 1)
  - `:ssep`, howto join the sections together (default ".")
  - `:lsep`, howto join a mask if required (default "/")
  - `:mask`, whether to add a mask (default false)
  - `:reverse`, whether to reverse fields before grouping/joining (default false)
  - `:padding`, whether to pad out the prefix' bits (default true)

  The defaults are geared towards IPv4 prefixes, but the options should be able
  to accomodate other domains as well.

  Notes:
  - the *prefix.bits*-length is omitted if equal to the *prefix.bits*-size
  - domain specific submodules probably implement their own formatter.

  ## Examples

      iex> new(<<10, 11, 12>>, 32) |> format()
      "10.11.12.0/24"

      # mask not appended as its redundant for a full-sized prefix
      iex> new(<<10, 11, 12, 128>>, 32) |> format()
      "10.11.12.128"

      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 16, base: 16, ssep: ":")
      "ACDC:1976:0:0:0:0:0:0/32"

      # similar, but grouping 4 fields, each of which is 4 bits wide
      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 4, base: 16, unit: 4, ssep: ":")
      "ACDC:1976:0000:0000:0000:0000:0000:0000/32"

      # this time, omit the acutal prefix length
      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      ...> |> format(width: 16, base: 16, ssep: ":", mask: false)
      "ACDC:1976:0:0:0:0:0:0"

      # ptr for IPv6 using the nibble format:
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

  # %Prefix{bits: <<10, 10, 10, 255, 255, 15::size(4)>>, maxlen: 32}
  # iex(540)> x |> Prefix.pad_right(44, 1) |> Prefix.format()
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

  def format(x, _) when is_exception(x), do: x
  def format(x, o), do: error(:format, {x, o})

  # Sorting

  @doc ~S"""
  Compare function for sorting.

  - `:eq` prefix1 is equal to prefix2
  - `:lt` prefix1 has more bits *or* lies to the left of prefix2
  - `:gt` prefix1 has less bits *or* lies to the right of prefix2

  The prefixes must have the same *maxlen* and are first compared by size
  (i.e. a *shorter* prefix is considered *larger*), and second on their
  bitstring value.

  ## Examples

      iex> compare(new(<<10>>, 32), new(<<11>>, 32))
      :lt

      iex> compare(new(<<11>>, 32), new(<<10>>, 32))
      :gt

      iex> compare(new(<<10>>, 32), new(<<10>>, 32))
      :eq

      iex> compare(new(<<10>>, 32), new(<<10>>, 128))
      %PrefixError{
        id: :compare,
        detail: {%Prefix{bits: <<10>>, maxlen: 32}, %Prefix{bits: <<10>>, maxlen: 128}}
      }

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
  def compare(x, y), do: error(:compare, {x, y})

  defp comparep(x, y) when bit_size(x) > bit_size(y), do: :lt
  defp comparep(x, y) when bit_size(x) < bit_size(y), do: :gt
  defp comparep(x, y) when x < y, do: :lt
  defp comparep(x, y) when x > y, do: :gt
  defp comparep(x, y) when x == y, do: :eq

  @doc """
  Contrast two prefixes.

  Contrasting two prefixes will yield one of:
  - `:equal` prefix1 is equal to prefix2
  - `:more` prefix1 is a more specific version of prefix2
  - `:less` prefix1 is a less specific version of prefix2
  - `:left` prefix1 is left-adjacent to prefix2
  - `:right` prefix1 is right-adjacent to prefix2
  - `:disjoint` prefix1 has no match with prefix2 whatsoever.

  ## Examples

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 10>>, 32))
      :equal

      iex> contrast(new(<<10, 10, 10>>, 32), new(<<10, 10>>, 32))
      :more

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 10, 10>>, 32))
      :less

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 11>>, 32))
      :left

      iex> contrast(new(<<10, 11>>, 32), new(<<10, 10>>, 32))
      :right

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 12>>, 32))
      :disjoint

  """
  @spec contrast(t, t) :: atom
  def contrast(prefix1, prefix2)
  def contrast(x, y) when valid?(x, y), do: contrastp(x.bits, y.bits)
  def contrast(x, _) when is_exception(x), do: x
  def contrast(_, y) when is_exception(y), do: y
  def contrast(x, y), do: error(:contrast, {x, y})

  # contrast the bits
  defp contrastp(x, y) when x == y, do: :equal

  defp contrastp(x, y) when bit_size(x) > bit_size(y) do
    if y == truncate(x, bit_size(y)),
      do: :more,
      else: :disjoint
  end

  defp contrastp(x, y) when bit_size(x) < bit_size(y) do
    if x == truncate(y, bit_size(x)),
      do: :less,
      else: :disjoint
  end

  defp contrastp(x, y) do
    size = bit_size(x) - 1
    <<n::bitstring-size(size), n1::1>> = x
    <<m::bitstring-size(size), _::1>> = y

    if n == m do
      if n1 == 0,
        do: :left,
        else: :right
    else
      :disjoint
    end
  end
end

defimpl String.Chars, for: Prefix do
  def to_string(prefix) do
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

  # invalid Prefix yields a count of 0
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
    do: [Prefix.member(pfx, n)]

  defp slicep(pfx, n),
    do: slicep(pfx, n - 1) ++ [Prefix.member(pfx, n)]

  def reduce(pfx, acc, fun),
    do: reduce(pfx, acc, fun, _idx = 0, _max = Prefix.size(pfx))

  defp reduce(_pfx, {:halt, acc}, _fun, _idx, _max),
    do: {:halted, acc}

  defp reduce(pfx, {:suspend, acc}, fun, idx, max),
    do: {:suspended, acc, &reduce(pfx, &1, fun, idx, max)}

  defp reduce(pfx, {:cont, acc}, fun, idx, max) when idx < max,
    do: reduce(pfx, fun.(Prefix.member(pfx, idx), acc), fun, idx + 1, max)

  defp reduce(_pfx, {:cont, acc}, _fun, _idx, _max),
    do: {:done, acc}
end
