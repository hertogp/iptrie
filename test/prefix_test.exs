defmodule PrefixTest do
  use ExUnit.Case
  doctest PrefixError, import: true
  doctest Prefix, import: true
  import Prefix
  require Prefix
  alias PrefixError
  alias Bitwise, as: B

  # two exceptions
  @pfxError PrefixError.new(:my_id, :my_detail)
  @runError RuntimeError.exception("ouch")

  # an illegal prefix, since bit_size(bits) > maxlen
  @pfxIllegal %Prefix{bits: <<1, 1, 1, 1>>, maxlen: 16}

  # Prefix
  # Guards
  test "valid?() - good input" do
    require Prefix
    pfx = %Prefix{bits: <<1>>, maxlen: 32}
    assert Prefix.valid?(pfx)
  end

  test "valid?() - bad input" do
    pfx = new(<<1, 1, 1>>, 32)
    # make pfx invalid by setting maxlen to be less than the bit size
    pfx = %Prefix{pfx | maxlen: 16}
    refute Prefix.valid?(pfx)
    # can't seem to test other invalid inputs like Prefix.valid?(42)
  end

  # Prefix.new()
  test "new()" do
    # minimal prefix
    pfx = new(<<>>, 0)
    assert is_struct(pfx)
    assert pfx.bits == <<>>
    assert pfx.maxlen == 0

    # with positive maxlen
    pfx = new(<<>>, 48)
    assert is_struct(pfx)
    assert pfx.bits == <<>>
    assert pfx.maxlen == 48

    # bits truncated to maxlen
    pfx = new(<<1, 1, 1, 1>>, 24)
    assert pfx.bits == <<1, 1, 1>>
    assert pfx.maxlen == 24

    # create new prefix out of old one
    # - normally not really useful as it changes the meaning of the prefix
    pfx = Prefix.new(pfx, 16)
    assert pfx.bits == <<1, 1>>
    assert pfx.maxlen == 16

    # bad input yields exception struct
    assert %PrefixError{id: :new} = new(42, 24)
    assert %PrefixError{id: :new} = new(<<1, 1>>, "32")
    assert %PrefixError{id: :new} = new(<<1, 1>>, -32)
    assert %PrefixError{id: :new} = new(@pfxIllegal, 32)

    # bad input: exception struct passthrough
    assert @pfxError == new(@pfxError, 32)
    assert @runError == new(@runError, 128)
  end

  # bit
  test "bit()" do
    # good input
    pfx = new(<<1, 2, 4, 8>>, 32)
    assert bit(pfx, 0) == 0

    assert bit(pfx, 7) == 1

    assert bit(pfx, 14) == 1
    assert bit(pfx, 15) == 0

    assert bit(pfx, 21) == 1
    assert bit(pfx, 22) == 0
    assert bit(pfx, 23) == 0

    assert bit(pfx, 28) == 1
    assert bit(pfx, 29) == 0
    assert bit(pfx, 30) == 0
    assert bit(pfx, 31) == 0

    # bits beyond maxlen are always 0
    assert bit(pfx, pfx.maxlen + 10) == 0

    # bad input
    assert %PrefixError{id: :bit} = bit(42, 0)

    # bad input: exception struct passthrough
    assert @pfxError == bit(@pfxError, 0)
    assert @runError == bit(@runError, 0)
  end

  # Prefix.bnot
  test "bnot()" do
    pfx1 = new(<<1, 2, 4, 8>>, 32)
    pfx2 = new(<<B.bnot(1), B.bnot(2), B.bnot(4), B.bnot(8)>>, 32)
    assert pfx1 == bnot(pfx2)
    assert pfx2 == bnot(pfx1)
    assert pfx1 == pfx1 |> bnot() |> bnot()
    assert pfx2 == pfx2 |> bnot() |> bnot()

    pfx1 = new(<<0, 0, 0, 0>>, 32)
    pfx2 = new(<<255, 255, 255, 255>>, 32)
    assert pfx1 == bnot(pfx2)
    assert pfx2 == bnot(pfx1)
    assert pfx1 == pfx1 |> bnot() |> bnot()
    assert pfx2 == pfx2 |> bnot() |> bnot()

    # bad input yields exception
    assert %PrefixError{id: :bnot} = bnot(42)

    # exceptions are passed through
    assert @pfxError == bnot(@pfxError)
    assert @runError == bnot(@runError)
  end

  # Prefix.band
  test "band()" do
    pfx1 = new(<<1, 2, 4, 8>>, 32)
    pfx2 = new(<<0, 0, 0, 0>>, 32)
    pfx3 = new(<<255, 255, 255, 255>>, 32)
    pfx4 = new(<<255, 255>>, 32)

    # all-zero's -> always all-zero's
    assert pfx2 == band(pfx1, pfx2)
    assert pfx2 == band(pfx2, pfx1)
    assert pfx2 == band(pfx2, pfx2)

    # all-one's -> always org prefix
    assert pfx1 == band(pfx1, pfx3)
    assert pfx1 == band(pfx3, pfx1)
    assert pfx3 == band(pfx3, pfx3)

    # shorter prefix is extended with 0's to fit longest prefix
    assert band(pfx1, pfx4) == new(<<1, 2, 0, 0>>, 32)
    assert band(pfx4, pfx1) == new(<<1, 2, 0, 0>>, 32)

    # bad input
    assert %PrefixError{id: :band} = band(@pfxIllegal, pfx1)
    assert %PrefixError{id: :band} = band("42", pfx1)
    assert %PrefixError{id: :band} = band(42, pfx1)

    # exceptions are passed through
    assert @pfxError == band(@pfxError, pfx1)
    assert @pfxError == band(pfx1, @pfxError)
    assert @runError == band(@runError, pfx1)
    assert @runError == band(pfx1, @runError)
  end

  # Prefix.bor
  test "bor()" do
    pfx1 = new(<<1, 2, 4, 8>>, 32)
    pfx2 = new(<<0, 0, 0, 0>>, 32)
    pfx3 = new(<<255, 255, 255, 255>>, 32)
    pfx4 = new(<<255, 255>>, 32)

    # all-zero's -> always original prefix
    assert pfx1 == bor(pfx1, pfx2)
    assert pfx1 == bor(pfx2, pfx1)
    assert pfx1 == bor(pfx1, pfx1)

    # all-one's -> always all-one's
    assert pfx3 == bor(pfx1, pfx3)
    assert pfx3 == bor(pfx3, pfx1)
    assert pfx3 == bor(pfx3, pfx3)

    # shorter prefix is extended with 0's to fit longest prefix
    assert bor(pfx1, pfx4) == new(<<255, 255, 4, 8>>, 32)
    assert bor(pfx4, pfx1) == new(<<255, 255, 4, 8>>, 32)

    # bad input
    assert %PrefixError{id: :bor} = bor(@pfxIllegal, pfx1)
    assert %PrefixError{id: :bor} = bor("42", pfx1)
    assert %PrefixError{id: :bor} = bor(42, pfx1)

    # exceptions are passed through
    assert @pfxError == bor(@pfxError, pfx1)
    assert @pfxError == bor(pfx1, @pfxError)
    assert @runError == bor(@runError, pfx1)
    assert @runError == bor(pfx1, @runError)
  end

  # Prefix.bxor
  test "bxor()" do
    pfx1 = new(<<1, 2, 4, 8>>, 32)
    pfx2 = new(<<0, 0, 0, 0>>, 32)
    pfx3 = new(<<255, 255, 255, 255>>, 32)
    pfx4 = new(<<255, 255>>, 32)

    # all-zero's -> always original prefix
    assert bxor(pfx1, pfx2) == pfx1
    assert bxor(pfx2, pfx1) == pfx1

    # self -> always all-zero's
    assert bxor(pfx1, pfx1) == new(<<0, 0, 0, 0>>, 32)

    # all-one's -> 255 - <num>
    assert bxor(pfx1, pfx3) == new(<<254, 253, 251, 247>>, 32)
    assert bxor(pfx3, pfx1) == new(<<254, 253, 251, 247>>, 32)

    # shorter prefix is extended with 0's to fit longest prefix
    assert bxor(pfx1, pfx4) == new(<<254, 253, 4, 8>>, 32)
    assert bxor(pfx4, pfx1) == new(<<254, 253, 4, 8>>, 32)

    # bad input
    assert %PrefixError{id: :bxor} = bxor(@pfxIllegal, pfx1)
    assert %PrefixError{id: :bxor} = bxor("42", pfx1)
    assert %PrefixError{id: :bxor} = bxor(42, pfx1)

    # exceptions are passed through
    assert @pfxError == bxor(@pfxError, pfx1)
    assert @pfxError == bxor(pfx1, @pfxError)
    assert @runError == bxor(@runError, pfx1)
    assert @runError == bxor(pfx1, @runError)
  end

  # Prefix.bset
  test "bset()" do
    pfx = new(<<1, 2, 4>>, 32)

    assert bset(pfx, 0) == new(<<0, 0, 0>>, 32)
    assert bset(pfx, 1) == new(<<255, 255, 255>>, 32)

    # bit != 0, means use `1`-bits
    assert bset(pfx, 2) == new(<<255, 255, 255>>, 32)

    # bad input
    assert %PrefixError{id: :bset} = bset(@pfxIllegal, 0)
    assert %PrefixError{id: :bset} = bset("42", 0)
    assert %PrefixError{id: :bset} = bset(42, 0)

    # exceptions are passed through
    assert @pfxError == bset(@pfxError, 0)
    assert @runError == bset(@runError, 1)
  end

  # Prefix.brot
  test "brot()" do
    pfx1 = new(<<1, 2, 4, 8>>, 32)

    # pos shifts, shifts to the right (pos x-axis)
    assert brot(pfx1, 1) == new(<<0, 129, 2, 4>>, 32)
    # n*8 positions means rotating bytes
    assert brot(pfx1, 0) == pfx1
    assert brot(pfx1, 8) == new(<<8, 1, 2, 4>>, 32)
    assert brot(pfx1, 16) == new(<<4, 8, 1, 2>>, 32)
    assert brot(pfx1, 24) == new(<<2, 4, 8, 1>>, 32)
    assert brot(pfx1, 32) == new(<<1, 2, 4, 8>>, 32)
    # round trippin' equals self
    pfx2 = new(<<0xACDC::16, 0x1976::16, 0::96>>, 128)
    assert brot(pfx2, bit_size(pfx2.bits)) == pfx2

    # neg shifts, shift to the left (neg x-axis)
    assert brot(pfx1, -1) == new(<<2, 4, 8, 16>>, 32)
    # n*8 positions means rotating bytes
    assert brot(pfx1, -8) == new(<<2, 4, 8, 1>>, 32)
    assert brot(pfx1, -16) == new(<<4, 8, 1, 2>>, 32)
    assert brot(pfx1, -24) == new(<<8, 1, 2, 4>>, 32)
    assert brot(pfx1, -32) == new(<<1, 2, 4, 8>>, 32)
    # round trippin' equals self
    pfx2 = new(<<0xACDC::16, 0x1976::16, 0::96>>, 128)
    assert brot(pfx2, -bit_size(pfx2.bits)) == pfx2

    # bad input
    assert %PrefixError{id: :brot} = brot(@pfxIllegal, 1)
    assert %PrefixError{id: :brot} = brot("42", 1)
    assert %PrefixError{id: :brot} = brot(42, 1)

    # exceptions are passed through
    assert @pfxError == brot(@pfxError, 0)
    assert @runError == brot(@runError, 0)
  end

  # Prefix.bsl
  test "bsl()" do
    pfx = new(<<255, 255, 255, 255>>, 32)

    # no shift, no effect
    assert bsl(pfx, 0) == pfx

    # pos shift, shifts to the left
    assert bsl(pfx, 1) == new(<<255, 255, 255, 254>>, 32)

    # neg shift, shifts to the right
    assert bsl(pfx, -1) == new(<<127, 255, 255, 255>>, 32)

    # shifting n*8 shifts bytes
    pfx = new(<<1, 2, 4, 8>>, 32)
    assert bsl(pfx, 8) == new(<<2, 4, 8, 0>>, 32)
    assert bsl(pfx, 16) == new(<<4, 8, 0, 0>>, 32)
    assert bsl(pfx, 24) == new(<<8, 0, 0, 0>>, 32)
    assert bsl(pfx, 32) == new(<<0, 0, 0, 0>>, 32)

    assert bsl(pfx, -8) == new(<<0, 1, 2, 4>>, 32)
    assert bsl(pfx, -16) == new(<<0, 0, 1, 2>>, 32)
    assert bsl(pfx, -24) == new(<<0, 0, 0, 1>>, 32)
    assert bsl(pfx, -32) == new(<<0, 0, 0, 0>>, 32)

    # shifting can go on endlessly
    assert bsl(pfx, 100 * bit_size(pfx.bits)) == new(<<0, 0, 0, 0>>, 32)
    assert bsl(pfx, -100 * bit_size(pfx.bits)) == new(<<0, 0, 0, 0>>, 32)

    # bad input
    assert %PrefixError{id: :bsl} = bsl(@pfxIllegal, 1)
    assert %PrefixError{id: :bsl} = bsl("42", 1)
    assert %PrefixError{id: :bsl} = bsl(42, 1)

    # exceptions are passed through
    assert @pfxError == bsl(@pfxError, 0)
    assert @runError == bsl(@runError, 0)
  end

  # Prefix.bsr
  test "bsr()" do
    pfx = new(<<255, 255, 255, 255>>, 32)

    # no shift, no effect
    assert bsr(pfx, 0) == pfx

    # pos shift, shifts to the left
    assert bsr(pfx, 1) == new(<<127, 255, 255, 255>>, 32)

    # neg shift, shifts to the right
    assert bsr(pfx, -1) == new(<<255, 255, 255, 254>>, 32)

    # shifting n*8 shifts bytes
    pfx = new(<<1, 2, 4, 8>>, 32)
    assert bsr(pfx, 8) == new(<<0, 1, 2, 4>>, 32)
    assert bsr(pfx, 16) == new(<<0, 0, 1, 2>>, 32)
    assert bsr(pfx, 24) == new(<<0, 0, 0, 1>>, 32)
    assert bsr(pfx, 32) == new(<<0, 0, 0, 0>>, 32)

    assert bsr(pfx, -8) == new(<<2, 4, 8, 0>>, 32)
    assert bsr(pfx, -16) == new(<<4, 8, 0, 0>>, 32)
    assert bsr(pfx, -24) == new(<<8, 0, 0, 0>>, 32)
    assert bsr(pfx, -32) == new(<<0, 0, 0, 0>>, 32)

    # shifting can go on endlessly
    assert bsr(pfx, 100 * bit_size(pfx.bits)) == new(<<0, 0, 0, 0>>, 32)
    assert bsr(pfx, -100 * bit_size(pfx.bits)) == new(<<0, 0, 0, 0>>, 32)

    # bad input
    assert %PrefixError{id: :bsr} = bsr(@pfxIllegal, 1)
    assert %PrefixError{id: :bsr} = bsr("42", 1)
    assert %PrefixError{id: :bsr} = bsr(42, 1)

    # exceptions are passed through
    assert @pfxError == bsr(@pfxError, 0)
    assert @runError == bsr(@runError, 0)
  end

  # Prefix.padr
  test "padr()" do
    pfx = new(<<1, 2>>, 32)

    # max padding
    assert padr(pfx) == new(<<1, 2, 0, 0>>, 32)
    assert padr(pfx, 0) == new(<<1, 2, 0, 0>>, 32)
    assert padr(pfx, 1) == new(<<1, 2, 255, 255>>, 32)

    # limited padding
    assert padr(pfx, 0, 8) == new(<<1, 2, 0>>, 32)
    assert padr(pfx, 1, 8) == new(<<1, 2, 255>>, 32)
    assert padr(pfx, 0, 7) == new(<<1, 2, 0::size(7)>>, 32)
    assert padr(pfx, 1, 7) == new(<<1, 2, 127::size(7)>>, 32)

    # padding is clipped to max length allowed
    assert padr(pfx, 0, 128) == new(<<1, 2, 0, 0>>, 32)
    assert padr(pfx, 1, 128) == new(<<1, 2, 255, 255>>, 32)

    # bad input
    assert %PrefixError{id: :padr} = padr(@pfxIllegal)
    assert %PrefixError{id: :padr} = padr("42")
    assert %PrefixError{id: :padr} = padr(42)

    # w/ bit to use for padding
    assert %PrefixError{id: :padr} = padr(@pfxIllegal, 0)
    assert %PrefixError{id: :padr} = padr("42", 1)
    assert %PrefixError{id: :padr} = padr(42, 0)

    # w/ bit to use for padding & num bits to add
    assert %PrefixError{id: :padr} = padr(@pfxIllegal, 0, 1)
    assert %PrefixError{id: :padr} = padr("42", 1, 1)
    assert %PrefixError{id: :padr} = padr(42, 0, 1)

    # exceptions are passed through
    assert @pfxError == padr(@pfxError)
    assert @runError == padr(@runError)
    assert @pfxError == padr(@pfxError, 0)
    assert @runError == padr(@runError, 1)
    assert @pfxError == padr(@pfxError, 0, 1)
    assert @runError == padr(@runError, 1, 1)
  end

  # Prefix.padl
  test "padl()" do
    pfx = new(<<1, 2>>, 32)

    # max padding
    assert padl(pfx) == new(<<0, 0, 1, 2>>, 32)
    assert padl(pfx, 0) == new(<<0, 0, 1, 2>>, 32)
    assert padl(pfx, 1) == new(<<255, 255, 1, 2>>, 32)

    # limited padding
    assert padl(pfx, 0, 8) == new(<<0, 1, 2>>, 32)
    assert padl(pfx, 1, 8) == new(<<255, 1, 2>>, 32)
    assert padl(pfx, 0, 7) == new(<<0::size(7), 1, 2>>, 32)
    assert padl(pfx, 1, 7) == new(<<127::size(7), 1, 2>>, 32)

    # padding is clipped to max length allowed
    assert padl(pfx, 0, 128) == new(<<0, 0, 1, 2>>, 32)
    assert padl(pfx, 1, 128) == new(<<255, 255, 1, 2>>, 32)

    # bad input
    assert %PrefixError{id: :padl} = padl(@pfxIllegal)
    assert %PrefixError{id: :padl} = padl("42")
    assert %PrefixError{id: :padl} = padl(42)

    # bad input: w/ bit to use for padding
    assert %PrefixError{id: :padl} = padl(@pfxIllegal, 0)
    assert %PrefixError{id: :padl} = padl("42", 1)
    assert %PrefixError{id: :padl} = padl(42, 0)

    # bad input: w/ bit to use for padding & num bits to add
    assert %PrefixError{id: :padl} = padl(@pfxIllegal, 0, 1)
    assert %PrefixError{id: :padl} = padl("42", 1, 1)
    assert %PrefixError{id: :padl} = padl(42, 0, 1)

    # exceptions are passed through
    assert @pfxError == padl(@pfxError)
    assert @runError == padl(@runError)
    assert @pfxError == padl(@pfxError, 0)
    assert @runError == padl(@runError, 1)
    assert @pfxError == padl(@pfxError, 0, 1)
    assert @runError == padl(@runError, 1, 1)
  end

  # Prefix.slice
  test "slice()" do
    pfx = new(<<10, 11, 12, 0::size(6)>>, 32)

    # get /31's out of /30
    pfxs = slice(pfx, 31)
    assert length(pfxs) == 2
    assert Enum.member?(pfxs, new(<<10, 11, 12, 0::size(7)>>, 32))
    assert Enum.member?(pfxs, new(<<10, 11, 12, 1::size(7)>>, 32))

    # get /32's out of /30
    pfxs = slice(pfx, 32)
    assert length(pfxs) == 4
    assert Enum.member?(pfxs, new(<<10, 11, 12, 0>>, 32))
    assert Enum.member?(pfxs, new(<<10, 11, 12, 1>>, 32))
    assert Enum.member?(pfxs, new(<<10, 11, 12, 2>>, 32))
    assert Enum.member?(pfxs, new(<<10, 11, 12, 3>>, 32))

    # bad input
    assert %PrefixError{id: :slice} = slice(@pfxIllegal, 32)
    assert %PrefixError{id: :slice} = slice("42", 32)
    assert %PrefixError{id: :slice} = slice(42, 32)

    # exceptions are passed through
    assert @pfxError == slice(@pfxError, 32)
    assert @runError == slice(@runError, 32)
  end

  # Prefix.fields
  test "fields()" do
    pfx = new(<<1, 2, 4, 8>>, 32)

    assert fields(pfx, 4) == [{0, 4}, {1, 4}, {0, 4}, {2, 4}, {0, 4}, {4, 4}, {0, 4}, {8, 4}]
    assert fields(pfx, 8) == [{1, 8}, {2, 8}, {4, 8}, {8, 8}]
    assert fields(pfx, 16) == [{258, 16}, {1032, 16}]

    # note last fields only has 8 bits left (32-24)
    # 66052 == (1<<<16) + (2<<<8) + (4)
    assert fields(pfx, 24) == [{66052, 24}, {8, 8}]
    # 16909320 == (1<<<24) + (2<<<16) + (4<<<8) + 8
    assert fields(pfx, 32) == [{16_909_320, 32}]

    assert "00000001000000100000010000001000" ==
             fields(pfx, 1)
             |> Enum.map(fn {n, _w} -> n end)
             |> Enum.join("")

    # bad input
    assert %PrefixError{id: :fields} = fields(@pfxIllegal, 4)
    assert %PrefixError{id: :fields} = fields("42", 4)
    assert %PrefixError{id: :fields} = fields(42, 3)

    # exceptions are passed through
    assert @pfxError == fields(@pfxError, 2)
    assert @runError == fields(@runError, 3)
  end

  # Prefix.digits
  test "digits()" do
    pfx = new(<<1, 2, 3>>, 32)

    # all bits wide
    assert digits(pfx, 32) == {{16_909_056}, 24}
    # 8 bits wide
    assert digits(pfx, 8) == {{1, 2, 3, 0}, 24}
    # 4 bits wide
    assert digits(pfx, 4) == {{0, 1, 0, 2, 0, 3, 0, 0}, 24}
    assert digits(new(<<0xACDC::16>>, 32), 4) == {{10, 12, 13, 12, 0, 0, 0, 0}, 16}

    # 1 bit wide
    assert digits(new(<<170>>, 8), 1) == {{1, 0, 1, 0, 1, 0, 1, 0}, 8}

    # bad input
    assert %PrefixError{id: :digits} = digits(@pfxIllegal, 4)
    assert %PrefixError{id: :digits} = digits("42", 4)
    assert %PrefixError{id: :digits} = digits(42, 3)

    # exceptions are passed through
    assert @pfxError == digits(@pfxError, 2)
    assert @runError == digits(@runError, 3)
  end

  # Prefix.undigits
  test "undigits()" do
    pfx = new(<<1, 2, 3>>, 32)
    d = {{16_909_056}, 24}

    assert undigits(d, 32) == new(<<1, 2, 3>>, 32)

    assert undigits({{1, 2, 3, 0}, 24}, 8) == new(<<1, 2, 3>>, 32)

    assert digits(pfx, 32) |> undigits(32) == pfx

    # 8 digits of 16 bits means maxlen of 128
    # {digits, 32} means bits are 32bits long
    assert undigits({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32}, 16) ==
             new(<<0xACDC::16, 0x1976::16>>, 128)

    # {digits, len}
    # each digit is interpreted as 1-bit wide
    # maxlen is 4*1 = 4 bits max
    # bits size is given by len in  {digits, len}
    assert undigits({{0, 1, 0, 1}, 2}, 1) == new(<<1::size(2)>>, 4)
    assert undigits({{0, 1, 0, 1}, 3}, 1) == new(<<2::size(3)>>, 4)
    assert undigits({{0, 1, 0, 1}, 4}, 1) == new(<<5::size(4)>>, 4)
    # len > numdigits * digitwidth has no effect, since all digits are used
    # with their given width
    assert undigits({{0, 1, 0, 1}, 8}, 1) == new(<<5::size(4)>>, 4)

    # bad input
    assert %PrefixError{id: :digits} = digits(@pfxIllegal, 4)
    assert %PrefixError{id: :digits} = digits("42", 4)
    assert %PrefixError{id: :digits} = digits(42, 3)

    # exceptions are passed through
    assert @pfxError == digits(@pfxError, 2)
    assert @runError == digits(@runError, 3)
  end

  # Prefix.sibling
  test "sibling()" do
    pfx = new(<<1, 2, 0>>, 32)

    assert sibling(pfx, 0) == pfx
    assert sibling(pfx, 1) == new(<<1, 2, 1>>, 32)
    assert sibling(pfx, -1) == new(<<1, 1, 255>>, 32)

    assert sibling(pfx, 255) == new(<<1, 2, 255>>, 32)
    assert sibling(pfx, -255) == new(<<1, 1, 1>>, 32)

    assert sibling(pfx, 256) == new(<<1, 3, 0>>, 32)
    assert sibling(pfx, -256) == new(<<1, 1, 0>>, 32)

    # wrap around, maxlen can be anything and won't change
    pfx = new(<<0, 0, 0>>, 55)
    assert sibling(pfx, -1) == new(<<255, 255, 255>>, 55)

    pfx = new(<<255, 255, 255>>, 44)
    assert sibling(pfx, 1) == new(<<0, 0, 0>>, 44)

    # bad input
    assert %PrefixError{id: :sibling} = sibling(@pfxIllegal, 4)
    assert %PrefixError{id: :sibling} = sibling("42", 4)
    assert %PrefixError{id: :sibling} = sibling(42, 3)

    # exceptions are passed through
    assert @pfxError == sibling(@pfxError, 2)
    assert @runError == sibling(@runError, 3)
  end

  # Prefix.size
  test "size()" do
    # size is determined by the 'spare' bits
    assert size(new(<<1, 1, 1>>, 32)) == 256
    assert size(new(<<1, 1>>, 32)) == 65536
    assert size(new(<<1>>, 32)) == B.bsl(1, 24)

    assert size(new(<<1, 1, 1, 1>>, 32)) == 1
    assert size(new(<<1, 1, 1>>, 24)) == 1
    assert size(new(<<1, 1>>, 16)) == 1
    assert size(new(<<1>>, 8)) == 1
    assert size(new(<<>>, 0)) == 1

    # bad input
    assert %PrefixError{id: :size} = size(@pfxIllegal)
    assert %PrefixError{id: :size} = size("42")
    assert %PrefixError{id: :size} = size(42)

    # exceptions are passed through
    assert @pfxError == size(@pfxError)
    assert @runError == size(@runError)
  end

  # Prefix.member
  test "member()" do
    pfx = new(<<1, 2, 4>>, 32)

    # self is a member at offset 0
    assert member(pfx, 0) == new(<<1, 2, 4, 0>>, 32)
    # last member
    assert member(pfx, 255) == new(<<1, 2, 4, 255>>, 32)
    # wrapping around
    assert member(pfx, 256) == new(<<1, 2, 4, 0>>, 32)

    # sub prefixes are members too, using 2 bits here
    assert member(pfx, 0, 2) == new(<<1, 2, 4, 0::2>>, 32)
    assert member(pfx, 1, 2) == new(<<1, 2, 4, 1::2>>, 32)
    assert member(pfx, 2, 2) == new(<<1, 2, 4, 2::2>>, 32)
    assert member(pfx, 3, 2) == new(<<1, 2, 4, 3::2>>, 32)

    # sub prefixes are members too, using 3 bits here
    assert member(pfx, 0, 3) == new(<<1, 2, 4, 0::3>>, 32)
    assert member(pfx, 1, 3) == new(<<1, 2, 4, 1::3>>, 32)
    assert member(pfx, 2, 3) == new(<<1, 2, 4, 2::3>>, 32)
    # last member
    assert member(pfx, 7, 3) == new(<<1, 2, 4, 7::3>>, 32)

    # sub prefixes are members too, using all bits
    assert member(pfx, 0, 8) == new(<<1, 2, 4, 0>>, 32)
    assert member(pfx, 1, 8) == new(<<1, 2, 4, 1>>, 32)
    # last member
    assert member(pfx, 255, 8) == new(<<1, 2, 4, 255>>, 32)
    assert member(pfx, 256, 8) == new(<<1, 2, 4, 0>>, 32)

    # bad input
    assert %PrefixError{id: :member} = member(@pfxIllegal, 0)
    assert %PrefixError{id: :member} = member(@pfxIllegal, 0, 0)
    assert %PrefixError{id: :member} = member(@pfxIllegal, 0)
    assert %PrefixError{id: :member} = member(@pfxIllegal, 0, 0)
    assert %PrefixError{id: :member} = member("42", 0)
    assert %PrefixError{id: :member} = member("42", 0, 0)
    assert %PrefixError{id: :member} = member(42, 0)
    assert %PrefixError{id: :member} = member(42, 0, 0)

    # exceptions are passed through
    assert @pfxError == member(@pfxError, 0)
    assert @pfxError == member(@pfxError, 0, 0)
    assert @runError == member(@runError, 0)
    assert @runError == member(@runError, 0, 0)

    # bad input
    assert %PrefixError{id: :size} = size(@pfxIllegal)
    assert %PrefixError{id: :size} = size("42")
    assert %PrefixError{id: :size} = size(42)

    # exceptions are passed through
    assert @pfxError == size(@pfxError)
    assert @runError == size(@runError)
  end

  # Prefix.format
  test "format()" do
    pfx = new(<<1, 2, 4>>, 32)

    # defaults are dotted, 8-bit numbers, /len only if bitsize < maxlen
    assert format(pfx) == "1.2.4.0/24"
    # bitstring at maxlen length, so /len is omitted
    assert format(new(<<1, 2, 4, 8>>, 32)) == "1.2.4.8"
    # same, but with non IP prefix
    assert format(new(<<1, 2, 4, 8, 16>>, 40)) == "1.2.4.8.16"

    # different formatting options
    assert format(pfx, width: 8) == "1.2.4.0/24"
    # use 16 bits to create a digit: 0x0102 and 0x0400 (since its padded to 32 bits)
    assert format(pfx, width: 16) == "258.1024/24"
    # base 10
    assert format(pfx, base: 10) == "1.2.4.0/24"
    # base 16 per output digit, so still 16 digits
    assert format(new(<<0xACDC::16, 0x1976::16>>, 128), base: 16) ==
             "AC.DC.19.76.0.0.0.0.0.0.0.0.0.0.0.0/32"

    assert format(new(<<0xACDC::16, 0x1976::16>>, 128), base: 16, unit: 2, ssep: ":") ==
             "ACDC:1976:00:00:00:00:00:00/32"

    assert format(pfx, lsep: "::") == "1.2.4.0::24"
    # group output digits in pairs of 2.
    assert format(pfx, unit: 2) == "12.40/24"
    assert format(pfx, ssep: "-") == "1-2-4-0/24"
    assert format(pfx, padding: false) == "1.2.4/24"
    assert format(pfx, mask: false) == "1.2.4.0"
    assert format(pfx, mask: false, padding: false) == "1.2.4"
    # mostly intended to allow for easy ptr record construction
    assert format(pfx, reverse: true) == "0.4.2.1/24"

    assert format(pfx, reverse: true, padding: false, mask: false) <> ".in-addr.arpa" ==
             "4.2.1.in-addr.arpa"

    # bad input
    assert %PrefixError{id: :format} = format(@pfxIllegal)
    assert %PrefixError{id: :format} = format("42")
    assert %PrefixError{id: :format} = format(42)

    # exceptions are passed through
    assert @pfxError == format(@pfxError)
    assert @runError == format(@runError)
  end

  # Prefix.compare
  test "compare()" do
    pfx = new(<<1, 2, 4>>, 32)

    assert compare(pfx, pfx) == :eq

    assert compare(pfx, new(<<1, 2, 3>>, 32)) == :gt
    assert compare(new(<<1, 2, 3>>, 32), pfx) == :lt

    # less bits means greater than ... more bits quite the opposite
    assert compare(pfx, new(<<1, 2>>, 32)) == :lt
    assert compare(new(<<1, 2>>, 32), pfx) == :gt

    # bad input
    assert %PrefixError{id: :compare} = compare(pfx, @pfxIllegal)
    assert %PrefixError{id: :compare} = compare(@pfxIllegal, pfx)
    assert %PrefixError{id: :compare} = compare(pfx, "42")
    assert %PrefixError{id: :compare} = compare("42", pfx)
    assert %PrefixError{id: :compare} = compare(pfx, 42)
    assert %PrefixError{id: :compare} = compare(42, pfx)

    # exceptions are passed through
    assert @pfxError == compare(pfx, @pfxError)
    assert @pfxError == compare(@pfxError, pfx)
    assert @runError == compare(@runError, pfx)
    assert @runError == compare(pfx, @runError)
  end

  # Prefix.contrast
  test "contrast()" do
    pfx = new(<<1, 2, 4>>, 32)

    assert contrast(pfx, pfx) == :equal

    assert contrast(pfx, new(<<1, 2, 5>>, 32)) == :left
    assert contrast(new(<<1, 2, 5>>, 32), pfx) == :right

    assert contrast(pfx, new(<<1, 2, 4, 0::1>>, 32)) == :less
    assert contrast(new(<<1, 2, 4, 0::1>>, 32), pfx) == :more

    assert contrast(pfx, new(<<1, 2, 6>>, 32)) == :disjoint

    # bad input
    assert %PrefixError{id: :contrast} = contrast(pfx, @pfxIllegal)
    assert %PrefixError{id: :contrast} = contrast(@pfxIllegal, pfx)
    assert %PrefixError{id: :contrast} = contrast(pfx, "42")
    assert %PrefixError{id: :contrast} = contrast("42", pfx)
    assert %PrefixError{id: :contrast} = contrast(pfx, 42)
    assert %PrefixError{id: :contrast} = contrast(42, pfx)

    # exceptions are passed through
    assert @pfxError == contrast(pfx, @pfxError)
    assert @pfxError == contrast(@pfxError, pfx)
    assert @runError == contrast(@runError, pfx)
    assert @runError == contrast(pfx, @runError)
  end

  # String.Chars.to_string
  test "String.Chars.to_string()" do
    # for maxlen 32, defaults to ipv4 addresses
    assert "#{new(<<1, 2, 4>>, 32)}" == "1.2.4.0/24"
    # max length, so /len is omitted
    assert "#{new(<<1, 2, 4, 8>>, 32)}" == "1.2.4.8"

    # maxlen 128 defaults to ipv6 address format (uppercase ...)
    assert "#{new(<<0xACDC::16, 0x1976::16>>, 128)}" == "ACDC:1976:0:0:0:0:0:0/32"

    # maxlen 48 defaults to MAC address format
    assert "#{new(<<0x4C, 0x8D, 0x79, 0x01, 0x02, 0x03>>, 48)}" == "4C:8D:79:1:2:3"

    # anything else comes out as dotted, 8-bit wide decimals
    assert "#{new(<<1, 2, 3, 4, 5>>, 40)}" == "1.2.3.4.5"
    assert "#{new(<<0x4C, 0x8D, 0x79, 0x01, 0x02>>, 40)}" == "76.141.121.1.2"

    # an invalid Prefix raises argument error
    pfx = new(<<1, 2, 4>>, 32)
    pfx = %Prefix{pfx | maxlen: 8}
    assert_raise ArgumentError, fn -> "#{pfx}" end
  end

  # Enumerable.count
  test "Enumerable.count()" do
    import Prefix
    pfx = new(<<1, 2, 4>>, 32)
    err = %Prefix{pfx | maxlen: 16}

    assert Enumerable.count(new(<<1, 2, 4>>, 32)) == {:ok, 256}
    assert Enumerable.count(new(<<1, 2>>, 32)) == {:ok, 65536}
    # empty prefix still counts a 1 prefix
    assert Enumerable.count(new(<<>>, 0)) == {:ok, 1}

    # faulty Prefix's have 0 members ...
    assert Enumerable.count(err) == {:ok, 0}
  end

  # Enumerable.member?
  test "Enumerable.member?()" do
    pfx = new(<<1, 2, 4>>, 32)

    assert Enumerable.member?(pfx, new(<<1, 2, 4, 0::1>>, 32)) == {:ok, true}

    # both prefix's must have the same maxlen
    assert Enumerable.member?(pfx, new(<<1, 2, 4, 0::1>>, 30)) == {:ok, false}
    assert Enumerable.member?(new(<<1, 2, 4, 0::1>>, 30), pfx) == {:ok, false}
  end

  # Enumerable.slice
  # Enumerable.reduce
end
