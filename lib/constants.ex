defmodule Iptrie.Constants do
  @moduledoc false

  use Bitwise

  defmacro __using__(_) do
    quote do
      @ip4 <<0::1>>
      @ip4_chunk 8
      @ip4_label 8
      @ip4_masks 0..32
      @ip4_maxlen 32
      @ip4_digits 4
      @ip4_digit 0..255

      @ip6 <<1::1>>
      @ip6_chunk 16
      @ip6_label 4
      @ip6_masks 0..128
      @ip6_maxlen 128
      @ip6_digits 8
      @ip6_digit 0..65535

      @all_ones <<65535::16, 65535::16, 65535::16, 65535::16, 65535::16, 65535::16, 65535::16,
                  65535::16>>
      @all_zeros <<0::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0::16>>
      @all_size 0..128
    end
  end
end
