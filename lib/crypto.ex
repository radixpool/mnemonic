defmodule Mnemonic.Crypto do
  @moduledoc false

  def pbkdf2(func, password, salt, 1), do: func.(password, <<salt::binary, 1::32>>)

  def pbkdf2(func, password, salt, iterations) when iterations > 1 do
    init_block = func.(password, <<salt::binary, 1::32>>)

    {result, _} =
      Enum.reduce(1..(iterations - 1), {init_block, init_block}, fn _i, {result, curr_block} ->
        next_block = func.(password, curr_block)
        {:crypto.exor(result, next_block), next_block}
      end)

    result
  end

  def hmac_sha512(key, data), do: :crypto.hmac(:sha512, key, data)

  def sha256(data), do: :crypto.hash(:sha256, data)
end
