defmodule Mnemonic.Wordlist do
  @moduledoc false

  @languages [
    :english,
    :chinese_simplified,
    :chinese_traditional,
    :french,
    :italian,
    :japanese,
    :korean,
    :spanish
  ]

  for lang <- @languages do
    @words :mnemonic
           |> :code.priv_dir()
           |> Path.join("/words/#{lang}.txt")
           |> File.stream!()
           |> Stream.map(&String.trim/1)
           |> Enum.to_list()

    def at(unquote(lang), index), do: Enum.at(@words, index)

    def find_index(unquote(lang), word) do
      Enum.find_index(@words, &(&1 === word))
    end
  end
end
