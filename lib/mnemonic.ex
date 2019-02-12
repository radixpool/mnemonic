defmodule Mnemonic do
  @moduledoc """
  BIP39 Implementation
  """

  alias Mnemonic.{Crypto, Wordlist}

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

  @valid_entropy_length [128, 160, 192, 224, 256]
  @valid_mnemonic_length [12, 15, 18, 21, 24]

  # SEE: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
  @ideographic_space "\u3000"

  defguardp valid_ent?(ent) when ent in @valid_entropy_length
  defguardp valid_entropy?(entropy) when valid_ent?(bit_size(entropy))
  defguardp supported_lang?(lang) when lang in @languages

  @typedoc """
  Supported mnemonic languages
  """
  @type language ::
          :english
          | :chinese_simplified
          | :chinese_traditional
          | :french
          | :italian
          | :japanese
          | :korean
          | :spanish

  @doc ~S"""
  Generate mnemonic sentences with given entropy length(in bits) and mnemonic language.
  Allowed entropy length are 128, 160, 192, 224 and 256. Supported languages are English, 
  Chinese(Simplified), Chinese(Tranditional), Japanese, Korean, Spanish, French and Italian.
  """
  @spec generate(ent :: integer(), lang :: language()) :: String.t() | {:error, term()}
  def generate(ent, lang) when valid_ent?(ent) and supported_lang?(lang) do
    ent
    |> generate_entropy()
    |> from_entropy(lang)
  end

  def generate(_, _), do: {:error, :invalid_entropy_length_or_language}

  @doc ~S"""
  Generate mnemonic sentences with given entropy and mnemonic language. The bits size of entropy
  should be in 128, 160, 192, 224 and 256. Supported languages are English, Chinese(Simplified), 
  Chinese(Tranditional), Japanese, Korean, Spanish, French and Italian.

  ## Examples

      iex> entropy = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      iex> Mnemonic.from_entropy(entropy, :english)
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

  """
  @spec from_entropy(entropy :: binary(), lang :: language()) :: String.t() | {:error, term()}
  def from_entropy(entropy, lang) when valid_entropy?(entropy) and supported_lang?(lang) do
    entropy
    |> append_checksum()
    |> generate_mnemonic(lang)
  end

  @doc ~S"""
  Generate seed by given mnemonic, passphrase and language. The seed is 64 bytes.

  ## Examples

      iex> mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      iex> Mnemonic.to_seed(mnemonic, "TREZOR", :english)
      <<197, 82, 87, 195, 96, 192, 124, 114, 2, 154, 235, 193, 181, 60, 5, 237, 3, 98,
        173, 163, 142, 173, 62, 62, 158, 250, 55, 8, 229, 52, 149, 83, 31, 9, 166, 152, 
        117, 153, 209, 130, 100, 193, 225, 201, 47, 44, 241, 65, 99, 12, 122, 60, 74, 
        183, 200, 27, 47, 0, 22, 152, 231, 70, 59, 4>>

  """
  @spec to_seed(mnemonic :: String.t(), passphrase :: String.t(), lang :: language()) ::
          binary | {:error, term()}
  def to_seed(mnemonic, passphrase \\ "", lang) when is_binary(mnemonic) do
    with mnemonic = normalize(mnemonic),
         {:ok, _entropy} <- validate(mnemonic, lang) do
      Crypto.pbkdf2(&Crypto.hmac_sha512/2, mnemonic, salt(passphrase), 2048)
    end
  end

  @doc ~S"""
  Check the given mnemonic is valid or not.

  ## Examples

      iex(17)> mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      iex(19)> Mnemonic.validate(mnemonic, :english)
      {:ok, <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>}
  """
  @spec validate(mnemonic :: String.t(), lang :: language()) :: {:ok, binary()} | {:error, term()}
  def validate(mnemonic, lang) when is_binary(mnemonic) and supported_lang?(lang) do
    mnemonic
    |> mnemonic_to_words()
    |> words_to_checksummed_entropy(lang)
    |> checksummed_entropy_to_entropy()
  end

  defp salt(passphrase), do: normalize("mnemonic" <> passphrase)

  defp generate_entropy(ent) do
    ent
    |> div(8)
    |> :crypto.strong_rand_bytes()
  end

  defp append_checksum(entropy) do
    cs =
      entropy
      |> bit_size()
      |> div(32)

    <<checksum::bits-size(cs), _rest::bits>> = Crypto.sha256(entropy)
    <<entropy::bits, checksum::bits>>
  end

  defp generate_mnemonic(entropy, lang) do
    joiner =
      case lang do
        :japanese -> @ideographic_space
        _otherwise -> " "
      end

    entropy
    |> split_to_group()
    |> Enum.map(&Wordlist.at(lang, &1))
    |> Enum.join(joiner)
  end

  defp split_to_group(entropy) do
    do_split_to_group(entropy, [])
  end

  defp do_split_to_group(<<>>, groups), do: groups

  defp do_split_to_group(<<group::11, rest::bits>>, groups) do
    do_split_to_group(rest, groups ++ [group])
  end

  defp mnemonic_to_words(mnemonic) do
    mnemonic
    |> String.trim()
    |> normalize()
    |> String.split(" ")
    |> case do
      words when length(words) in @valid_mnemonic_length -> {:ok, words}
      _otherwise -> {:error, :invalid_words}
    end
  end

  defp words_to_checksummed_entropy({:error, error}, _lang), do: {:error, error}

  defp words_to_checksummed_entropy({:ok, words}, lang) when is_list(words) do
    indexes = Enum.map(words, &Wordlist.find_index(lang, &1))

    case Enum.any?(indexes, &is_nil(&1)) do
      true ->
        {:error, :invalid_words}

      false ->
        checksummed_entropy =
          indexes
          |> Enum.reverse()
          |> Enum.reduce(<<>>, &<<&1::11, &2::bits>>)

        {:ok, checksummed_entropy}
    end
  end

  defp checksummed_entropy_to_entropy({:error, error}), do: {:error, error}

  defp checksummed_entropy_to_entropy({:ok, checksummed_entropy}) do
    checksummed_entropy
    |> extract_entropy()
    |> validate_checksum()
  end

  defp extract_entropy(checksummed_entropy) when is_bitstring(checksummed_entropy) do
    ent =
      bit_size(checksummed_entropy)
      |> Kernel.*(32)
      |> div(33)

    cs = div(ent, 32)

    with <<entropy::bits-size(ent), checksum::bits-size(cs)>> <- checksummed_entropy do
      {:ok, entropy, checksum}
    else
      _error -> {:error, :invalid_mnemonic}
    end
  end

  defp validate_checksum({:error, error}), do: {:error, error}

  defp validate_checksum({:ok, entropy, checksum}) do
    cs = bit_size(checksum)

    <<valid_checksum::bits-size(cs), _rest::bits>> = Crypto.sha256(entropy)

    if valid_checksum == checksum do
      {:ok, entropy}
    else
      {:error, :invalid_mnemonic_checksum}
    end
  end

  defp normalize(string), do: :unicode.characters_to_nfkd_binary(string)
end
