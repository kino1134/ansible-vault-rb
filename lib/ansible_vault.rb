# coding: utf-8

require 'ansible_vault/version'
require 'ansible_vault/decrypter'
require 'ansible_vault/encrypter'

module AnsibleVault
  class << self

    # 指定されたファイルをパスワードで暗号化する
    # 空パスワードも一応許可している
    # @param src  [String] 暗号元ファイルパス
    # @param dest [String] 暗号先ファイルパス
    # @param label [String] vault-id ラベル
    # @param password [String] パスワード
    # @param salt [String] ソルトとして使うバイト文字列
    #   指定しなかった場合、ランダム
    # @return [String] 暗号化されたコンテキスト
    #   指定されたファイルがすでに暗号化されていた場合、空文字を返す
    def write(src, dest, password, label=nil, salt=nil)
      cipher_text = encrypt(File.read(src, encoding: 'ascii-8bit', mode: 'rt'), password, label, salt)
      File.write(dest, cipher_text, encoding: 'ascii-8bit', mode: 'rt') unless cipher_text.empty?
      cipher_text
    end

    # 指定されたファイルをパスワードで復号化する
    # @param src  [String] 復号元ファイル
    # @param dest [String] 復号先ファイル
    # @param password [String] パスワード
    # @return [String] 復号化されたコンテキスト
    #   すでに復号化されている・パスワードが間違っている場合、空文字を返す
    def read(src, dest, password)
      plain_text = decrypt(File.read(src, encoding: 'ascii-8bit'), password)
      File.write(dest, plain_text, encoding: 'ascii-8bit') unless plain_text.empty?
      plain_text
    end

    # @see write
    def encrypt(text, password, label=nil, salt=nil)
      Encrypter.new.encrypt(text, password, label, salt)
    end

    # see read
    def decrypt(text, password)
      Decrypter.new.decrypt(text, password)
    end

    # 現時点でのソルトを取得する
    # @param text [String] ボルト文字列
    # @return ソルトを表すバイト文字列
    def salt(text)
      arr = Decrypter.new.decode_file(text)
      arr[1]
    end

  end
end
