# coding: utf-8

require 'ansible_vault/base'
require 'securerandom'

module AnsibleVault
  class Encrypter < Base

    # AESにおける1ブロックあたりのバイト数
    BLOCK_SIZE = 16
    # 一行あたりの文字数
    LINE_PER_CHARS = 80

    # @see AnsibleVault.encrypt
    def encrypt(text, password, label=nil, salt=nil)
      if text =~ FILE_HEADER_PATTERN
        STDERR.puts 'すでに暗号化されています。'
        return ''
      end

      header = FILE_HEADER_11
      if (label)
        header = FILE_HEADER_12 + label
      end

      salt ||= SecureRandom.random_bytes(KEY_LENGTH)
      cipher_key, hmac_key, iv = derive_keys(password, salt)

      cipher = cipher(:encrypt, cipher_key, iv)
      cipher_text = cipher.update(padding(text)) + cipher.final
      hmac = calculated_hmac(cipher_text, hmac_key)

      raw_body = [hexlify(salt), hmac, hexlify(cipher_text)].join("\n")
      [header, *split(hexlify(raw_body))].join("\n")
    end

    private

    def padding(str)
      len = BLOCK_SIZE - str.bytesize % BLOCK_SIZE
      str + (len.chr * len)
    end

    def split(str)
      str.scan(/.{,#{LINE_PER_CHARS}}/)
    end
  end
end
