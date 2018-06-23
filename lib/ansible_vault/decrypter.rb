# coding: utf-8

require 'ansible_vault/base'

module AnsibleVault
  class Decrypter < Base

    # @see AnsibleVault.decrypt
    def decrypt(text, password)
      header, salt, hmac, cipher_text = decode_file(text)
      unless header == FILE_HEADER
        STDERR.puts 'すでに復号化されています。'
        return ''
      end

      cipher_key, hmac_key, iv = derive_keys(password, salt)
      unless hmac == calculated_hmac(cipher_text, hmac_key)
        STDERR.puts 'HMACの値が一致しません。'
        return ''
      end

      cipher = cipher(:decrypt, cipher_key, iv)
      text = cipher.update(cipher_text) + cipher.final
      unpadding(text)
    end

    private

    def decode_file(text)
      header, *rest =  text.lines.map(&:chomp)
      salt_str, hmac, rest = unhexlify(rest.join).split("\n", 3)
      cipher_text = unhexlify(rest)
      salt = unhexlify(salt_str)
      [header, salt, hmac, cipher_text]
    end

    def unpadding(text)
      len = text[-1].codepoints.first
      text.sub(/#{len.chr}{#{len}}\z/, '')
    end

  end
end
