# coding: utf-8

require 'openssl'

# 暗号化ファイルのフォーマットは以下記載の通り
# @see https://docs.ansible.com/ansible/2.4/vault.html#vault-payload-format-1-1
module AnsibleVault
  class Base

    # Ansible Vaultヘッダ(1.1)
    FILE_HEADER_11 = "$ANSIBLE_VAULT;1.1;AES256".freeze
    # Ansible Vaultヘッダ(1.2)
    FILE_HEADER_12 = "$ANSIBLE_VAULT;1.2;AES256;".freeze
    # Ansible Vaultヘッダを表す正規表現
    FILE_HEADER_PATTERN = /\A\$ANSIBLE_VAULT;1\.\d;AES(?:256)?(?:;.+)?/
    # 共通鍵・HMAC鍵の長さ
    KEY_LENGTH = 32
    # Initialization Vectorの長さ
    IV_LENGTH = 16
    # 共通鍵生成時の繰り返し回数
    KDF_ITERATIONS = 10_000
    # 共通鍵・HMACを作成する際のハッシュ関数名
    HASH_ALGORITHM = 'SHA256'.freeze
    # 暗号化・復号化を行う方式名
    CIPHER = 'AES-256-CTR'.freeze

    # バイナリの16進表現を返す
    # @param bin_data [String] バイナリ文字列
    # return 16進文字列
    def hexlify(bin_data)
      bin_data.unpack('H*').first
    end

    # 16進表記文字列のバイナリを返す
    # @param hex_data [String] 16進文字列
    # return バイナリ文字列
    def unhexlify(hex_data)
      [hex_data].pack('H*')
    end

    # 暗号化・復号化に使用する共通鍵を作成する
    # @param password [String] パスワード
    # @param salt [String] ソルト
    # @return [Array] 以下を格納した配列
    #   共通鍵・HMACに使う鍵・Initialization Vector
    def derive_keys(password, salt)
      all_length = (2 * KEY_LENGTH + IV_LENGTH)
      key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt,
        KDF_ITERATIONS, all_length, HASH_ALGORITHM)
      cipher_key = key[0,              KEY_LENGTH]
      hmac_key   = key[KEY_LENGTH,     KEY_LENGTH]
      iv         = key[KEY_LENGTH * 2, IV_LENGTH]
      [cipher_key, hmac_key, iv]
    end

    # バイナリ文字列のハッシュ値を求める
    # @param [String] バイナリ文字列
    # @param [String] 利用する鍵
    # @return [String] 16進表記のハッシュ文字列
    def calculated_hmac(cipher_text, hmac_key)
      digest = OpenSSL::Digest.new(HASH_ALGORITHM)
      hmac_algorithm = OpenSSL::HMAC.new(hmac_key, digest)
      hmac_algorithm << cipher_text
      hmac_algorithm.hexdigest
    end

    # 暗号化・復号化器をセットアップする
    # @param mode [Symbol] :encrypt or :decrypt
    # @param cipher_key [String] 暗号鍵
    # @param iv [String] Initialization Vector
    # @return [OpenSSL::Cipher] 暗号化・復号化器
    def cipher(mode, cipher_key, iv)
      OpenSSL::Cipher.new(CIPHER).tap do |cipher|
        cipher.public_send(mode)
        cipher.key = cipher_key
        cipher.iv = iv
      end
    end

  end
end
