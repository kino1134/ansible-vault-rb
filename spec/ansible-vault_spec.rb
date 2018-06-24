# coding: utf-8

require 'spec_helper'

describe AnsibleVault do

  it 'has a version number' do
    expect(AnsibleVault::VERSION).not_to be nil
  end

  before(:context) do
    @password = 'test-vault-password'
    @salt = ['4a6b67ff79f7c495feede7d48cf3831694302eccf3e51c849626429d5473de8b'].pack('H*')
    @plain_file_path = 'spec/data/plain.txt'
    @cipher_file_path = 'spec/data/secret.txt'
    @label_file_path = 'spec/data/secret_label.txt'
    @original_plain_text = File.read(@plain_file_path, encoding: 'ascii-8bit')
    @original_cipher_text = File.read(@cipher_file_path)
    @original_label_text = File.read(@label_file_path)
  end

  it 'decrypt' do
    plain_text = AnsibleVault.decrypt(@original_cipher_text, @password)
    expect(@original_plain_text).to eq(plain_text)
  end

  it 'encrypt' do
    cipher_text = AnsibleVault.encrypt(@original_plain_text, @password, nil, @salt)
    expect(@original_cipher_text).to eq(cipher_text)
  end

  it 'read' do
    dest = 'spec/data/decrypt.txt'
    plain_text = AnsibleVault.read(@cipher_file_path, dest, @password)

    expect(@original_plain_text).to eq(plain_text)
    expect(File.read(@plain_file_path)).to eq(File.read(dest))
  end

  it 'write' do
    dest = 'spec/data/encrypt.txt'
    cipher_text = AnsibleVault.write(@plain_file_path, dest, @password, nil, @salt)

    expect(@original_cipher_text).to eq(cipher_text)
    expect(File.read(@cipher_file_path)).to eq(File.read(dest))
  end

  it 'decrypt_label' do
    plain_text = AnsibleVault.decrypt(@original_label_text, @password)
    expect(@original_plain_text).to eq(plain_text)
  end

  it 'encrypt_label' do
    cipher_text = AnsibleVault.encrypt(@original_plain_text, @password, 'label_test', @salt)
    expect(@original_label_text).to eq(cipher_text)
  end

end
