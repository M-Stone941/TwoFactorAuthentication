# frozen_string_literal: true

require 'rspec'
require_relative '../twofish'
require_relative '../encryptionUtilities'

RSpec.describe 'Twofish' do
  context 'encrypt' do
    it 'encrypts a single block correctly' do
      key=hex_to_dec_array("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF")
      plaintext = hex_to_dec_array("00000000000000000000000000000000")
      ciphertext = hex_to_dec_array("37527BE0052334B89F0CFCCAE87CFA20")

      expect(twofish_encrypt_block(plaintext, key).flatten).to eq(ciphertext)
    end

    it 'encrypts multiple block correctly' do
      key=hex_to_dec_array("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF")
      plaintext = hex_to_dec_array("0000000000000000000000000000000000000000000000000000000000000000")
      ciphertext = hex_to_dec_array("37527BE0052334B89F0CFCCAE87CFA2037527BE0052334B89F0CFCCAE87CFA20")

      expect(twofish_encrypt(plaintext, key, FalseClass).flatten).to eq(ciphertext)
    end

  end

  context 'decrypt' do
    it 'decrypts a single block correctly' do
      key=hex_to_dec_array("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF")
      ciphertext = hex_to_dec_array("37527BE0052334B89F0CFCCAE87CFA20")
      plaintext = hex_to_dec_array("00000000000000000000000000000000")

      expect(twofish_decrypt_block(ciphertext, key).flatten).to eq(plaintext)
    end

    it 'decrypts multiple blocks correctly' do
      key=hex_to_dec_array("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF")
      ciphertext = hex_to_dec_array("37527BE0052334B89F0CFCCAE87CFA2037527BE0052334B89F0CFCCAE87CFA20")
      plaintext = hex_to_dec_array("0000000000000000000000000000000000000000000000000000000000000000")

      expect(twofish_decrypt(ciphertext, key).flatten).to eq(plaintext)
    end
  end
end

