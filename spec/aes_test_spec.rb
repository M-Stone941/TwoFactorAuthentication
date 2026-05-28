# frozen_string_literal: true

require 'rspec'
require_relative '../aes'
require_relative '../encryptionUtilities'

RSpec.describe 'AES' do
  context 'encrypt' do
    it 'encrypts a single block correctly' do
      plaintext = hex_to_dec_array("6BC1BEE2 2E409F96 E93D7E11 7393172A".split.join(""))
      key = hex_to_dec_array("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join(""))
      expectedCiphertext = hex_to_dec_array("F3EED1BD B5D2A03C 064B5A7E 3DB181F8".split.join(""))

      expect(aes256encrypt(plaintext, key, FalseClass).flatten).to eq(expectedCiphertext)

    end

    it 'encrypts multiple block correctly' do
      plaintext = hex_to_dec_array("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710".split.join(""))
      key = hex_to_dec_array("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join(""))
      expectedCiphertext = hex_to_dec_array("F3EED1BD B5D2A03C 064B5A7E 3DB181F8 591CCB10 D410ED26 DC5BA74A 31362870 B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D 23304B7A 39F9F3FF 067D8D8F 9E24ECC7".split.join(""))

      expect(aes256encrypt(plaintext,key, FalseClass).flatten).to eql expectedCiphertext
    end
  end

  context 'decrypt' do
    it 'decrypts a single block correctly' do
      ciphertext = hex_to_dec_array("F3EED1BD B5D2A03C 064B5A7E 3DB181F8".split.join(""))
      key = hex_to_dec_array("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join(""))
      expectedPlaintext = hex_to_dec_array("6BC1BEE2 2E409F96 E93D7E11 7393172A".split.join(""))

      expect(aes256decryptblock(ciphertext, key).flatten).to eql expectedPlaintext

    end

    it 'decrypts multiple block correctly' do
      ciphertext = hex_to_dec_array("F3EED1BD B5D2A03C 064B5A7E 3DB181F8 591CCB10 D410ED26 DC5BA74A 31362870 B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D 23304B7A 39F9F3FF 067D8D8F 9E24ECC7".split.join(""))
      key = hex_to_dec_array("603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join(""))
      expectedPlaintext = hex_to_dec_array("6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710".split.join(""))

      expect(aes256decrypt(ciphertext, key).flatten).to eql expectedPlaintext
    end
  end
end

