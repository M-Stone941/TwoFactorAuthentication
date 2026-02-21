require_relative "encryptionUtilities"
require 'securerandom'

SBOXHEX =[
  %w[63 	7c 	77 	7b 	f2 	6b 	6f 	c5 	30 	01 	67 	2b 	fe 	d7 	ab 	76 ],
  %w[ca 	82 	c9 	7d 	fa 	59 	47 	f0 	ad 	d4 	a2 	af 	9c 	a4 	72 	c0 ],
 	%w[b7 	fd 	93 	26 	36 	3f 	f7 	cc 	34 	a5 	e5 	f1 	71 	d8 	31 	15 ],
 	%w[04 	c7 	23 	c3 	18 	96 	05 	9a 	07 	12 	80 	e2 	eb 	27 	b2 	75 ],
 	%w[09 	83 	2c 	1a 	1b 	6e 	5a 	a0 	52 	3b 	d6 	b3 	29 	e3 	2f 	84 ],
 	%w[53 	d1 	00 	ed 	20 	fc 	b1 	5b 	6a 	cb 	be 	39 	4a 	4c 	58 	cf ],
 	%w[d0 	ef 	aa 	fb 	43 	4d 	33 	85 	45 	f9 	02 	7f 	50 	3c 	9f 	a8 ],
 	%w[51 	a3 	40 	8f 	92 	9d 	38 	f5 	bc 	b6 	da 	21 	10 	ff 	f3 	d2 ],
 	%w[cd 	0c 	13 	ec 	5f 	97 	44 	17 	c4 	a7 	7e 	3d 	64 	5d 	19 	73 ],
 	%w[60 	81 	4f 	dc 	22 	2a 	90 	88 	46 	ee 	b8 	14 	de 	5e 	0b 	db ],
 	%w[e0 	32 	3a 	0a 	49 	06 	24 	5c 	c2 	d3 	ac 	62 	91 	95 	e4 	79 ],
 	%w[e7 	c8 	37 	6d 	8d 	d5 	4e 	a9 	6c 	56 	f4 	ea 	65 	7a 	ae 	08 ],
 	%w[ba 	78 	25 	2e 	1c 	a6 	b4 	c6 	e8 	dd 	74 	1f 	4b 	bd 	8b 	8a ],
 	%w[70 	3e 	b5 	66 	48 	03 	f6 	0e 	61 	35 	57 	b9 	86 	c1 	1d 	9e ],
 	%w[e1 	f8 	98 	11 	69 	d9 	8e 	94 	9b 	1e 	87 	e9 	ce 	55 	28 	df ],
 	%w[8c 	a1 	89 	0d 	bf 	e6 	42 	68 	41 	99 	2d 	0f 	b0 	54 	bb 	16 ]
]

SBOXDECIMAL = SBOXHEX.map do |a|
  a.map { |x|x.to_i(16) }
end



def aes256encrypt(plaintext, key)
  plaintext = pad_message(plaintext)
  plaintext = string_to_hex(plaintext)
  block_count = plaintext.length/32
  ciphertext = ""
  (0..block_count - 1).each { |i|
    block = plaintext[i... i + 31]
    ciphertext += aes256encryptblock(block, key)
  }
end

def aes256encryptblock(block, key)
  #NUMBER_OF_ROUNDS = 14
  #
  #expandedKey = key_expansion(key)
  #get roundKey1 from expandedKey
  # block = add_round_key(block, expandedKey, 0)
  #for round from 1 to NUMBER_OF_ROUNDS-1
  #   block = subbytes(block)
  #   block = shiftrows(block)
  #   block = mixcolumns(block)
  #   block = addRoundKey(block, expandedKey, round)

  #block = subbytes(block)
  #block = shiftrows(block)
  #block = addRoundKey(block, expandedKey, 14)
  puts "aes256encryptblock hasn't been coded yet"
  block
end

def key_expansion(key)
end

def add_round_key(block,expanded_key,round_num)
end

def sub_bytes(block)
end

def shift_rows(block)
end

def mix_columns(block)
end




def aes256decrypt(ciphertext, key)
end

def aes_encryption_menu
  puts "Please enter the message to be encrypted: "
  plaintext = gets.chomp
  puts "Would you like to choose a 16 character key yourself, or have one randomly generated?"
  response = ""
  while (response != "1") and (response != "2")
    puts "Press 1 to choose your own key, or press 2 to have one automatically generated:"
    response = gets.chomp
  end
  if response == "1"
    key = ""
    while key.length != 16
      puts "Please enter a 16 character key to encrypt the message with:"
      key = gets.chomp
      if key.length < 16
        puts "That is too short to be a key"
      elsif key.length > 16
        puts "That is too long to be a key"
      end
    end
  else
    key = SecureRandom.alphanumeric(16)
  end
  printf "Your key is: %s\n", key
  puts "You will need to save the key in order to decrypt the message.\n\n"
  printf "The encrypted message is %s\n\n",aes256encrypt(plaintext, key)
end

def aes_decryption_menu
  puts "Please enter the message to be decrypted: "
  ciphertext = gets.chomp
  puts "Please enter the key used to encrypt the message:"
  key = gets.chomp
  aes256decrypt(ciphertext, key)
end