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

INVERSESBOXHEX = [
  %w[52 	09 	6a 	d5 	30 	36 	a5 	38 	bf 	40 	a3 	9e 	81 	f3 	d7 	fb],
 	%w[7c 	e3 	39 	82 	9b 	2f 	ff 	87 	34 	8e 	43 	44 	c4 	de 	e9 	cb],
 	%w[54 	7b 	94 	32 	a6 	c2 	23 	3d 	ee 	4c 	95 	0b 	42 	fa 	c3 	4e],
 	%w[08 	2e 	a1 	66 	28 	d9 	24 	b2 	76 	5b 	a2 	49 	6d 	8b 	d1 	25],
 	%w[72 	f8 	f6 	64 	86 	68 	98 	16 	d4 	a4 	5c 	cc 	5d 	65 	b6 	92],
 	%w[6c 	70 	48 	50 	fd 	ed 	b9 	da 	5e 	15 	46 	57 	a7 	8d 	9d 	84],
 	%w[90 	d8 	ab 	00 	8c 	bc 	d3 	0a 	f7 	e4 	58 	05 	b8 	b3 	45 	06],
 	%w[d0 	2c 	1e 	8f 	ca 	3f 	0f 	02 	c1 	af 	bd 	03 	01 	13 	8a 	6b],
 	%w[3a 	91 	11 	41 	4f 	67 	dc 	ea 	97 	f2 	cf 	ce 	f0 	b4 	e6 	73],
 	%w[96 	ac 	74 	22 	e7 	ad 	35 	85 	e2 	f9 	37 	e8 	1c 	75 	df 	6e],
 	%w[47 	f1 	1a 	71 	1d 	29 	c5 	89 	6f 	b7 	62 	0e 	aa 	18 	be 	1b],
 	%w[fc 	56 	3e 	4b 	c6 	d2 	79 	20 	9a 	db 	c0 	fe 	78 	cd 	5a 	f4],
 	%w[1f 	dd 	a8 	33 	88 	07 	c7 	31 	b1 	12 	10 	59 	27 	80 	ec 	5f],
 	%w[60 	51 	7f 	a9 	19 	b5 	4a 	0d 	2d 	e5 	7a 	9f 	93 	c9 	9c 	ef],
 	%w[a0 	e0 	3b 	4d 	ae 	2a 	f5 	b0 	c8 	eb 	bb 	3c 	83 	53 	99 	61],
 	%w[17 	2b 	04 	7e 	ba 	77 	d6 	26 	e1 	69 	14 	63 	55 	21 	0c 	7d]
]

INVERSESBOXDECIMAL = INVERSESBOXHEX.map do |a|
  a.map { |x|x.to_i(16) }
end

Nk = 8 #number of words in key (each word is 4 characters ie 32 bits long)
Nr = 14 #number of rounds that the algorithm is run

Rcon =[ #Round constant - used in key expansion
  [1,0,0,0],
  [2,0,0,0],
  [4,0,0,0],
  [8,0,0,0],
  [16,0,0,0],
  [32,0,0,0],
  [64,0,0,0],
  [128,0,0,0],
  [27,0,0,0],
  [54,0,0,0]
]

GaloisFieldReductionConstant = 283
# need to use this to do multiplication in the Galois Field (2^8)
# 283 in binary is 1 0001 1011 which represents the polynomial x^8 + x^4 + x^3 + x + 1

MixColumnsConstant = [
  [2,3,1,1],
  [1,2,3,1],
  [1,1,2,3],
  [3,1,1,2]
]

InverseMixColumnsConstant = [
  [14,11,13,9],
  [9,14,11,13],
  [13,9,14,11],
  [11,13,9,14]
]

def sbox(byte, inverse)
  column = byte.div(16)
  row = byte.modulo(16)
  if inverse==FalseClass
    result = SBOXDECIMAL[column][row]
  else
    result = INVERSESBOXDECIMAL[column][row]
  end
  result
end

def rotWord(word)
  rotatedWord = [0,0,0,0]
  rotatedWord[0] = word[1]
  rotatedWord[1] = word[2]
  rotatedWord[2] = word[3]
  rotatedWord[3] = word[0]
  rotatedWord
end

def subWord(word)
  [sbox(word[0]), sbox(word[1]), sbox(word[2]), sbox(word[3])]
end

def key_expansion(key)
  i = 0
  expandedKey = []
  # first 8 words of the key are the same as the original key
  while i <= Nk-1
    expandedKey[i] = key[(4*i)..(4*i+3)]
    i += 1
  end

  while i <= (4*Nr + 3)
    #printf "Round %i\n",i
    temp = expandedKey[i-1]
    # print "Temp: "
    # printInHex(temp)
    if i.modulo(Nk) == 0
=begin
      print "After rotword: "
      printInHex(rotWord(temp))
      print "After subword: "
      printInHex(subWord(rotWord(temp)))
      print "Rcon[i/Nk]: "
      print Rcon[i/Nk]
      printInHex(Rcon[i/Nk])
      print "After xor: "
      subWord(rotWord(temp)).zip(Rcon[i/Nk-1]).each do |x, y|
        printf "x is %s\n",x.to_s(16)
        printf "y is %s\n",y.to_s(16)
        printf "x xor y is %s\n", (x^y).to_s(16)
      end
=end

      temp = subWord(rotWord(temp)).zip(Rcon[i/Nk-1]).map { |array| array[0]^array[1] }
    elsif (Nk>6) and (i.modulo(Nk) == 4)
      temp = subWord(temp)
    end
    expandedKey[i] = expandedKey[i-Nk].zip(temp).map { |array| array[0]^array[1] }
    i += 1
  end
  expandedKey

end

#testKey = [96, 61, 235, 16, 21, 202, 113, 190, 43, 115, 174, 240, 133, 125, 119, 129, 31, 53, 44, 7, 59, 97, 8, 215, 45, 152, 16, 163, 9, 20, 223, 244]
#result = key_expansion(testKey)
#result.each { |i| printInHex(i) }


def add_round_key(state,roundKey)
  (0..3).each do |i|
    (0..3).each do |j|
      state[i][j] = state[i][j]^roundKey[i][j]
    end
  end
  state
end

def sub_bytes(state,inverse=FalseClass)
  (0..3).each { |i|
    (0..3).each { |j|
      state[i][j] = sbox(state[i][j], inverse)
    }
  }
  state
end

def shift_rows(state, inverse=FalseClass)
  newState = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
  if inverse==FalseClass
    (0..3).each { |i|
      (0..3).each { |j|
        new_i = (i-j)%4
        newState[new_i][j] = state[i][j]
      }
    }
  else
      (0..3).each { |i|
        (0..3).each { |j|
          new_i = (i+j)%4
          newState[new_i][j] = state[i][j]
        }
      }
  end
    newState
end

def xTimes(number)
  # multiplies by two in the Galois field 2^8
  if number.div(128)==0
    number*2
  else
    (number*2)^GaloisFieldReductionConstant
  end
end

def galoisTimes(number1, number2)
  # multiply two numbers in the galois field 2^8
  sum = 0
  index = 0
  while number2 > 0
    remainder = number2 % 2
    if remainder == 1
      temp = number1
      index.times do |i|
        temp = xTimes(temp)
      end
      sum = sum^temp
    end
    number2 = number2 / 2
    index += 1
  end
  sum
end

def mix_single_column(column,inverse)
  result = [0,0,0,0]
  (0..3).each do |i|
    if inverse==FalseClass
      row = MixColumnsConstant[i]
    else
      row = InverseMixColumnsConstant[i]
    end
    sum = 0
    (0..3).each do |j|
      sum = sum^galoisTimes(column[j],row[j])
    end
    result[i] = sum
  end
  result
end

def mix_columns(state, inverse=FalseClass)
  (0..3).each do |i|
    column = [state[i][0],state[i][1],state[i][2],state[i][3]]
    mixedColumn = mix_single_column(column,inverse)
    state[i][0] = mixedColumn[0]
    state[i][1] = mixedColumn[1]
    state[i][2] = mixedColumn[2]
    state[i][3] = mixedColumn[3]
  end
  state
end

#puts mix_single_column([99, 71, 162, 240])
#puts mix_columns([242, 10, 34, 92 ])
#puts mix_columns([198, 198, 198, 198])
#puts mix_columns([212, 212, 212, 213])
#puts mix_columns([45, 38, 49, 76 ])
#

def aes256encryptblock(block, key)
  state = []
  state.push(block[0..3])
  state.push(block[4..7])
  state.push(block[8..11])
  state.push(block[12..15])

  expandedKey = key_expansion(key)
  roundKey0 = expandedKey[0..3]
  state = add_round_key(state, roundKey0)
  #puts "After key addition" #correct
  #printInHex(state)
  roundNum = 1
  while roundNum <= (Nr - 1)
    state = sub_bytes(state)
    #puts "after subbytes" #correct
    #printInHex(state)
    state = shift_rows(state)
    #puts "After shift rows"
    #printInHex(state) #correct
    state = mix_columns(state)
    #puts "After mix columns"
    #printInHex(state) #correct
    state = add_round_key(state, expandedKey[4*roundNum..(4*roundNum + 3)])
    #puts "After round #{roundNum}" #correct
    #printInHex(state)
    roundNum += 1
  end

  state = sub_bytes(state)
  state = shift_rows(state)
  state = add_round_key(state, expandedKey[4*Nr..(4*Nr + 3)])

  state
end

#block = "6BC1BEE2 2E409F96 E93D7E11 7393172A".split.join("")
#key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join("")

#result = aes256encryptblock(hex_to_dec_array(block),hex_to_dec_array(key))
#puts "result is: "
#printInHex(result)

def aes256encrypt(plaintext, key, unconvertedText=TrueClass)
  intArray = []
  if unconvertedText==TrueClass
    plaintext = pad_message(plaintext)
    intArray = string_to_ascii(plaintext)
  else
    intArray = plaintext
  end
  block_count = intArray.length/16
  ciphertext = []
  (0..block_count - 1).each { |i|
    block = intArray[i*16..i*16 + 15]
    encryptedBlock = aes256encryptblock(block, key)
    ciphertext.push(encryptedBlock)
  }
  ciphertext
end

=begin
plainText = "6BC1BEE2 2E409F96 E93D7E11 7393172A
AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
30C81C46 A35CE411 E5FBC119 1A0A52EF
F69F2445 DF4F9B17 AD2B417B E66C3710".split.join("")
key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join("")

result = aes256encrypt(hex_to_dec_array(plainText),hex_to_dec_array(key), FalseClass)
puts "result is: "
printInHex(result)
=end

def aes256decryptblock(block, key)
  state = []
  state.push(block[0..3])
  state.push(block[4..7])
  state.push(block[8..11])
  state.push(block[12..15])

  expandedKey = key_expansion(key)
  state = add_round_key(state, expandedKey[4*Nr..(4*Nr + 3)])
  Nr.step(1, -1) do |round|
    state = shift_rows(state,inverse=TrueClass)
    state = sub_bytes(state,inverse=TrueClass)
    state = add_round_key(state, expandedKey[4*round..(4*round + 3)])
    state = mix_columns(state,inverse=TrueClass)
  end
  state = shift_rows(state,inverse=TrueClass)
  state = sub_bytes(state,inverse=TrueClass)
  state = add_round_key(state, expandedKey[0..3])
  state
end

block = "6BC1BEE2 2E409F96 E93D7E11 7393172A".split.join("")
key = "603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4".split.join("")
aes256decryptblock(hex_to_dec_array(block),hex_to_dec_array(key))

def aes256decrypt(ciphertext, key)
  block_count = ciphertext.length/16
  plaintext = []
  (0..block_count - 1).each { |i|
    block = ciphertext[i*16..i*16 + 15]
    decryptedBlock = aes256decryptblock(block, key)
    plaintext.push(decryptedBlock)
  }
  plaintext
end

def aes_encryption_menu
  puts "Please enter the message to be encrypted: "
  plaintext = gets.chomp
  puts "Would you like to choose a 32 character key yourself, or have one randomly generated?"
  response = ""
  while (response != "1") and (response != "2")
    puts "Press 1 to choose your own key, or press 2 to have one automatically generated:"
    response = gets.chomp
  end
  if response == "1"
    key = ""
    while key.length != 32
      puts "Please enter a 32 character key to encrypt the message with:"
      key = gets.chomp
      if key.length < 32
        puts "That is too short to be a key"
      elsif key.length > 32
        puts "That is too long to be a key"
      end
    end
  else
    key = SecureRandom.alphanumeric(32)
  end
  printf "Your key is: %s\n", key
  puts "You will need to save the key in order to decrypt the message.\n\n"
  puts "The encrypted message is: \n"
  printInHex(aes256encrypt(plaintext, string_to_ascii(key)))
end

def aes_decryption_menu
  ciphertextDone = FalseClass
  while ciphertextDone != TrueClass
    puts "Please enter the message to be decrypted."
    puts "It should be written in a hexadecimal format"
    puts "This means that it should use the digits 0-9 and letters a-f only."
    ciphertext = gets.chomp
    ciphertext = ciphertext.split.join("")
    ciphertext = ciphertext.downcase
    if ciphertext =~ /^[0123456789abcdef]+$/
      ciphertext = hex_to_dec_array(ciphertext)
      ciphertextDone = TrueClass
    end
    key = ""
    while key.length != 32
      puts "Please enter the 32 character key that this message was encrypted with:"
      key = gets.chomp
      if key.length < 32
        puts "That is too short"
      elsif key.length > 32
        puts "That is too long"
      end
    end

    message = ascii_to_string(aes256decrypt(ciphertext, key))
    message = unpad_message(message)
    puts "The decrypted message is: #{message}"
  end

end