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

def aes256encrypt(plaintext, key)
  plaintext = pad_message(plaintext)
  asciiArray = string_to_ascii(plaintext)
  block_count = asciiArray.length/16
  ciphertext = ""
  (0..block_count - 1).each { |i|
    block = asciiArray[i... i + 15]
    ciphertext += aes256encryptblock(block, key)
  }
end



def sbox(byte)
  column = byte.div(16)
  row = byte.modulo(16)
  SBOXDECIMAL[column][row]
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
  state.zip(roundKey).map { |pair| pair[0]^pair[1] }
  state
end

def sub_bytes(state)
  range(0..3).each { |i|
    range(0..3).each { |j|
      state[i][j] = sbox(state[i][j])
    }
  }
  state
end

def shift_rows(state)
  range(0..3).each { |rowIndex|
    tempRow = [0,0,0,0]
    range(0..3).each { |colIndex|
      newColIndex = colIndex - rowIndex
      if newColIndex < 0
        newColIndex += 4
      end
      tempRow[newColIndex] = state[colIndex]
    }
    state[rowIndex] = tempRow
  }
  state
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

def mix_columns(state)
  result = [0,0,0,0]
  (0..3).each do |i|
    row = MixColumnsConstant[i]
    sum = 0
    (0..3).each do |j|
      sum = sum^galoisTimes(state[j],row[j])
    end
    result[i] = sum
  end
  result
end

#puts mix_columns([99, 71, 162, 240])
#puts mix_columns([242, 10, 34, 92 ])
#puts mix_columns([ 	198, 198, 198, 198])
#puts mix_columns([212, 212, 212, 213])
#puts mix_columns([45, 38, 49, 76 ])

def aes256encryptblock(block, key)
  puts "aes256encryptblock hasn't been fully coded yet"
  puts "the function mix_columns hasn't been implemented"
  state = []
  state.push(block[0..3])
  state.push(block[4..7])
  state.push(block[8..11])
  state.push(block[12..15])

  expandedKey = key_expansion(key)
  roundKey0 = expandedKey[0..3]
  state = add_round_key(block, roundKey0)
  roundNum = 1
  while roundNum <= (Nr - 1)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state) #hasn't been done yet
    state = add_round_key(block, expandedKey[4*roundNum..(4*roundNum + 3)])
    roundNum += 1
  end

  state = sub_bytes(state)
  state = shift_rows(state)
  state = add_round_key(state, expandedKey[4*Nr..(4*Nr + 3)])

  state
end

#aes256encryptblock([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"abc")


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