require_relative "encryptionUtilities"
require_relative 'galoisField'
require 'matrix'

N = 256 #Length of key in bits once padded
K = N/64  #Used in key scheduling - K=4

RS =[   #Used for keyscheduling
  %w[01 A4 55 87 5A 58 DB 9E],
  %w[A4 56 82 F3 1E C6 68 E5],
  %w[02 A1 FC C1 47 AE 3D 19],
  %w[A4 55 87 5A 58 DB 9E 03]
]

RSDECIMAL = RS.map do |a|
  a.map { |x|x.to_i(16) }
end


MDS = [
  %w[01 EF 5B 5B],
  %w[5B EF EF 01],
  %w[EF 5B 01 EF],
  %w[EF 01 EF 5B]
]

MSDECIMAL = MDS.map do |a|
  a.map { |x|x.to_i(16) }
end

Q0SBOX0 = %w[ 8, 1, 7, D, 6, F, 3, 2, 0, B, 5, 9, E, C, A, 4 ]
Q0SBOX0.map { |x|x.to_i(16) }
Q0SBOX1 = %w[ E, C, B, 8, 1, 2, 3, 5, F, 4, A, 6, 7, 0, 9, D ]
Q0SBOX1.map { |x|x.to_i(16) }
Q0SBOX2 = %w[ B, A, 5, E, 6, D, 9, 0, C, 8, F, 3, 2, 4, 7, 1 ]
Q0SBOX2.map { |x|x.to_i(16) }
Q0SBOX3 = %w[ D, 7, F, 4, 1, 2, 6, E, 9, B, 3, 0, 8, 5, C, A ]
Q0SBOX3.map { |x|x.to_i(16) }

Q0SBOXES = [Q0SBOX0, Q0SBOX1, Q0SBOX2, Q0SBOX3]

Q1SBOX0 = %w[ 2, 8, B, D, F, 7, 6, E, 3, 1, 9, 4, 0, A, C, 5 ]
Q1SBOX0.map { |x|x.to_i(16) }
Q1SBOX1 = %w[ 1, E, 2, B, 4, C, 3, 7, 6, D, A, 5, F, 9, 0, 8 ]
Q1SBOX1.map { |x|x.to_i(16) }
Q1SBOX2 = %w[ 4, C, 7, 5, 1, 6, 9, A, 0, E, D, 8, 2, B, 3, F ]
Q1SBOX2.map { |x|x.to_i(16) }
Q1SBOX3 = %w[ B, 9, 5, 1, C, 3, D, E, 6, 4, 7, F, 2, 0, 8, A ]
Q1SBOX3.map { |x|x.to_i(16) }

Q1SBOXES = [Q1SBOX0, Q1SBOX1, Q1SBOX2, Q1SBOX3]

def rotateNibbleRight(nibbleInt, rotationNum)
  #rotates a nibble (4 bits) to the right by a given amount
  # e.g. 13 is 1101 in binary, rotating it right by 1 gives 1110 which is 14
  for i in 0...rotationNum
    if nibbleInt.modulo(2)==0
      nibbleInt = nibbleInt/2
    else
      nibbleInt = nibbleInt/2
      nibbleInt = nibbleInt+8
    end
  end
  nibbleInt
end

def rotateWordLeft(wordArray, rotationNum)
  # rotates a 32 bit word left by a given amount
  # the word is initially stored as an array of 4 integers with values within 0-255
  word = wordToSingleInt(wordArray)
  # now it's a single integer between 0 and (2^32-1)
  for i in 0...rotationNum
    word = word*2
    if word > (2**32)
      word = word - (2**32)
      word = word + 1
    end
  end
  wordToArray(word)
end

def wordToSingleInt(wordAsArray)
  # converts word as an array of 4 ints 0...256, to a single integer 0...(2^32)
  wordAsArray[0]*(256^3) + wordAsArray[1]*(256^2) + wordAsArray[2]*256 + wordAsArray[3]
end

def wordToArray(wordAsInt)
  # converts word represented as a single integer 0...(2^32) to an array of 4 ints 0...256
  wordAsArray = [0,0,0,0]
  wordAsArray[0] = wordAsInt.div(256^3)
  wordAsInt = wordAsInt.modulo(256^3)
  wordAsArray[1] = wordAsInt.div(256^2)
  wordAsInt = wordAsInt.modulo(256^2)
  wordAsArray[2] = wordAsInt.div(256)
  wordAsInt = wordAsInt.modulo(256)
  wordAsArray[3]  = wordAsInt
  wordAsArray
end

def permutation(x,q)
  #x is a byte - represented as an int between 0 and 255
  # q is either 0 or 1 depending on which sboxes should be used
  sboxes = []
  if q == 0
    sboxes = Q0SBOXES
  elsif q == 1
    sboxes = Q1SBOXES
  else
    print "Invalid value of q in permutation()"
  end
  a0 = x.div(16)
  b0 = x.modulo(16)
  a1 = a0^b0
  b1 = a0^(rotateNibbleRight(b0,1))^((8*a0).modulo(16))
  a2 = sboxs[0][a1]
  b2 = sboxes[1][b1]
  a3 = a2^b2
  b3 =a2^(rotateNibbleRight(b2,1))^((8*a2).modulo(16))
  a4 = sboxes[2][a3]
  b4 = sboxes[3][b3]
  y = (16*b4) + a4
  y
end

def twofish_key_schedule(key)
  key = stringToAscii(key)
  while key.length < (N/8)
    key.append(0)
  end
  wordsArray = Array.new(2*K)
  for i in 0..((2*K)-1)
    wordsArray[i] = [key[i*4],key[i*4+1],key[i*4+2],key[i*4+3]]
  end
  #wordsArray has 2K (which is 8) elements.
  # each element is an array of 4 numbers between 0-255 (representing 8 bits)
  arrayMeven = []
  arrayModd = []
  for i in 0..((2*K)-1)
    if (i.even?)
      arrayMeven.append(wordsArray[i])
    else
      arrayModd.append(wordsArray[i])
    end
  end
  arrayS = []
  for i in 0..((2*K)-1)
    word = wordsArray[i]
    resultWord = galoisMatrixMultiply(word, RSDECIMAL)
    arrayS.prepend(resultWord)
  end
  [arrayMeven, arrayModd, arrayS]
end

def twofishF(r0,r1,roundNum,expandedKey,arrayS)
  t0 = wordToSingleInt(h(r0,arrayS))
  t1 = wordToSingleInt(h(rotateWordLeft(r1,8),arrayS))
  f0 = wordToArray((t0^t1^wordToSingleInt(expandedKey[(2*roundNum)+8]).modulo(2**32)))
  f1 = wordToArray((t0^(2*t1)^wordToSingleInt(expandedKey[(2*roundNum)+9]).modulo(2**32)))
  [f0, f1]
end

def keyExpansion(mEven,mOdd)
  rho = 2^24 + 2^16 + 2^8 +2^0
  expandedKey = Array.new(40)
  (0..19).each { |i|
    a = twofishH(wordToArray(2 * i * rho), mEven)
    a = wordToSingleInt(a)
    b = rotateWordLeft(h(wordToArray((2 * i + 1) * rho), mOdd), 8)
    b = wordToSingleInt(b)
    expandedKey[2 * i] = (a + b).modulo(2 ^ 32)
    expandedKey[2 * i + 1] = rotateWordLeft((a + 2 * b).modulo(2 ^ 32), 9)
  }
  expandedKey
end

def twofishH(x,l)
  # x is a word - 32bytes represented as an array of 4 integers, each in range 0-255
  # l is a list of k words. k = 4 as I'm using a 256 bit key.
  if k==4
    x[0] = permutation(x[0],1)
    x[1] = permutation(x[1],0)
    x[2] = permutation(x[2],0)
    x[3] = permutation(x[3],1)
    x = x.zip(l[3]).map {|i| a[i]^b[i]}
  end
  if k>=3
    x[0] = permutation(x[0],1)
    x[1] = permutation(x[1],1)
    x[2] = permutation(x[2],0)
    x[3] = permutation(x[3],0)
    x = x.zip(l[2]).map {|i| a[i]^b[i]}
  end
  x[0] = permutation(x[0],0)
  x[1] = permutation(x[1],1)
  x[2] = permutation(x[2],0)
  x[3] = permutation(x[3],1)
  x = x.zip(l[1]).map {|i| a[i]^b[i]}

  x[0] = permutation(x[0],0)
  x[1] = permutation(x[1],0)
  x[2] = permutation(x[2],1)
  x[3] = permutation(x[3],1)
  x = x.zip(l[0]).map {|i| a[i]^b[i]}

  x[0] = permutation(x[0],1)
  x[1] = permutation(x[1],0)
  x[2] = permutation(x[2],1)
  x[3] = permutation(x[3],0)

  galoisMatrixMultiply(x, MSDECIMAL)
end

def twofish_encrypt_block(block,key)
  wordsArray = block.each_slice(4).to_a

  mEven,mOdd,arrayS = twofish_key_schedule(key)
  expandedKey = keyExpansion(mEven,mOdd)

  #Input whitening
  wordsArray[0] = wordToArray(wordToSingleInt(wordsArray[0])^wordToSingleInt(key[0]))
  wordsArray[1] = wordToArray(wordToSingleInt(wordsArray[1])^wordToSingleInt(key[1]))
  wordsArray[2] = wordToArray(wordToSingleInt(wordsArray[2])^wordToSingleInt(key[2]))
  wordsArray[3] = wordToArray(wordToSingleInt(wordsArray[3])^wordToSingleInt(key[3]))

  (0...16).each { |i|

  }
end
def twofish_encrypt(message,key)

end

def twofish_decrypt_block(block,key)

end

def twofish_decrypt(message,key)

end

def twofish_encryption_menu

end

def twofish_decryption_menu

end