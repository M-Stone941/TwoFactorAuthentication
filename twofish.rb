require_relative "encryptionUtilities"
require_relative 'galoisField'

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


MDS = [ #used in function g
  %w[01 EF 5B 5B],
  %w[5B EF EF 01],
  %w[EF 5B 01 EF],
  %w[EF 01 EF 5B]
]

MSDECIMAL = MDS.map do |a|
  a.map { |x|x.to_i(16) }
end

Q0SBOX0 = [ 8, 1, 7, D, 6, F, 3, 2, 0, B 5 9 E C A 4 ]
Q0SBOX1 = [ E, C, B, 8, 1, 2, 3, 5, F 4 A 6 7 0 9 D ]
Q0SBOX2 = [ B, A, 5, E, 6, D, 9, 0, C 8 F 3 2 4 7 1 ]
Q0SBOX3 = [ D, 7, F, 4, 1, 2, 6, E, 9 B 3 0 8 5 C A ]

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

def twofishF(r0,r1,roundNum)
  f0 =r0
  f1=r1
  [f0, f1]
end

def twofishG(x)
  z=x
  z
end

def twofishH(x,l)
  z=x
  z
end

def twofish_encrypt_block(block,key)
  #input whiten
  # 16 rounds
  # unswap
  # output whiten
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