def pad_message(message, block_size=16)
  padded_message = message + "p"
  while padded_message.length%block_size != 0
    padded_message = padded_message+"0"
  end
  padded_message
end

def unpad_message(message)
  unpad_message = message
  while unpad_message[-1] == "0"
    unpad_message.chop!
  end
  if unpad_message[-1] == "p"
    return unpad_message.chop!
  else
    puts "String unpadding unsuccessful"
    puts "Original string"+unpad_message
  end
end

def string_to_ascii(string)
  string.unpack("c*")
end

def ascii_to_string(ascii)
  [ascii].pack('c*')
end

def printInHex(intArray)
  intArray = intArray.flatten
  i = 0
  hexArray = []
  while i < intArray.length
    temp = intArray[i].to_s(16)
    if temp.length == 1
      temp = "0"+temp
    end
    hexArray[i] = temp
    i += 1
  end
  i = 0
  while i < hexArray.length
    printf "%s%s%s%s\n", hexArray[i],hexArray[i+1],hexArray[i+2],hexArray[i+3]
    i += 4
  end
end

def hex_to_dec_array(hex)
  decArray = []
  (0..(hex.length/2 - 1)).each { |i|
    hexNum = hex[i*2..i*2+1]
    decNum = hexNum.to_i(16)
    decArray[i] = decNum
  }
  decArray
end




