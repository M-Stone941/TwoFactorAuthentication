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
  i = 0
  while i < intArray.length
    temp = intArray[i].to_s(16)
    if temp.length == 1
      temp = "0"+temp
    end
    intArray[i] = temp
    i += 1
  end
  i = 0
  while i < intArray.length
    printf "%s%s%s%s\n", intArray[i],intArray[i+1],intArray[i+2],intArray[i+3]
    i += 4
  end
end




