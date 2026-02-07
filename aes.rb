def pad_message(message, block_size=16)
  padded_message = message + "p"
  while padded_message.length%block_size != 0
    padded_message = padded_message+"0"
  end
  return padded_message
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

def aes_encryption
  puts "AES encryption has not yet been implemented"
end

def aes_decryption
  puts "AES decryption has not yet been implemented"
end