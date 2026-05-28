require_relative 'aes'
require_relative 'twofish'

def main_menu
  running = TrueClass
  while running==TrueClass
    puts "Would you like to encrypt a message, decrypt a message or exit this program?"
    puts "Press 1 to encrypt, 2 to decrypt or 3 to exit the program"
    response = gets.chomp
    if response == "1"
      encryption_menu
    elsif response == "2"
      decryption_menu
    elsif response == "3"
      puts "Exiting program"
      running = FalseClass
    end
  end
end

def encryption_menu
  running = TrueClass
  while running==TrueClass
    puts "Select an encryption standard, or go back to main menu"
    puts "Press 1 for AES, 2 for Twofish or 3 to return to the main menu"
    response = gets.chomp
    if response == "1"
      aes_encryption_menu
      printf("************\n")
      running = FalseClass
    elsif response == "2"
      twofish_encryption_menu
      printf("************\n")
      running = FalseClass
    elsif response == "3"
      running = FalseClass
    end
  end
end

def decryption_menu
  running = TrueClass
  while running==TrueClass
    puts "Select an encryption standard, or go back to main menu"
    puts "Press 1 for AES, 2 for Twofish or 3 to return to the main menu"
    response = gets.chomp
    if response == "1"
      aes_decryption_menu
      printf("************\n")
      running = FalseClass
    elsif response == "2"
      twofish_decryption_menu
      printf("************\n")
      running = FalseClass
    elsif response == "3"
      running = FalseClass
    end
  end
end


main_menu