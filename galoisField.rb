GaloisFieldReductionConstant = 283
# need to use this to do multiplication in the Galois Field (2^8)
# 283 in binary is 1 0001 1011 which represents the polynomial x^8 + x^4 + x^3 + x + 1

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

def galoisMatrixMultiply (array1, array2)
  array1size = [array1[0].length,array1.length]
  array2size = [array2[0].length,array2.length]
  resultArrayRow = Array.new(array1size[0])
  resultArray = Array.new(array2size[1], resultArrayRow)
  if array1size[1] != array2size[0]
    print "These two arrays are not compatible"
  else
    for i in 0...array1.size[0]
      for j in 0...array2.size[1]
        sum = 0
        for k in 0...array1.size[1]
          sum = sum + galoisTimes(array1[i][k],array2[k][j])
        end
        while sum.div(256)!=0
          sum = sum^GaloisFieldReductionConstant
        end
        resultArrayRow[i][j] = sum
      end
    end
  end
  resultArray
end