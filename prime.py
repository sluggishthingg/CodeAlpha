def reverse_number(number):

    reversed_number=0
    
    if number == 0:
        return 0

    if number < 0:
        return 0
    
    while number>0:

        digit = number % 10
        reversed_number = reversed_number * 10 + digit
        number = number // 10
    return reversed_number
# Test the function
num = 1234
print("Original number:", num)
print("Reversed number:", reverse_number(num))

