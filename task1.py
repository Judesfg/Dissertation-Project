A = 'A'
B = 'B'
C = 'C'
D = 'D'
E = 'E'
F = 'F'

def expression(input, output):
    x = []
    y = []
    for i in range(4):
        if input[i] == '0':
            x.append(False)
        else:
            x.append(True)
        if output[i] == '0':
            y.append(False)
        else:
            y.append(True)
    print(f"Expression 1 (X2 xor X3): {x[1] ^ x[2]}")
    print(f"Expression 2 (Y1 xor Y3 xor Y4): {y[0] ^ y[2] ^ y[3]}")
    print(f"Expression 3 (X1 xor X4): {x[0] ^ x[3]}")
    print(f"Expression 4 (Y2): {y[1]}")
    print(f"Expression 5 (X3 xor X4): {x[2] ^ x[3]}")
    print(f"Expression 6 (Y1 xor Y4): {y[0] ^ y[3]}")
    print()

def substitution(x):
    if x == '0':
        expression(f'{0x0:0>4b}', f'{0x3:0>4b}')
    elif x == '1':
        expression(f'{0x1:0>4b}', f'{0xA:0>4b}')
    elif x == '2':
        expression(f'{0x2:0>4b}', f'{0x6:0>4b}')
    elif x == '3':
        expression(f'{0x3:0>4b}', f'{0xC:0>4b}')
    elif x == '4':
        expression(f'{0x4:0>4b}', f'{0x5:0>4b}')
    elif x == '5':
        expression(f'{0x5:0>4b}', f'{0x9:0>4b}')
    elif x == '6':
        expression(f'{0x6:0>4b}', f'{0x0:0>4b}')
    elif x == '7':
        expression(f'{0x7:0>4b}', f'{0x7:0>4b}')
    elif x == '8':
        expression(f'{0x8:0>4b}', f'{0xE:0>4b}')
    elif x == '9':
        expression(f'{0x9:0>4b}', f'{0x4:0>4b}')
    elif x == 'A':
        expression(f'{0xA:0>4b}', f'{0xD:0>4b}')
    elif x == 'B':
        expression(f'{0xB:0>4b}', f'{0x1:0>4b}')
    elif x == 'C':
        expression(f'{0xC:0>4b}', f'{0x2:0>4b}')
    elif x == 'D':
        expression(f'{0xD:0>4b}', f'{0xF:0>4b}')
    elif x == 'E':
        expression(f'{0xE:0>4b}', f'{0xB:0>4b}')
    elif x == 'F':
        expression(f'{0xF:0>4b}', f'{0x8:0>4b}')

substitution('0')
input()
substitution('1')
input()
substitution('2')
input()
substitution('3')
input()
substitution('4')
input()
substitution('5')
input()
substitution('6')
input()
substitution('7')
input()
substitution('8')
input()
substitution('9')
input()
substitution('A')
input()
substitution('B')
input()
substitution('C')
input()
substitution('D')
input()
substitution('E')
input()
substitution('F')
input()