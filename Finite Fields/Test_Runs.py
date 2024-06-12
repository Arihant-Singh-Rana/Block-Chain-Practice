from Classes import FieldElement
# Checking the if the __eq__ method works properly
a = FieldElement(7,13)
print("Equality : (True Case)",a==a)
b = FieldElement(6,13)
print ("Equality : (Flase Case)",a == b)

#Checking the if the __ne__ method works properly
a = FieldElement(7,13)
b = FieldElement(4,13)
print("Inequality : (Flase Case)",a != a)
print("Inequality : (True Case)",a != b)

# Checking the if __add__ method works properly
a = FieldElement(7,13)
b = FieldElement(12,13)
c = FieldElement(6,13)
ans = a+b

print("Addition : (Correct answer)",c == ans)

# Checking the if __sub__ method works properly
a = FieldElement(7,13)
b = FieldElement(12,13)
c = FieldElement(8,13)
ans = a-b

print("Subtraction : (Correct answer) ",c == ans)

# Checking the if __mul__ method works properly
a = FieldElement(2,13)
b = FieldElement(10,13)
c = FieldElement(7,13)
ans = a*b

print("Multiplication :(Correct answer) ",c == ans)

# Checking the if __pow__ method works properly
a = FieldElement(2,13)
b = 2
c = FieldElement(4,13)
ans = a**b

print("Exponent :(Correct answer) ",c == ans)

# Checking the if __truediv__ method works properly for division

# a / b = a * [b**-1] -> According to Fermat’s Little Theorem => a / b = a * [b**(-1(prime-1))] -> a * [b**(prime-2)]
a = FieldElement(3, 31)
b = FieldElement(24, 31)
c = FieldElement(4,31)
ans = a/b

print("Divison :(Correct answer) ",c == ans)


################################################################

from Classes import Point

#Checking the __inti__ method:
#Correct point on the curve y**2 = x**3 + 5*x + 7
a = Point(-1,-1,5,7)
print("Correct point on the curve :",a)
#Wrong point on the curve y**2 = x**3 + 5*x + 7
#a = Point(2,4,5,7)
#print("Correct point on the curve :",a)

#Checing the __eq__ method:

a = Point(-1,-1,5,7)
b = Point(18,77,5,7)

print("Equality : (True Case)",a==a)
print("Equality : (False Case)",a==b)


#Checing the __ne__ method:

a = Point(-1,-1,5,7)
b = Point(18,77,5,7)

print("Equality : (Flase Case)",a!=a)
print("Equality : (True Case)",a!=b)

#Checking __add__ method:

a = Point(2, 5, 5, 7)
b = Point(-1, -1, 5, 7)
c = Point(3, -7, 5, 7)

print("Addition : (True Case)",a+b == c)

################################################################

#Using both clases to create Ellipitic curves over finite fields

prime = 223
a = FieldElement(num=0, prime=prime)
b = FieldElement(num=7, prime=prime) 
x1 = FieldElement(num=192, prime=prime)
y1 = FieldElement(num=105, prime=prime)
x2 = FieldElement(num=17, prime=prime)
y2 = FieldElement(num=56, prime=prime)
p1 = Point(x1, y1, a, b)
p2 = Point(x2, y2, a, b)
print(p1+p2)

#Scaler multiplication of the point
prime = 223
a = FieldElement(0, prime)
b = FieldElement(7, prime)
x = FieldElement(47, prime) 
y = FieldElement(71, prime) 
p = Point(x, y, a, b)
for s in range(1,21):
    result = s*p
    print('{}*(47,71)=({},{})'.format(s,result.x.num,result.y.num))

########################################################################

# We specify the prime of the finite field, p = 2**(256)-2**32-977... which is a really huge number

# Wroking with secp256k1 Curve

gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 # X-Coordinate of the point 
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 # Y-Coordinate of the point
p = 2**256 - 2**32 - 977
#  Using equation to check whether the point is correct or not => y**2 = x**3 + b -> a = 0, b = 7
print("Calcuting whether the point exists on the curve : (True Case)",gy**2 % p == (gx**3 + 7) % p) 

# Let the order of the gourp be 'n' so 'n*G' should be equal to infinity
'''n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
x= FieldElement(gx, p)
y = FieldElement(gy, p)
seven = FieldElement(7,p)
zero = FieldElement(0,p)
G = Point(x, y, zero, seven)
print("Verifying the order of the group : ",n*G)

print(n*G)'''

# Now checking G,N are working or not creyed in the Classes file

from Classes import G,N

print("Imported G and N from the Classes.py file :",N*G)

################################################################
# Public Key Cryptography
# For verification purposes
# 'eG=P', where 'P' is the public key and 'e' is the private key.
# 'kG=R' here "k" is a random number and 'R' is a point after multiplication and we need it's X-Coordinates only
# we will make use of (s,r) which is the signature for verification
# for verification we will calulate "u" and "v" with the help of 's' and 'z'
from Classes import S256Point
z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423 
r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6 
s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec 
px = 0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574 
py = 0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4 
point = S256Point(px, py)

s_inv = pow(s, N-2, N)
u = z * s_inv % N

v = r * s_inv % N
print("Signature : (s,r) => ({},{})".format(s, r))
print("Verifying the signature :",(u*G + v*point).x.num == r) 


# Trying to create a new signature
from Classes import hash256
e = int.from_bytes(hash256(b'my secret'), 'big')
z = int.from_bytes(hash256(b"Arihant's Message"), 'big')
k = 1234567890
r = (k*G).x.num
k_inv = pow(k, N-2, N)
s = (z+r*e) * k_inv % N
point = e*G
print(point)
print("Printing 'z' that we calculated :",hex(z))
print("Printing 'r' which is the X-Coordinate of 'R'(which we got from K*G) that we calculated :",hex(r))
print("Printing 's' which is calculated using the hash of the message z, the private key, and the random number used to generate r which is 'k' in this case :",hex(s))