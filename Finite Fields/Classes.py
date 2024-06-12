import hashlib

def hash256(s):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

class FieldElement():
    def __init__(self, num, prime):
        if num >= prime and num < 0:
            err = "Num {} is not in the field range : 0 to {}".format(num, prime-1)
            raise ValueError(err)
        self.num = num
        self.prime = prime
    
    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)
    
    def __eq__(self,other) -> bool:
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime
    
    def __ne__(self,other) -> bool:
        if other is None: 
            return True
        return not(self == other)
    
    def __add__(self,other):
        if self.prime != other.prime:
            raise TypeError("Cannot add 2 elements of different fields")
        n = (self.num + other.num)%self.prime
        return self.__class__(n,self.prime)
    
    def __sub__(self,other):
        if other.prime != self.prime:
            raise TypeError("Cannot subtract 2 elements of different fields")
        n = (self.num - other.num)%self.prime
        return self.__class__(n,self.prime)
    
    def __mul__(self, other):
    
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __pow__(self, exponent):
        newExponent = exponent % (self.prime - 1) #To bring the number within prime finite range of the field.
        num = pow(self.num,newExponent,self.prime)
        return self.__class__(num, self.prime)
    
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        #Applying Fermat’s Little Theorem which will help us in capping the numbers within the field range and also helps in division like handling negative exponents.

        inverse = pow(other.num,self.prime-2,self.prime)
        n = (self.num * inverse)% self.prime
        return self.__class__(n , self.prime)
    
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


# Class For Elliptic Curve Points

class Point():

    def __init__(self,x,y,a,b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)
        
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b
    
    def __ne__(self, other):
        return not(self == other)
    
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format (self, other))
        
        #Accounting for points at infinty
        if self.x is None:
            return other
        if other.x is None:
            return self
        
         # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y: 
            return self.__class__(None,None,self.a,self.b)

        # Case 2: self.x ≠ other.x
        # Formula (x3,y3)==(x1,y1)+(x2,y2)
        # s=(y2-y1)/(x2-x1)
        # x3=s**2-x1-x2
        # y3=s*(x1-x3)-y1
        if self.x != other.x:
            s = (other.y - self.y)/(other.x - self.x)
            x3 = s**2 - other.x - self.x
            y3 = s*(self.x-x3)-self.y
            return self.__class__(x3,y3,self.a,self.b)

        # Case 3: self == other
        # Formula (x3,y3)=(x1,y1)+(x1,y1)
        # s=(3*x1**2+a)/(2*y1)
        # x3=s**2-2*x1
        # y3=s*(x1-x3)-y1
        if self == other:
            s =  (3 * self.x**2 + self.a) / (2*self.y)
            x3 = s**2-2*self.x
            y3 = s*(self.x - x3) - self.y
            return self.__class__(x3,y3,self.a,self.b) 
        
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result
    
# Creating S256Feild Class using it as an extension of FeildElement class
P = 2**256 - 2**32 - 977
class S256Field(FieldElement):
    def __init__(self, num, prime=None): 
        super().__init__(num=num, prime=P)
    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)
    
# Creating S256Point class using it as an extension of Point Class
A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 # Order if the Group
class S256Point(Point):

    def __init__(self, x, y, a =  None, b = None):
        a = S256Field(A)
        b = S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else : ## If this trigger it means x and y are none representing the infinity point
            super().__init__(x=x, y=y, a=a, b=b) # We will directly pass the value of x and y
    
    def __rmul__(self, coefficient): 
        coef = coefficient % N # We can mod by 'n' because 'nG = 0'. That is, every n times we cycle back to zero or the point at infinity.
        return super().__rmul__(coef)
    
    # Creating Verification method 
    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N) 
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self 
        return total.x.num == sig.r # Extracting X-Coordinate with the help of '.x.num'
# Defining G to easily use it directly when needed

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

########################################################################

# Creating Signature Class
class Signature:
    def __init__(self, r, s): 
        self.r = r
        self.s = s
    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s) 