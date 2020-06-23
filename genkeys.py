#!/usr/bin/env python
import sys
import os
import random

# Calculates the mod inverse of number a with respect to mod value m
def getModInverse(a, m):
    # ax + my = 1
    # ax = 1 mod m
    
    temp = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (a > 1):
        quotient = a // temp
        temp2 = temp

        temp = a % temp
        a = temp2
        temp2 = y

        y = x - quotient * y
        x = temp2

    # If negative, add value of m
    if (x < 0):
        x = x + m

    return x

# Calculates the GCD of the 2 numbers 
def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)

# Determines if the given number is prime based on the Miller-Rabin test
def rabinMillerTest(numberToTest, keyLength):
    if numberToTest == 2:
        return True

    if numberToTest % 2 == 0:
        return False

    r, s = 0, numberToTest - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(keyLength):
        a = random.randrange(2, numberToTest - 1)
        x = pow(a, s, numberToTest)
        if x == 1 or x == numberToTest - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, numberToTest)
            if x == numberToTest - 1:
                break
        else:
            return False
    return True

    return isPrime

# Returns true if the given number is prime
def isPrime(numberToTest, keyLength):
    if (numberToTest >= 2):
        if (numberToTest & 1 != 0):
            return rabinMillerTest(numberToTest, keyLength)
    else:
        return False

# Gets a random prime number based on the key length
def getPrime(keyLength):
    value = None

    while value == None:
        numberToTest = int(os.urandom(keyLength).hex(), 16)

        if isPrime(numberToTest, keyLength):
            value = numberToTest

    return value

# Generates the value of e based on the given key length, p and q values. It is assumed that p and q are co-primes
def generateE(keyLength, p, q):
    e = None

    while e == None:
        numberToTest = int(os.urandom(keyLength).hex(), 16)

        if gcd(numberToTest, (p - 1) * (q - 1)) == 1:
            e = numberToTest

    return e

# Writes the key to a file with the given file name. The exponent refers to e or d depending on
# if it is the public or private key
def writeFile(n, exponent, fileName):
    file = open(fileName, "w")
    file.write("{0},{1}".format(str(n), str(exponent)))
    file.close()

def generateKeyPair(name):
    keyLength = 128

    p = getPrime(keyLength)
    q = getPrime(keyLength)
    n = p * q

    e = generateE(keyLength, p, q)
    d = getModInverse(e, (p - 1) * (q - 1))

    writeFile(n, e, "{0}.pub".format(name))
    writeFile(n, d, "{0}.priv".format(name))    

if __name__ == "__main__":
    if len(sys.argv) > 1:
        name = sys.argv[1]
        generateKeyPair(name)
    else:
        print("Error: must enter one name as an argument")
