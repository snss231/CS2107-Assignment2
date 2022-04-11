#!/usr/local/bin/python3

import json
from hashlib import sha512

from Crypto.Util.number import getPrime, getRandomRange, getRandomNBitInteger, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

FLAG = "<REDACTED>"

firstPartFlag = FLAG[:len(FLAG)//2]
secondPartFlag = FLAG[len(FLAG)//2:]

def objToString(obj):
    jsonString = json.dumps(obj)
    return jsonString

def stringToObj(s):
    try:
        return json.loads(s)
    except:
        print("Your input is not a valid json string... Try again!")
        exit(0)

def encrypt(msg: bytes, key: int):
    key = long_to_bytes(key)
    key = sha512(key).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(msg, 16))
    return {"iv": cipher.iv.hex(), "ciphertext": ct.hex()}

# If unpad error occurs then it means that 
# you are not supplying the right input
def decrypt(iv: str, ct: str, key: int):
    iv = bytes.fromhex(iv); ct = bytes.fromhex(ct)
    key = long_to_bytes(key)
    key = sha512(key).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = unpad(cipher.decrypt(ct), 16)
    return ct

def verifyParameter(obj):
    if ('n' not in obj):
        print("Parameter n not found in input")
        exit(0)

    if ('g' not in obj):
        print("Parameter g not found in input")
        exit(0)

    if ('pub' not in obj):
        print("Parameter pub not found in input")
        exit(0)

    condition1 = obj['n'].bit_length() > 500
    condition2 = 1 < obj['g'] < obj['n'] - 1
    condition3 = 1 < obj['pub'] < obj['n'] - 1
    condition4 = obj['g'] != obj['pub']
    if (condition1 and condition2 and condition3 and condition4): 
        return

    print("Something's not right with the parameter... Try again!")
    exit(0)


class Alice:
    def establishConnection(self):
        self.n = getPrime(512)
        self.g = getRandomRange(2, self.n - 1)
        self.priv = getRandomNBitInteger(512)
        self.pub = pow(self.g, self.priv, self.n)
        return {"g" : self.g, "n": self.n, "pub" : self.pub}
        
    def getSharedKey(self, obj):
        self.check(obj)
        self.key = pow(obj['pub'], self.priv, self.n)

    def check(self, obj):
        verifyParameter(obj)
        
        condition1 = self.n == obj['n']
        condition2 = self.g == obj['g']
        condition3 = self.g != obj['pub']

        if (condition1 and condition2 and condition3): 
            return

        print("Something's not right with the parameter... Try again!")
        exit(0)

class Bob:
    def acceptConnection(self, obj):
        verifyParameter(obj)
        self.n = obj['n']
        self.g = obj['g']
        self.priv = getRandomNBitInteger(512)
        self.pub = pow(self.g, self.priv, self.n)
        self.getSharedKey(obj)
        return {"g" : self.g, "n" : self.n, "pub" : self.pub}

    def getSharedKey(self, obj):
        self.key = pow(obj['pub'], self.priv, self.n)
        

def printArt():
    print('''
                                                -----
                                              /      \\
                                              )      |
       :================:                      "    )/
      /||              ||                      )_ /*
     / ||    System    ||                          *
    |  ||     Down     ||                   (=====~*~======)
     \ || Please wait  ||                  0      \ /       0
       ==================                //   (====*====)   ||
........... /      \.............       //         *         ||
:\        ############            \    ||    (=====*======)  ||
: ---------------------------------     V          *          V
: |  *   |__________|| ::::::::::  |    o   (======*=======) o
\ |      |          ||   .......   |    \\\\         *         ||
  --------------------------------- 8   ||   (=====*======)  //
                                     8   V         *         V
  --------------------------------- 8   =|=;  (==/ * \==)   =|=
  \   ###########################  \   / ! \     _ * __    / | \\
   \  +++++++++++++++++++++++++++   \  ! !  !  (__/ \__)  !  !  !
    \ ++++++++++++++++++++++++++++   \        0 \ \V/ / 0
     \________________________________\     ()   \o o/   ()
      *********************************     ()           ()

                                 -Targon (Ed Wisniewski)-\n''')

def printMenu():
    print("Welcome Mallory! You are now about to intercept the connection between Alice and Bob\n")
    print("Alice and Bob are using Diffie Hellman key exchange algorithm to establish a shared key")
    print("The shared key is then used as the key for AES CBC for encryption\n")
    print("Decrypt the message sent by them to obtain the flag!\n")


if __name__ == "__main__":
    printArt()
    printMenu()
    
    alice = Alice()
    bob = Bob()

    fromAlice = alice.establishConnection()
    print("Alice just sent this:\n")
    print(objToString(fromAlice) + "\n")

    payload = input("What do you want to send to Bob?\n")
    payload = stringToObj(payload)

    print("Bob has received your input!")
    fromBob = bob.acceptConnection(payload)

    print("Bob just sent this:\n")
    print(objToString(fromBob) + "\n")

    payload = input("What do you want to send to Alice?\n")
    payload = stringToObj(payload)

    print("Alice has received your input!")
    alice.getSharedKey(payload)

    print("Alice and Bob have sent their respective encrypted message!\n")

    print("From Alice:")

    ct1 = encrypt(firstPartFlag, alice.key)
    print(objToString(ct1))

    print("From Bob:")

    ct2 = encrypt(secondPartFlag, bob.key)
    print(objToString(ct2))

    print("Good luck finding the flag! Bye mallory!")
