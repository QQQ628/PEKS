from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from random import SystemRandom
#coding=utf-8
from pypbc import *
import hashlib
import time

start = time.clock()


# Signing authority (SA) key
priv = RSA.generate(2048)
pub = priv.publickey()

## Protocol: Blind signature ##

# must be guaranteed to be chosen uniformly at random
start3 = time.clock()
r = SystemRandom().randrange(pub.n >> 10, pub.n)


for i in range(0,50):
 msgi = 'key' * 5 # large message (larger than the modulus)
 msg=msgi.encode('utf-8')
# hash message so that messages of arbitrary length can be signed
 hash1 = SHA256.new()
 hash1.update(msg)
 msgDigest = hash1.digest()

# user computes
 msg_blinded = pub.blind(msgDigest,r)

# SA computes
 msg_blinded_signature = priv.sign(msg_blinded, 0)

# user computes
 msg_signature = pub.unblind(msg_blinded_signature[0], r)

# Someone verifies
 hash1= SHA256.new()
 hash1.update(msg)
 msgDigest = hash1.digest()
 if str(pub.verify(msgDigest, (msg_signature,))):
     ksd=hash(msg_signature)
 #print("Message is authentic: " + str(pub.verify(msgDigest, (msg_signature,))))
elapsed = (time.clock() - start3)
print("ksd Time used:",elapsed)


Hash1 = hashlib.sha256
Hash2 = hashlib.sha256

def KeyGen(qbits=512, rbits=160):
 params= Parameters(qbits=qbits, rbits=rbits)
 pairing= Pairing(params)
 g = Element.random(pairing, G2)
 sk = Element.random(pairing, Zr)
 pk = Element(pairing, G2, value = g ** sk)
 return [params, g, sk, pk]


def PEKS(params, g, pk, word):
 pairing = Pairing(params)
 hash_value = Element.from_hash(pairing, G1, Hash1(str(word).encode('utf-8')).hexdigest())
 r = Element.random(pairing, Zr)
 temp = pairing.apply(hash_value, pk ** r)
 return [g ** r, Hash2(str(temp).encode('utf-8')).hexdigest()]

def Trapdoor(params, sk, word):
 pairing = Pairing(params)
 hash_value = Element.from_hash(pairing, G1, Hash1(str(word).encode('utf-8')).hexdigest())
 return hash_value ** sk


def Test(params, pk, cipher, td):
 pairing = Pairing(params)
 [A, B] = cipher
 td = Element(pairing, G1, value=str(td))
 temp = pairing.apply(td, A)
 temp = Hash2(str(temp).encode('utf-8')).hexdigest()
 return temp == B

if __name__ == '__main__':

 [params, g, sk, pk] = KeyGen(512, 160)
 start1 = time.clock()
 for i in range(0,50): 
  cipher = PEKS(params, g, pk, ksd)
 #cipher = PEKS(params, g, pk, ksd)
 elapsed = (time.clock() - start1)
 print("PEKS Time used:",elapsed)
 start2 = time.clock()
 for i in range(0,50):
  td = Trapdoor(params, sk, ksd)
 elapsed = (time.clock() - start2)
 print("TD Time used:",elapsed)
 
 #print(Test(params, pk, cipher, td))
 start4=time.clock()
 for i in range(0,50):
  assert(Test(params, pk, cipher, td))
 #td = Trapdoor(params, sk, "GG")
 #assert(not Test(params, pk, cipher, td))

 elapsed = (time.clock() - start4)
 print("Test used:",elapsed)

