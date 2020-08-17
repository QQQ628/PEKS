#coding=utf-8

from pypbc import *
import hashlib

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
 cipher = PEKS(params, g, pk, "GQW")
 td = Trapdoor(params, sk, "GQW")
 assert(Test(params, pk, cipher, td))
 td = Trapdoor(params, sk, "GQK")
 assert(not Test(params, pk, cipher, td))

