from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from random import SystemRandom
#coding=utf-8
import hashlib
import time
import gmpy

def KeyGen():
 sk = RSA.generate(1024)
 pk = sk.publickey()
 v = SystemRandom().randrange(pk.n >> 10, pk.n)
 e=pk.e
 d=sk.d
 n=pk.n
 a= SystemRandom().randrange(pk.n >> 10, pk.n)
 g=(a**2)%n 
 return [e,d,n,v,g]

def TagBlock(e,d,n,v,g,m,i):
 v1=str(v)
 i1=str(i)
 wi=int(str(v1)+str(i1))
 hash=SHA256.new()
 hi=hash.update(wi)
 mes=hi*(g**m)
 Tim=sk.sign(mes,0)
 return  [wi,tim]


def GenProof(n,g,F=[],c,gs,TM=[]):
 T=1
 for i in range(0,c):
   gs=gs*(gs**F[c])
   T=TM[i]*T
 T=T%n
 gs=gs%n
 hash=SHA256.new()
 pho=hash.update(gs)
 return [T,pho]


def CheckProof(n,d,e,v,g,c,gs,T,pho):
 rho=T**e
 v1=str(v)
 for i in range(0,c):
    i1=str(i)
    wi=int(str(v1)+str(i1))
    hash=SHA256.new()
    hi=hash.update(wi)
    rho=rho/hi
 check=(rho**s)%n
 if rho==pho:
    return 1
 else return 0

if __name__=='__main__':
 [e,d,n,v,g]=keyGen(512)
 s=1234
 gs=g**s
 F=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]
 for i in F
  [wi,tim]=TagBlock(e,d,n,v,g,F[i],i)
  
