from Crypto.Hash import SHA256
from random import SystemRandom
#coding=utf-8
from pypbc import *
import hashlib
import time


def setup():
 stored_params = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
"""
 params = Parameters(param_string=stored_params)
 pairing = Pairing(params)
 #print(params)#通过双线性映射构建群
 g=Element.random( pairing, G2 )
 h=Element.random(pairing,G2)
 return [pairing,g,h]

def GenCom(ri,h):
 ci=Element(pairing,G2,value=h**ri)
 return ci

 


if __name__ == '__main__': 
 [pairing,g,h]=setup()
 s=1
 t=4 
 x=10000000 #由第一个用户向第二个用户转账2$
 

#构造简单的用户匿名集和其对应的账户余为g
 L={}
 for i in range(100):
  a=Element(pairing,Zr,value=1)
  L[i]=Element(pairing,G2,value=g**a)
  #print("L:",L[i])
  
 start1 = time.clock()

#......创造commitment.......
 start3 = time.clock()
 r=Element.random(pairing,Zr)
 C=Element(pairing,G2,value=(g**x)*(h**r))
 elapsed=(time.clock()-start3)
 print("C used:",elapsed) 
 #print("C:",C) #构造C
 Com={}
 for i in L:
  if i!=t and i!=s:
   ri=Element.random(pairing,Zr)
   Com[i]=GenCom(ri,h) #构造除了ct cs外的com
  if i==t:
   rt=Element.random(pairing,Zr)
   ct=Element(pairing,G2,value=C*(h**rt))
   Com[t]=ct #计算ct
 elapsed = (time.clock() - start1)
 print("Com used:",elapsed)

 start2 = time.clock()

   
#.....更新账户.........
 for i in L:
  if i==s:
   L[s]=L[s]*(Com[t]**(-a))
  if i!=s:
   L[i]=L[i]*Com[i]
 elapsed = (time.clock() - start2)
 print("Update used:",elapsed)
    

