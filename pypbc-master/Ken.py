import math
import sys
from Crypto.PublicKey import RSA
 
keypair = RSA.generate(1024)
 
keypair.p = 275127860351348928173285174381581152299
keypair.q = 319576316814478949870590164193048041239
keypair.e = 65537
 
keypair.n = keypair.p * keypair.q
Qn = int((keypair.p-1) * (keypair.q-1))
 
i = 1
while (True):
    x = (Qn * i ) + 1
    if (x % keypair.e == 0):
        keypair.d = x / keypair.e
        break
    i += 1
 
private = open('pri.pem','wb')
private.write(keypair.exportKey())
private.close()
