from hashlib import blake2b
import binascii
import random
import string
from math import pow
import time
global st,et
global q,h
a = random.randint(2, 10)

# st=time.process_time_ns()
def xor_strings(xs,ys):
    
    return "".join(chr(ord(x)^ ord(y)) for x,y in zip(xs,ys))

def ASCII(s):
    x = 0
    for i in range(len(s)):
        x += ord(s[i])*2**(8 * (len(s) - i - 1))
    return x


def randomString2(length=8):
    letters=string.ascii_lowercase
    
    test_str=''.join(random.sample(letters,length))
    
    res = ''.join(format(ord(i), 'b') for i in test_str)
    
    return(str(res))


def gcd(a, b):
    if a < b: 
        return gcd(b, a) 
    elif a % b == 0: 
        return b; 
    else: 
        return gcd(b, a % b)

# Generating large random number

def gen_key(q):
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q) 
    return key 

# Modular exponentiation

def power(a, b, c):
    x = 1
    y = a 

    while b > 0: 
            if b % 2 == 0: 
                    x = (x * y) % c; 
            y = (y * y) % c 
            b = int(b / 2) 

    return x % c 

# Asymmetric encryption

def encrypt(msg,q, h, g):

    en_msg = []

    k = gen_key(q)# Private key for sender 
    s = power(h, k, q) 
    p = power(g, k, q)

    for i in range(0, len(msg)): 
            en_msg.append(msg[i])        
            
    #print("g^k used : ", p) 
    #print("g^ak used : ", s) 
    for i in range(0, len(en_msg)): 
            en_msg[i] = s * ord(en_msg[i])        

    return en_msg,p 

def decrypt(emsg1,p, key, q):

    dr_msg = []
    
    h = power(p, key, q) 
    for i in range(0, len(emsg1)): 
            dr_msg.append(chr(int(emsg1[i]/h)))
    
    dr_msg = ''.join(dr_msg)

    return dr_msg


def padded(msg,ran,t):
    global X,Y,p,r
    
    msg=msg+t
    
    H=blake2b(ran.encode('utf-8')).hexdigest()
    
    X=xor_strings(msg,H)
    
    G=blake2b(X.encode('utf-8')).hexdigest()
    
    Y=xor_strings(ran,G)
    
    X,p = encrypt(X,q, h, g)
    
    Y,r= encrypt(Y,q,h,g)
    

def unpadded(X,Y):

    X= decrypt(X, p, key, q)

    Y=decrypt(Y,r,key,q)
    
    r1=xor_strings(Y,blake2b(X.encode('utf-8')).hexdigest())
    
    mn=xor_strings(X,blake2b(r1.encode('utf-8')).hexdigest())
    
    return mn
def scheme():
    global X,Y,g,q,h,key 
    # msg = input("Enter your message: ")
    msg = ''
    enc_time, dec_time = 0, 0  
    f = open('test1.txt', 'r')
    loops = 0
    while True:
        t='000000000'
        msg = f.readline()
        if not msg:
            break
        ran=randomString2()
        
        # print('Original Message:',msg)

        q = random.randint(pow(10, 20), pow(10, 50)) 
        g = random.randint(2, q) 

        key = gen_key(q)# Private key for receiver 
        h = power(g, key, q) 
        # print("g used : ", g) 
        # print("g^a used : ", h)
        st = time.time()
        padded(msg,ran,t)
        et = time.time()
        enc_time += (et-st)

        dec_st = time.time()
        dec_msg = unpadded(X,Y).strip(t)
        dec_et = time.time()
        dec_time += (dec_et - dec_st)
        loops += 1 
    f.close()
    # print('Total looped:',loops)

    assert all(ch1==ch2 for ch1, ch2 in zip(msg, dec_msg)), 'Wrong!!! Decrypted mesage is not same'
    # print('After unpadding:', dec_msg)
    # print('Total time taken for enc.:{0:.5f} seconds'.format(enc_time*1000))
    f = open('runtimes.txt', 'a')    
    f.write(str(dec_time)+'\n')
    f.close()
    # et=time.process_time_ns()
    # print('The program executes in:',et-st)

if __name__ == '__main__':
    for i in range(1000):
        scheme()
    print('Done!')