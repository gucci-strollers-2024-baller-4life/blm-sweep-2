import sys, hashlib, hmac, struct, time, os
from coincurve import PrivateKey

WL = [w.strip() for w in open(os.environ.get('WL', os.path.join(os.path.dirname(os.path.abspath(__file__)),'bip39_english.txt')))]
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ESC="1tzieUfbeQghz2zjDeGHcAEfzCRgX6eLi"
H=1<<31

def b58(b):
    n=int.from_bytes(b,'big'); s=''
    while n: n,r=divmod(n,58); s=A58[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\x00')))+s
def hash160(b): return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()
def p2pkh(h): return b58(b'\x00'+h+hashlib.sha256(hashlib.sha256(b'\x00'+h).digest()).digest()[:4])
def mnem(ent):
    bits="".join(f"{b:08b}" for b in ent)
    bits+="".join(f"{b:08b}" for b in hashlib.sha256(ent).digest())[:len(ent)*8//32]
    return " ".join(WL[int(bits[i:i+11],2)] for i in range(0,len(bits),11))
def ckd(k,c,i):
    data=(b'\x00'+k.to_bytes(32,'big') if i>=H else PrivateKey(k.to_bytes(32,'big')).public_key.format(True))+struct.pack('>I',i)
    I=hmac.new(c,data,hashlib.sha512).digest()
    return (int.from_bytes(I[:32],'big')+k)%N, I[32:]
PATHS=[[H+44,H+0,H+0,0,0],[H+44,H+0,H+0,1,0],[H+44,H+0,H+0,0,1]]
def derive(ent):
    m=mnem(ent); seed=hashlib.pbkdf2_hmac('sha512', m.encode(), b'mnemonic', 2048)
    I=hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); root=(int.from_bytes(I[:32],'big'), I[32:])
    for p in PATHS:
        k,c=root
        for x in p: k,c=ckd(k,c,x)
        pk=PrivateKey(k.to_bytes(32,'big'))
        for comp in (True,False):
            if p2pkh(hash160(pk.public_key.format(compressed=comp)))==ESC: return m,p,comp
    return None

if sys.argv[1]=='selftest':
    ent=b'\x00'*16
    print('mnemonic:', mnem(ent))
    m=mnem(ent); seed=hashlib.pbkdf2_hmac('sha512', m.encode(), b'mnemonic', 2048)
    I=hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); root=(int.from_bytes(I[:32],'big'), I[32:])
    k,c=root
    for x in [H+44,H+0,H+0,0,0]: k,c=ckd(k,c,x)
    pk=PrivateKey(k.to_bytes(32,'big'))
    print('addr44 compressed:', p2pkh(hash160(pk.public_key.format(compressed=True))))
    sys.exit(0)

hitsf=sys.argv[1]; out=open('MATCH.txt','a')
t0=time.time(); n=0; seen=set()
with open(hitsf) as f:
    for line in f:
        parts=line.split()
        if len(parts)!=5: continue
        h=parts[4]
        if h in seen: continue
        seen.add(h); n+=1
        r=derive(bytes.fromhex(h))
        if r:
            print('*** MATCH', parts[:4], h, r, flush=True)
            out.write(f"{line.strip()} {r}\n"); out.flush()
        if n%500==0: print(f"{n} checked {time.time()-t0:.0f}s", file=sys.stderr, flush=True)
print(f"checked {n} in {time.time()-t0:.0f}s", file=sys.stderr, flush=True)
