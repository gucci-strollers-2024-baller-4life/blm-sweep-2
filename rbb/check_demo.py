import sys,hashlib,hmac,struct,os
from coincurve import PrivateKey
WL=[w.strip() for w in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'bip39_english.txt'))]
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ESC="1tzieUfbeQghz2zjDeGHcAEfzCRgX6eLi"; H=1<<31
def b58(b):
    n=int.from_bytes(b,'big'); s=''
    while n: n,r=divmod(n,58); s=A58[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\x00')))+s
def h160(b): return hashlib.new('ripemd160',hashlib.sha256(b).digest()).digest()
def p2pkh(h): return b58(b'\x00'+h+hashlib.sha256(hashlib.sha256(b'\x00'+h).digest()).digest()[:4])
def mnem(ent):
    x=int.from_bytes(ent,'big'); cs=hashlib.sha256(ent).digest()[0]>>4
    x=(x<<4)|cs
    return ' '.join(WL[(x>>(11*(11-i)))&0x7FF] for i in range(12))
def ckd(k,c,i):
    data=(b'\x00'+k.to_bytes(32,'big') if i>=H else PrivateKey(k.to_bytes(32,'big')).public_key.format(True))+struct.pack('>I',i)
    I=hmac.new(c,data,hashlib.sha512).digest()
    return (int.from_bytes(I[:32],'big')+k)%N, I[32:]
PATHS=[[H+44,H+0,H+0,0,0],[H+44,H+0,H+0,1,0],[H+44,H+0,H+0,0,1]]
def derive(ent):
    m=mnem(ent); seed=hashlib.pbkdf2_hmac('sha512',m.encode(),b'mnemonic',2048)
    I=hmac.new(b"Bitcoin seed",seed,hashlib.sha512).digest(); root=(int.from_bytes(I[:32],'big'),I[32:])
    for p in PATHS:
        k,c=root
        for i in p: k,c=ckd(k,c,i)
        pk=PrivateKey(k.to_bytes(32,'big'))
        for comp in (True,False):
            if p2pkh(h160(pk.public_key.format(comp)))==ESC: return m,p,comp
    return None
tot=0;hits=0
for fn in sys.argv[1:]:
    for line in open(fn):
        p=line.split()
        if len(p)<5: continue
        tot+=1
        r=derive(bytes.fromhex(p[-1]))
        if r: hits+=1; print("MATCH",p[0],p[1],p[2],p[3],p[-1],r,flush=True)
print("checked",tot,"hits",hits)
