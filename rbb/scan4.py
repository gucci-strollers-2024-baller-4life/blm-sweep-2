import sys,hashlib,hmac,struct,time,os,json
from coincurve import PrivateKey
D=os.path.dirname(os.path.abspath(__file__))
WL=[w.strip() for w in open(os.path.join(D,'bip39_english.txt'))]
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; H=1<<31
ESC=os.environ.get('ESC','14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W')
def b58(b):
    n=int.from_bytes(b,'big'); s=''
    while n: n,r=divmod(n,58); s=A58[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\x00')))+s
def h160(b): return hashlib.new('ripemd160',hashlib.sha256(b).digest()).digest()
def p2pkh(h): return b58(b'\x00'+h+hashlib.sha256(hashlib.sha256(b'\x00'+h).digest()).digest()[:4])
def mnem(e):
    x=int.from_bytes(e,'big'); cs=hashlib.sha256(e).digest()[0]>>4; x=(x<<4)|cs
    return ' '.join(WL[(x>>(11*(11-i)))&0x7FF] for i in range(12))
def ckd(k,c,i):
    d=(b'\x00'+k.to_bytes(32,'big') if i>=H else PrivateKey(k.to_bytes(32,'big')).public_key.format(True))+struct.pack('>I',i)
    I=hmac.new(c,d,hashlib.sha512).digest(); return (int.from_bytes(I[:32],'big')+k)%N, I[32:]
def addrs(md):
    s=hashlib.pbkdf2_hmac('sha512',mnem(md).encode(),b'mnemonic',2048)
    I=hmac.new(b"Bitcoin seed",s,hashlib.sha512).digest(); k,c=int.from_bytes(I[:32],'big'),I[32:]
    for i in (H+44,H+0,H+0,0,0): k,c=ckd(k,c,i)
    pk=PrivateKey(k.to_bytes(32,'big'))
    return [p2pkh(h160(pk.public_key.format(True))),p2pkh(h160(pk.public_key.format(False)))]
base=open(os.path.join(D,'base_chapter_lf.txt'),'rb').read()
paras=base.split(b'\n\n')
edges=[]; off=0; starts=[]
for p in paras:
    starts.append(off); off+=len(p)+2
    a=[i for i,ch in enumerate(p) if chr(ch).isalpha()]
    if a: edges.append((starts[-1]+a[0], starts[-1]+a[-1]))
n=len(edges)
mod=int(os.environ.get('MOD','40')); shard=int(os.environ.get('SHARD','0')); secs=float(os.environ.get('SECS','20000'))
print('base',len(base),hashlib.md5(base).hexdigest(),'paras',len(paras),'edges',n,'mod',mod,'shard',shard,flush=True)
state=os.environ.get('STATE','state4_%d.json'%shard)
t0=time.time(); done=0; idx=0
cur=bytearray(base)
for a in range(n-3):
    for b in range(a+1,n-2):
        for c in range(b+1,n-1):
            for d in range(c+1,n):
                idx+=1
                if idx%mod!=shard: continue
                for (p,q) in (edges[a],edges[b],edges[c],edges[d]):
                    cur[p]=ord(chr(cur[p]).lower()); cur[q]=ord(chr(cur[q]).upper())
                md=hashlib.md5(bytes(cur)).digest()
                done+=1
                if ESC in addrs(md):
                    open('MATCH4.txt','w').write(json.dumps({'a':a,'b':b,'c':c,'d':d,'md5':md.hex()}))
                    print('MATCH',a,b,c,d,md.hex(),flush=True)
                for (p,q) in (edges[a],edges[b],edges[c],edges[d]):
                    cur[p]=base[p]; cur[q]=base[q]
                if done%20000==0:
                    json.dump({'idx':idx,'done':done,'a':a},open(state,'w'))
                    el=time.time()-t0
                    if el>secs: print('stop',done,'rate',round(done/el,1),flush=True); sys.exit(0)
print('finished',done,flush=True)
