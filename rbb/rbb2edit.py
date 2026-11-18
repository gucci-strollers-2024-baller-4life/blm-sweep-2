#!/usr/bin/env python3
"""RBB-07: two-edit artifacts at paragraph boundaries, derived end to end.

Space: choose two distinct (site, op) edits at paragraph-boundary sites of the
ITASM CRLF2 chapter base, apply both, MD5, BIP44 m/44'/0'/0'/0/0, compare to the
live escrow. No prefix oracle exists for the chapter, so every candidate is a
full derivation.

usage: rbb2edit.py <base> <alphabet-set> <mod> <shard> [max_seconds]
"""
import sys, os, hashlib, hmac, struct, time, itertools
from coincurve import PrivateKey

WLl = [w.strip() for w in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bip39_english.txt'))]
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ESC = "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W"
H = 1 << 31


def b58(b):
    n = int.from_bytes(b, 'big'); s = ''
    while n:
        n, r = divmod(n, 58); s = A58[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\x00'))) + s


def h160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def p2pkh(h):
    return b58(b'\x00' + h + hashlib.sha256(hashlib.sha256(b'\x00' + h).digest()).digest()[:4])


def mnem(ent):
    bits = "".join(f"{b:08b}" for b in ent)
    bits += "".join(f"{b:08b}" for b in hashlib.sha256(ent).digest())[:len(ent) * 8 // 32]
    return " ".join(WLl[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def ckd(k, c, i):
    d = (b'\x00' + k.to_bytes(32, 'big') if i >= H else PrivateKey(k.to_bytes(32, 'big')).public_key.format(True)) + struct.pack('>I', i)
    I = hmac.new(c, d, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], 'big') + k) % N, I[32:]


def addr(ent):
    m = mnem(ent)
    seed = hashlib.pbkdf2_hmac('sha512', m.encode(), b'mnemonic', 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], 'big'), I[32:]
    for x in (H + 44, H + 0, H + 0, 0, 0):
        k, c = ckd(k, c, x)
    return p2pkh(h160(PrivateKey(k.to_bytes(32, 'big')).public_key.format(compressed=True)))


def build_ops(base, aset):
    sites = set()
    i = base.find(b'\r\n\r\n')
    while i != -1:
        if i > 0:
            sites.add(i - 1)
        if i + 4 < len(base):
            sites.add(i + 4)
        i = base.find(b'\r\n\r\n', i + 1)
    sites = sorted(sites)
    if aset == 'narrow':
        chars = [b'\xc2\xa0', b'\xe2\x80\x8b', b'\xef\xbb\xbf', b'\t', b'\r', b'\n']
    else:
        chars = [bytes([c]) for c in range(32, 127)] + [b'\xc2\xa0', b'\xe2\x80\x8b', b'\xef\xbb\xbf']
    ops = []
    for s in sites:
        for ch in chars:
            ops.append((s, ch))
        ops.append((s, 'case'))
    return sites, ops


def apply_edit(buf, site, ch):
    if ch == 'case':
        c = buf[site]
        if 65 <= c <= 90:
            buf[site] = c + 32
        elif 97 <= c <= 122:
            buf[site] = c - 32
    else:
        buf[site:site] = b''  # no-op guard
        buf[site] = ch[0] if len(ch) == 1 else buf[site]
        if len(ch) > 1:
            return ('multi', site, ch)


def main():
    base_path, aset, mod, shard = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    maxt = float(sys.argv[5]) if len(sys.argv) > 5 else 1e9
    base = open(base_path, 'rb').read()
    sites, ops = build_ops(base, aset)
    total = len(ops) * (len(ops) - 1) // 2
    print(f"base {len(base)}B md5 {hashlib.md5(base).hexdigest()[:12]} sites {len(sites)} ops {len(ops)} pairs {total}", flush=True)
    t0 = time.time(); n = 0; hit = None
    for a in range(len(ops)):
        sa, ca = ops[a]
        for b in range(a + 1, len(ops)):
            n += 1
            if (n % mod) != shard:
                continue
            sb, cb = ops[b]
            buf = bytearray(base)
            for s, c in ((sa, ca), (sb, cb)):
                if c == 'case':
                    ch = buf[s]
                    if 65 <= ch <= 90:
                        buf[s] = ch + 32
                    elif 97 <= ch <= 122:
                        buf[s] = ch - 32
                else:
                    buf[s:s] = c
            h = hashlib.md5(bytes(buf)).hexdigest()
            if addr(bytes.fromhex(h)) == ESC:
                hit = (sa, ca, sb, cb, h)
                print('*** MATCH', sa, ca, sb, cb, h, flush=True)
                with open('MATCH_RBB.txt', 'a') as f:
                    f.write(f"{sa} {ca} {sb} {cb} {h}\n")
                return
            if n % 20000 == 0 and time.time() - t0 > maxt:
                print(f"stop at n={n} after {time.time()-t0:.0f}s", flush=True)
                return
    print(f"done n={n} pairs={total} elapsed={time.time()-t0:.0f}s rate={n/max(1,time.time()-t0):.0f}/s hit={hit}", flush=True)


main()
