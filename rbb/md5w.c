#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

/* ---- MD5 (RFC 1321), compact single-lane ---- */
static uint32_t K[64]; static int kinit=0;
static const uint32_t Kc[64]={
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
static const int S[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
#define ROTL(x,c) (((x)<<(c))|((x)>>(32-(c))))
typedef struct { uint32_t a,b,c,d; } MD5CTX;
static void md5_init(MD5CTX*s){ s->a=0x67452301;s->b=0xefcdab89;s->c=0x98badcfe;s->d=0x10325476; }
static void md5_block(MD5CTX*s,const unsigned char*p){
  uint32_t M[16]; for(int i=0;i<16;i++) M[i]=(uint32_t)p[i*4]|((uint32_t)p[i*4+1]<<8)|((uint32_t)p[i*4+2]<<16)|((uint32_t)p[i*4+3]<<24);
  uint32_t a=s->a,b=s->b,c=s->c,d=s->d;
  for(int i=0;i<64;i++){
    uint32_t f; int g;
    if(i<16){f=(b&c)|(~b&d);g=i;}
    else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)&15;}
    else if(i<48){f=b^c^d;g=(3*i+5)&15;}
    else {f=c^(b|~d);g=(7*i)&15;}
    uint32_t tmp=d; d=c; c=b;
    b=b+ROTL(a+f+Kc[i]+M[g],S[i]);
    a=tmp;
  }
  s->a+=a;s->b+=b;s->c+=c;s->d+=d;
}
/* hash a buffer of len bytes; writes 16-byte digest */
static void md5_buf(const unsigned char*buf,size_t len,unsigned char out[16]){
  MD5CTX s; md5_init(&s);
  size_t n=len/64; 
  for(size_t i=0;i<n;i++) md5_block(&s,buf+i*64);
  unsigned char tail[128]; size_t rem=len%64;
  memset(tail,0,128); memcpy(tail,buf+n*64,rem);
  tail[rem]=0x80;
  size_t tl = (rem<56)?64:128;
  uint64_t bits=(uint64_t)len*8;
  for(int i=0;i<8;i++) tail[tl-8+i]=(unsigned char)(bits>>(8*i));
  md5_block(&s,tail); if(tl==128) md5_block(&s,tail+64);
  uint32_t v[4]={s.a,s.b,s.c,s.d};
  for(int i=0;i<4;i++){ out[i*4]=(unsigned char)v[i]; out[i*4+1]=(unsigned char)(v[i]>>8); out[i*4+2]=(unsigned char)(v[i]>>16); out[i*4+3]=(unsigned char)(v[i]>>24);}
}
static void hex(const unsigned char*d,char*o){for(int i=0;i<16;i++)sprintf(o+i*2,"%02x",d[i]);}

int LOOSE=0;
int main(int argc,char**argv){
  /* usage: md5w <base> <w> <start> <max_seconds> <hits> <state> <mod> <shard> */
  const char*bf=argv[1]; int W=atoi(argv[2]); long long start=atoll(argv[3]);
  double maxt=atof(argv[4]); const char*hitsf=argv[5]; const char*statef=argv[6];
  long long mod=(argc>7)?atoll(argv[7]):1, shard=(argc>8)?atoll(argv[8]):0;
  int amin=(argc>9)?atoi(argv[9]):0, amax=(argc>10)?atoi(argv[10]):1<<30;
  { const char*e=getenv("LOOSE_PFX"); if(e&&e[0]=='1') LOOSE=1; }
  FILE*f=fopen(bf,"rb"); if(!f){perror("base");return 1;}
  static unsigned char base[8192]; size_t len=fread(base,1,8192,f); fclose(f);
  unsigned char chk[16]; char chx[40]; md5_buf(base,len,chk); hex(chk,chx);
  fprintf(stderr,"base len=%zu md5=%s\n",len,chx);
  /* words: first + last letter index of each [A-Za-z]+ run */
  int wf[4096], wl[4096], nw=0;
  for(size_t i=0;i<len;){
    if(isalpha(base[i])){ size_t j=i; while(j<len&&isalpha(base[j])) j++;
      wf[nw]=(int)i; wl[nw]=(int)(j-1); nw++; i=j; }
    else i++;
  }
  fprintf(stderr,"words=%d w=%d subsets=%s\n",nw,W,"");
  static unsigned char work[8192]; memcpy(work,base,len);
  FILE*hf=fopen(hitsf,"a"); FILE*sf=fopen(statef,"w");
  time_t t0=time(0); long long n=0, pref=0;
  int idx[8]; for(int i=0;i<W;i++) idx[i]=amin+i;
  while(1){
    if(idx[0]>=amax) break;
    n++; 
    if(n>start && ((mod<=1)||((n%mod)==shard))){
      for(int i=0;i<W;i++){ int w=idx[i]; unsigned char c1=base[wf[w]];
        work[wf[w]] = (unsigned char)tolower(c1);
        if(wl[w]!=wf[w]) work[wl[w]] = (unsigned char)toupper(base[wl[w]]); }
      unsigned char dig[16]; md5_buf(work,len,dig);
      for(int i=0;i<W;i++){ work[wf[idx[i]]]=base[wf[idx[i]]]; work[wl[idx[i]]]=base[wl[idx[i]]]; }
      if(dig[0]==0x3c && (LOOSE || ((dig[1]>>4)==0x6))){ char h[40]; hex(dig,h); pref++;
        fprintf(hf,"%d",idx[0]); for(int i=1;i<W;i++) fprintf(hf," %d",idx[i]);
        fprintf(hf," %s\n",h); fflush(hf); }
    }
    if((n&0x3FFF)==0){ fprintf(sf,"%lld\n",n); fflush(sf);
      double el=difftime(time(0),t0); if(el>maxt){ fprintf(stderr,"stop n=%lld %.0fs rate=%.0f/s pref=%lld\n",n,el,n/el,pref); fclose(hf);fclose(sf);return 0; } }
    /* next subset of size W over nw items */
    int i=W-1;
    while(i>=0 && idx[i]==nw-W+i) i--;
    if(i<0) break;
    idx[i]++; for(int j=i+1;j<W;j++) idx[j]=idx[j-1]+1;
  }
  fprintf(sf,"%lld\n",n); fflush(sf);
  double el=difftime(time(0),t0);
  fprintf(stderr,"done n=%lld %.0fs rate=%.0f/s pref=%lld\n",n,el,n/(el>0?el:1),pref);
  fclose(hf); fclose(sf); return 0;
}
