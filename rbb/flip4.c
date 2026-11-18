#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "md5x.h"
static unsigned char buf[8192], tmp[8192];
static int pos[4096];
static uint32_t st0[256][4];
static inline void md5_from(int blk,const unsigned char*m,size_t n,unsigned char out[16]){
  uint32_t st[4]; memcpy(st,st0[blk],16);
  size_t i=(size_t)blk*64;
  for(;i+64<=n;i+=64) md5block(st,m+i);
  unsigned char tail[128]; memset(tail,0,128); size_t rem=n-i; memcpy(tail,m+i,rem); tail[rem]=0x80;
  size_t tl=(rem<56)?64:128; unsigned long long bits=(unsigned long long)n*8;
  for(int k=0;k<8;k++) tail[tl-8+k]=(bits>>(8*k))&0xff;
  md5block(st,tail); if(tl==128) md5block(st,tail+64);
  for(int k=0;k<4;k++){out[4*k]=st[k]&0xff;out[4*k+1]=(st[k]>>8)&0xff;out[4*k+2]=(st[k]>>16)&0xff;out[4*k+3]=(st[k]>>24)&0xff;}
}
int main(int argc,char**argv){
  const char*bf=argv[1]; int a0=atoi(argv[2]),b0=atoi(argv[3]),c0=atoi(argv[4]);
  double maxt=atof(argv[5]); const char*hf=argv[6];
  long long mod=atoll(argv[7]), shard=atoll(argv[8]);
  FILE*f=fopen(bf,"rb"); size_t n=fread(buf,1,sizeof(buf),f); fclose(f);
  int np=0; for(size_t i=0;i<n;i++) if(isalpha(buf[i])) pos[np++]=(int)i;
  { uint32_t s[4]={0x67452301,0xefcdab89,0x98badcfe,0x10325476};
    for(int b=0;b<= (int)(n/64);b++){ memcpy(st0[b],s,16); if(b<(int)(n/64)) md5block(s,buf+(size_t)b*64); } }
  unsigned char d0[16]; md5_from(0,buf,n,d0);
  fprintf(stderr,"base=%s len=%zu md5=%02x%02x%02x%02x alpha=%d mod=%lld shard=%lld\n",bf,n,d0[0],d0[1],d0[2],d0[3],np,mod,shard);
  FILE*hfp=fopen(hf,"a"); time_t t0=time(0); long long ord=0, done=0, hits=0;
  long long cnt=shard;
  const char*hexd="0123456789abcdef";
  for(int a=a0;a<np-3;a++){
    for(int b=(a==a0?b0:a+1);b<np-2;b++){
      for(int c=(a==a0&&b==b0?c0:b+1);c<np-1;c++){
        int blk=pos[a]/64;
        memcpy(tmp,buf,n); tmp[pos[a]]^=0x20; tmp[pos[b]]^=0x20; tmp[pos[c]]^=0x20;
        for(int e=c+1;e<np;e++){
          ord++;
          if(cnt==0){ cnt=mod; } else { cnt--; continue; }
          tmp[pos[e]]^=0x20;
          unsigned char dg[16]; md5_from(blk,tmp,n,dg);
          if(dg[0]==0x3c && (dg[1]>>4)==0x6){
            char h[33]; for(int k=0;k<16;k++){h[2*k]=hexd[dg[k]>>4];h[2*k+1]=hexd[dg[k]&15];} h[32]=0;
            fprintf(hfp,"%d %d %d %d %s\n",a,b,c,e,h); hits++;
          }
          tmp[pos[e]]^=0x20; done++;
          if((done&0xFFFFF)==0 && difftime(time(0),t0)>maxt){
            fprintf(stderr,"stop elapsed=%.0fs quads=%lld hits=%lld at %d %d %d\n",difftime(time(0),t0),done,hits,a,b,c);
            fclose(hfp); return 0;
          }
        }
      }
    }
  }
  fprintf(stderr,"DONE quads=%lld hits=%lld elapsed=%.0fs\n",done,hits,difftime(time(0),t0));
  fclose(hfp); return 0;
}
