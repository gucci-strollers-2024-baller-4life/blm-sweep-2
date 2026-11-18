#!/bin/sh
cd /tmp/bs2
rm -f lw4_h.txt lw4_s.txt
LOOSE_PFX=1 /tmp/md5w2 rbb/demo_base.txt 4 0 99999 lw4_h.txt lw4_s.txt > lw4_scan.log 2>&1
echo "scan done $(date -u +%H:%MZ) lines=$(wc -l < lw4_h.txt)" >> lw4_scan.log
python3 check_fast.py lw4_h.txt > lw4_check.log 2>&1
echo "check done $(date -u +%H:%MZ)" >> lw4_scan.log
