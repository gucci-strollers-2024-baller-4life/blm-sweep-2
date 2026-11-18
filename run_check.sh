#!/bin/sh
cd /tmp/bs2
nohup python3 check_fast.py lw4_h.txt > lw4_fast.log 2>&1
