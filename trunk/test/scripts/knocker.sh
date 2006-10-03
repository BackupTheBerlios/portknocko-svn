#!/bin/bash
# $1 -> IP src
# $2 -> PORT dst
# $3 -> digest file
# $4 -> -2 if UDP
hping localhost -a $1 -p $2 -c 1 -S -q -d 32 -E $3 --fast $4 2> /dev/null 1> /dev/null
