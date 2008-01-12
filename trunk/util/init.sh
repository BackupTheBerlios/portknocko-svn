#!/bin/sh

./reset.sh

#modprobe cn
#modprobe sha256

modprobe ipt_pknock

iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

dmesg -c 2> /dev/null 1> /dev/null
