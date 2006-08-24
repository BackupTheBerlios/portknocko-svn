#!/bin/bash
iptables -F
iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state NEW -p tcp -m pknock --knockports 2000,2001 --name SSH --dport 22 -j ACCEPT
