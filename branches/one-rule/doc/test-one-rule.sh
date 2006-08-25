#!/bin/bash

iptables -P INPUT DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m pknock --knockports 2001,2000 --name SSH -m tcp --dport 22 -j ACCEPT
