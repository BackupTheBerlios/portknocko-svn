#!/bin/bash

iptables -P INPUT ACCEPT
iptables -F INPUT

rmmod ipt_pknock
