#!/bin/bash

function load() {
	modprobe cn
	insmod ../kernel/ipt_pknock.ko
}

function unload() {
	scripts/reset.sh
}

function rule() {
	iptables -A INPUT -m state --state NEW -m pknock $4 --name $1 --time 5 --knockports $2 -p udp --dport $3 -j ACCEPT 1> /dev/null
}

function expect() {
	dmesg | grep ipt_pknock | tail -n 1 >> $file
	echo $1 >> $file
	echo -n '.'
}

function knock() {
	scripts/knocker.sh $1 $2
}

function set_hmac() {
	scripts/build_digest.sh $1 $2
}

function run() {
	testcase=$(cat $1)
	eval "$testcase"
}

function init() {
	scripts/init.sh 2> /dev/null 1> /dev/null
	> $1
	echo '' > "cache/digest.txt"
}

if [ -z $1 ]; then 
    echo "usage: $0 <testfile>"
    exit 1
fi

testsuite=$1

file="cache/result.txt"

init $file

run $testsuite

python py/tester.py $file
