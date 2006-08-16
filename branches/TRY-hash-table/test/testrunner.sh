#!/bin/bash

function expect() {
	tail -n 1 /proc/net/ipt_pknock/$2 >> $file
	echo $1 >> $file
}

function knock() {
	hping localhost -a $1 -p $2 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
}

function run() {
	testcase=$(cat $1)
	eval "$testcase"
}

function init() {
	./reset.sh
	./rules.sh 2> /dev/null 1> /dev/null
	> $1
}

if [ -z $1 ]; then 
    echo "You must specify a test file"
    exit 1
fi

if [ ! -r $1 ]; then 
    echo "You must specify an existing test file"
    exit 1
fi

testsuite=$1

file="result.txt"

init $file

run $testsuite

python tester.py $file
