./reset.sh
./rules.sh 2> /dev/null 1> /dev/null
#dmesg -c 2> /dev/null 1> /dev/null

file="output.txt"

> $file

hping localhost -a 192.168.0.10 -p 2000 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/SSH >> $file
echo "MATCHING,192.168.0.10" >> $file

hping localhost -a 192.168.0.10 -p 2001 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/SSH >> $file
echo "ALLOWED,192.168.0.10" >> $file

hping localhost -a 192.168.0.11 -p 2000 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/SSH >> $file
echo "MATCHING,192.168.0.11" >> $file

hping localhost -a 10.0.0.1 -p 2002 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
hping localhost -a 10.0.0.1 -p 2003 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/HTTP >> $file
echo "ALLOWED,10.0.0.1" >> $file

hping localhost -a 10.0.0.2 -p 2004 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
hping localhost -a 10.0.0.2 -p 2005 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/HTTP2 >> $file
echo "ALLOWED,10.0.0.2" >> $file

hping localhost -a 10.0.0.3 -p 2004 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/HTTP2 >> $file
echo "MATCHING,10.0.0.3" >> $file

hping localhost -a 10.0.0.4 -p 2004 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/HTTP2 >> $file
echo "MATCHING,10.0.0.4" >> $file

python assert.py $file
