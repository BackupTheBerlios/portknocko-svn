./reset.sh
./test.sh 2> /dev/null 1> /dev/null
#dmesg -c 2> /dev/null 1> /dev/null

file="output.txt"

> $file

hping localhost -a 192.168.0.10 -p 2000 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/SSH >> $file
echo "MATCHING" >> $file

hping localhost -a 192.168.0.10 -p 2001 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/SSH >> $file
echo "ALLOWED" >> $file

hping localhost -a 192.168.0.11 -p 2000 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/SSH >> $file
echo "MATCHING" >> $file

hping localhost -p 2002 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
hping localhost -p 2003 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/HTTP >> $file
echo "ALLOWED" >> $file

hping localhost -p 2004 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
hping localhost -p 2005 -c 1 -S -2 -q --fast 2> /dev/null 1> /dev/null
tail -n 1 /proc/net/ipt_pknock/HTTP2 >> $file
echo "ALLOWED" >> $file

python assert.py $file
