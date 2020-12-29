#!/bin/sh

cmd_function(){
k=0
#echo $1
for var in $1
do
if [ $k -eq 0 ]
then
ip=`echo $var | grep -E "([0-9]{1,3}\.){3}[0-9]"`
fi
mac=`echo $var | grep ..:..:..:..:..:..`
if [ -n "$ip" ]
then
/usr/bin/arp -d $ip
k=1
fi

if [ -n "$mac" ] && [ $k -eq 1 ]
then
echo "$ip-$mac"
k=0
fi

done
}

#date
#br=`ifconfig | grep br | awk '{printf "%s\n", $1}'`

i="1"
#j="1"
#date
#while ( [ "$j" -lt "8" ] )
#do
ip=`ifconfig br-lan | grep "inet addr" | awk '{printf "%s", $2}' | cut -d ":" -f 2 | awk -F"." '{printf "%s.%s.%s.", $1, $2, $3}'`1
lan_mask=`ifconfig br-lan | grep "Mask:" | awk '{printf "%s", $4}' | cut -d ":" -f 2 | awk -F"." '{printf "%s.%s.%s.%s", $1, $2, $3, $4}'`
MASKLAN=`ipcalc.sh $ip $lan_mask | grep PREFIX | awk -F'=' '{printf $2}'`
#echo "$ip"
cmd_function "`nmap -sn $ip/$MASKLAN -e br-lan -n`"

#j=`expr $j + 1`
#done
#date
while ( [ "$i" -lt "16" ] )
do
#	echo "i = $i"
	if [ `ifconfig | grep -w br-vlan$i | wc -l` -eq "1" ] && [ `ifconfig br-vlan$i | grep "inet addr" | wc -l` -eq "1" ]
	then
	ip=`ifconfig br-vlan$i | grep "inet addr" | awk '{printf "%s", $2}' | cut -d ":" -f 2 | awk -F"." '{printf "%s.%s.%s.", $1, $2, $3}'`1
	vlan_mask=`ifconfig br-vlan$i | grep "Mask:" | awk '{printf "%s", $4}' | cut -d ":" -f 2 | awk -F"." '{printf "%s.%s.%s.%s", $1, $2, $3, $4}'`
	MASKVLAN=`ipcalc.sh $ip $vlan_mask | grep PREFIX | awk -F'=' '{printf $2}'`
#	echo "$ip"
	cmd_function "`nmap -sn $ip/$MASKVLAN -e br-vlan$i -n`"
	fi
	i=`expr $i + 1`
done

#date
