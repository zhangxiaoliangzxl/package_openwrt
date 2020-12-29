#!/bin/sh

. /lib/network/config.sh
. /lib/functions.sh

ubus_get_ip_by_interface() {
    local name=$1
    local ipaddr=

    ubus_call network.interface.$name status || return 0
    json_select ipv4-address || return 0
    json_select 1 || return 0
    json_get_var ipaddr address || return 0
    echo $ipaddr
    return 1
}

LAN_PORTO=$(uci get network.lan.proto 2>/dev/null)
if [ $LAN_PORTO != "dhcp" ];then
	exit
fi

IFNAMNES="eth0.1 eth0.2"
IFNAMNE=$1

for name in $IFNAMNES
do
	if [ $name == $IFNAMNE ];then
		IFSTATE=$(ifconfig $IFNAMNE | grep RUNNING)
		if [ -z "$IFSTATE" ];then
			echo $IFNAMNE link change down > /dev/console
		else
			echo $IFNAMNE link change up > /dev/console
			oldip=$(ubus_get_ip_by_interface lan)
			if [ -n "$oldip" ];then
				echo "br-lan need renew ip addr" > /dev/console
				#renew dhcp
				PID=$(pidof udhcpc)
				#Release current lease
				kill -SIGUSR2 $PID
				#Renew current lease
				kill -SIGUSR1 $PID
				/etc/init.d/ac_platform restart
			fi
		fi
	fi
done
