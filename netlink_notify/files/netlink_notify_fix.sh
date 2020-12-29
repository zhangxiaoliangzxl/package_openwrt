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

renew_addr()
{
	#renew dhcp
	PID=$(pidof udhcpc)
	#Release current lease
	kill -SIGUSR2 $PID
	#Renew current lease
	kill -SIGUSR1 $PID
	/etc/init.d/ac_platform restart
}

get_link_status()
{
	PORT2_state=`swconfig dev switch0 port 2 get link | awk '{print $2}' | cut -d":" -f2`
	PORT3_state=`swconfig dev switch0 port 3 get link | awk '{print $2}' | cut -d":" -f2`		
}

check_link_state()
{
	oldip=$(ubus_get_ip_by_interface lan)
	
	#port2
	if [ "$PORT2_state" != "$PORT2_oldstate" ];then
		if [ "$PORT2_state" == "down" ];then
			echo switch port2 link change down > /dev/console
		else
			echo switch port2 link change up > /dev/console
			if [ -n "$oldip" ];then
				echo "br-lan need renew ip addr" > /dev/console
				renew_addr;
			fi
		fi
		
		PORT2_oldstate=$PORT2_state
	fi
	
	#port3
	if [ "$PORT3_state" != "$PORT3_oldstate" ];then
		if [ "$PORT3_state" == "down" ];then
			echo switch port3 link change down > /dev/console
		else
			echo switch port3 link change up > /dev/console
			if [ -n "$oldip" ];then
				echo "br-lan need renew ip addr" > /dev/console
				renew_addr;
			fi
		fi
		
		PORT3_oldstate=$PORT3_state
	fi
}

get_link_status;
PORT2_oldstate=$PORT2_state
PORT3_oldstate=$PORT3_state

echo "netlink_notify init ......" > /dev/console
echo $PORT2_oldstate $PORT2_state > /dev/console
echo $PORT3_oldstate $PORT3_state > /dev/console

while true
do
	LAN_PORTO=$(uci get network.lan.proto 2>/dev/null)
	if [ $LAN_PORTO != "dhcp" ];then
		sleep 30;
	else
		get_link_status;
		check_link_state;
		sleep 2;
	fi
done
