#!/bin/sh

APMODE=$(uci get wtp.cfg.apmode)
WTPENABLE=$(uci get wtp.cfg.enable)

echo apmode:$APMODE enable:$WTPENABLE

bridge_set(){
	if [ "$1" -eq "1" ];then
		echo "set bridge mode ..."
		cp /etc/config/network /usr/capwap/network_fat
		cp /etc/config/wireless /usr/capwap/wireless_fat
		
		uci delete network.wan
		uci delete network.wan6
	
		uci set network.lan.ifname='eth0.1 eth0.2'
		uci set network.lan.proto='dhcp'
		uci set network.lan.type='bridge'
			
		uci delete network.lan.ipaddr
		uci delete network.lan.netmask
		uci delete network.lan.ip6assign

		uci set network.@switch[-1].enable_vlan=1
		uci commit network
	fi

	if [ "$1" -eq "0" ];then
		echo "set wan ..."

		mv /usr/capwap/network_fat /etc/config/network
		mv /usr/capwap/wireless_fat /etc/config/wireless

	fi
}

dnsmasq_set(){
	if [ "$1" -eq "1" ]
	then
		echo "stop dnsmasq ..."
		/etc/init.d/dnsmasq stop   
		/etc/init.d/dnsmasq disable
	fi
	
	if [ "$1" -eq "0" ]
	then
		echo "start dnsmasq ..."
		/etc/init.d/dnsmasq restart
		/etc/init.d/dnsmasq enable
	fi
}

firewall_set(){
	if [ "$1" -eq "1" ]
	then
		echo "stop firewall ..."
		/etc/init.d/firewall stop
		/etc/init.d/firewall disable
	fi
		
	if [ "$1" -eq "0" ]
	then
		echo "start firewall ..."
		/etc/init.d/firewall restart
		/etc/init.d/firewall enable
	fi
}

if [ "$WTPENABLE" -eq "0" ] && [ "$APMODE" == "fit" ];then
	echo "set Fat mode"
	dnsmasq_set 0
	firewall_set 0
	bridge_set 0
	mv /etc/modules.d/70-cloud_wlan /usr/capwap/
	rmmod -f cloud_wlan
	killall WTP
	#crontab -r
	sed -i -e '/capwap/d' /etc/crontabs/root
	/etc/init.d/network restart
	uci set wtp.cfg.apmode=fat
	uci commit wtp
	logger "AP is set in Fat mode ..."

elif [ "$WTPENABLE" -eq "1" ] && [ "$APMODE" == "fat" ];then
	echo "set Fit mode"
	dnsmasq_set 1
	firewall_set 1
	bridge_set 1
	echo "*/5 * * * * /usr/capwap/nmapip.sh > /tmp/capwap/ip-mac" >> /etc/crontabs/root
	cp -rf /usr/capwap/70-cloud_wlan /etc/modules.d/70-cloud_wlan
	#/etc/init.d/WTP enable
	#/etc/init.d/network restart
	uci set wtp.cfg.apmode=fit
	uci commit wtp
	logger "AP is set in Fit mode ..."
fi


