#!/usr/bin/lua
--require("curl");
--所有终端站点
stations={
	--['12:23:34:44:56']= {
	--	--current nums
	--	count = 0,
	--	stamp = 0,
	--	rssi = -54,
	--},
};

--表、函数、线程、以及完全用户数据在 Lua 中被称为 对象： 变量并不真的 持有它们的值，而仅保存了对这些对象的 引用

function upload(thefile)
	local data=nil;
	local file = io.open(thefile, "r");
	local apmac;
	os.execute("cat /sys/class/net/br-lan/address | head -n 1 | tr 'a-z' 'A-Z' | tr -d '\n' > /tmp/cscan/apmac");
	local fapmac= io.open("/tmp/cscan/apmac");
	assert(fapmac);
	for line in fapmac:lines() do
		apmac=line;
		if apmac ~= nil then
			break;
		end
	end
	assert(file);
	for line in file:lines() do
		--for a,b in string.gmatch(line,"(.+),(.+)") do
		local a,b = string.match(line,"(.+),(.+)");
		--	end
		--print(a,b);
		if nil ~= a and nil ~= b and nil == stations[a] then
			local child={};
			child.count=1;
			child.stamp=os.time();
			child.rssi=b;
			stations[a]=child;
		--	print("nil add==> "..a, stations[a].count, stations[a].stamp, stations[a].rssi);
		elseif nil ~= a and nil ~= stations[a].stamp then --and os.time()-stations[a].stamp < 9 then
			stations[a].count = stations[a].count + 1;
			stations[a].rssi = math.floor((stations[a].rssi + b)/2);
		--	print("exist add==> "..a, stations[a].count, stations[a].stamp, stations[a].rssi);
		elseif nil ~= a then
		--	table.remove(stations, a);
			stations[a]=nil;
		end
		--os.exit();
	end
	io.close(file);
	--for  j, k in pairs(teststation) do
	for  a, b in pairs(stations) do
		--print(a, b.count, b.stamp, b.rssi);
		if data == nil then
			data = "data=*CHTS*"..tostring(apmac).."/"..tostring(a).." "..string.gsub(tostring(b.rssi),"%s", "").."/";
		else
			data = tostring(data)..tostring(a).." "..string.gsub(tostring(b.rssi),"%s","").."/";
		end
		--print(a, stations[a].stamp, stations[a].count, stations[a].rssi);	
	end
	--print(data);
	--include the end of content
	if data == nil then 
		data="NULL";	
		--cf=">"..thefile;
		--os.execute(cf);
		return data;
	end
	data = tostring(data).."*STCH*";
--	cf=">"..thefile;
--	os.execute(cf);
	return data;
	--for line in io.lines(thefile)
	--do
	--	print(line);
	--end
end

--luacurl=1;
--function loginWeb(ip, data) 
--	c = curl.easy_init();
--	--c:setopt(curl.OPT_VERBOSE, 1); 
--	c:setopt(curl.OPT_POST, 1); 
--	c:setopt(curl.OPT_TIMEOUT, 3); 
--	c:setopt(curl.OPT_SSL_VERIFYHOST, 0); 
--	c:setopt(curl.OPT_SSL_VERIFYPEER, 0); 
--	if string.match(ip, "http://") == nil then
--		c:setopt(curl.OPT_URL, "http://"..ip.."/");
--	else
--		c:setopt(curl.OPT_URL, ip);
--	end
--	c:setopt(curl.OPT_POSTFIELDS, "data="..data)
--	c:setopt(curl.OPT_WRITEFUNCTION, function(buffer)
--		--print(buffer);
--		luacurl=buffer;
--		return #buffer;
--	end);
--	c:perform();
--end
--loginWeb("120.25.226.16", do_file("./12"));
--
--function upload(addr, file)
--	local state = loginWeb(addr, do_file(file));
--	--print(luacurl);
--	return luacurl;
--end
--upload("shizhai.airocov.com", "./12");
