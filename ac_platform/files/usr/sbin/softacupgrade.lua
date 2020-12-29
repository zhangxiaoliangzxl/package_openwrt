local n = require "nixio"

function fork_exec(command)
	local pid = nixio.fork()
	if pid > 0 then
		return
	elseif pid == 0 then
		-- change to root dir
		nixio.chdir("/")

		-- patch stdin, out, err to /dev/null
		local null = nixio.open("/dev/null", "w+")
		if null then
			nixio.dup(null, nixio.stderr)
			nixio.dup(null, nixio.stdout)
			nixio.dup(null, nixio.stdin)
			if null:fileno() > 2 then
				null:close()
			end
		end

		-- replace with target command
		nixio.exec("/bin/sh", "-c", command)
	end
end

function mysleep(n)
   os.execute("sleep " .. n)
end

fork_exec("/etc/init.d/ac_platform stop") 
mysleep(2)
fork_exec("/bin/opkg install /tmp/softac.ipk")
mysleep(2)
fork_exec("/etc/init.d/ac_platform start")  
 
