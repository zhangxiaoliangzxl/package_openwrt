#CC=mips-openwrt-linux-gcc

CFLAGS   = -Os -Wall
LDFLAGS  = 
#LDFLAGS_a  = -lpthread -lcurl -ljson-c -lsqlite3 

all: pspi

objs=pspi.o

$(objs): %.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $^

pspi: $(objs)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o pspi
