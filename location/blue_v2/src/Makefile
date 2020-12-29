	
LOCAL_LIBRARY +=
LOCAL_LDFLAGS += -lm -lpthread -lcjson
# -lpthread -luci
LOCAL_CFLAGS += -fno-stack-protector


TARGETS1 = blue_v2

SRCS1 = ${wildcard *.c}
OBJS1 = $(patsubst %.c, %.o, $(SRCS1))

CFLAGS += $(LOCAL_CFLAGS)
LDFLAGS += $(LOCAL_LIBRARY) $(LOCAL_LDFLAGS)

$(info $(OBJS))
$(info $(TARGETS))

all: $(TARGETS1)


$(TARGETS1):$(OBJS1)
	$(CC)  -o $@ $^  $(LDFLAGS) $(CFLAGS)

$(OBJS1): %.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean :
	@rm -rf $(TARGETS1) ${wildcard *.o}

#.SUFFIXES:
.PHONY : all clean
