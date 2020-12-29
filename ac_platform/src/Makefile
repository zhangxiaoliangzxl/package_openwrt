ROOTPATH=.
INCLUDE = -I$(ROOTPATH)/elog
LOCAL_LIBRARY +=
LOCAL_LDFLAGS += -lm -lpthread -lssl -lcrypto -luci -lcurl -lcjson

LOCAL_CFLAGS += -fno-stack-protector -Wno-unused-but-set-variable
#-Wno-format-security

TARGET = ac_platform

OBJ_MAIN += $(patsubst %.c, %.o, $(wildcard *.c))
OBJ_LOG += $(patsubst %.c, %.o, $(wildcard $(ROOTPATH)/elog/*.c))

CFLAGS += $(LOCAL_CFLAGS)
LDFLAGS += $(LOCAL_LIBRARY) $(LOCAL_LDFLAGS)

$(info $(TARGET))
$(info $(OBJ_MAIN))
$(info $(OBJ_LOG))

all: $(TARGET)

$(TARGET):$(OBJ_MAIN) $(OBJ_LOG)
	$(CC)  -o $@ $^  $(LDFLAGS) $(CFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)

clean :
	@rm -rf $(TARGET) ${wildcard *.o}

#.SUFFIXES:
.PHONY : all clean
