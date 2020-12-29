ROOTPATH=.
INCLUDE = -I$(ROOTPATH)/elog
INCLUDE += -I$(ROOTPATH)/inc	
LOCAL_LIBRARY +=
LOCAL_LDFLAGS += -lm -lpthread -lcjson
# -lprotobuf-c
#-lmsgpackc
# -lpthread -luci
LOCAL_CFLAGS += -fno-stack-protector

TARGET = blelink
TEST = blelinktest

OBJ_LOG += $(patsubst %.c, %.o, $(wildcard $(ROOTPATH)/elog/*.c))
OBJ_MAIN += $(patsubst %.c, %.o, $(wildcard $(ROOTPATH)/main/*.c))
OBJ_TEST += $(patsubst %.c, %.o, $(wildcard $(ROOTPATH)/test/*.c))

CFLAGS += $(LOCAL_CFLAGS)
LDFLAGS += $(LOCAL_LIBRARY) $(LOCAL_LDFLAGS)

$(info $(TARGET))
$(info $(OBJ_MAIN))
$(info $(OBJ_LOG))

all: $(TARGET) $(TEST)

$(TARGET):$(OBJ_MAIN) $(OBJ_LOG)
	$(CC)  -o $@ $^  $(LDFLAGS) $(CFLAGS)
	
$(TEST):$(OBJ_TEST)
	$(CC)  -o $@ $^  $(LDFLAGS) $(CFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)

clean :
	#@rm -rf $(TARGET) ${wildcard *.o}
	rm -rf $(TARGET) $(TEST) main/*.o elog/*.o test/*.o

#.SUFFIXES:
.PHONY : all clean
