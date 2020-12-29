.NOTPARALLEL:
WTP_OBJS = WTP.o WTPConfigFile.o WTPProtocol.o WTPProtocol_User.o WTPDiscoveryState.o WTPJoinState.o WTPConfigureState.o WTPDataCheckState.o WTPRunState.o WTPRunStateCheck.o WTPRetransmission.o WTPSulkingState.o CWCommon.o CWConfigFile.o CWErrorHandling.o CWSafeList.o CWList.o CWLog.o CWNetwork.o CWProtocol.o CWRandom.o CWSecurity.o CWOpenSSLBio.o CWStevens.o CWThread.o CWBinding.o CWVendorPayloadsWTP.o WTPBinding.o WTPDriverInteraction.o WTPSettingsFile.o timerlib.o DTTConfigUpdate.o DTTWltp.o DTTConfigbin.o DTTKmodCommunicate.o DTTAclConfig.o

WTP_NAME = WTP

TARGET_CFLAGS += -ggdb3
LFLAGS += -lcrypto -lssl -lpthread -ldl
CFLAGS += -Wall -D_REENTRANT -DCW_NO_DTLS  -DCW_NO_DTLSCWParseConfigurationUpdateRequest -DOPENSSL_NO_KRB5 -o0 #-g -DCW_DEBUGGING -DWRITE_STD_OUTPUT

.PHONY: all
all:$(WTP_NAME)
$(WTP_NAME): $(WTP_OBJS)
	$(CC) $(WTP_OBJS) $(CFLAGS) $(LFLAGS) $(LDFLAGS) -o $@

