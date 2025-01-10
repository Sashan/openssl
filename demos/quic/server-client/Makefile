#
# To run the demo when linked with a shared library (default) ensure that
# libcrypto and libssl are on the library path. For example:
#
#    LD_LIBRARY_PATH=../.. ./server 4444 \
#    	../../test/certs/servercert.pem \
#    	../../test/certs/serverkey.pem
#
# TODO(QUIC SERVER): Add build.info.
#
CFLAGS  += -g -O0 -Wall -Wsign-compare
LDLIBS  = -lcrypto -lssl

all: qclient qserver qclient-listene

qclient: qclient_qserver.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

qserver: qclient
	cp qclient qserver
	cp qclient qclient-listene

clean:
	$(RM) qclient qclient-listene qserver *.o
