all:	quic-new-from-listener \
	quic-client-server \
	file_list.h	\
	file_1024.txt	\
	file_2048.txt	\
	file_3072.txt	\
	file_4096.txt	\
	file_1234.txt

CPPFLAGS=-I/home/sashan/work.openssl/openssl.binaries/openssl-master.listener/include
LDFLAGS=-L/home/sashan/work.openssl/openssl.binaries/openssl-master.listener/lib/
LIBS=-lcrypto
LIBS+=-lssl
quic-new-from-listener: quic-new-from-listener.c file_list.h
	$(CC) -g -O0 $(CPPFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

quic-client-server: quic-client-server.c file_list.h
	$(CC) -g -O0 $(CPPFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)

file_1024.txt:
	perl -e 'print "a" x 1024;' > $@

file_2048.txt:
	perl -e 'print "a" x 2048;' > $@

file_3072.txt:
	perl -e 'print "a" x 3072;' > $@

file_4096.txt:
	perl -e 'print "a" x 4096;' > $@

file_1234.txt:
	perl -e 'print "a" x 1234;' > $@

file_list.h:
	echo '#ifndef _FILE_LIST_H_' > $@
	echo '#define _FILE_LIST_H_' >> $@
	echo 'static const char *files[] = {' >> $@
	echo '    "file_1024.txt",' >> $@
	echo '    "file_2048.txt",' >> $@
	echo '    "file_3072.txt",' >> $@
	echo '    "file_4096.txt",' >> $@
	echo '    "file_1234.txt",' >> $@
	echo '    NULL' >> $@
	echo '};' >> $@
	echo '#endif	/* _FILE_LIST_H_ */'>> $@

clean:
	rm -f file_*.txt
	rm -f file_list.h
	rm -f quic-new-from-listener
	rm -f quic-client-server
