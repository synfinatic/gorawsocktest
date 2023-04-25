FILES := csocktest.c ifaddrlist.c
OS ?= $(shell uname -s | tr "[:upper:]" "[:lower:]")
DEFS :=  -DHAVE_SYS_SELECT_H=1 -DHAVE_NET_ROUTE_H=1 -DHAVE_NET_IF_DL_H=1 -DHAVE_STRERROR=1 -DHAVE_USLEEP=1 -DHAVE_SETLINEBUF=1 -DHAVE_ICMP_NEXTMTU=1 -DIP_HDRINCL=1 -DSO_SNDBUF=1 -DHAVE_RAW_OPTIONS=1

ALL: csocktest-$(OS)

.PHONY: csocktest-linux csocktest-darwin csocktest-freebsd

csocktest-linux:
	gcc -lc -o csocktest \
		-Ilinux-include \
		-DHAVE_USLEEP=1 \
		-DHAVE_STRERROR=1 \
		$(DEFS) $(FILES) findsaddr-linux.c

csocktest-darwin:
	gcc -lc -o csocktest \
		-DHAVE_SYS_SOCKIO_H=1 \
		-DHAVE_SOCKADDR_SA_LEN=1 \
		$(DEFS) $(FILES) findsaddr-socket.c strerror.c usleep.c

csocktest-freebsd:
	gcc -lc -o csocktest \
		-DBYTESWAP_IP_HDR=1 \
		-DHAVE_USLEEP=1 \
		-DHAVE_STRERROR=1 \
		$(DEFS) $(FILES) findsaddr-generic.c
