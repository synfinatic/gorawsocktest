FILES := csocktest.c ifaddrlist.c findsaddr-socket.c
OS ?= $(shell uname -s | tr "[:upper:]" "[:lower:]")
DEFS :=  -DHAVE_SYS_SELECT_H=1 -DHAVE_SYS_SOCKIO_H=1 -DHAVE_NET_ROUTE_H=1 -DHAVE_NET_IF_DL_H=1 -DHAVE_STRERROR=1 -DHAVE_USLEEP=1 -DHAVE_SETLINEBUF=1 -DHAVE_SOCKADDR_SA_LEN=1 -DHAVE_ICMP_NEXTMTU=1 -DIP_HDRINCL=1 -DSO_SNDBUF=1 -DHAVE_RAW_OPTIONS=1

ALL: csocktest-$(OS)

.PHONY: csocktest-linux csocktest-darwin csocktest-freebsd

csocktest-linux:
	gcc -lc -o csocktest $(FILES) findsaddr-linux.c

csocktest-darwin:
	gcc -lc -o csocktest $(DEFS) $(FILES) strerror.c usleep.c version.c

csocktest-freebsd:
	gcc -lc -o csocktest $(DEFS) $(FILES) findsaddr-generic.c
