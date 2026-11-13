CC = cc
CFLAGS = -Wall -Wextra -O2

proxy: proxy.c
	$(CC) $(CFLAGS) proxy.c -o proxy

clean:
	rm -rf proxy

.PHONY: clean
