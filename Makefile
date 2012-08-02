all:
#	gcc -O3 -fomit-frame-pointer -msse4.2 -s -Wall -Werror -o halbpd halbpd.c -lssl -lst -ljemalloc
	gcc -O3 -fomit-frame-pointer -mcpu=corei7-avx -s -Wall -Werror -o halbpd halbpd.c -lssl -lst -ljemalloc
#	gcc -g -Wall -Werror -o halbpd halbpd.c -lssl -lst

keys:
	openssl genrsa 1024 > server.key
	openssl req -new -x509 -nodes -sha1 -days 365 -subj '/CN=localhost' -key ./server.key > server.crt

install: all
	mv halbpd /usr/local/bin
	mkdir -p /etc/halbpd
	cp config.sample /etc/halbpd/config
	openssl genrsa 1024 > /etc/halbpd/server.key
	openssl req -new -x509 -nodes -sha1 -days 365 -subj '/CN=localhost' -key /etc/halbpd/server.key > /etc/halbpd/server.crt

deb:
	sudo checkinstall --exclude=/home --fstrans=no --requires 'libst1,libssl1.0.0,libjemalloc'
