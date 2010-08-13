all:
	gcc -O3 -fomit-frame-pointer -march=opteron -msse -msse2 -msse3 -mfpmath=sse -s -Wall -Werror -o halbpd halbpd.c -lssl -lst -L. -lm
#	gcc -g -Wall -Werror -o halbpd halbpd.c -lssl -lst -L. -lm

keys:
	openssl genrsa 1024 > server.key
	openssl req -new -x509 -nodes -sha1 -days 365 -subj '/CN=localhost' -key ./server.key > server.crt

