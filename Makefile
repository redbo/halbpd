all:
	gcc -O3 -s -Wall -Werror -o halbd halbd.c -lssl -lst -L. -lm

keys:
	openssl genrsa 1024 > server.key
	openssl req -new -x509 -nodes -sha1 -days 365 -subj '/CN=localhost' -key ./server.key > server.crt

