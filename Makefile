all: compdetect compdetect_client compdetect_server

compdetect: compdetect.c
	gcc -o compdetect compdetect.c -ljansson -lpthread

compdetect_client: compdetect_client.c
	gcc -o compdetect_client compdetect_client.c -ljansson

compdetect_server: compdetect_server.c
	gcc -o compdetect_server compdetect_server.c -ljansson

clean:
	rm -f compdetect compdetect_client compdetect_server
