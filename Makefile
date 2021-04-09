all: replayer.c
	gcc replayer.c -lpcap -ldumbnet -o replayer

clean:
	$(RM) replayer
