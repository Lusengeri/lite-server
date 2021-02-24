all: lite logging.o

lite:lite.c logging.o
	gcc lite.c logging.o -o lite -lssl -lcrypto

logging.o: logging.c
	gcc -c logging.c
clean:
	rm *.o lite


