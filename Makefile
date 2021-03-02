all: lite allog.o list.o

lite:lite.c ../allog/allog.o ../allog/list.o
	gcc lite.c ../allog/allog.o ../allog/list.o -o lite -lssl -lcrypto

allog.o: ../allog/allog.c
	gcc -c ../allog/allog.c

list.o: ../allog/list.c
	gcc -c ../allog/list.c

clean:
	rm *.o lite


