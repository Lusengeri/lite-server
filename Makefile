lite:lite.c
	gcc lite.c -o lite -lssl -lcrypto

clean:
	rm *.pem lite
