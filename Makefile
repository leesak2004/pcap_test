pcap_test: pcap.o main.o
	gcc -o pcap_test pcap.o main.o

pcap.o: pcap.c pcap.h
	gcc -c -o pcap.o pcap.c

main.o: main.c pcap.h
	gcc -c -o main.o main.c

clean:
	rm *.o pcap_test
