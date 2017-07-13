pcap_test: pcap.o main.o
	gcc -o pcap_test pcap.o main.o -lpcap

pcap.o: pcap.c pcap.h
	gcc -c -o pcap.o pcap.c -lpcap

main.o: main.c pcap.h
	gcc -c -o main.o main.c -lpcap

clean:
	rm *.o pcap_test
