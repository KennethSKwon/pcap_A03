all:
	gcc -o pcap_A03_v1 pcap_A03_v1.c -lpcap -w

clean:
	rm pcap_A03_v1
	rm index.html* -rf