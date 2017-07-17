#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>

int main(int argc, char *argv[])
{
    int i;
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *pkt_data;
    struct ether_header *p_analyze;
    int res;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while(1){
        /* Grab a packet */
        res = pcap_next_ex(handle, &header, &pkt_data);
        if(res == 1)
        {
          p_analyze = (struct ether_header *) pkt_data;
          printf("====================Source====================\n");
          printf("MAC Address : ");
          for(i = 0; i < ETH_ALEN; i ++)
          {
            printf("%02x",*((p_analyze->ether_shost)+i));
            if(i < 5)
                printf(":");
          }
          printf("\n");
          printf("IP : ");
          for(i = 26; i < 30; i ++)
              printf("%d.",*(pkt_data+i));
          printf("\b \n");
          printf("Port : %d\n",*(pkt_data+34)+*(pkt_data+35));
          printf("==================Destination=================\n");
          printf("MAC Address : ");
          for(i = 0; i < ETH_ALEN; i ++)
          {
            printf("%02x",*((p_analyze->ether_dhost)+i));
            if(i < 5)
                printf(":");
          }
          printf("\n");
          printf("IP : ");
          for(i = 30; i < 34; i ++)
              printf("%d.",*(pkt_data+i));
          printf("\b \n");
          printf("Port : %d\n",*(pkt_data+36)+*(pkt_data+37));
          printf("=====================Data=====================\n");
          printf("Data(Hex) : ");
          for(i = 54; *(pkt_data+i) != NULL; i ++)
          {
            printf("%X",*(pkt_data+i));
          }
          printf("\n");
          printf("Data(Char) : ");
          for(i = 54; *(pkt_data+i) != NULL; i ++)
          {
            printf("%c",*(pkt_data+i));
          }
          printf("\n\n");
        }
    }
    pcap_close(handle);
    return(0);
}
