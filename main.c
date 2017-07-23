#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

int main(int argc, char *argv[])
{
    int i;
    int res;
    int dataAddr;
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    char filter_exp[] = "port 80";	/* The filter expression */
    struct bpf_program fp;		/* The compiled filter */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    struct ether_header *p_analyze;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    pcap_t *handle;			/* Session handle */
    const u_char *pkt_data;


    /* Open the session in promiscuous mode */
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return(2);
    }
    while(1){
        /* Grab a packet */
        res = pcap_next_ex(handle, &header, &pkt_data);
        p_analyze = (struct ether_header *) pkt_data;
        ip_header = (struct iphdr *)(pkt_data+sizeof(*p_analyze));
        tcp_header = (struct tcphdr *)(pkt_data+sizeof(p_analyze)+((ip_header->ihl)*4));
        if(res == 1)
            if(ntohs(p_analyze->ether_type) == ETHERTYPE_IP && ip_header->protocol == IPPROTO_TCP)
            {
                printf("ETHERTYPE IS IP! and PROTOCOL IS TCP!\n");
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
                dataAddr = sizeof(p_analyze)+sizeof(tcp_header)+sizeof(ip_header);
                printf("Data(Hex) : ");
                for(i = dataAddr; i < header->len; i ++)
                {
                    printf("%X",*(pkt_data+i));
                }
                printf("\n");
                printf("Data(Char) : ");

                for(i = dataAddr; i < header->len;  i ++)
                {
                    printf("%c",*(pkt_data+i));
                }
                printf("\n\n");
            }
    }
    pcap_close(handle);
    return(0);
}
