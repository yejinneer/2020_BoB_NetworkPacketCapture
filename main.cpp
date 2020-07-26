#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

//#define ETHERTYPE_IP            0x0800  /* IP protocol */



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    struct libnet_ethernet_hdr *eth_hdr;
    //안에 uint8_t  ether_dhost[ETHER_ADDR_LEN], ether_shost[ETHER_ADDR_LEN]
    //    uint16_t ether_type 가 있음.

    struct libnet_ipv4_hdr *ipv4_hdr;
    //안에 struct in_addr ip_src, ip_dst가 있음.

    struct libnet_tcp_hdr *tcp_hdr;
    //안에 uint16_t th_sport, th_dport가 있음.
    uint16_t eth_type;


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("\n--------Network Packet--------\n");
        printf("%u bytes captured\n", header->caplen);


        eth_hdr = (struct libnet_ethernet_hdr *)packet;
        packet += sizeof(struct libnet_ethernet_hdr);
        ipv4_hdr = (struct libnet_ipv4_hdr *)packet;
        eth_type = ntohs(eth_hdr->ether_type);


        //Ethernet Header의 MAC주소 출력
        printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_dhost[0],eth_hdr->ether_dhost[1],
                eth_hdr->ether_dhost[2],eth_hdr->ether_dhost[3],
                eth_hdr->ether_dhost[4],eth_hdr->ether_dhost[5]);
        printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_shost[0],eth_hdr->ether_shost[1],
                eth_hdr->ether_shost[2],eth_hdr->ether_shost[3],
                eth_hdr->ether_shost[4],eth_hdr->ether_shost[5]);

        if(eth_type == ETHERTYPE_IP){
            //IP Header의 IP주소 출력
            printf("Src Address : %s\n", inet_ntoa(ipv4_hdr->ip_src));
            printf("Dst Address : %s\n", inet_ntoa(ipv4_hdr->ip_dst));
            if(ipv4_hdr->ip_p == IPPROTO_TCP){
                tcp_hdr = (struct libnet_tcp_hdr *)(packet+ipv4_hdr->ip_hl *4);
                //TCP Header의 Port번호 출력
                printf("Src Port : %d\n", ntohs(tcp_hdr->th_sport));
                printf("Dst Port : %d\n", ntohs(tcp_hdr->th_dport));
            }
        }
        //Data Payload 부분 16바이트 출력
        int len = 0;
        packet+=40;
        while (len < 16){
            printf("%02x ", *(packet++));
            if(!(++len % 8)) printf("\n");
        }
    }


}
