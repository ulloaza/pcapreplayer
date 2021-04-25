#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <dumbnet.h>
#include <fcntl.h>
#include <string.h>

#define CMD " tcp and dst host %s and src host %s"

/* AUTHOR SELF NOTES FOR USING LIBDNET:
 * uint8 can be called normally.
 * uint16 requires ntohs
 * uint32 requires ntohl
 * */

// PROTOTYPES FOLLOW:
void usage(void);
void open_devices(void);
void setfilter();
void rmnl(char *s);
void proc_Seq(unsigned char *user, struct pcap_pkthdr *h, unsigned char *pack );
void proc_pkt(const unsigned char *pack);
int load_address(FILE *fp, char *ip, char *hw,struct addr *ad, struct addr *ha);
void readcfg(char *filename);
void load_error(int e, char *mach);

// Config arrays for reading in config file.
char logfile[32], iface[32]; 
char lvIP[32], lvMac[32];       // log victim ascii ip and mac addresses
char laIP[32], laMac[32];       // log attack ascii ip and mac addresses
char reaIP[32], reaMac[32];       // my ascii ip and mac addresses
char revIP[32], revMac[32];       // replay ascii ip and mac addresses
char timing[32];
char lvPort[10], laPort[10], reaPort[10], revPort[10];
int locPort, remPort;
unsigned int newAck = 0;



/* Better timeval struct to preserve caplen and len */
struct timev {
    unsigned int tv_sec;
    unsigned int tv_usec;
};
/* data prefixing each packet */
struct cust_pkthdr {
    struct timev ts;
    int caplen;
    int len;
};

struct pcap_file_header pcaphdr;
struct cust_pkthdr pkthdr;

// Addr structures for config and log
struct addr localIP, localMac;                     // my ip and mac address structures
struct addr remoteIP, remoteMac;                   // ReVictim ip and mac address structures
struct addr logatkIP, logatkMac;                   // Log attacker ip and mac address structures
struct addr logvicIP, logvicMac;                   // Log victim ip and mac address structures

/* Safely assumed max snaplen. Potential for overflow. 
May try to fix later tho. */
char buffer[65535];
char ebuf[2048];

// Sets relative time of the first ingested packet, sets counter vars.
int firsttime = 0;
unsigned int counter = 0;
unsigned int b_sec = 0;
int b_usec = 0;
int fd;
int sending;
int err;
int initpkt = 0;

intf_t *i;
eth_t *e;
pcap_t *p;
struct bpf_program fcode;
uint32_t localnet, netmask;
char *cfile;

int main(int argc, char **argv) {
    // Detect switch and arg check
    if ( argc == 2 ) {
        cfile = argv[1];
        sending = 0;
        }
    else if ( argc == 3 ) {
        cfile = argv[2];
        if (strcmp(argv[1], "-s") == 0) {
            sending = 1;
            }
        }
    else {
        usage();
        }

    readcfg(cfile);
    open_devices();
    setfilter();

    fd = open(logfile, O_RDONLY);
    if (fd == -1) {
        printf("ERROR: Could not find pcap file %s", argv[1]);
    }
    // Precursory PCAP Header Info
    read(fd, &pcaphdr, sizeof(pcaphdr));
    printf("PCAP_MAGIC\n");
    printf("Version major number = %u\n", pcaphdr.version_major);
    printf("Version minor number = %u\n", pcaphdr.version_minor);
    printf("GMT to local correction = %u\n", pcaphdr.thiszone);
    printf("Timestamp accuracy = %u\n", pcaphdr.sigfigs);
    printf("Snaplen = %u\n", pcaphdr.snaplen);
    printf("Linktype = %u\n", pcaphdr.linktype);
    printf("\n");


    // Read and process packet header
    while(read(fd, &pkthdr, sizeof(pkthdr))) {
        
        unsigned int c_sec = 0;
        int c_usec = 0;

        if(firsttime == 0) { 
            firsttime = 1;
            b_sec = pkthdr.ts.tv_sec;
            b_usec = pkthdr.ts.tv_usec;
        }
        c_sec = pkthdr.ts.tv_sec - b_sec;
        c_usec = pkthdr.ts.tv_usec - b_usec;
        while (c_usec < 0) {
            c_usec += 1000000;
            c_sec--;
        }    
        
        printf("Packet %u\n", counter);
        printf("%u.%06d\n", c_sec, c_usec);
        printf("Captured Packet Length = %u\n", pkthdr.caplen);
        printf("Actual Packet Length = %u\n", pkthdr.len);

        // Read next packet
        read(fd, buffer, pkthdr.caplen);
        proc_pkt(&buffer[0]);
        printf("\n");
        counter++;
    }

}

// Usage display
void usage(void) {
    fprintf(stderr, "Usage: replayer [-s] <configuration file>\n");
    fprintf(stderr, "         configuration file format\n");
    fprintf(stderr, "            <client mac>\n");
    fprintf(stderr, "            <tcpdump log file>\n");
    fprintf(stderr, "            <victim ip>\n");
    fprintf(stderr, "            <victim mac>\n");
    fprintf(stderr, "            <victim port>\n");
    fprintf(stderr, "            <attacker ip>\n");
    fprintf(stderr, "            <attacker mac>\n");
    fprintf(stderr, "            <attacker port>\n");
    fprintf(stderr, "            <replay victim ip>\n");
    fprintf(stderr, "            <replay victim mac>\n");
    fprintf(stderr, "            <replay victim port>\n");
    fprintf(stderr, "            <replay attacker ip>\n");
    fprintf(stderr, "            <replay attacker mac>\n");
    fprintf(stderr, "            <replay attacker port>\n");
    fprintf(stderr, "            <interface>\n");
    fprintf(stderr, "            <timing>\n");
    fprintf(stderr, "         [-s - Send packets to config victim]\n");
    exit(-1);
}

// Loads two ascii addresses into respective addr ip and addr mac form.
int load_address(FILE *fp, char *ip, char *hw,struct addr *ad, struct addr *ha) {
  /* Get ip address */
  if ( fgets(ip, 32, fp) == NULL ) 
    return(-1);
  rmnl(ip);
  if ( addr_aton(ip, ad) == -1 ) 
    return(-2);
  /* Get hardware address */
  if ( fgets(hw, 32, fp) == NULL ) 
    return(-3);
  rmnl(hw);
  if ( addr_aton(hw, ha) == -1 ) {
    return(-4);
  }
  return(0);
}

// Set the bpf filter to only accept tcp packets from the clients
// to this machine.
void setfilter() {
  char cmd[128];
  if ( pcap_lookupnet(iface, &localnet, &netmask, ebuf) < 0 ) {
    fprintf(stderr,"pcap_lookupnet: %s\n", ebuf);
    exit(-1);
  }
  snprintf(cmd, sizeof(cmd), CMD, reaIP, revIP);
  printf("Filter:%s\n",cmd);
  if ( pcap_compile(p, &fcode, cmd, 0, netmask) < 0 ) {
    fprintf(stderr,"pcap_compile: %s\n", pcap_geterr(p));
    exit(-1);
  }
  if ( pcap_setfilter(p, &fcode) < 0 ) {
    fprintf(stderr,"pcap_setfilter: %s\n", pcap_geterr(p));
    exit(-1);
  }
}

// Replace newline with null character
void rmnl(char *s) {
  while ( *s != '\n' && *s != '\0' )
    s++;
  *s = '\0';
}

void readcfg(char *filename) {
  FILE *fp;

  fp = fopen(filename,"r");
  if ( fp == NULL ) {
    perror(filename);
    exit(-1);
  }
  if ( fgets(logfile, 32, fp) == NULL ) 
    exit(-1);
  rmnl(logfile);

  // Get log vic addresses & Port dest
  if ( (err = load_address(fp,lvIP,lvMac,&logvicIP,&logvicMac)) < 0 )
    load_error(err,"Log Victim");
  if ( fgets(lvPort, 10, fp) == NULL ) 
    exit(-1);
  rmnl(lvPort);

  // Get log attack addresses
  if ( (err = load_address(fp,laIP,laMac,&logatkIP,&logatkMac)) < 0 )
    load_error(err,"Log Attacker");
  if ( fgets(laPort, 10, fp) == NULL ) 
    exit(-1);
  rmnl(laPort);

  // Get replay victim addresses
  if ( (err = load_address(fp,revIP,revMac,&remoteIP,&remoteMac)) < 0 )
    load_error(err,"Replay victim");
  fscanf(fp, "%d ", &remPort);
  remPort = htons(remPort);
  
  // Get my addresses
  if ( (err = load_address(fp,reaIP,reaMac,&localIP,&localMac)) < 0 )
    load_error(err,"Replay attacker");
  fscanf(fp, "%d ", &locPort);
  locPort = htons(locPort);

  if ( fgets(iface, sizeof(iface), fp) == NULL ) {
    fprintf(stderr, "Interface too large\n");
    exit(-1);
  }
  rmnl(iface);

  if ( fgets(timing, 32, fp) == NULL ) 
    exit(-1);
  rmnl(timing);

  fclose(fp);
}

void open_devices(void) {

    i = intf_open();
    if ( i == NULL ) {
      perror("intf open error");
      exit(-1);
    }
  
    e = eth_open(iface);
    if ( e == NULL ) {
      perror("eth open error");
      exit(-1);
    }

    p = pcap_open_live(iface, 65535, 1, 1000, ebuf);
    if ( p == NULL ) {
      perror(ebuf);
      exit(-1);
    }
}

// Get seq number from host packet
void proc_Seq(unsigned char *user, struct pcap_pkthdr *h, unsigned char *pack ){
    // victim response packet headers
    struct eth_hdr *eth_hdr;
    struct ip_hdr *ip_hdr;
    struct tcp_hdr *tcp_hdr;
    eth_hdr = (struct eth_hdr *)pack;
    ip_hdr = (struct ip_hdr *)(pack + ETH_HDR_LEN);
    tcp_hdr = (struct tcp_hdr *)(pack + ETH_HDR_LEN + IP_HDR_LEN);
    
    // If we haven't threeway-handshake'd, find init Ack
    if (newAck == 0){
        newAck = ntohl(tcp_hdr->th_seq);
        newAck++;
        return;
    }
    // Else just use the len for the ack
    else {
        newAck = newAck + ntohl(ip_hdr->ip_len);
        return;
    }
}

// Proccess packet for retransmission or discard
void proc_pkt(const unsigned char *pack) {
    struct addr addr;
    struct addr curpktSIP, curpktSMac;
    struct addr curpktDIP, curpktDMac;
    struct eth_hdr *eth_hdr;
    struct ip_hdr *ip_hdr;
    struct arp_hdr *arp_hdr;
    int n;

    eth_hdr = (struct eth_hdr *)pack;

    // Prints MAC information
    addr_pack(&curpktSMac,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(eth_hdr->eth_src),ETH_ADDR_LEN);
    addr_pack(&curpktDMac,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(eth_hdr->eth_dst),ETH_ADDR_LEN);
    
    printf(" eth_src = %s\n", addr_ntoa(&curpktSMac));
    printf(" rep_src = %s\n", addr_ntoa(&localMac));
    printf(" eth_dst = %s\n", addr_ntoa(&curpktDMac));
    printf(" rep_dst = %s\n", addr_ntoa(&remoteMac));

    addr_pack(&addr,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(eth_hdr->eth_type),ETH_TYPE_LEN);
    
    // Handles actions and printing for IP packets
    if(ntohs(eth_hdr->eth_type) == ETH_TYPE_IP) {
        ip_hdr = (struct ip_hdr *)(pack + ETH_HDR_LEN);    
        printf("\tIP\n");
        printf("\t ip_len = %i\n", ntohs(ip_hdr->ip_len));
        addr_pack(&curpktSIP,ADDR_TYPE_IP,IP_ADDR_BITS,&(ip_hdr->ip_src),IP_ADDR_LEN);
        addr_pack(&curpktDIP,ADDR_TYPE_IP,IP_ADDR_BITS,&(ip_hdr->ip_dst),IP_ADDR_LEN);

        // Compare config info with current packet, skip if invalid
        if(addr_cmp(&curpktSIP, &logatkIP) != 0) {
            printf("\n\t Packet skipped!\n");
            return;
        }
        if(addr_cmp(&curpktDIP, &logvicIP) != 0) {
            printf("\n\t Packet skipped!\n");
            return;
        }

        printf("\t ip_src = %s\n", addr_ntoa(&curpktSIP));
        printf("\t rep_src = %s\n", addr_ntoa(&localIP));
        printf("\t ip_dst = %s\n", addr_ntoa(&curpktDIP));
        printf("\t rep_dst = %s\n", addr_ntoa(&remoteIP));

        // Discovers IP Protocol and sets next header pointer
        if(ip_hdr->ip_p == IP_PROTO_TCP) {
            printf("\t TCP\n");
            struct tcp_hdr *tcp_hdr;
            tcp_hdr = (struct tcp_hdr *)(pack + ETH_HDR_LEN + IP_HDR_LEN);
            printf("\t   Src Port = %i\n", ntohs(tcp_hdr->th_sport));
            printf("\t   Dst Port = %i\n", ntohs(tcp_hdr->th_dport));
            // Replace ports
            tcp_hdr->th_sport = locPort;
            tcp_hdr->th_dport = remPort;
            printf("\t   New Src Port = %i\n", ntohs(tcp_hdr->th_sport));
            printf("\t   New Dst Port = %i\n", ntohs(tcp_hdr->th_dport));
            printf("\t   Seq = %u\n", ntohl(tcp_hdr->th_seq));
            printf("\t   Ack = %u\n", ntohl(tcp_hdr->th_ack));

            // Replace source address with attacker address and port
            memcpy( &eth_hdr->eth_src, &localMac.addr_eth, ETH_ADDR_LEN);
            memcpy( &ip_hdr->ip_src, &localIP.addr_ip, IP_ADDR_LEN);

            // Replace destination address with new victim client and port
            memcpy( &eth_hdr->eth_dst, &remoteMac.addr_eth, ETH_ADDR_LEN);
            memcpy( &ip_hdr->ip_dst, &remoteIP.addr_ip, IP_ADDR_LEN);
            
            if(sending == 1){
                // Send packet
                if(strcmp(timing, "delay") == 0)
                    usleep(500);
                if(initpkt == 1){
                    if ( pcap_loop(p, 1, (pcap_handler)proc_Seq, (unsigned char *)NULL) < 0 ) {
                        fprintf(stderr, "%s: pcap_loop: %s\n", "proxy", pcap_geterr(p));
                        return;
                    }
                    tcp_hdr->th_ack = htonl(newAck);
                    printf("\t   New Ack = %u\n", ntohl(tcp_hdr->th_ack));
                    // Compute both ip and tcp checksums
                    ip_checksum((void *)ip_hdr, ntohs(ip_hdr->ip_len));
                    n = eth_send(e,pack,pkthdr.len);
                    if ( n != pkthdr.len ) {
                        fprintf(stderr,"Partial packet transmission %d/%d\n",n,pkthdr.len);
                    }
                    printf("\n\t   Packet Sent!\n");
                }
                else {
                    // Compute both ip and tcp checksums
                    printf("\t   New Ack = %u\n", ntohl(tcp_hdr->th_ack));
                    ip_checksum((void *)ip_hdr, ntohs(ip_hdr->ip_len));
                    n = eth_send(e,pack,pkthdr.len);
                    initpkt++;
                    if ( n != pkthdr.len ) {
                        fprintf(stderr,"Partial packet transmission %d/%d\n",n,pkthdr.len);
                       }
                    printf("\n\t   Packet Sent!\n");
                }
            }
            else {
                printf("\n\t   Packet Not Sent\n");
            }
        }

        else if(ip_hdr->ip_p == IP_PROTO_UDP) {
            printf("\t UDP\n");
            struct udp_hdr *udp_hdr;
            udp_hdr = (struct udp_hdr *)(pack + ETH_HDR_LEN + IP_HDR_LEN);
            printf("\t   Src Port = %i\n", ntohs(udp_hdr->uh_sport));
            printf("\t   Dst Port = %i\n", ntohs(udp_hdr->uh_dport));
        }

        else if(ip_hdr->ip_p == IP_PROTO_ICMP) {
            printf("\t ICMP\n");
            struct icmp_hdr *icmp_hdr;
            icmp_hdr = (struct icmp_hdr *)(pack + ETH_HDR_LEN + IP_HDR_LEN);

            // What kind of ICMP
            if(icmp_hdr->icmp_type == ICMP_ECHOREPLY)
                {printf("\t  icmp_type = echo reply\n");}
            else if(icmp_hdr->icmp_type == ICMP_ECHO)
                {printf("\t  icmp_type = echo\n");}
            else if(icmp_hdr->icmp_type == ICMP_UNREACH)
                {printf("\t  icmp_type = dest_unreach\n");}
            else if(icmp_hdr->icmp_type == ICMP_SRCQUENCH)
                {printf("\t  icmp_type = source quench\n");}
            else if(icmp_hdr->icmp_type == ICMP_REDIRECT)
                {printf("\t  icmp_type = route redirection\n");}
            else if(icmp_hdr->icmp_type == ICMP_RTRADVERT)
                {printf("\t  icmp_type = route advertisement\n");}
            else if(icmp_hdr->icmp_type == ICMP_TIMEXCEED)
                {printf("\t  icmp_type = time exceed\n");}
            else if(icmp_hdr->icmp_type == ICMP_ALTHOSTADDR)
                {printf("\t  icmp_type = alt host address\n");}
            else if(icmp_hdr->icmp_type == ICMP_REDIRECT)
                {printf("\t  icmp_type = route redirection\n");}
            else if(icmp_hdr->icmp_type == ICMP_TSTAMP)
                {printf("\t  icmp_type = time stamp request\n");}
            else if(icmp_hdr->icmp_type == ICMP_TSTAMPREPLY)
                {printf("\t  icmp_type = time stamp reply\n");}
            else if(icmp_hdr->icmp_type == ICMP_INFO)
                {printf("\t  icmp_type = icmp info request\n");}
            else if(icmp_hdr->icmp_type == ICMP_INFOREPLY)
                {printf("\t  icmp_type = icmp info reply\n");}
            else if(icmp_hdr->icmp_type == ICMP_MASK)
                {printf("\t  icmp_type = icmp mask request\n");}
            else if(icmp_hdr->icmp_type == ICMP_MASKREPLY)
                {printf("\t  icmp_type = icmp mask reply\n");}
            else if(icmp_hdr->icmp_type == ICMP_TRACEROUTE)
                {printf("\t  icmp_type = traceroute\n");}
            else if(icmp_hdr->icmp_type == ICMP_DATACONVERR)
                {printf("\t  icmp_type = data conversion error\n");}
            else if(icmp_hdr->icmp_type == ICMP_MOBILE_REDIRECT)
                {printf("\t  icmp_type = mobile host redirection\n");}
            else if(icmp_hdr->icmp_type == ICMP_IPV6_WHEREAREYOU)
                {printf("\t  icmp_type = ipv6 where are you\n");}
            else if(icmp_hdr->icmp_type == ICMP_IPV6_IAMHERE)
                {printf("\t  icmp_type = ipv6 i am here\n");}
            else if(icmp_hdr->icmp_type == ICMP_MOBILE_REG)
                {printf("\t  icmp_type = mobile registration request\n");}
            else if(icmp_hdr->icmp_type == ICMP_MOBILE_REGREPLY)
                {printf("\t  icmp_type = mobile registration reply\n");}
            else if(icmp_hdr->icmp_type == ICMP_DNS)
                {printf("\t  icmp_type = domain name request\n");}
            else if(icmp_hdr->icmp_type == ICMP_DNSREPLY)
                {printf("\t  icmp_type = domain name reply\n");}
            else if(icmp_hdr->icmp_type == ICMP_SKIP)
                {printf("\t  icmp_type = skip\n");}
            else if(icmp_hdr->icmp_type == ICMP_PHOTURIS)
                {printf("\t  icmp_type = photouris\n");}
            else { 
                printf("\t  icmp_type = unknown\n");
            }

        }

        else if(ip_hdr->ip_p == IP_PROTO_IGMP) {
            printf("\t IGMP\n");
            struct igmp_hdr *igmp_hdr;
            igmp_hdr = (struct igmp_hdr *)(pack + ETH_HDR_LEN + IP_HDR_LEN);
        }

        else {
            printf("\t  Other\n");
        }
    }

    // Handles actions and printing for ARP packets
    else if(ntohs(eth_hdr->eth_type) == ETH_TYPE_ARP){
        printf("\tARP\n");
        arp_hdr = (struct arp_hdr *)(pack + ETH_HDR_LEN);
        if(ntohs(arp_hdr->ar_op) == ARP_OP_REQUEST) {
                printf("\t arp_op = request\n");
                }
        else if(ntohs(arp_hdr->ar_op) == ARP_OP_REPLY) {
                printf("\t arp_op = reply\n");
                }
        else if(ntohs(arp_hdr->ar_op) == ARP_OP_REVREQUEST) {
                printf("\t arp_op = reverse request\n");
                }
        else if(ntohs(arp_hdr->ar_op) == ARP_OP_REVREPLY) {
                printf("\t arp_op = reverse reply\n");
                }
    }
    else {
        printf("\tUnknown packet\n");
    }
}

void load_error(int e, char *mach) {
  if ( e == -1 )
    fprintf(stderr, "%s ip too large\n", mach);
  else if ( e == -2 )
    fprintf(stderr, "%s ip incorrectly formatted\n", mach);
  else if ( e == -3 )
    fprintf(stderr, "%s mac address too large\n", mach);
  else if ( e == -4 )
    fprintf(stderr, "%s mac address incorrectly formatted\n", mach);
  else
    fprintf(stderr, "Unknown error %d for %s\n", e, mach);
  exit(-1);
}