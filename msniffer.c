
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include <time.h>

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_timestamp(const struct pcap_pkthdr *header);
void print_eth_header(const u_char *buffer);
void print_ip_header(const u_char *buffer);
void print_tcp(const u_char *buffer);
void print_udp(const u_char *buffer);

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
char filter[] = "ip";


int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n, pckcnt;

    struct bpf_program fp;
	bpf_u_int32 net;

    // list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	// print available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	printf("\n");
	printf("\n");



	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];
	printf("\n");

   	printf("Enter the number of packets you want to sniff : ");
	scanf("%d" , &pckcnt);
	printf("\n");

    printf("Which filter would you like to apply : ");
    scanf("%s",filter);
	printf("\n");

	
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 100 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");
	
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
    exit(EXIT_FAILURE);
    }

	printf("Processing packets..\r\n");
	
	pcap_loop(handle , pckcnt , process_packet , NULL);
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);

	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
    total++;
    
    print_timestamp(header);
    print_eth_header(buffer);
    print_ip_header(buffer);

    printf(" ------------------------------------ \n");

}

void print_timestamp(const struct pcap_pkthdr *header)
{
    printf("\n");

    time_t t0 = header->ts.tv_sec;
    struct tm  ts;
    char       buf[80];
    ts = *localtime(&t0);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    printf("Timestamp: %s\n", buf);
}

void print_eth_header(const u_char *buffer)
{
	struct ethhdr *eth = (struct ethhdr *)buffer;
	
    printf("\n");
    printf("Ethernet Header\n");
    printf("   Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   Protocol            : %u \n",(unsigned short)eth->h_proto);
    printf("\n");

}

void print_ip_header(const u_char *buffer)
{
    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
  
	unsigned short iphdrlen;		
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	printf("IP Header\n");
	printf("    IP Version        : %d\n",(unsigned int)iph->version);
	printf("    IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("    Type Of Service   : %d\n",(unsigned int)iph->tos);
	printf("    IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	printf("    Identification    : %d\n",ntohs(iph->id));
	printf("    Source IP         : %s\n" , inet_ntoa(source.sin_addr) );
	printf("    Destination IP    : %s\n" , inet_ntoa(dest.sin_addr) );
    printf("    Protocol:         : ");

    switch (iph->protocol) 
	{
		case 1: 
            icmp++;
			printf("ICMP \n");
			break;
		
		case 2:
            igmp++;
			printf("IGMP \n");
			break;
		
		case 6:
			tcp++;
            printf("TCP \n");
            print_tcp(buffer);
			break;
		
		case 17:
			udp++;;
			printf("UDP \n");
            print_udp(buffer);
			break;
		
		default:
			others++;
            printf("--- \n");
			break;
	}

}

void print_tcp(const u_char *buffer)
{
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
    printf("\n");
	printf("TCP Header \n");	
		
	//print_ip_header(Buffer,Size);
		
	printf("\n");
	printf("TCP Header\n");
	printf("    Source Port      : %u\n",ntohs(tcph->source));
	printf("    Destination Port : %u\n",ntohs(tcph->dest));
	printf("    Sequence Number    : %u\n",ntohl(tcph->seq));
	printf("    Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	printf("    Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	printf("    Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	printf("    Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	printf("    Push Flag            : %d\n",(unsigned int)tcph->psh);
	printf("    Reset Flag           : %d\n",(unsigned int)tcph->rst);
	printf("    Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	printf("    Finish Flag          : %d\n",(unsigned int)tcph->fin);
	printf("    Window         : %d\n",ntohs(tcph->window));
	printf("    Checksum       : %d\n",ntohs(tcph->check));
	printf("    Urgent Pointer : %d\n",tcph->urg_ptr);
	printf("\n");


    // TODO: print data 
}

void print_udp(const u_char *buffer)
{
   	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
 	
    printf("\n");
	printf("UDP Header\n");
	printf("    Source Port      : %d\n" , ntohs(udph->source));
	printf("    Destination Port : %d\n" , ntohs(udph->dest));
	printf("    UDP Length       : %d\n" , ntohs(udph->len));
	printf("    UDP Checksum     : %d\n" , ntohs(udph->check));
    printf("\n");
}

