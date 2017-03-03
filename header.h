#ifdef __linux__
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <string.h>

typedef int SOCKET;
#define SOCKET_ERROR (-1)

#define sleep(x)	usleep(x*1000)
#elif WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <Mstcpip.h>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "User32.lib")


#define ICMP_ECHO               8       /* Echo Request                 */


#define poll(a, b, c)			WSAPoll(a, b, c)
#define close(x)				closesocket(x)
#define sleep(x)				Sleep(x)
struct iphdr
{
	uint8_t ihl : 4;
	uint8_t	version : 4;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
};

struct icmphdr
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union
	{
		struct
		{
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
	} un;
};
#endif


void die(char *reason, int code);
uint16_t calculateChecksum(uint8_t *data, uint32_t len);
void cleanup();