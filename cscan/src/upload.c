#include "main.h"
#include "upload.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <unistd.h>

/* create a client udp socket */
int udp_client_init(const char *ipaddr, int port, \
		struct sockaddr_in *server)
{
	int sockfd;
	memset(server, 0, sizeof(struct sockaddr_in));
	server->sin_family = PF_INET;
	server->sin_addr.s_addr = inet_addr(ipaddr);
	server->sin_port = htons(port);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("%s %d:%s\n", __FILE__, __LINE__, strerror(errno));
		return -1;
	}
	return sockfd;
}

/* create a server udp socket */
int udp_server_init(const char *ipaddr, int port, \
		struct sockaddr_in *server)
{
	int sockfd, ret;
	memset(server, 0, sizeof(struct sockaddr_in));
	server->sin_family = PF_INET;
	server->sin_addr.s_addr = inet_addr(ipaddr);
	server->sin_port = htons(port);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("%s %d:%s\n", __FILE__, __LINE__, strerror(errno));
		return -1;
	}

	ret = bind(sockfd, (struct sockaddr *)server, sizeof(struct sockaddr));
	if (ret < 0)
	{
		printf("%s %d:%s\n", __FILE__, __LINE__, strerror(errno));
		return -1;
	}
	
	return sockfd;
}

/* send some data to a udp socket */
int udp_send(const int sockfd, const char *data, \
		const struct sockaddr_in *dest)
{
	int ret;
	ret = sendto(sockfd, (void *)data, strlen(data), 0, \
			(struct sockaddr *)dest, sizeof(struct sockaddr));
	if (ret < 0)
	{
		printf("%s %d %d:%s\n", __FILE__, __LINE__, errno,  strerror(errno));
		return -1;
	}
	return 1;
}

/* recevie some data form a udp socket */
int udp_recv(const int sockfd, char *data, \
		const int n, const struct sockaddr_in *src)
{
	int ret;
	memset(data, 0, n);
	socklen_t len = sizeof(struct sockaddr);
	ret = recvfrom(sockfd, (void *)data, n, 0, \
			(struct sockaddr *)src, &len);
	if (ret < 0)
	{
		printf("%s %d %d:%s\n", __FILE__, __LINE__, errno,  strerror(errno));
		return -1;
	}
	return 1;
}

int udp_request(const char *ipaddr, int port, const char *data)
{
	int sockfd, ret;
	struct sockaddr_in server;
	sockfd = udp_client_init(ipaddr, port, &server);
	if (sockfd < 0)
	{
		return sockfd;
	}

	ret = udp_send(sockfd, data, &server);
	if (ret < 0)
	{
		close(sockfd);
		return ret;
	}
	close(sockfd);
	return 1;
}

/* create a client tcp socket */
int tcp_client_init(const char *ipaddr, int port, \
		struct sockaddr_in *server)
{
	int sockfd;
	int opt = 1;
	memset(server, 0, sizeof(struct sockaddr_in));
	server->sin_family = PF_INET;
	server->sin_addr.s_addr = inet_addr(ipaddr);
	server->sin_port = htons(port);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("%s %d:%s\n", __FILE__, __LINE__, strerror(errno));
		return -1;
	}

	setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

	return sockfd;
}


/* send some data to a tcp socket */
int tcp_send(const int sockfd, const char *data, \
		__attribute__((unused)) const struct sockaddr_in *dest)
{
	int ret;
	if(! data)return -1;
	ret = write(sockfd, (void *)data, strlen(data));
	if (ret < 0)
	{
		printf("%s %d %d:%s\n", __FILE__, __LINE__, errno,  strerror(errno));
		return -1;
	}
	return 1;
}

int tcp_request(const char *ipaddr, int port, const char *data)
{
	int sockfd, ret;
	struct sockaddr_in server;
	int result;
	sockfd = tcp_client_init(ipaddr, port, &server);
	if (sockfd < 0)
	{
		printf("tcp init error\n");
		return sockfd;
	}

	result =  connect(sockfd,(struct sockaddr *)&server, sizeof(server));
	if (result == -1)
	{
		perror("client");
		sleep(1);
		return result;
	}

	ret = tcp_send(sockfd, data, &server);
	if (ret < 0)
	{
		close(sockfd);
		return ret;
	}
	close(sockfd);
	return 1;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	strncpy((char *)userdata, ptr, 16>strlen((char*)ptr)?strlen((char*)ptr):16);
	return size * nmemb;
}


static int do_request(const char *url, const char *data, char *rdata)
{
	CURL *curl;
	CURLcode res;
	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if (!curl)
	{
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return CURLERR;
	}
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
//	curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
//	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
//	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rdata);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

	res =  curl_easy_perform(curl);
	if (res != CURLE_OK)
	{
	//	PRINTF("%s:%d\n", curl_easy_strerror(res), res);
		printf(": curl response not ok!\n");
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return CURLERR;
	}
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return CURLOK;
}


int curl_request(const char *url, char *data, char *ret)
{
	return do_request(url, data, ret);
}
