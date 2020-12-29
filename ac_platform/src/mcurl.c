#include "mcurl.h"
#include <unistd.h>
#include "base64.h"
#include "elog/elog.h"

void my_curl_init()
{
	curl_global_init(CURL_GLOBAL_ALL);
}

void my_curl_uninit()
{
	curl_global_cleanup();
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	char *retdata = NULL;

	/* base64_decode ret data */
#ifdef USE_BASE64
	retdata = base64_decode(ptr);
#else
	retdata = ptr;
#endif

	strncpy((char *)userdata, retdata, 4096);

#ifdef USE_BASE64
	if (retdata)
		free(retdata);
#endif
	return size * nmemb;
}

static int do_request(const char *url, int method, const char *data, char *rdata)
{
	int num = 3;
	char errbuf[CURL_ERROR_SIZE];

	CURL *curl;

	CURLcode res;
	memset(errbuf, 0, sizeof(errbuf));

	curl = curl_easy_init();

	if (!curl)
	{
		return CURLERR;
	}

	/* 设置curl地址 */
	curl_easy_setopt(curl, CURLOPT_URL, url);
	/* 设置https选项 */
	curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	/* 设置返回值处理函数 */
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rdata);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	/* 设置出错返回原因 */
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	/* 设置超时选项 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);

	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);

	if (method == POST)
	{
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	}

	/* 循环执行curl访问，直到执行成功或者次数超过5次为止 */
	while (num--)
	{
		/* 执行curl访问 */
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			/* 出错处理 */
			log_e("curl error:%s", errbuf);
			if (num < 1)
			{
				curl_easy_cleanup(curl);

				return CURLERR;
			}
		}
		else
		{
			/* 成功返回 */
			break;
		}
	}

	curl_easy_cleanup(curl);
	return res;
}

int curl_request(const char *url, int method, char *data, char *ret)
{
	int result = CURLERR;
	char *indata = NULL;

/* base64_encode data */
#ifdef USE_BASE64
	if ((method == POST) && (data != NULL))
	{
		indata = base64_encode(data);
	}
#else
	indata = data;
#endif

	result = do_request(url, method, indata, ret);

#ifdef USE_BASE64
	if (indata)
		free(indata);
#endif

	return result;
}
