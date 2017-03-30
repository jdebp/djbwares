/* Public domain. */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "error.h"
#include "byte.h"
#include "str.h"
#include "env.h"
#include "ucspi.h"

const char * ucspi_get_localip_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	char * x;
	x = env_get("PROTO");
	if (!x) return def;
	if (str_equal(x, "TCP")) {
		x = env_get("TCPLOCALIP");
		return x ? (const char *)x : def_tcp;
	}
	if (str_equal(x, "SSL")) {
		x = env_get("SSLLOCALIP");
		return x ? (const char *)x : def_ssl;
	}
	return def;
}

const char * ucspi_get_localport_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	char * x;
	x = env_get("PROTO");
	if (!x) return def;
	if (str_equal(x, "TCP")) {
		x = env_get("TCPLOCALPORT");
		return x ? (const char *)x : def_tcp;
	}
	if (str_equal(x, "SSL")) {
		x = env_get("SSLLOCALPORT");
		return x ? (const char *)x : def_ssl;
	}
	return def;
}

const char * ucspi_get_localhost_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	char * x;
	x = env_get("PROTO");
	if (!x) return def;
	if (str_equal(x, "TCP")) {
		x = env_get("TCPLOCALHOST");
		return x ? (const char *)x : def_tcp;
	}
	if (str_equal(x, "SSL")) {
		x = env_get("SSLLOCALHOST");
		return x ? (const char *)x : def_ssl;
	}
	return def;
}

const char * ucspi_get_remoteip_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	char * x;
	x = env_get("PROTO");
	if (!x) return def;
	if (str_equal(x, "TCP")) {
		x = env_get("TCPREMOTEIP");
		return x ? (const char *)x : def_tcp;
	}
	if (str_equal(x, "SSL")) {
		x = env_get("SSLREMOTEIP");
		return x ? (const char *)x : def_ssl;
	}
	return def;
}

const char * ucspi_get_remoteport_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	char * x;
	x = env_get("PROTO");
	if (!x) return def;
	if (str_equal(x, "TCP")) {
		x = env_get("TCPREMOTEPORT");
		return x ? (const char *)x : def_tcp;
	}
	if (str_equal(x, "SSL")) {
		x = env_get("SSLREMOTEPORT");
		return x ? (const char *)x : def_ssl;
	}
	return def;
}
