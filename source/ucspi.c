/* Public domain. */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "error.h"
#include "byte.h"
#include "str.h"
#include "env.h"
#include "ucspi.h"

static const char * ucspi_all(const char * tcp_var, const char * ssl_var, const char * def_tcp, const char * def_ssl, const char * def)
{
	char * x;
	x = env_get("PROTO");
	if (!x) return def;
	if (str_equal(x, "TCP")) {
		x = env_get(tcp_var);
		if (!x) return def_tcp;
		return (const char *)x;
	}
	if (str_equal(x, "SSL")) {
		x = env_get(ssl_var);
		if (!x) return def_ssl;
		return (const char *)x;
	}
	return def;
}

const char * ucspi_get_localip_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	return ucspi_all("TCPLOCALIP", "SSLLOCALIP", def_tcp, def_ssl, def);
}

const char * ucspi_get_localport_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	return ucspi_all("TCPLOCALPORT", "SSLLOCALPORT", def_tcp, def_ssl, def);
}

const char * ucspi_get_localhost_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	return ucspi_all("TCPLOCALHOST", "SSLLOCALHOST", def_tcp, def_ssl, def);
}

const char * ucspi_get_remoteip_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	return ucspi_all("TCPREMOTEIP", "SSLREMOTEIP", def_tcp, def_ssl, def);
}

const char * ucspi_get_remoteport_str(const char * def_tcp, const char * def_ssl, const char * def)
{
	return ucspi_all("TCPREMOTEPORT", "SSLREMOTEPORT", def_tcp, def_ssl, def);
}
