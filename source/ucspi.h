/* Public domain. */

#ifndef UCSPI_H
#define UCSPI_H

const char * ucspi_get_localip_str(const char * def_tcp, const char * def_ssl, const char * def);
const char * ucspi_get_localport_str(const char * def_tcp, const char * def_ssl, const char * def);
const char * ucspi_get_localhost_str(const char * def_tcp, const char * def_ssl, const char * def);
const char * ucspi_get_remoteip_str(const char * def_tcp, const char * def_ssl, const char * def);
const char * ucspi_get_remoteport_str(const char * def_tcp, const char * def_ssl, const char * def);

#endif
