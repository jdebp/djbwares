#include "mem.h"
#include "case.h"
#include "buffer.h"
#include "strerr.h"
#include "ip.h"
#include "uint16.h"
#include "socket.h"
#include "droproot.h"
#include "qlog.h"
#include "response.h"
#include "dns_server.h"
#include "dns_domain.h"
#include "dns_constants.h"
#include "dns_packet.h"
#include <unistd.h>

static struct ip_address iplocal = IP_ADDRESS_INIT;
static struct ip_address ipremote = IP_ADDRESS_INIT;
static uint16 portlocal = 53; /* DNS */
static uint16 portremote;

static char buf[513];
static int len;

static char *q;

static int doit(unsigned int *max_response)
{
  unsigned int pos;
  char header[HEADER_SIZE];
  char qtype[2];
  char qclass[2];
  uint16 numqueries;
  uint16 numanswers;
  uint16 numauthority;
  uint16 numglue;
  unsigned int j;

  *max_response = 512;
  header[0] = header[1] = '\0';
  qtype[0] = qtype[1] = '\0';
  qclass[0] = qclass[1] = '\0';

  if (len >= sizeof buf) goto NOQ;
  pos = dns_packet_copy(buf,len,0,header,HEADER_SIZE); if (!pos) goto NOQ;
  if (header[2] & 128) goto NOQ; /* must not respond to responses */

  uint16_unpack_big(header + HEADER_QUERY,&numqueries);
  if (1 != numqueries) goto NOQ;
  uint16_unpack_big(header + HEADER_ANSWER,&numanswers);
  if (numanswers) goto WEIRDRECORDS;
  uint16_unpack_big(header + HEADER_AUTHORITY,&numauthority);
  if (numauthority) goto WEIRDRECORDS;
  uint16_unpack_big(header + HEADER_ADDITIONAL,&numglue);
  if (numglue > 1) goto WEIRDRECORDS;

  pos = dns_packet_getname(buf,len,pos,&q); if (!pos) goto NOQ;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) goto NOQ;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) goto NOQ;

  if (!response_query(q,qtype,qclass)) goto NOQ;
  response_id(header + HEADER_ID);
  if (!dns_packet_internetclass(qclass)) goto WEIRDCLASS;
  response[2] |= 4;	/* set AA=1 */
  response[3] &= ~128;	/* set RA=0 */
  if (!(header[2] & 1)) response[2] &= ~1; /* echo client's RD */

  if (header[2] & 126) goto BADFMT; /* OPCODE must be 0, and TC and AA must be 0 */
  if (dns_packet_typematch(qtype,DNS_T_AXFR) || dns_packet_typematch(qtype,DNS_T_IXFR)) goto NOTIMP;

  for (j = 0;j < numglue;++j) {
    char rrfixed[RRFIXED_SIZE];
    uint16 udpsize;
    uint16 datalen;
    pos = dns_packet_skipname(buf,len,pos); if (!pos) goto NOQ;
    pos = dns_packet_copy(buf,len,pos,rrfixed,RRFIXED_SIZE); if (!pos) goto NOQ;
    uint16_unpack_big(rrfixed + RRFIXED_DATALEN,&datalen);
    if (!dns_packet_rrtypematch(rrfixed,DNS_T_OPT)) goto BADFMT;
    uint16_unpack_big(rrfixed + RRFIXED_CLASS,&udpsize);
    if (udpsize > 512 && udpsize <= MAX_RESPONSE) *max_response = udpsize;
    pos += datalen;
  }

  case_lowerb(q,dns_domain_length(q));
  if (!respond(q,qtype,*max_response,&ipremote)) {
    qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," - ");
    return 0;
  }
  qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," + ");
  return 1;

  NOTIMP:
  response[3] &= ~15;
  response[3] |= 4; /* Not Implemented */
  qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," x ");
  return 1;

  BADFMT:
  response[3] &= ~15;
  response[3] |= 1; /* Format Error */
  qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," B ");
  return 0;

  WEIRDCLASS:
  response[3] &= ~15;
  response[3] |= 1; /* Format Error */
  qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," C ");
  return 0;

  WEIRDRECORDS:
  response[3] &= ~15;
  response[3] |= 1; /* Format Error */
  qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," R ");
  return 0;

  NOQ:
  qlog(&ipremote,portremote,header + HEADER_ID,*max_response,q,qtype," / ");
  return 0;
}

int main(void)
{
  int udp53, do_udp_options;

  udp53 = -1;
  do_udp_options = 1;
  socket_listen_get_udp(fatal,&udp53,&do_udp_options,&portlocal,&iplocal,portlocal);

  droproot(fatal);

  if (do_udp_options)
    socket_tryreservein(udp53,65536);

  initialize();

  buffer_putsflush(buffer_2,starting);

  if (!dns_domain_copy(&q,""))
      strerr_die2sys(111,fatal,"unable to initialize query-name buffer: ");

  for (;;) {
    unsigned int max_response;
    len = socket_recv(udp53,buf,sizeof buf,&ipremote,&portremote);
    if (len < 0) continue;
    if (!doit(&max_response)) continue;
    if (response_len > max_response) response_tc();
    socket_send(udp53,response,response_len,&ipremote,portremote);
    /* may block for buffer space; if it fails, too bad */
  }
}
