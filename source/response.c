#include "dns_domain.h"
#include "dns_constants.h"
#include "dns_packet.h"
#include "byte.h"
#include "uint16.h"
#include "response.h"

char response[MAX_RESPONSE];
unsigned int response_len = 0; /* <= MAX_RESPONSE */
static unsigned int tctarget;

#define NAMES 100
static char name[NAMES][128];
static uint16 name_ptr[NAMES]; /* each < 16384 (0x4000) */
static unsigned int name_num;

int response_addbytes(const char *buf,unsigned int len)
{
  if (len > sizeof response - response_len) return 0;
  byte_copy(response + response_len,len,buf);
  response_len += len;
  return 1;
}

int response_addname(const char *d)
{
  unsigned int dlen;
  unsigned int i;
  char buf[2];

  dlen = dns_domain_length(d);

  while (*d) {
    for (i = 0;i < name_num;++i)
      if (dns_domain_equal(d,name[i])) {
        uint16_pack_big(buf,49152 /* 0xC000 */ + name_ptr[i]);
        return response_addbytes(buf,2);
      }
    if (dlen <= 128)
      if (name_num < NAMES)
        /* The sophomoric DNS compression mechanism strikes again.
        ** Do not bother remembering a name if we cannot legally construct a back-pointer to it.
        ** Pointers are 16-bit packet offsets with the 2 MSBs set to 1 (i.e. 0xC000 = 49152).
        */
        if (response_len < 16384) {
          byte_copy(name[name_num],dlen,d);
          name_ptr[name_num] = response_len;
          ++name_num;
        }
    i = (unsigned char) *d;
    ++i;
    if (!response_addbytes(d,i)) return 0;
    d += i;
    dlen -= i;
  }
  return response_addbytes(d,1);
}

int response_query(const char *q,const char qtype[2],const char qclass[2])
{
  response_len = 0;
  name_num = 0;
  /* QA = 1, AA = 0, RD = 1, TC = 0, RA = 1, RCODE = 0 */
  if (!response_addbytes("\0\0\201\200\0\1\0\0\0\0\0\0",HEADER_SIZE)) return 0;
  if (!response_addname(q)) return 0;
  if (!response_addbytes(qtype,2)) return 0;
  if (!response_addbytes(qclass,2)) return 0;
  tctarget = response_len;
  return 1;
}

static unsigned int dpos;

static int flaghidettl = 0;

void response_hidettl(void)
{
  flaghidettl = 1;
}

int response_rstart(const char *d,const char type[2],uint32 ttl)
{
  char ttlstr[4];
  if (!response_addname(d)) return 0;
  if (!response_addbytes(type,2)) return 0;
  if (!response_addbytes(DNS_C_IN,2)) return 0;
  if (flaghidettl) ttl = 0;
  uint32_pack_big(ttlstr,ttl);
  if (!response_addbytes(ttlstr,4)) return 0;
  if (!response_addbytes("\0\0",2)) return 0;
  dpos = response_len;
  return 1;
}

void response_rfinish(int x)
{
  uint16_pack_big(response + dpos - 2,response_len - dpos);
  if (!++response[x + 1]) ++response[x];
}

int response_cname(const char *c,const char *d,uint32 ttl)
{
  if (!response_rstart(c,DNS_T_CNAME,ttl)) return 0;
  if (!response_addname(d)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  return 1;
}

int response_placeholder_soa(const char *apex,uint32 ttl)
{
  /* SERIAL=1 REFRESH=16384 RETRY=2048 EXPIRY=1048576 MIN=2560 */
  static const char b[20] = "\000\000\000\001""\000\000\100\000""\000\000\010\000""\000\020\000\000""\000\000\012\000";
  static const char n[6]  = "\001a\002ns";
  static const char h[12] = "\012hostmaster";
  if (!response_rstart(apex,DNS_T_SOA,ttl)) return 0;
  if (!response_addbytes(n,sizeof n - 1)) return 0;
  if (!response_addname(apex)) return 0;
  if (!response_addbytes(h,sizeof h - 1)) return 0;
  if (!response_addname(apex)) return 0;
  if (!response_addbytes(b,sizeof b)) return 0;
  response_rfinish(RESPONSE_AUTHORITY);
  return 1;
}

void response_nxdomain(void)
{
  response[3] &= ~15;
  response[3] |= 3; /* RCODE=No Such Domain */
  response[2] |= 4; /* set AA=1 */
}

void response_refuse(void)
{
  response[3] &= ~15;
  response[3] |= 5; /* RCODE=Refused */
  response[2] &= ~4;  /* set AA=0 */
}

void response_servfail(void)
{
  response[3] &= ~15;
  response[3] |= 2; /* RCODE=Server Failure */
}

int response_noany(const char *d)
{
  if (!response_rstart(d,DNS_T_HINFO,TTL_POSITIVE)) return 0;
  if (!response_addbytes("\7RFC8482",8)) return 0;
  if (!response_addbytes("\0",1)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  return 1;
}

int response_noopt(const char *d)
{
  if (!response_rstart(d,DNS_T_HINFO,TTL_POSITIVE)) return 0;
  if (!response_addbytes("\7RFC2671",8)) return 0;
  if (!response_addbytes("\0",1)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  return 1;
}

int response_noaxfr(const char *d)
{
  if (!response_rstart(d,DNS_T_HINFO,TTL_POSITIVE)) return 0;
  if (!response_addbytes("\7RFC5936",8)) return 0;
  if (!response_addbytes("\0",1)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  return 1;
}

int response_badip4(const char *d)
{
  if (!response_rstart(d,DNS_T_HINFO,TTL_POSITIVE)) return 0;
  if (!response_addbytes("\7RFC1035",8)) return 0;
  if (!response_addbytes("\0",1)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  return 1;
}

void response_id(const char id[2])
{
  byte_copy(response,2,id);
}

void response_tc(void)
{
  response[2] |= 2; /* set TC=1 */
  response_len = tctarget;
}
