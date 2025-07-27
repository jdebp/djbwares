#include "byte.h"
#include "dns.h"
#include "dd.h"
#include "response.h"

const char *fatal = "walldns: fatal: ";
const char *starting = "starting walldns\n";

void initialize(void)
{
  ;
}

int respond(char *q,char qtype[2])
{
  int flaga;
  int flagaaaa;
  int flagptr;
  char ip[32];
  int j,k;

  flaga = byte_equal(qtype,2,DNS_T_A);
  flagaaaa = byte_equal(qtype,2,DNS_T_AAAA);
  flagptr = byte_equal(qtype,2,DNS_T_PTR);
  if (byte_equal(qtype,2,DNS_T_ANY)) goto NO_ANY;

  if (flaga || flagaaaa || flagptr) {
    if (dd4(q,"",ip) == 4) {
      if (flaga) {
        if (!response_rstart(q,DNS_T_A,655360)) return 0;
        if (!response_addbytes(ip,4)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
    j = dd4(q,"\7in-addr\4arpa",ip);
    if (j >= 0) {
      if (flaga && (j == 4)) {
        if (!response_rstart(q,DNS_T_A,655360)) return 0;
        for (k = 4;k--;) {
          if (!response_addbytes(ip + k,1)) return 0;
        }
        response_rfinish(RESPONSE_ANSWER);
      }
      if (flagptr) {
        if (!response_rstart(q,DNS_T_PTR,655360)) return 0;
        if (!response_addname(q)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
    j = dd6(q,"\3ip6\4arpa",ip);
    if (j >= 0) {
      if (flagaaaa && (j == 32)) {
        if (!response_rstart(q,DNS_T_AAAA,655360)) return 0;
        for (k = 16;k--;) {
          if (!response_addbytes(ip + k,1)) return 0;
        }
        response_rfinish(RESPONSE_ANSWER);
      }
      if (flagptr) {
        if (!response_rstart(q,DNS_T_PTR,655360)) return 0;
        if (!response_addname(q)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
  }
  goto REFUSE;

NO_ANY:
  if (!response_noany(q)) return 0;
  return 1;

  REFUSE:
  response[2] &= ~4;
  response[3] &= ~15;
  response[3] |= 5;
  return 1;
}
