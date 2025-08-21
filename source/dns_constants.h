#ifndef DNS_TYPES_H
#define DNS_TYPES_H

/* Resource record type and class constants */

#define DNS_C_IN "\0\1"
#define DNS_C_ANY "\0\377"

#define DNS_T_0 "\0\0"
#define DNS_T_A "\0\1"
#define DNS_T_NS "\0\2"
#define DNS_T_CNAME "\0\5"
#define DNS_T_SOA "\0\6"
#define DNS_T_PTR "\0\14"
#define DNS_T_HINFO "\0\15"
#define DNS_T_MX "\0\17"
#define DNS_T_TXT "\0\20"
#define DNS_T_RP "\0\21"
#define DNS_T_SIG "\0\30"
#define DNS_T_KEY "\0\31"
#define DNS_T_AAAA "\0\34"
#define DNS_T_LOC "\0\35"
#define DNS_T_SRV "\0\41"
#define DNS_T_OPT "\0\51"
#define DNS_T_SVCB "\0\100"
#define DNS_T_HTTPS "\0\101"
#define DNS_T_IXFR "\0\373"
#define DNS_T_AXFR "\0\374"
#define DNS_T_ANY "\0\377"

#define TTL_NS 259200 /* 3 days */
#define TTL_POSITIVE 86400 /* 1 day */
#define TTL_NEGATIVE 2560
#define TTL_STATIC_POSITIVE 1209600 /* 1 fortnight */
#define TTL_STATIC_NEGATIVE 1209600 /* 1 fortnight */
#define TTL_CACHE_CAP 1209600 /* 1 fortnight */
#define TTL_SOA_MAX 3600
#define TTL_ARITH_OVERFLOW 2147483647 /* per RFC2181. dnscache originally capped at less than half this. */

#endif
