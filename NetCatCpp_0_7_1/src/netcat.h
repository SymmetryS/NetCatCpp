/*
 * netcat.h -- main header project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: netcat.h,v 1.35 2004/01/03 16:42:07 themnemonic Exp $
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#ifndef NETCAT_H
#define NETCAT_H
#include <iostream>

#include <arpa/inet.h> /* inet_ntop(), inet_pton() */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h> /* defines MAXHOSTNAMELEN and other stuff */
#include <sys/socket.h>
#include <sys/time.h>  /* timeval, time_t */
#include <sys/types.h> /* basic types definition */
#include <sys/uio.h>   /* needed for reading/writing vectors */
#include <unistd.h>

/* other misc unchecked includes */
#if 0
#include <netinet/in_systm.h> /* misc crud that netinet/ip.h references */
#include <netinet/ip.h>       /* IPOPT_LSRR, header stuff */
#endif

/* These are useful to keep the source readable */
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

/* find a random routine */
#if defined(HAVE_RANDOM) && defined(HAVE_SRANDOM)
#define USE_RANDOM /* try with most modern random routines */
#define SRAND srandom
#define RAND random
#elif defined(HAVE_RAND) && defined(HAVE_SRAND)
#define USE_RANDOM /* otherwise fallback to the older rand() */
#define SRAND srand
#define RAND rand
#endif /* if none of them are here, CHANGE OS! */

/* This must be defined to the longest possible internet address length in
   string notation.
   Bugfix: Looks like Solaris 7 doesn't define this standard. It's ok to use
   the following workaround since this is going to change to introduce IPv6
   support. */
#ifdef INET_ADDRSTRLEN
#define NETCAT_ADDRSTRLEN INET_ADDRSTRLEN
#else
#define NETCAT_ADDRSTRLEN 16
#endif

/* FIXME: I should search more about this portnames standards.  At the moment
   i'll fix my own size for this */
#define NETCAT_MAXPORTNAMELEN 64

/* Find out whether we can use the RFC 2292 extensions on this machine
   (I've found out only linux supporting this feature so far) */
#ifdef HAVE_STRUCT_IN_PKTINFO
#if defined(SOL_IP) && defined(IP_PKTINFO)
#define USE_PKTINFO
#endif
#endif

/* MAXINETADDR defines the maximum number of host aliases that are saved after
   a successfully hostname lookup. Please not that this value will also take
   a significant role in the memory usage. Approximately one struct takes:
   MAXINETADDRS * (NETCAT_ADDRSTRLEN + sizeof(struct in_addr)) */
#define MAXINETADDRS 6

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

/* FIXME: shall we really change this define? probably not. */
#ifdef MAXHOSTNAMELEN
#undef MAXHOSTNAMELEN /* might be too small on aix, so fix it */
#endif
#define MAXHOSTNAMELEN 256

/* TRUE and FALSE values for logical type `bool' */
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* this is just a logical type, but helps a lot */
#ifndef __cplusplus
#ifndef bool
#define bool unsigned char
#endif
#endif
#define BOOL_TO_STR(__var__) (__var__ ? "TRUE" : "FALSE")
#define NULL_STR(__var__) (__var__ ? __var__ : "(null)")

/* there are some OS that still doesn't support POSIX standards */
#ifndef HAVE_IN_PORT_T
typedef unsigned short in_port_t;
#endif

// Netcat basic operating modes.
enum nc_mode_t : uint32_t
{
	NETCAT_UNSPEC,
	NETCAT_CONNECT,  // Client
	NETCAT_LISTEN,   // Server
	NETCAT_TUNNEL    // Port Scanning
};

static const char* nc_mode_str(const nc_mode_t mode)
{
	switch (mode)
	{
		case NETCAT_UNSPEC:
			return "MODE_UNSPEC";
		case NETCAT_CONNECT:
			return "MODE_CONNECT";
		case NETCAT_LISTEN:
			return "MODE_LISTEN";
		case NETCAT_TUNNEL:
			return "MODE_TUNNEL";
		default:
			return "MODE_UNKNOWN";
	}
}

static std::ostream& operator<<(std::ostream& os, const nc_mode_t mode)
{
	os << nc_mode_str(mode);
	return os;
}

// Recognized protocols.
enum nc_proto_t : uint32_t
{
	NETCAT_PROTO_UNSPEC,
	NETCAT_PROTO_TCP,
	NETCAT_PROTO_UDP
};

static const char* nc_proto_str(const nc_proto_t proto)
{
	switch (proto)
	{
		case NETCAT_PROTO_UNSPEC:
			return "PROTO_UNSPEC";
		case NETCAT_PROTO_TCP:
			return "PROTO_TCP";
		case NETCAT_PROTO_UDP:
			return "PROTO_UDP";
		default:
			return "PROTO_UNKNOWN";
	}
}

static std::ostream& operator<<(std::ostream& os, const nc_proto_t proto)
{
	os << nc_proto_str(proto);
	return os;
}

/*
    Used for queues buffering and data tracking purposes.  The `head' field is
    a pointer to the begin of the buffer segment, while `pos' indicates the
    actual position of the data stream.  If `head' is NULL, it means that there
    is no dynamically-allocated data in this buffer, *BUT* it MAY still contain
    some local data segment (for example allocated inside the stack).
    `len' indicates the length of the buffer starting from `pos'.
*/
class nc_buffer_t
{
public:
	friend std::ostream& operator<<(std::ostream& os, const nc_buffer_t& buf)
	{
		os << "nc_buffer_t{ .head = " << static_cast<const void*>(buf.head) << ", .pos = " << static_cast<const void*>(buf.pos) << ", .len = " << buf.len << " }";
		return os;
	}

public:
	unsigned char* head;
	unsigned char* pos;
	int len;
};

// This is the standard netcat hosts record.  It contains an "authoritative" `name' field, which may be empty,
// and a list of IP addresses in the network notation and in the dotted string notation.
class nc_host_t
{
public:
	friend std::ostream& operator<<(std::ostream& os, const nc_host_t& host)
	{
		os << "nc_host_t{ .name = \"" << host.name << "\", .addrs = [";
		for (int i = 0; i < MAXINETADDRS; ++i)
		{
			if (host.addrs[i][0] == '\0')
			{
				break;  // 空字符串表示结束
			}
			if (i != 0)
			{
				os << ", ";
			}
			os << "\"" << host.addrs[i] << "\"";
		}
		os << "], .iaddrs = [";
		for (int i = 0; i < MAXINETADDRS; ++i)
		{
			if (host.addrs[i][0] == '\0')
			{
				break;  // 空字符串表示结束
			}
			if (i != 0)
			{
				os << ", ";
			}
			os << "\"" << host.iaddrs[i].s_addr << "\"";
		}
		os << "] }";
		return os;
	}

public:
	char name[MAXHOSTNAMELEN];                    // dns name
	char addrs[MAXINETADDRS][NETCAT_ADDRSTRLEN];  // ascii-format IP addresses
	struct in_addr iaddrs[MAXINETADDRS];          // real addresses
};

// Standard netcat port record. It contains the port `name', which may be empty, and the port number both as number and as string.
class nc_port_t
{
public:
	friend std::ostream& operator<<(std::ostream& os, const nc_port_t& port)
	{
		os << "nc_port_t{ .name = \"" << port.name << "\", .ascnum = \"" << port.ascnum << "\", .num = " << port.num << ", .netnum = " << port.netnum << " }";
		return os;
	}

public:
	char name[NETCAT_MAXPORTNAMELEN];  // canonical port name
	char ascnum[8];                    // ascii port number
	unsigned short num;                // port number
	in_port_t netnum;                  // port number in network byte order. // FIXME: this is just a test!
};

// This is a more complex struct that holds socket records. [...]
class nc_sock_t
{
public:
	friend std::ostream& operator<<(std::ostream& os, const nc_sock_t& sock)
	{
		os << "nc_sock_t\n{\n"
		   << " .fd = " << sock.fd << ",\n"
		   << " .domain = " << sock.domain << ",\n"
		   << " .timeout = " << sock.timeout << ",\n"
		   << " .proto = " << sock.proto << ",\n"
		   << " .local_host = " << sock.local_host << ",\n"
		   << " .host = " << sock.host << ",\n"
		   << " .local_port = " << sock.local_port << ",\n"
		   << " .port = " << sock.port << ",\n"
		   << " .sendq = " << sock.sendq << ",\n"
		   << " .recvq = " << sock.recvq << "\n}";
		return os;
	}

public:
	int fd;
	int domain;
	int timeout;
	nc_proto_t proto;
	nc_host_t local_host;
	nc_host_t host;
	nc_port_t local_port;
	nc_port_t port;
	nc_buffer_t sendq;
	nc_buffer_t recvq;
};

// Netcat includes.

#include "intl.h"
#include "misc.h"
#include "proto.h"

#endif /* !NETCAT_H */
