/****************************************************************************
*																			*
*						cryptlib TCP/IP Interface Routines					*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/stream.h"
#else
  #include "crypt.h"
  #include "misc/stream.h"
#endif /* Compiler-specific includes */

#ifdef USE_TCP

#ifdef __BEOS__
  /* If we're building under BeOS the system may have the new(er) BONE
     (BeOs Network Environment) network stack that didn't quite make it into
	 BeOS v5 before the demise of Be Inc but was leaked after Be folded, as
	 was the experimental/developmental Dano release of BeOS, which would
	 have become BeOS 5.1 and also has a newer network stack.  In order to
	 detect this we have to pull in sys/socket.h before we try anything
	 else */
  #include <sys/socket.h>
#endif /* __BEOS__ */

#if defined( __WINDOWS__ )
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #if defined( _MSC_VER ) && ( _MSC_VER > 1300 )
	/* VC++ 7 and newer have IPv6 support included in ws2tcpip.h, VC++ 6
	   can have it bolted-on using the IPv6 Technology Preview but it's
	   not present by default.  In addition the Tech.Preview is quite buggy
	   and unstable, leaking handles and memory and in some cases leading to
	   runaway memory consumption that locks up the machine if the process
	   isn't killed in time, so we don't want to encourage its use */
	 /* #include <tpipv6.h> */	/* From IPv6 Tech.Preview */
  #endif /* VC++ 7 and newer */
  #if defined( _MSC_VER ) && ( _MSC_VER > 1300 )
	/* VC++ 7 and newer have DNS headers */
	#include <windns.h>
  #else
	/* windns.h is quite new and many people don't have it yet, not helped
	   by the fact that it's also changed over time.  For example,
	   DnsRecordListFree() has also been DnsFreeRecordList() and DnsFree()
	   at various times, with the parameters changing to match.  Because of
	   this, we have to define our own (very cut-down) subset of what's in
	   there here.  We define PIP4_ARRAY as a void * since it's only used to
	   specify optional DNS servers to query, we never need this so we just
	   set the parameter to NULL.  As with the DnsXXX functions, PIP4_ARRAY
	   has changed over time.  It was known as PIP_ARRAY in the original
	   VC++ .NET release, but was renamed PIP4_ARRAY for .NET 2003, although
	   some MSDN entries still refer to PIP_ARRAY even in the 2003 version */
	typedef LONG DNS_STATUS;
	typedef void *PIP4_ARRAY;
	typedef DWORD IP4_ADDRESS;
	typedef enum { DnsFreeFlat, DnsFreeRecordList } DNS_FREE_TYPE;
	typedef enum { DnsConfigPrimaryDomainName_W, DnsConfigPrimaryDomainName_A,
				   DnsConfigPrimaryDomainName_UTF8, DnsConfigAdapterDomainName_W,
				   DnsConfigAdapterDomainName_A, DnsConfigAdapterDomainName_UTF8,
				   DnsConfigDnsServerList, DnsConfigSearchList,
				   DnsConfigAdapterInfo, DnsConfigPrimaryHostNameRegistrationEnabled,
				   DnsConfigAdapterHostNameRegistrationEnabled,
				   DnsConfigAddressRegistrationMaxCount, DnsConfigHostName_W,
				   DnsConfigHostName_A, DnsConfigHostName_UTF8,
				   DnsConfigFullHostName_W, DnsConfigFullHostName_A,
				   DnsConfigFullHostName_UTF8 } DNS_CONFIG_TYPE;
	#define DNS_TYPE_A				1
	#define DNS_TYPE_PTR			12
	#define DNS_TYPE_SRV			33
	#define DNS_QUERY_STANDARD		0
	#define DNS_QUERY_BYPASS_CACHE	8
	typedef struct {
		DWORD Section : 2;
		DWORD Delete : 1;
		DWORD CharSet : 2;
		DWORD Unused : 3;
		DWORD Reserved : 24;
		} DNS_RECORD_FLAGS;
	typedef struct {
		IP4_ADDRESS IpAddress;
		} DNS_A_DATA, *PDNS_A_DATA;
	typedef struct {
		LPTSTR pNameHost;
		} DNS_PTR_DATA, *PDNS_PTR_DATA;
	typedef struct {
		LPTSTR pNameTarget;
		WORD wPriority;
		WORD wWeight;
		WORD wPort;
		WORD Pad;
		} DNS_SRV_DATA, *PDNS_SRV_DATA;
	typedef struct _DnsRecord {
		struct _DnsRecord *pNext;
		LPTSTR pName;
		WORD wType;
		WORD wDataLength;
		union {
			DWORD DW;
			DNS_RECORD_FLAGS S;
		} Flags;
		DWORD dwTtl;
		DWORD dwReserved;
		union {
			DNS_A_DATA A;
			DNS_PTR_DATA PTR, Ptr,
						 NS, Ns,
						 CNAME, Cname,
						 MB, Mb,
						 MD, Md,
						 MF, Mf,
						 MG, Mg,
						 MR, Mr;
	#if 0
			DNS_MINFO_DATA MINFO, Minfo,
						   RP, Rp;
			DNS_MX_DATA MX, Mx,
						AFSDB, Afsdb,
						RT, Rt;
			DNS_TXT_DATA HINFO, Hinfo,
						 ISDN, Isdn,
						 TXT, Txt,
						 X25;
			DNS_NULL_DATA Null;
			DNS_WKS_DATA WKS, Wks;
			DNS_AAAA_DATA AAAA;
			DNS_KEY_DATA KEY, Key;
			DNS_SIG_DATA SIG, Sig;
			DNS_ATMA_DATA ATMA, Atma;
			DNS_NXT_DATA NXT, Nxt;
	#endif /* 0 */
			DNS_SRV_DATA SRV, Srv;
	#if 0
			DNS_TKEY_DATA TKEY, Tkey;
			DNS_TSIG_DATA TSIG, Tsig;
			DNS_WINS_DATA WINS, Wins;
			DNS_WINSR_DATA WINSR, WinsR,
						   NBSTAT, Nbstat;
	#endif /* 0 */
			} Data;
		} DNS_RECORD, *PDNS_RECORD;
  #endif /* 0 */

  /* For backwards-compatibility purposes, wspiapi.h overrides the new
     address/name-handling functions introduced for IPv6 with complex
	 macros that substitute inline function calls that try and dynamically
	 load different libraries depending on the Windows version and call
	 various helper functions to provide the same service.  Since we
	 dynamically load the required libraries, we don't need any of this
	 complexity, so we undefine the macros in order to make our own ones
	 work */
  #ifdef getaddrinfo
	#undef freeaddrinfo
	#undef getaddrinfo
	#undef getnameinfo
  #endif /* getaddrinfo defined as macros in wspiapi.h */
#elif defined( __BEOS__ ) && !defined( BONE_VERSION )
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <socket.h>

  /* BeOS doesn't define any of the PF_xxx's, howewever it does defines
     some of the AF_xxx equivalents, since these are synonyms we just
	 define the PF_xxx's ourselves */
  #define PF_UNSPEC					0
  #define PF_INET					AF_INET

  /* BeOS doesn't define in_*_t's */
  #define in_addr_t					u_long
  #define in_port_t					u_short

  /* BeOS doesn't define NO_ADDRESS, but NO_DATA is a synonym for this */
  #define NO_ADDRESS				NO_DATA

  /* BeOS doesn't support checking for anything except readability in
	 select() and only supports one or two socket options, so we define
	 our own versions of these functions that no-op out unsupported
	 options */
  #define select( sockets, readFD, writeFD, exceptFD, timeout ) \
		  my_select( sockets, readFD, writeFD, exceptFD, timeout )
  #define getsockopt( socket, level, optname, optval, optlen ) \
		  my_getsockopt( socket, level, optname, optval, optlen )
  #define setsockopt( socket, level, optname, optval, optlen ) \
		  my_setsockopt( socket, level, optname, optval, optlen )

  /* The following options would be required, but aren't provided by BeOS.
     If you're building under a newer BeOS version that supports these
     options, you'll also need to update my_set/setsockopt() to no longer
     no-op them out */
  #define SO_ERROR					-1
  #define TCP_NODELAY				-1
#elif ( defined( __BEOS__ ) && defined( BONE_VERSION ) ) || \
	  defined ( __SYMBIAN32__ ) || defined( __TANDEMOSS__ ) || \
	  defined( __UNIX__ )
  /* C_IN is a cryptlib.h value which is also defined in some versions of
     netdb.h, so we have to undefine it before we include any network
	 header files */
  #undef C_IN
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #if defined( __APPLE__ ) || defined( __BEOS__ ) || \
	  defined( __bsdi__ ) || defined( __FreeBSD__ ) || \
	  defined( __hpux ) || defined( __MVS__ ) || \
	  defined( __OpenBSD__ ) || \
	  ( defined( sun ) && OSVERSION <= 5 ) || \
	  defined( __SYMBIAN32__ ) || defined( __VMCMS__ )
	#include <netinet/in.h>
  #endif /* OS x || BeOS || *BSDs || PHUX || SunOS 4.x/2.5.x || Symbian OS */
  #include <arpa/inet.h>
  #if defined( __APPLE__ ) && !defined( BIND_8_COMPAT )
	/* In OS X 10.3 (Panther), Apple broke the bind interface by changing the
	   BIND_4_COMPAT define to BIND_8_COMPAT ("Apple reinvented the wheel and
	   made it square" is one of the more polite comments on this change).
	   In order to get things to work, we have to define BIND_8_COMPAT here,
	   which forces the inclusion of nameser_compat.h when we include
	   nameser.h.  All (non-Apple) systems automatically define BIND_4_COMPAT
	   to force this inclusion, since Bind9 support (in the form of anything
	   other than the installed binaries) is still pretty rare */
	#define BIND_8_COMPAT
  #endif /* Mac OS X without backwards-compatibility bind define */
  #ifndef __SYMBIAN32__
	#include <arpa/nameser.h>
  #endif /* Symbian OS */
  #if defined( __MVS__ ) || defined( __VMCMS__ )
	/* The following have conflicting definitions in xti.h */
	#undef T_NULL
	#undef T_UNSPEC
  #endif /* MVS || VM */
  /* netinet/tcp.h is a BSD-ism, but all Unixen seem to use this even if
     XPG4 and SUS say it should be in xti.h */
  #if !defined( __MVS__ )
	#include <netinet/tcp.h>
  #endif /* !MVS */
  #ifndef __SYMBIAN32__
	#include <resolv.h>
  #endif /* Symbian OS */
  #ifndef TCP_NODELAY
	#include <xti.h>
	#if defined( __MVS__ ) || defined( __VMCMS__ )
	  /* The following have conflicting definitions in nameser.h */
	  #undef T_NULL
	  #undef T_UNSPEC
	#endif /* MVS || VM */
  #endif /* TCP_NODELAY */
  #ifdef __SCO_VERSION__
	#include <signal.h>
	#ifndef SIGIO
	  #include <sys/signal.h>
	#endif /* SIGIO not defined in signal.h - only from SCO */
  #endif /* UnixWare/SCO */
  #ifdef _AIX
	#include <sys/select.h>
  #endif /* Aches */
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <sys/types.h>
#endif /* OS-specific includes and defines */

/* Now that we've included all of the networking headers, try and guess
   whether this is an IPv6-enabled system.  We can detect this by the
   existence of definitions for the EAI_xxx return values from
   getaddrinfo().  Note that we can't safely detect it using the more
   obvious AF_INET6 since many headers defined this in anticipation of IPv6
   long before the remaining code support was present */

#if defined( EAI_BADFLAGS ) && defined( EAI_NONAME )
  #define IPv6
#endif /* getaddrinfo() return values defined */

/* BeOS with the BONE network stack has the necessary IPv6 defines but no
   actual IPv6 support, so we disable it again */

#if defined( __BEOS__ ) && defined( BONE_VERSION ) && defined( IPv6 )
  #undef IPv6
#endif /* BeOS with BONE */

/* The size of a (v4) IP address and the number of IP addresses we try to
   connect to for a given host, used if we're providing a enumated (IPv4-
   only) getaddrinfo() */

#define IP_ADDR_SIZE	4
#define IP_ADDR_COUNT	16

/* Portability defines */

#ifdef __WINDOWS__
  #define isBadSocket( socket )		( ( socket ) == INVALID_SOCKET )
  #define isSocketError( status )	( ( status ) == SOCKET_ERROR )
  #define isBadAddress( address )	( ( address ) == INADDR_NONE )
  #define isNonblockWarning()		( WSAGetLastError() == WSAEWOULDBLOCK )

  #define getErrorCode()			WSAGetLastError()
  #define getHostErrorCode()		WSAGetLastError()

  /* Windows doesn't define in_*_t's */
  #define in_addr_t					u_long
  #define in_port_t					u_short

  /* Size parameters are int (== size_t) */
  #define SIZE_TYPE					int
#else
  #define INVALID_SOCKET			-1
  #define isBadSocket( socket )		( ( socket ) == -1 )
  #define isSocketError( status )	( ( status ) == -1 )
  #define isBadAddress( address )	( ( address ) == ( in_addr_t ) -1 )
  #if defined( __SYMBIAN32__ )
	/* Symbian OS doesn't support nonblocking I/O */
	#define isNonblockWarning()		0
  #elif defined( __BEOS__ )
	#if defined( BONE_VERSION )
	  /* BONE returns "Operation now in progress" */
	  #define isNonblockWarning()	( errno == EWOULDBLOCK || \
									  errno == 0x80007024 )
	#else
	  /* BeOS, even though it supposedly doesn't support nonblocking
	     sockets, can return EWOULDBLOCK */
	  #define isNonblockWarning()	( errno == EWOULDBLOCK )
	#endif /* BeOS with/without BONE */
  #else
	#define isNonblockWarning()		( errno == EINPROGRESS )
  #endif /* Symbian OS vs.other OSes */

  #define getErrorCode()			errno
  #if ( defined( __MVS__ ) && defined( _OPEN_THREADS ) )
	/* MVS converts this into a hidden function in the presence of threads,
	   but not transparently like other systems */
	#define getHostErrorCode()		( *__h_errno() )
  #else
	#define getHostErrorCode()		h_errno
  #endif /* MVS */

  /* AIX doesn't define sockaddr_storage in its IPv6 headers so we define a
	 placeholder equivalent here */
  #if defined( IPv6 ) && defined( _AIX ) && OSVERSION <= 5
	struct sockaddr_storage {
		union {
			struct sockaddr_in6 bigSockaddrStruct;
			char padding[ 128 ];
			};
		};
  #endif /* AIX IPv6 versions without sockaddr_storage */

  /* The generic sockaddr struct used to reserve storage for protocol-
     specific sockaddr structs.  The IPv4 equivalent is given further
	 down in the IPv6-mapping definitions */
  #ifdef IPv6
	#define SOCKADDR_STORAGE		struct sockaddr_storage
  #endif /* IPv6 */

  /* Many older Unixen don't define the in_*_t's */
  #if defined( __APPLE__ ) || defined( __BEOS__ ) || \
	  defined( __bsdi__ ) || defined( __CYGWIN__ ) || \
	  defined( __FreeBSD__ ) || defined( __hpux ) || \
	  defined( __linux__ ) || defined( __OpenBSD__ ) || \
	  ( defined( sun ) && OSVERSION <= 5 )
	#ifndef in_addr_t
	  #define in_addr_t				u_long
	  #define in_port_t				u_short
	#endif /* in_addr_t */
  #endif /* Older Unixen without in_*_t's */

  /* Some systems use int for size parameters to socket functions and some
     use size_t (and just to be difficult some use socklen_t, which we use
	 if we can get it).  The following is required to distinguish the
	 different ones to avoid compiler warnings on systems that insist on
	 having it one particular way */
  #if defined( socklen_t ) || defined( __socklen_t_defined )
	#define SIZE_TYPE				socklen_t
  #elif defined( __APPLE__ ) || defined( __BEOS__ )
	#define SIZE_TYPE				int
  #else
	#define SIZE_TYPE				size_t
  #endif /* Different size types */

  /* PHUX generally doesn't define h_errno, we have to be careful here since
     later versions may use macros to get around threading issues so we check
	 for the existence of a macro with the given name before defining our own
	 version */
  #if defined( __hpux ) && !defined( h_errno )
	/* Usually missing from netdb.h */
	extern int h_errno;
  #endif /* PHUX && !h_errno */

  /* The Bind namespace (via nameser.h) was cleaned up between the old
     (widely-used) Bind4 API and the newer (little-used) Bind8/9 one.  In
	 order to handle both, we use the newer definitions, but map them back
	 to the Bind4 forms if required.  The only thing this doesn't give us
	 is the HEADER struct, which seems to have no equivalent in Bind8/9 */
  #ifndef NS_PACKETSZ
	#define NS_PACKETSZ				PACKETSZ
	#define NS_HFIXEDSZ				HFIXEDSZ
	#define NS_RRFIXEDSZ			RRFIXEDSZ
	#define NS_QFIXEDSZ				QFIXEDSZ
  #endif /* Bind8 names */

  /* Windows and BeOS use a distinct socket handle type and require the use
     of separate closesocket() and ioctlsocket() functions because socket
	 handles aren't the same as standard Windows/BeOS handles */
  #ifdef SOCKET
	/* MP-RAS has already defined this */
	#undef SOCKET
  #endif /* SOCKET */
  #define SOCKET					int
  #if !defined( __BEOS__ ) || \
	  ( defined( __BEOS__ ) && defined( BONE_VERSION ) )
	#define closesocket				close
  #endif /* BeOS without BONE */
  #define ioctlsocket				ioctl
#endif /* OS-specific portability defines */

/* BeOS with the BONE network stack has just enough IPv6 defines present to
   be awkward, so we temporarily re-enable IPv6 and then use a BONE-specific
   subset of IPv6 defines further on */

#if defined( __BEOS__ ) && defined( BONE_VERSION )
  #define IPv6
#endif /* BeOS with BONE */

/* IPv6 emulation functions used to provide a single consistent interface */

#ifndef IPv6
  /* The addrinfo struct used by getaddrinfo() */
  struct addrinfo {
	int ai_flags;				/* AI_PASSIVE, NI_NUMERICHOST */
	int ai_family;				/* PF_INET */
	int ai_socktype;			/* SOCK_STREAM */
	int ai_protocol;			/* IPPROTO_TCP */
	size_t ai_addrlen;			/* Length of ai_addr */
	char *ai_canonname;			/* CNAME for nodename */
	struct sockaddr *ai_addr;	/* IPv4 or IPv6 sockaddr */
	struct addrinfo *ai_next;	/* Next addrinfo structure list */
	};

  /* The generic sockaddr struct used to reserve storage for protocol-
     specific sockaddr structs.  This isn't quite right but since all
	 we're using it for is to reserve storage (we never actually look
	 inside it) it's OK to use here  */
  typedef char SOCKADDR_STORAGE[ 128 ];

  /* getaddrinfo() flags and values */
  #define AI_PASSIVE		0x1		/* Flag for hints are for getaddrinfo() */

  /* getnameinfo() flags and values.  We have to use slightly different
     values for these under Windows because Windows uses different values
	 for these than anyone else, and even if we're not on an explicitly
	 IPv6-enabled system we could still end up dynamically pulling in the
	 required libraries, so we need to ensure that we're using the same flag
	 values that Windows does */
  #ifdef __WINDOWS__
	#define NI_NUMERICHOST	0x2		/* Return numeric form of host addr.*/
	#define NI_NUMERICSERV	0x8		/* Return numeric form of host port */
  #else
	#define NI_NUMERICHOST	0x1		/* Return numeric form of host addr.*/
	#define NI_NUMERICSERV	0x2		/* Return numeric form of host port */
  #endif /* __WINDOWS__ */

  /* If there's no getaddrinfo() available and we're not using dynamic
     linking, use an emulation of the function */
  #ifndef __WINDOWS__
	#define getaddrinfo		my_getaddrinfo
	#define freeaddrinfo	my_freeaddrinfo
	#define getnameinfo		my_getnameinfo

	static int my_getaddrinfo( const char *nodename, const char *servname,
							   const struct addrinfo *hints,
							   struct addrinfo **res );
	static void my_freeaddrinfo( struct addrinfo *ai );
	static int my_getnameinfo( const struct sockaddr *sa, SIZE_TYPE salen,
							   char *node, SIZE_TYPE nodelen,
							   char *service, SIZE_TYPE servicelen,
							   int flags );
  #endif /* __WINDOWS__ */
#endif /* IPv6 */

/* A subset of the above for BeOS with the BONE network stack.  See the
   full IPv6 version above for descriptions of the entries */

#if defined( __BEOS__ ) && defined( BONE_VERSION )
  #undef IPv6						/* We really don't do IPv6 */

  typedef char SOCKADDR_STORAGE[ 128 ];

  #define getaddrinfo		my_getaddrinfo
  #define freeaddrinfo		my_freeaddrinfo
  #define getnameinfo		my_getnameinfo

  static int my_getaddrinfo( const char *nodename, const char *servname,
							 const struct addrinfo *hints,
							 struct addrinfo **res );
  static void my_freeaddrinfo( struct addrinfo *ai );
  static int my_getnameinfo( const struct sockaddr *sa, SIZE_TYPE salen,
							 char *node, SIZE_TYPE nodelen,
							 char *service, SIZE_TYPE servicelen,
							 int flags );
#endif /* BeOS with BONE */

/* Values defined in some environments but not in others.  MSG_NOSIGNAL is
   used to avoid SIGPIPEs on writes if the other side closes the connection,
   if it's not implemented in this environment we just clear the write flag.
   T_SRV and NS_SRVFIXEDSZ are used for DNS SRV lookups.  Newer versions of
   bind use a ns_t_srv enum for T_SRV but since we can't autodetect this via
   the preprocessor we always defien T_SRV ourselves */

#ifndef SHUT_WR
  #define SHUT_WR					1
#endif /* SHUT_WR */
#ifndef MSG_NOSIGNAL
  #define MSG_NOSIGNAL				0
#endif /* MSG_NOSIGNAL */
#ifndef T_SRV
  #define T_SRV						33
#endif /* !T_SRV */
#ifndef NS_SRVFIXEDSZ
  #define NS_SRVFIXEDSZ				( NS_RRFIXEDSZ + 6 )
#endif /* !NS_SRVFIXEDSZ */
#ifndef AI_ADDRCONFIG
  #define AI_ADDRCONFIG				0
#endif /* !AI_ADDRCONFIG */

/* The traditional way to set a descriptor to nonblocking mode was an
   ioctl with FIONBIO, however Posix prefers the O_NONBLOCK flag for fcntl
   so we use this if it's available.

   Unfortunately if we haven't got the fcntl() interface available there's
   no way to determine whether a socket is non-blocking or not, which is
   particularly troublesome for Windows where we need to ensure that the
   socket is blocking in order to avoid Winsock bugs with nonblocking
   sockets.  Although WSAIoctl() would appear to provide an interface for
   obtaining the nonblocking status, it doesn't provide any more
   functionality than ioctlsocket(), returning an error if we try and read
   the FIONBIO value.

   The best we can do in this case is to force the socket to be blocking,
   which somewhat voids the guarantee that we leave the socket as we found
   it, but OTOH if we've been passed an invalid socket the caller will have
   to abort and fix the problem anyway, so changing the socket state isn't
   such a big deal.

   BeOS is even worse, not only is there no way to determine whether a
   socket is blocking or not, it'll also quite happily perform socket
   functions like setsockopt() on a file descriptor (for example stdout),
   so we can't even use this as a check for socket validity as it is under
   other OSes.  Because of this the check socket function will always
   indicate that something vaguely handle-like is a valid socket */

#if defined( F_GETFL ) && defined( F_SETFL ) && defined( O_NONBLOCK )
  #define getSocketNonblockingStatus( socket, value ) \
			{ \
			value = fcntl( socket, F_GETFL, 0 ); \
			if( !isSocketError( value ) ) \
				value = ( value & O_NONBLOCK ) ? TRUE : FALSE; \
			}
  #define setSocketNonblocking( socket ) \
			{ \
			const int flags = fcntl( socket, F_GETFL, 0 ); \
			fcntl( socket, F_SETFL, flags | O_NONBLOCK ); \
			}
  #define setSocketBlocking( socket ) \
			{ \
			const int flags = fcntl( socket, F_GETFL, 0 ); \
			fcntl( socket, F_SETFL, flags & ~O_NONBLOCK ); \
			}
#elif defined( FIONBIO )
  #define getSocketNonblockingStatus( socket, value ) \
			{ \
			long nonBlock = FALSE; \
			value = ioctlsocket( socket, FIONBIO, &nonBlock ); \
			if( !isSocketError( value ) ) \
				value = 0; \
			}
  #define setSocketNonblocking( socket ) \
			{ \
			long nonBlock = TRUE; \
			ioctlsocket( socket, FIONBIO, &nonBlock ); \
			}
  #define setSocketBlocking( socket ) \
			{ \
			long nonBlock = FALSE; \
			ioctlsocket( socket, FIONBIO, &nonBlock ); \
			}
#elif defined( __BEOS__ )
  #define getSocketNonblockingStatus( socket, value ) \
			{ \
			int nonBlock = FALSE; \
			setsockopt( socket, SOL_SOCKET, SO_NONBLOCK, &nonBlock, sizeof( int ) ); \
			}
  #define setSocketNonblocking( socket ) \
			{ \
			int nonBlock = TRUE; \
			setsockopt( socket, SOL_SOCKET, SO_NONBLOCK, &nonBlock, sizeof( int ) ); \
			}
  #define setSocketBlocking( socket ) \
			{ \
			int nonBlock = FALSE; \
			setsockopt( socket, SOL_SOCKET, SO_NONBLOCK, &nonBlock, sizeof( int ) ); \
			}
#elif defined( __SYMBIAN32__ )
  /* Symbian OS doesn't support nonblocking I/O */
  #define getSocketNonblockingStatus( socket, value )	value = 0
  #define setSocketNonblocking( socket )
  #define setSocketBlocking( socket )
#else
  #error Need to create macros to handle nonblocking I/O
#endif /* Handling of blocking/nonblocking sockets */

/* gethostbyname is a problem function because the standard version is non-
   thread-safe due to the use of static internal storage to contain the
   returned host info.  Some OSes (Windows, PHUX >= 11.0, OSF/1 >= 4.0,
   Aches >= 4.3) don't have a problem with this because they use thread
   local storage, but others either require the use of nonstandard _r
   variants or simply don't handle it at all.  To make it even more
   entertaining, there are at least three different variations of the _r
   form:

	Linux (and glibc systems in general, but not BeOS with BONE):

	int gethostbyname_r( const char *name, struct hostent *result_buf,
						 char *buf, size_t buflen, struct hostent **result,
						 int *h_errnop);

	Slowaris >= 2.5.1, IRIX >= 6.5, QNX:

	struct hostent *gethostbyname_r( const char *name,
									 struct hostent *result, char *buffer,
									 int buflen, int *h_errnop );

	OSF/1, Aches (deprecated, see above):

	int gethostbyname_r( const char *name, struct hostent *hptr,
						 struct hostent_data *hdptr );

   To work around this mess, we define macros for thread-safe versions of
   gethostbyname that can be retargeted to the appropriate function as
   required */

#if defined( USE_THREADS ) && defined( __GLIBC__ ) && ( __GLIBC__ >= 2 ) && \
	( !defined( __BEOS__ ) || !defined( BONE_VERSION ) )
  #define gethostbyname_vars() \
		  char hostBuf[ 4096 ]; \
		  struct hostent hostEnt;
  #define gethostbyname_threadsafe( hostName, hostEntPtr, hostErrno ) \
		  if( gethostbyname_r( hostName, &hostEnt, hostBuf, 4096, &hostEntPtr, &hostErrno ) < 0 ) \
			hostEntPtr = NULL
#elif defined( USE_THREADS ) && \
	  ( ( defined( sun ) && OSVERSION > 4 ) || \
		( defined( __sgi ) && OSVERSION >= 6 ) || defined( __QNX__ ) )
  #define gethostbyname_vars() \
		  char hostBuf[ 4096 ]; \
		  struct hostent hostEnt;
  #define gethostbyname_threadsafe( hostName, hostEntPtr, hostErrno ) \
		  hostEntPtr = gethostbyname_r( hostName, &hostEnt, hostBuf, 4096, &hostErrno )
#else
  #define gethostbyname_vars()
  #define gethostbyname_threadsafe( hostName, hostEntPtr, hostErrno ) \
		  hostEntPtr = gethostbyname( hostName ); \
		  hostErrno = h_errno;
#endif /* Various gethostbyname variants */

/* For some connections that involve long-running sessions we need to be
   able to gracefully recover from local errors such as an interrupted system
   call, and remote errors such as the remote process or host crashing and
   restarting, which we can do by closing and re-opening the connection.  The
   various situations are:

	Local error:
		Retry the call on EAGAIN or EINTR

	Process crashes and restarts:
		Write: Remote host sends a RST in response to an attempt to continue
				a TCP session that it doesn't remember, which is reported
				locally as the dreaded (if you ssh or NNTP to remote hosts a
				lot) connection reset by peer error.
		Read: Remote host sends a FIN, we read 0 bytes.

	Network problem:
		Write: Data is resent, if a read is pending it returns ETIMEDOUT,
				otherwise write returns EPIPE or SIGPIPE (although we try
				and avoid the latter using MSG_NOSIGNAL).  Some
				implementations may also return ENETUNREACH or EHOSTUNREACH
				if they receive the right ICMP information.
		Read: See above, without the write sematics.

	Host crashes and restarts:
		Write: Looks like a network outage until the host is restarted, then
				gets an EPIPE/SIGPIPE.
		Read: As for write, but gets a ECONNRESET.

   The following macros check for various non-fatal/recoverable error
   conditions, in the future we may want to address some of the others listed
   above as well.  A restartable error is a local error for which we can
   retry the call, a recoverable error is a remote error for which we would
   need to re-establish the connection.  Note that any version of Winsock
   newer than the 16-bit ones shouldn't give us an EINPROGRESS, however some
   early stacks would still give this on occasions such as when another
   thread was doing (blocking) name resolution, and even with the very latest
   versions this is still something that can cause problems for other
   threads */

#ifdef __WINDOWS__
  #define isRecoverableError( status )	( ( status ) == WSAECONNRESET )
  #define isRestartableError()			( WSAGetLastError() == WSAEWOULDBLOCK || \
										  WSAGetLastError() == WSAEINPROGRESS )
  #define isTimeoutError()				( WSAGetLastError() == WSAETIMEDOUT )
#else
  #define isRecoverableError( status )	( ( status ) == ECONNRESET )
  #define isRestartableError()			( errno == EINTR || errno == EAGAIN )
  #define isTimeoutError()				( errno == ETIMEDOUT )
#endif /* OS-specific status codes */

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   libraries */

static INSTANCE_HANDLE hTCP = NULL_INSTANCE;
static INSTANCE_HANDLE hDNS = NULL_INSTANCE;
static INSTANCE_HANDLE hIPv6 = NULL_INSTANCE;

#ifdef __WINDOWS__
  #ifdef WSAAPI
	#define SOCKET_API	WSAAPI
  #else
    #define SOCKET_API	FAR PASCAL
  #endif /* WSAAPI */
#else
  #define SOCKET_API
  #define FAR
#endif /* Different socket API calling conventions */

typedef SOCKET ( SOCKET_API *ACCEPT )( SOCKET s, struct sockaddr *addr,
									   int *addrlen );
typedef int ( SOCKET_API *BIND )( SOCKET s, const struct sockaddr FAR *addr,
								  int namelen );
typedef int ( SOCKET_API *CONNECT )( SOCKET s, const struct sockaddr *name,
									 int namelen );
typedef struct hostent FAR * ( SOCKET_API *GETHOSTBYNAME )( const char FAR *name );
typedef struct hostent FAR * ( SOCKET_API *GETHOSTNAME )( char FAR * name,
														  int namelen );
typedef int ( SOCKET_API *GETSOCKOPT )( SOCKET s, int level, int optname,
										char *optval, int FAR *optlen );
typedef u_long ( SOCKET_API *HTONL )( u_long hostlong );
typedef u_short ( SOCKET_API *HTONS )( u_short hostshort );
typedef unsigned long ( SOCKET_API *INET_ADDR )( const char FAR *cp );
typedef char FAR * ( SOCKET_API *INET_NTOA )( struct in_addr in );
typedef int ( SOCKET_API *LISTEN )( SOCKET s, int backlog );
typedef u_long ( SOCKET_API *NTOHL )( u_long netlong );
typedef u_short ( SOCKET_API *NTOHS )( u_short netshort );
typedef int ( SOCKET_API *RECV )( SOCKET s, char *buf, int len, int flags );
typedef int ( SOCKET_API *SELECT )( int nfds, fd_set *readfds,
									fd_set *writefds, fd_set *exceptfds,
									const struct timeval *timeout );
typedef int ( SOCKET_API *SEND )( SOCKET s, const char *buf, int len,
								  int flags );
typedef int ( SOCKET_API *SETSOCKOPT )( SOCKET s, int level, int optname,
										char *optval, int optlen );
typedef int ( SOCKET_API *SHUTDOWN )( SOCKET s, int how );
typedef SOCKET ( SOCKET_API *SOCKETFN )( int af, int type, int protocol );
#ifdef __WINDOWS__
typedef int ( SOCKET_API *CLOSESOCKET )( SOCKET s );
typedef int ( SOCKET_API *FDISSETFN )( SOCKET, fd_set * );
typedef int ( SOCKET_API *IOCTLSOCKET )( SOCKET s, long cmd,
										u_long FAR *argp );
typedef int ( SOCKET_API *WSACLEANUP )( void );
typedef int ( SOCKET_API *WSAGETLASTERROR )( void );
typedef int ( SOCKET_API *WSASTARTUP )( WORD wVersionRequested,
										LPWSADATA lpWSAData );
typedef DNS_STATUS ( WINAPI *DNSQUERY )( const LPSTR lpstrName,
										 const WORD wType, const DWORD fOptions,
										 const PIP4_ARRAY aipServers,
										 PDNS_RECORD *ppQueryResultsSet,
										 PVOID *pReserved );
typedef DNS_STATUS ( WINAPI *DNSQUERYCONFIG )( const DNS_CONFIG_TYPE Config,
											   const DWORD Flag,
											   const PWSTR pwsAdapterName,
											   PVOID pReserved, PVOID pBuffer,
											   PDWORD pBufferLength );
typedef VOID ( WINAPI *DNSRECORDLISTFREE )( PDNS_RECORD pRecordList,
											DNS_FREE_TYPE FreeType );
#endif /* __WINDOWS__ */
typedef void ( SOCKET_API *FREEADDRINFO )( struct addrinfo *ai );
typedef int ( SOCKET_API *GETADDRINFO )( const char *nodename,
										 const char *servname,
										 const struct addrinfo *hints,
										 struct addrinfo **res );
typedef int ( SOCKET_API *GETNAMEINFO )( const struct sockaddr *sa,
										 SIZE_TYPE salen, char *node,
										 SIZE_TYPE nodelen, char *service,
										 SIZE_TYPE servicelen, int flags );
static ACCEPT paccept = NULL;
static BIND pbind = NULL;
static CONNECT pconnect = NULL;
static GETHOSTBYNAME pgethostbyname = NULL;
static GETHOSTNAME pgethostname = NULL;
static GETSOCKOPT pgetsockopt = NULL;
static HTONL phtonl = NULL;
static HTONS phtons = NULL;
static INET_ADDR pinet_addr = NULL;
static INET_NTOA pinet_ntoa = NULL;
static LISTEN plisten = NULL;
static NTOHL pntohl = NULL;
static NTOHS pntohs = NULL;
static RECV precv = NULL;
static SELECT pselect = NULL;
static SEND psend = NULL;
static SETSOCKOPT psetsockopt = NULL;
static SHUTDOWN pshutdown = NULL;
static SOCKETFN psocket = NULL;
#ifdef __WINDOWS__
static CLOSESOCKET pclosesocket = NULL;
static FDISSETFN pFDISSETfn = NULL;
static IOCTLSOCKET pioctlsocket = NULL;
static WSACLEANUP pWSACleanup = NULL;
static WSAGETLASTERROR pWSAGetLastError = NULL;
static WSASTARTUP pWSAStartup = NULL;
static DNSQUERY pDnsQuery = NULL;
static DNSQUERYCONFIG pDnsQueryConfig = NULL;
static DNSRECORDLISTFREE pDnsRecordListFree = NULL;
#endif /* __WINDOWS__ */
static FREEADDRINFO pfreeaddrinfo = NULL;
static GETADDRINFO pgetaddrinfo = NULL;
static GETNAMEINFO pgetnameinfo = NULL;
#if ( defined( sun ) && OSVERSION > 4 )
static int *h_errnoPtr;

#undef getHostErrorCode
#define getHostErrorCode()	*h_errnoPtr

#undef htonl	/* Slowaris has defines that conflict with our ones */
#undef htons
#undef ntohl
#undef ntohs
#endif /* Slowaris */

#define accept				paccept
#define bind				pbind
#define connect				pconnect
#define gethostbyname		pgethostbyname
#define gethostname			pgethostname
#define getsockopt			pgetsockopt
#define htonl				phtonl
#define htons				phtons
#define inet_addr			pinet_addr
#define inet_ntoa			pinet_ntoa
#define listen				plisten
#define ntohl				pntohl
#define ntohs				pntohs
#define recv				precv
#define select				pselect
#define send				psend
#define setsockopt			psetsockopt
#define shutdown			pshutdown
#define socket				psocket
#ifdef __WINDOWS__
#define closesocket			pclosesocket
#define __WSAFDIsSet		pFDISSETfn
#define ioctlsocket			pioctlsocket
#define WSACleanup			pWSACleanup
#define WSAGetLastError		pWSAGetLastError
#define WSAStartup			pWSAStartup
#define DnsQuery			pDnsQuery
#define DnsQueryConfig		pDnsQueryConfig
#define DnsRecordListFree	pDnsRecordListFree
#endif /* __WINDOWS__ */
#define freeaddrinfo		pfreeaddrinfo
#define getaddrinfo			pgetaddrinfo
#define getnameinfo			pgetnameinfo

/* Dynamically load and unload any necessary TCP/IP libraries.  Under Windows
   the dynamic loading is complicated by the existence of Winsock 1 vs.
   Winsock 2, all recent systems will use Winsock 2 but we allow for Winsock 1
   as well just in case, and for use on 16-bit systems */

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#define TCP_LIBNAME			"winsock.dll"
  #else
	#define TCP_LIBNAME			"ws2_32.dll"
	#define WINSOCK_OLD_LIBNAME	"wsock32.dll"
  #endif /* __WIN16__ */
#else
  #define TCP_LIBNAME			"libsocket.so"
#endif /* OS-specific TCP/IP library naming */

int netInitTCP( void )
	{
	STATIC_FN int initSocketPool( void );
#ifdef __WINDOWS__
	WSADATA wsaData;
  #ifdef __WIN16__
	UINT errorMode;
  #endif /* __WIN16__ */
	BOOLEAN ip6inWinsock = FALSE;
#endif /* __WINDOWS__ */

	/* Obtain a handle to the modules containing the TCP/IP functions */
#ifdef __WINDOWS__
  #ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hTCP = DynamicLoad( TCP_LIBNAME );
	SetErrorMode( errorMode );
	if( hTCP < HINSTANCE_ERROR )
		{
		hTCP = NULL_INSTANCE;
		return( CRYPT_ERROR );
		}
  #else
	if( ( hTCP = DynamicLoad( TCP_LIBNAME ) ) == NULL_INSTANCE && \
		( hTCP = DynamicLoad( WINSOCK_OLD_LIBNAME ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
	hDNS = DynamicLoad( "dnsapi.dll" );
	if( DynamicBind( hTCP, "getaddrinfo" ) != NULL )
		ip6inWinsock = TRUE;
	else
		/* Newer releases of Windows put the IPv6 functions in the Winsock 2
		   library, older (non-IPv6-enabled) releases had it available as an
		   experimental add-on using the IPv6 Technology Preview library */
		hIPv6 = DynamicLoad( "wship6.dll" );
  #endif /* Win16 vs.Win32 */
#else
	if( ( hTCP = DynamicLoad( TCP_LIBNAME ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
#endif /* OS-specific dynamic load */

	/* Now get pointers to the functions */
	accept = ( ACCEPT ) DynamicBind( hTCP, "accept" );
	bind = ( BIND ) DynamicBind( hTCP, "bind" );
	connect = ( CONNECT ) DynamicBind( hTCP, "connect" );
	gethostbyname = ( GETHOSTBYNAME ) DynamicBind( hTCP, "gethostbyname" );
	gethostname = ( GETHOSTNAME ) DynamicBind( hTCP, "gethostname" );
	getsockopt = ( GETSOCKOPT ) DynamicBind( hTCP, "getsockopt" );
	htonl = ( HTONL ) DynamicBind( hTCP, "htonl" );
	htons = ( HTONS ) DynamicBind( hTCP, "htons" );
	inet_addr = ( INET_ADDR ) DynamicBind( hTCP, "inet_addr" );
	inet_ntoa = ( INET_NTOA ) DynamicBind( hTCP, "inet_ntoa" );
	listen = ( LISTEN ) DynamicBind( hTCP, "listen" );
	ntohl = ( NTOHL ) DynamicBind( hTCP, "ntohl" );
	ntohs = ( NTOHS ) DynamicBind( hTCP, "ntohs" );
	recv = ( RECV ) DynamicBind( hTCP, "recv" );
	select = ( SELECT ) DynamicBind( hTCP, "select" );
	send = ( SEND ) DynamicBind( hTCP, "send" );
	setsockopt = ( SETSOCKOPT ) DynamicBind( hTCP, "setsockopt" );
	shutdown = ( SHUTDOWN ) DynamicBind( hTCP, "shutdown" );
	socket = ( SOCKETFN ) DynamicBind( hTCP, "socket" );
#ifdef __WINDOWS__
	closesocket = ( CLOSESOCKET ) DynamicBind( hTCP, "closesocket" );
	__WSAFDIsSet = ( FDISSETFN ) DynamicBind( hTCP, "__WSAFDIsSet" );
	ioctlsocket = ( IOCTLSOCKET ) DynamicBind( hTCP, "ioctlsocket" );
	WSACleanup = ( WSACLEANUP ) DynamicBind( hTCP, "WSACleanup" );
	WSAGetLastError = ( WSAGETLASTERROR ) DynamicBind( hTCP, "WSAGetLastError" );
	WSAStartup = ( WSASTARTUP ) DynamicBind( hTCP, "WSAStartup" );
	if( hDNS != NULL_INSTANCE )
		{
		DnsQuery = ( DNSQUERY ) DynamicBind( hDNS, "DnsQuery_A" );
		DnsQueryConfig = ( DNSQUERYCONFIG ) DynamicBind( hDNS, "DnsQueryConfig" );
		DnsRecordListFree = ( DNSRECORDLISTFREE ) DynamicBind( hDNS, "DnsRecordListFree" );
		if( DnsQuery == NULL || DnsQueryConfig == NULL || \
			DnsRecordListFree == NULL )
			{
			DynamicUnload( hDNS );
			hDNS = NULL_INSTANCE;
			}
		}
	if( ip6inWinsock || hIPv6 != NULL_INSTANCE )
		{
		INSTANCE_HANDLE hAddr = ip6inWinsock ? hTCP : hIPv6;

		freeaddrinfo = ( FREEADDRINFO ) DynamicBind( hAddr, "freeaddrinfo" );
		getaddrinfo = ( GETADDRINFO ) DynamicBind( hAddr, "getaddrinfo" );
		getnameinfo = ( GETNAMEINFO ) DynamicBind( hAddr, "getnameinfo" );
		if( freeaddrinfo == NULL || getaddrinfo == NULL || \
			getnameinfo == NULL )
			{
			if( hIPv6 != NULL_INSTANCE )
				{
				DynamicUnload( hIPv6 );
				hIPv6 = NULL_INSTANCE;
				}
			DynamicUnload( hTCP );
			hTCP = NULL_INSTANCE;
			return( CRYPT_ERROR );
			}
		}
#endif /* __WINDOWS__ */
	if( freeaddrinfo == NULL )
		{
		static int my_getaddrinfo( const char *nodename, const char *servname,
								   const struct addrinfo *hints,
								   struct addrinfo **res );
		static void my_freeaddrinfo( struct addrinfo *ai );
		static int my_getnameinfo( const struct sockaddr *sa, SIZE_TYPE salen,
								   char *node, SIZE_TYPE nodelen,
								   char *service, SIZE_TYPE servicelen,
								   int flags );

		/* If we couldn't dynamically bind the IPv6 name/address functions,
		   use a local emulation */
		getaddrinfo = ( GETADDRINFO ) my_getaddrinfo;
		freeaddrinfo = ( FREEADDRINFO ) my_freeaddrinfo;
		getnameinfo = ( GETNAMEINFO ) my_getnameinfo;
		}
#if ( defined( sun ) && OSVERSION > 4 )
	h_errnoPtr = ( int * ) DynamicBind( hTCP, "h_errno" );
	if( h_errnoPtr == NULL )
		{
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
		return( CRYPT_ERROR );
		}
#endif /* Slowaris */

	/* Make sure that we got valid pointers for every TCP/IP function */
	if( accept == NULL || bind == NULL || connect == NULL || \
		gethostbyname == NULL || gethostname == NULL || \
		getsockopt == NULL || htonl == NULL || htons == NULL || \
		inet_addr == NULL || inet_ntoa == NULL || listen == NULL || \
		ntohl == NULL || ntohs == NULL || recv == NULL || \
		select == NULL || send == NULL || setsockopt == NULL || \
		shutdown == NULL || socket == NULL )
		{
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
		if( hDNS != NULL_INSTANCE )
			{
			DynamicUnload( hDNS );
			hDNS = NULL_INSTANCE;
			}
		if( hIPv6 != NULL_INSTANCE )
			{
			DynamicUnload( hIPv6 );
			hIPv6 = NULL_INSTANCE;
			}
		return( CRYPT_ERROR );
		}

#ifdef __WINDOWS__
	if( closesocket == NULL || __WSAFDIsSet == NULL || \
		ioctlsocket == NULL || WSACleanup == NULL || \
		WSAGetLastError == NULL || WSAStartup == NULL || \
		( WSAStartup( 2, &wsaData ) && WSAStartup( 1, &wsaData ) ) )
		{
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
		if( hDNS != NULL_INSTANCE )
			{
			DynamicUnload( hDNS );
			hDNS = NULL_INSTANCE;
			}
		if( hIPv6 != NULL_INSTANCE )
			{
			DynamicUnload( hIPv6 );
			hIPv6 = NULL_INSTANCE;
			}
		return( CRYPT_ERROR );
		}
#endif /* __WINDOWS__ */

	/* Set up the socket pool state information */
	return( initSocketPool() );
	}

void netEndTCP( void )
	{
	STATIC_FN void endSocketPool( void );

	/* Clean up the socket pool state information */
	endSocketPool();

	if( hIPv6 != NULL_INSTANCE )
		{
		DynamicUnload( hIPv6 );
		hIPv6 = NULL_INSTANCE;
		}
	if( hDNS != NULL_INSTANCE )
		{
		DynamicUnload( hDNS );
		hDNS = NULL_INSTANCE;
		}
	if( hTCP != NULL_INSTANCE )
		{
#ifdef __WINDOWS__
		/* Wipe the Sheets Afterwards and Cleanup */
		WSACleanup();
#endif /* __WINDOWS__ */
		DynamicUnload( hTCP );
		}
	hTCP = NULL_INSTANCE;
	}

/* Return the status of the network interface */

static BOOLEAN transportOKFunction( void )
	{
	return( hTCP != NULL_INSTANCE ? TRUE : FALSE );
	}
#else

int netInitTCP( void )
	{
	STATIC_FN int initSocketPool( void );

#ifdef __SCO_VERSION__
	struct sigaction act, oact;

	/* Work around the broken SCO/UnixWare signal-handling, which sometimes
	   sends a nonblocking socket a SIGIO (thus killing the process) when
	   waiting in a select() (this may have been fixed by the switch to
	   blocking sockets necessitated by Winsock bugs with non-blocking
	   sockets).  Since SIGIO is an alias for SIGPOLL, SCO doesn't help by
	   reporting this as a "polling alarm".  To fix this we need to catch
	   and swallow SIGIOs */
	memset( &act, 0, sizeof( act ) );
	act.sa_handler = SIG_IGN;
	sigemptyset( &act.sa_mask );
	if( sigaction( SIGIO, &act, &oact ) < 0 )
		{
		/* This assumes that stderr is open, i.e. that we're not a daemon
		   (this should be the case at least during the development/debugging
		   stage) */
		fprintf( stderr, "cryptlib: sigaction failed, errno = %d, "
				 "file = %s, line = %d.\n", errno, __FILE__, __LINE__ );
		abort();
		}

	/* Check for handler override. */
	if( oact.sa_handler != SIG_DFL && oact.sa_handler != SIG_IGN )
		{
		/* We overwrote the caller's handler, reinstate the old handler and
		   warn them about this */
		fprintf( stderr, "Warning: Conflicting SIGIO handling detected in "
				 "UnixWare socket bug\n         workaround, file " __FILE__
				 ", line %d.  This may cause\n         false SIGIO/SIGPOLL "
				"errors.\n", __LINE__ );
		sigaction( SIGIO, &oact, &act );
		}
#endif /* UnixWare/SCO */

	/* Set up the socket pool state information */
	return( initSocketPool() );
	}

void netEndTCP( void )
	{
	STATIC_FN void endSocketPool( void );

	/* Clean up the socket pool state information */
	endSocketPool();

#ifdef __SCO_VERSION__
	signal( SIGIO, SIG_DFL );
#endif /* UnixWare/SCO */
	}

static BOOLEAN transportOKFunction( void )
	{
	return( TRUE );
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map of common error codes to strings */

typedef struct {
	const int errorCode;		/* Native error code */
	const int cryptErrorCode;	/* cryptlib error code */
	const BOOLEAN isFatal;		/* Seriousness level */
	const char *errorString;	/* Error message */
	} SOCKETERROR_INFO;

#ifdef __WINDOWS__

static const FAR_BSS SOCKETERROR_INFO socketErrorInfo[] = {
	{ WSAECONNREFUSED, CRYPT_ERROR_PERMISSION, TRUE,
		"WSAECONNREFUSED: The attempt to connect was rejected" },
	{ WSAEADDRNOTAVAIL, CRYPT_ERROR_NOTFOUND, TRUE,
		"WSAEADDRNOTAVAIL: The remote address is not a valid address" },
	{ WSAECONNABORTED, CRYPT_OK, TRUE,
		"WSAECONNABORTED: Connection was terminated due to a time-out or "
		"other failure" },
	{ WSAECONNRESET, CRYPT_OK, TRUE,
		"WSAECONNRESET: Connection was reset by the remote host executing "
		"a close" },
	{ WSAEHOSTUNREACH, CRYPT_OK, TRUE,
		"WSAEHOSTUNREACH: Remote host cannot be reached from this host at "
		"this time" },
	{ WSAEMSGSIZE, CRYPT_ERROR_OVERFLOW, FALSE,
		"WSAEMSGSIZE: Message is larger than the maximum supported by the "
		"underlying transport" },
	{ WSAENETDOWN, CRYPT_OK, FALSE,
		"WSAENETDOWN: The network subsystem has failed" },
	{ WSAENETRESET, CRYPT_OK, FALSE,
		"WSAENETRESET: Connection was broken due to keep-alive detecting a "
		"failure while operation was in progress" },
	{ WSAENETUNREACH, CRYPT_ERROR_NOTAVAIL, FALSE,
		"WSAENETUNREACH: Network cannot be reached from this host at this "
		"time" },
	{ WSAENOBUFS, CRYPT_ERROR_MEMORY, FALSE,
		"WSAENOBUFS: No buffer space available" },
	{ WSAENOTCONN, CRYPT_OK, TRUE,
		"WSAENOTCONN: Socket is not connected" },
	{ WSAETIMEDOUT, CRYPT_ERROR_TIMEOUT, FALSE,
		"WSAETIMEDOUT: Function timed out before completion" },
	{ WSAHOST_NOT_FOUND, CRYPT_ERROR_NOTFOUND, FALSE,
		"WSAHOST_NOT_FOUND: Host not found" },
	{ WSATRY_AGAIN,  CRYPT_OK, FALSE,
		"WSATRY_AGAIN: Host not found (non-authoritative)" },
	{ WSANO_DATA,  CRYPT_OK, FALSE,
		"WSANO_DATA: Valid name, no data record of requested type" },
	{ CRYPT_ERROR }
	};
#define hostErrorInfo	socketErrorInfo		/* Winsock uses unified error codes */

#define TIMEOUT_ERROR	WSAETIMEDOUT		/* Code for timeout error */

#else

static const FAR_BSS SOCKETERROR_INFO socketErrorInfo[] = {
	{ EADDRNOTAVAIL, CRYPT_ERROR_NOTFOUND, TRUE,
		"EADDRNOTAVAIL: Specified address is not available from the local "
		"machine" },
	{ ECONNREFUSED, CRYPT_ERROR_PERMISSION, TRUE,
		"ECONNREFUSED: Attempt to connect was rejected" },
	{ EINTR, CRYPT_OK, FALSE,
		"EINTR: Function was interrupted by a signal" },
	{ EMFILE, CRYPT_OK, FALSE,
		"EMFILE: Per-process descriptor table is full" },
#ifndef __SYMBIAN32__
	{ ECONNRESET, CRYPT_OK, TRUE,
		"ECONNRESET: Connection was forcibly closed by remote host" },
	{ EMSGSIZE, CRYPT_ERROR_OVERFLOW, FALSE,
		"EMSGSIZE: Message is too large to be sent all at once" },
	{ ENETUNREACH, CRYPT_OK, FALSE,
		"ENETUNREACH: No route to the network or host is present" },
	{ ENOBUFS, CRYPT_ERROR_MEMORY, FALSE,
		"ENOBUFS: Insufficient system resources available to complete the "
		"call" },
	{ ENOTCONN, CRYPT_OK, TRUE,
		"ENOTCONN: Socket is not connected" },
#endif /* Symbian OS */
	{ ETIMEDOUT, CRYPT_ERROR_TIMEOUT, FALSE,
		"ETIMEDOUT: Function timed out before completion" },
	{ HOST_NOT_FOUND, CRYPT_ERROR_NOTFOUND, TRUE,
		"HOST_NOT_FOUND: Not an official hostname or alias" },
	{ NO_ADDRESS, CRYPT_ERROR_NOTFOUND, TRUE,
		"NO_ADDRESS: Name is valid but does not have an IP address at the "
		"name server" },
	{ TRY_AGAIN, CRYPT_OK, FALSE,
		"TRY_AGAIN: Local server did not receive a response from an "
		"authoritative server" },
	{ CRYPT_ERROR }
	};

#define TIMEOUT_ERROR	ETIMEDOUT			/* Code for timeout error */

static const FAR_BSS SOCKETERROR_INFO hostErrorInfo[] = {
	{ HOST_NOT_FOUND, CRYPT_ERROR_NOTFOUND, TRUE,
		"HOST_NOT_FOUND: Host not found" },
	{ NO_ADDRESS, CRYPT_ERROR_NOTFOUND, TRUE,
		"NO_ADDRESS: No address record available for this name" },
	{ CRYPT_ERROR }
	};
#endif /* System-specific socket error codes */

/* Get and set the low-level error information from a socket- and host-
   lookup-based error */

static int mapError( STREAM *stream, const SOCKETERROR_INFO *errorInfo,
					 const int errorCode, int status )
	{
	int i;

	*stream->errorMessage = '\0';
	for( i = 0; errorInfo[ i ].errorCode != CRYPT_ERROR; i++ )
		if( errorInfo[ i ].errorCode == stream->errorCode )
			{
			strcpy( stream->errorMessage, errorInfo[ i ].errorString );
			if( errorInfo[ i ].cryptErrorCode != CRYPT_OK )
				/* There's a more specific error code than the generic one
				   we've been given available, use that instead */
				status = errorInfo[ i ].cryptErrorCode;
			if( errorInfo[ i ].isFatal )
				/* It's a fatal error, make it persistent for the stream */
				stream->status = status;
			break;
			}
	return( status );
	}

static int getSocketError( STREAM *stream, const int status )
	{
	/* Get the low-level error code and map it to an error string if
	   possible */
	stream->errorCode = getErrorCode();
	return( mapError( stream, socketErrorInfo, stream->errorCode,
					  status ) );
	}

static int getHostError( STREAM *stream, const int status )
	{
	/* Get the low-level error code and map it to an error string if
	   possible */
	stream->errorCode = getHostErrorCode();
	return( mapError( stream, hostErrorInfo, stream->errorCode,
					  status ) );
	}

static int setSocketError( STREAM *stream, const char *errorMessage,
						   const int status, const BOOLEAN isFatal )
	{
	/* Set a cryptlib-supplied socket error message.  Since this doesn't
	   correspond to any system error, we clear the error code */
	stream->errorCode = 0;
	strcpy( stream->errorMessage, errorMessage );
	if( isFatal )
		/* It's a fatal error, make it persistent for the stream */
		stream->status = status;
	return( status );
	}

#if defined( __BEOS__ ) && !defined( BONE_VERSION )

/* BeOS doesn't support checking for anything except readability in select()
   and only supports one or two socket options, so we define our own
   versions of these functions that no-op out unsupported options */

#undef select   /* Restore normal select() around the wrapper */

static int my_select( int socket_range, struct fd_set *read_bits,
					  struct fd_set *write_bits,
					  struct fd_set *exception_bits,
					  struct timeval *timeout )
	{
	/* BeOS doesn't support nonblocking connects, it always waits about a
	   minute for the connect and then times out, so it we get a wait on a
	   connecting socket we report it as being successful by exiting with
	   the fds as set by the caller and a successful return status */
	if( read_bits != NULL && write_bits != NULL )
		return( 1 );

	/* Since BeOS doesn't support checking for writeability or errors, we
	   have to clear these values before we call select() so the caller
	   won't find anything still set when we return */
	if( write_bits != NULL )
		FD_ZERO( write_bits );
	if( exception_bits != NULL )
		FD_ZERO( exception_bits );

	return( select( socket_range, read_bits, NULL, NULL, timeout ) );
	}

#define select( sockets, readFD, writeFD, exceptFD, timeout ) \
		my_select( sockets, readFD, writeFD, exceptFD, timeout )

static int my_setsockopt( int socket, int level, int option,
						  const void *data, uint size )
	{
	if( option != SO_NONBLOCK && option != SO_REUSEADDR )
		return( 0 );
	return( setsockopt( socket, level, option, data, size ) );
	}

static int my_getsockopt( int socket, int level, int option,
						  void *data, uint *size )
	{
	BYTE buffer[ 8 ];
	int count;

	if( option != SO_ERROR )
		return( 0 );
	*( ( int * ) data ) = 0;	/* Clear return status */

	/* It's unclear whether the following setsockopt actually does anything
	   under BeOS or not.  If it fails, the alternative below may work */
#if 1
	return( setsockopt( socket, level, option, data, *size ) );
#else
	count = recv( socket, buffer, 0, 0 );
	printf( "recv( 0 ) = %d, errno = %d.\n", count, errno );
	if( count < 0 )
		*( ( int * ) data ) = errno;
#endif /* 1 */
	}
#endif /* BeOS without BONE */

/* Emulation of IPv6 networking functions.  We include these unconditionally
   under Windows because with dynamic binding we can't be sure that they're
   needed or not */

#if !defined( IPv6 ) || defined( __WINDOWS__ )

static int addAddrInfo( struct addrinfo *prevAddrInfoPtr,
						struct addrinfo **addrInfoPtrPtr,
						const void *address, const int port )
	{
	struct addrinfo *addrInfoPtr;
	struct sockaddr_in *sockAddrPtr;

	/* Allocate the new element, clear it, and set fixed fields for IPv4 */
	if( ( addrInfoPtr = clAlloc( "addAddrInfo", \
								 sizeof( struct addrinfo ) ) ) == NULL || \
		( sockAddrPtr = clAlloc( "addAddrInfo", \
								 sizeof( struct sockaddr ) ) ) == NULL )
		{
		if( addrInfoPtr != NULL )
			clFree( "addAddrInfo", addrInfoPtr );
		return( -1 );
		}
	memset( addrInfoPtr, 0, sizeof( struct addrinfo ) );
	memset( sockAddrPtr, 0, sizeof( struct sockaddr ) );
	if( prevAddrInfoPtr != NULL )
		prevAddrInfoPtr->ai_next = addrInfoPtr;
	addrInfoPtr->ai_family = PF_INET;
	addrInfoPtr->ai_socktype = SOCK_STREAM;
	addrInfoPtr->ai_protocol = IPPROTO_TCP;
	addrInfoPtr->ai_addrlen = sizeof( struct sockaddr_in );
	addrInfoPtr->ai_addr = ( struct sockaddr * ) sockAddrPtr;

	/* Set the port and address information */
	sockAddrPtr->sin_family = AF_INET;
	sockAddrPtr->sin_port = htons( ( in_port_t ) port );
	memcpy( &sockAddrPtr->sin_addr.s_addr, address, IP_ADDR_SIZE );
	*addrInfoPtrPtr = addrInfoPtr;
	return( 0 );
	}

static int my_getaddrinfo( const char *nodename, const char *servname,
						   const struct addrinfo *hints,
						   struct addrinfo **res )
	{
	struct hostent *pHostent;
	struct addrinfo *currentAddrInfoPtr = NULL;
	const int port = aToI( servname );
	int hostErrno, i;
	gethostbyname_vars();

	assert( nodename != NULL || ( hints->ai_flags & AI_PASSIVE ) );
	assert( servname != NULL );
	assert( isReadPtr( hints, sizeof( struct addrinfo ) ) );

	/* Clear return value */
	*res = NULL;

	/* Perform basic error checking */
	if( ( nodename == NULL && !( hints->ai_flags & AI_PASSIVE ) ) || \
		servname == NULL )
		return( -1 );

	/* If there's no interface specified and we're creating a server-side
	   socket, prepare to listen on any interface.  Note that BeOS can only
	   bind to one interface at a time, so INADDR_ANY actually binds to the
	   first interface it finds */
	if( nodename == NULL && ( hints->ai_flags & AI_PASSIVE ) )
		{
		const in_addr_t address = INADDR_ANY;

		return( addAddrInfo( NULL, res, &address, port ) );
		}

	/* If it's a dotted address, there's a single address, convert it to
	   in_addr form and return it.  Note for EBCDIC use that since this is
	   an emulation of an OS function the string is already in EBCDIC form,
	   so we don't use the cryptlib-internal functions for this */
	if( isdigit( *nodename ) )
		{
		const in_addr_t address = inet_addr( nodename );

		if( isBadAddress( address ) )
			return( -1 );
		return( addAddrInfo( NULL, res, &address, port ) );
		}

	/* It's a host name, convert it to the in_addr form */
	gethostbyname_threadsafe( nodename, pHostent, hostErrno );
	if( pHostent == NULL || pHostent->h_length != IP_ADDR_SIZE )
		return( -1 );
	for( i = 0; pHostent->h_addr_list[ i ] != NULL && i < IP_ADDR_COUNT; i++ )
		{
		int status;

		if( currentAddrInfoPtr == NULL )
			{
			status = addAddrInfo( NULL, res, pHostent->h_addr_list[ i ], port );
			currentAddrInfoPtr = *res;
			}
		else
			status = addAddrInfo( currentAddrInfoPtr, &currentAddrInfoPtr,
								  pHostent->h_addr_list[ i ], port );
		if( status != 0 )
			{
			freeaddrinfo( *res );
			return( status );
			}
		}
	return( 0 );
	}

static void my_freeaddrinfo( struct addrinfo *ai )
	{
	while( ai != NULL )
		{
		struct addrinfo *addrInfoCursor = ai;

		ai = ai->ai_next;
		if( addrInfoCursor->ai_addr != NULL )
			clFree( "my_freeaddrinfo", addrInfoCursor->ai_addr );
		clFree( "my_freeaddrinfo", addrInfoCursor );
		}
	}

static int my_getnameinfo( const struct sockaddr *sa, SIZE_TYPE salen,
						   char *node, SIZE_TYPE nodelen, char *service,
						   SIZE_TYPE servicelen, int flags )
	{
	const struct sockaddr_in *sockAddr = ( struct sockaddr_in * ) sa;
	const char *ipAddress;

	/* Clear return values */
	strcpy( node, "<Unknown>" );
	strcpy( service, "0" );

	/* Get the remote system's address and port number */
	if( ( ipAddress = inet_ntoa( sockAddr->sin_addr ) ) == NULL )
		return( -1 );
	strncpy( node, ipAddress, nodelen );
	node[ nodelen - 1 ] = '\0';
	sPrintf( service, "%d", ntohs( sockAddr->sin_port ) );

	return( 0 );
	}
#endif /* !IPv6 || __WINDOWS__ */

/* Use DNS SRV to auto-detect host information */

#if defined( __WINDOWS__ )

static void convertToSrv( char *srvName, const char *hostName )
	{
	const int nameLength = strlen( hostName );
	int i;

	/* Prepend the service info to the start of the host name.  This
	   converts foo.bar.com into _pkiboot._tcp.bar.com in preparation for
	   the DNS SRV lookup */
	for( i = 0; i < nameLength; i++ )
		if( hostName[ i ] == '.' )
			break;
	if( i < nameLength && ( nameLength - i ) < MAX_URL_SIZE - 16 )
		{
		memcpy( srvName, "_pkiboot._tcp.", 14 );
		memcpy( srvName + 14, hostName + i, nameLength - i + 1 );
		}
	else
		strcpy( srvName, "_pkiboot._tcp.localhost" );
	}

static int getSrvFQDN( STREAM *stream, char *fqdn )
	{
	PDNS_RECORD pDns = NULL;
	struct hostent *hostInfo;
	static char cachedFQDN[ MAX_URL_SIZE + 1 ];
	static time_t lastFetchTime = 0;

	/* The uncached FQDN check is quite slow and resource-intensive (it
	   seems to do a full reload of the DNS subsystem), to lighten the load
	   we only try a new one once a minute */
	if( lastFetchTime >= getTime() - 60 )
		{
		strcpy( fqdn, cachedFQDN );
		return( CRYPT_OK );
		}

	/* If we're doing a full autodetect, we first have to determine the
	   local host's FQDN.  This gets quite tricky because the behavior of
	   gethostbyaddr() changed with Win2K so we have to use the DNS API, but
	   this isn't available in older versions of Windows.  If we're using
	   the DNS API, we have to use the barely-documented
	   DNS_QUERY_BYPASS_CACHE option to get what we want */
	if( gethostname( cachedFQDN, MAX_DNS_SIZE ) == 0 && \
		( hostInfo = gethostbyname( cachedFQDN ) ) != NULL )
		{
		int i;

		for( i = 0; hostInfo->h_addr_list[ i ] != NULL; i++ )
			{
			struct in_addr address;

			/* Reverse the byte order for the in-addr.arpa lookup and
			   convert the address to dotted-decimal notation */
			address.S_un.S_addr = *( ( DWORD * ) hostInfo->h_addr_list[ i ] );
			sprintf( cachedFQDN, "%s.in-addr.arpa", inet_ntoa( address ) );

			/* Check for a name */
			if( DnsQuery( cachedFQDN, DNS_TYPE_PTR, DNS_QUERY_BYPASS_CACHE,
						  NULL, &pDns, NULL ) == 0 )
				break;
			}
		}
	if( pDns == NULL )
		return( setSocketError( stream, "Couldn't determine FQDN of local "
								"machine", CRYPT_ERROR_NOTFOUND, TRUE ) );
	convertToSrv( cachedFQDN, pDns->Data.PTR.pNameHost );
	DnsRecordListFree( pDns, DnsFreeRecordList );

	/* Remember the value we just found to lighten the load on the
	   resolver */
	strcpy( fqdn, cachedFQDN );
	lastFetchTime = getTime();

	return( CRYPT_OK );
	}

static int findHostInfo( STREAM *stream, char *hostName, int *hostPort,
						 const char *name )
	{
	PDNS_RECORD pDns = NULL, pDnsInfo = NULL, pDnsCursor;
	DWORD dwRet;
	int nameLength, priority = 32767;

	/* If we're running on anything other than a heavily-SP'd Win2K or WinXP,
	   there's not much that we can do */
	if( hDNS == NULL_INSTANCE )
		return( setSocketError( stream, "DNS services not available",
								CRYPT_ERROR_NOTFOUND, TRUE ) );

	/* If we're doing a full autodetect, we construct the SRV query using
	   the local machine's FQDN.  This fails more often than not because of
	   NATing and use of private networks, but at least we can try */
	if( !strCompareZ( name, "[Autodetect]" ) )
		{
		const int status = getSrvFQDN( stream, hostName );
		if( cryptStatusError( status ) )
			return( status );
		name = hostName;
		}

	/* Perform a DNS SRV lookup to find the host info.  SRV has basic load-
	   balancing facilities, but for now we just use the highest-priority
	   host we find (it's rarely-enough used that we'll be lucky to find SRV
	   info, let alone any load-balancing setup) */
	dwRet = DnsQuery( ( const LPSTR ) name, DNS_TYPE_SRV, DNS_QUERY_STANDARD,
					  NULL, &pDns, NULL );
	if( dwRet != 0 || pDns == NULL )
		return( getSocketError( stream, CRYPT_ERROR_NOTFOUND ) );
	for( pDnsCursor = pDns; pDnsCursor != NULL;
		 pDnsCursor = pDnsCursor->pNext )
		if( pDnsCursor->Data.SRV.wPriority < priority )
			{
			priority = pDnsCursor->Data.SRV.wPriority;
			pDnsInfo = pDnsCursor;
			}
	if( pDnsInfo == NULL || \
		strlen( pDnsInfo->Data.SRV.pNameTarget ) > MAX_URL_SIZE - 1 )
		{
		DnsRecordListFree( pDns, DnsFreeRecordList );
		return( setSocketError( stream, "Invalid DNS SRV entry for host",
								CRYPT_ERROR_NOTFOUND, TRUE ) );
		}

	/* Copy over the host info for this SRV record */
	nameLength = strlen( pDnsInfo->Data.SRV.pNameTarget ) + 1;
	memcpy( hostName, pDnsInfo->Data.SRV.pNameTarget, nameLength );
	*hostPort = pDnsInfo->Data.SRV.wPort;

	/* Clean up */
	DnsRecordListFree( pDns, DnsFreeRecordList );
	return( CRYPT_OK );
	}

#elif defined( __UNIX__ )

#define SRV_PRIORITY_OFFSET	( NS_RRFIXEDSZ + 0 )
#define SRV_WEIGHT_OFFSET	( NS_RRFIXEDSZ + 2 )
#define SRV_PORT_OFFSET		( NS_RRFIXEDSZ + 4 )
#define SRV_NAME_OFFSET		( NS_RRFIXEDSZ + 6 )

static int getFQDN( STREAM *stream, char *fqdn )
	{
	struct hostent *hostInfo;
	char *hostNamePtr = NULL;
	int i;

	/* First, get the host name, and if it's the FQDN, exit */
	if( gethostname( fqdn, MAX_DNS_SIZE ) == -1 )
		return( CRYPT_ERROR_NOTFOUND );
	if( strchr( fqdn, '.' ) != NULL )
		/* If the hostname has a dot in it, it's the FQDN */
		return( CRYPT_OK );

	/* Now get the hostent info and walk through it looking for the FQDN */
	if( ( hostInfo = gethostbyname( fqdn ) ) == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	for( i = 0; hostInfo->h_addr_list[ i ] != NULL; i++ )
		{
		char **aliasPtrPtr;

		/* If the hostname has a dot in it, it's the FQDN.  This should be
		   the same as the gethostname() output, but we check again just in
		   case */
		if( strchr( hostInfo->h_name, '.' ) != NULL )
			{
			hostNamePtr = hostInfo->h_name;
			break;
			}

		/* Try for the FQDN in the aliases */
		if( hostInfo->h_aliases == NULL )
			continue;
		for( aliasPtrPtr = hostInfo->h_aliases;
			 *aliasPtrPtr != NULL && !strchr( *aliasPtrPtr, '.' );
			 aliasPtrPtr++ );
		if( *aliasPtrPtr != NULL )
			{
			hostNamePtr = *aliasPtrPtr;
			break;
			}
		}
	if( hostNamePtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* We found the FQDN, return it to the caller */
	strcpy( fqdn, hostNamePtr );
	return( CRYPT_OK );
	}

static int findHostInfo( STREAM *stream, char *hostName, int *hostPort,
						 const char *name )
	{
	union {
		HEADER header;
		BYTE buffer[ NS_PACKETSZ ];
		} dnsQueryInfo;
	char *namePtr, *endPtr;
	int resultLen, nameLen, qCount, aCount, minPriority = 32767, i;

	/* If we're doing a full autodetect, we construct the SRV query using
	   the local machine's FQDN.  This fails more often than not because of
	   NATing and use of private networks, but at least we can try */
	if( !strCompareZ( name, "[Autodetect]" ) )
		{
		const int status = getFQDN( stream, hostName );
		if( cryptStatusError( status ) )
			return( status );
		name = hostName;
		}
#ifdef EBCDIC_CHARS
	else
		/* We're about to use OS functions, convert the input to EBCDIC.  If
		   we've used autodetection, the output from getFQDN will already be
		   in EBCDIC form */
		name = bufferToEbcdic( hostName, name );
#endif /* EBCDIC_CHARS */

	/* Try and fetch a DNS SRV record (RFC 2782) matching the host info */
	resultLen = res_query( name, C_IN, T_SRV, dnsQueryInfo.buffer,
						   NS_PACKETSZ );
	if( resultLen < NS_HFIXEDSZ || resultLen > NS_PACKETSZ )
		return( getSocketError( stream, CRYPT_ERROR_NOTFOUND ) );
	if( dnsQueryInfo.header.rcode || dnsQueryInfo.header.tc )
		/* If we get a non-zero response code (rcode) or the results were
		   truncated (tc), we can't go any further.  In theory a truncated
		   response is probably OK since many servers return the address
		   records for the host in the Additional Data section to save the
		   client having to perform a second lookup and we don't need these
		   at this point so we can ignore the fact that they've been
		   truncated, but for now we treat truncation as an error */
		return( setSocketError( stream, "RR contains non-zero response "
								"code or response was truncated",
								CRYPT_ERROR_NOTFOUND, FALSE ) );
	qCount = ntohs( dnsQueryInfo.header.qdcount );
	aCount = ntohs( dnsQueryInfo.header.ancount );
	if( qCount < 0 || aCount <= 0 )
		/* No answer entries, we're done */
        return( setSocketError( stream, "RR contains no answer entries",
								CRYPT_ERROR_NOTFOUND, FALSE ) );

	/* Skip the queries */
	namePtr = dnsQueryInfo.buffer + NS_HFIXEDSZ;
	endPtr = dnsQueryInfo.buffer + resultLen;
	for( i = 0; i < qCount; i++ )
		{
		nameLen = dn_skipname( namePtr, endPtr );
		if( nameLen <= 0 )
	        return( setSocketError( stream, "RR contains invalid question",
		                            CRYPT_ERROR_BADDATA, FALSE ) );
		namePtr += nameLen + NS_QFIXEDSZ;
		}

	/* Process the answers.  SRV has basic load-balancing facilities, but
	   for now we just use the highest-priority host we find (it's rarely-
	   enough used that we'll be lucky to find SRV info, let alone any load-
	   balancing setup) */
	for( i = 0; i < aCount; i++ )
		{
		int priority, port;

		nameLen = dn_skipname( namePtr, endPtr );
		if( nameLen <= 0 )
	        return( setSocketError( stream, "RR contains invalid answer",
	                                CRYPT_ERROR_BADDATA, FALSE ) );
		namePtr += nameLen;
		priority = ntohs( *( ( u_short * ) ( namePtr + SRV_PRIORITY_OFFSET ) ) );
		port = ntohs( *( ( u_short * ) ( namePtr + SRV_PORT_OFFSET ) ) );
		namePtr += NS_SRVFIXEDSZ;
		if( priority < minPriority )
			{
			/* We've got a new higher-priority host, use that */
			nameLen = dn_expand( dnsQueryInfo.buffer, endPtr,
								 namePtr, hostName, MAX_URL_SIZE - 1 );
			*hostPort = port;
			minPriority = priority;
			}
		else
			/* It's a lower-priority host, skip it */
			nameLen = dn_skipname( namePtr, endPtr );
		if( nameLen <= 0 )
	        return( setSocketError( stream, "RR contains invalid answer",
	                                CRYPT_ERROR_NOTFOUND, FALSE ) );
		hostName[ nameLen ] = '\0';
		namePtr += nameLen;
		}
#ifdef EBCDIC_CHARS
	ebcdicToAscii( hostName, strlen( hostName ) );
#endif /* EBCDIC_CHARS */

	return( CRYPT_OK );
	}

#else

/* If there's no DNS support available in the OS, there's not much that we
   can do to handle automatic host detection */

#define findHostInfo( stream, nameBuffer, localPort, name )	CRYPT_ERROR_NOTFOUND

#endif /* OS-specific host detection */

/* Get a host's IP address */

static int getAddressInfo( STREAM *stream, struct addrinfo **addrInfoPtrPtr,
						   const char *name, const int port,
						   const BOOLEAN isServer )
	{
	struct addrinfo hints;
	char nameBuffer[ MAX_URL_SIZE ], portBuffer[ 16 ];
	int localPort = port;

	assert( isServer || name != NULL );

	/* If we're a client and using auto-detection of a PKI service, try and
	   locate it via DNS SRV */
	if( !isServer && \
		( !strCompareZ( name, "[Autodetect]" ) || *name == '_' ) )
		{
		int status;

		status = findHostInfo( stream, nameBuffer, &localPort, name );
		if( cryptStatusError( status ) )
			return( status );
		name = nameBuffer;
		}

#ifdef EBCDIC_CHARS
	if( name != NULL )
		name = bufferToEbcdic( nameBuffer, name );
#endif /* EBCDIC_CHARS */

	/* Set up the port information and hint information needed by
	   getaddrinfo().  The use of PF_UNSPEC is a bit problematic because RFC
	   2553 is usually interpreted to mean "look for all addresses" rather
	   than the more sensible of "look for any address".  The reason why
	   this is a problem is because getaddrinfo() ends up looking for
	   unnecessary IPv6 addresses, either by returning IPv6 addresses when
	   the system doesn't do IPv6 or spending a lot of time groping around
	   for IPv6 stuff and/or further unnecessary addresses when it's already
	   got what it needs.  This is made worse by confusion over
	   implementation details, for example early implementations of
	   getaddrinfo() in glibc would always try an AAAA lookup even on an
	   IPv4-only system/network, resulting in long delays as the resolver
	   timed out and fell back to a straight A lookup.  There was some
	   disagreement over whether this was right or wrong, and how to fix it
	   (IPv6 purists who never noticed the problem seemed to think it was
	   right, everyone else thought it was wrong).  Variations of this
	   problem exist, e.g. if an IPv4 address is in /etc/hosts and DNS is
	   down, the resolver will still spend ages (several minutes in some
	   cases) groping around for an IPv6 address before it finally gives up
	   and falls back to what it already knows from /etc/hosts.  Switching
	   the hint from AF_UNSPEC to AF_INET bypasses this problem, but has the
	   downside of disabling IPv6 use.

	   This problem was partially fixed post-RFC 2553 by adding the
	   AI_ADDRCONFIG flag, which tells getaddrinfo() to only do AAAA queries
	   if the system has at least one IPv6 source address configured, and
	   the same for A and IPv4 (in other words it applies some common sense,
	   which is how it should have behaved in the first place).
	   Unfortunately this flag isn't very widely supported yet, so it usually
	   ends up being no-op'd out at the start of this file */
	sPrintf( portBuffer, "%d", port );
	memset( &hints, 0, sizeof( struct addrinfo ) );
	if( isServer )
		/* If it's a server, set the AI_PASSIVE flag so that if the
		   interface we're binding to isn't explicitly specified we get
		   any interface */
		hints.ai_flags = AI_PASSIVE;
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if( getaddrinfo( name, portBuffer, &hints, addrInfoPtrPtr ) )
		return( getHostError( stream, CRYPT_ERROR_OPEN ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Network Socket Manager							*
*																			*
****************************************************************************/

/* cryptlib's separation kernel causes some problems with objects that use
   sockets, both because it doesn't allow sharing of sockets (which is a
   problem because the Unix server programming model assumes that a single
   process will listen on a socket and fork off children to handle incoming
   connections (in fact the accept() function more or less forces you to do
   this whether you want to or not) and because when a thread is blocked in
   an object waiting on a socket there's no way to unblock it apart from
   killing the thread (actually we could create some sort of lookback socket
   and wait for it alongside the listen socket in the pre-accept select wait,
   signalling a shutdown by closing the loopback socket, but this starts to
   get ugly).  In order to work around this we maintain a socket pool that
   serves two functions:

	- Maintains a list of sockets that an object is listening on to allow a
	  listening socket to be reused rather than having to listen on a
	  socket and close it as soon as an incoming connection is made in
	  order to switch to the connected socket.

	- Allows sockets to be closed from another thread, which results in any
	  objects waiting on them being woken up and exiting.

   For now we limit the socket pool to a maximum of 256 sockets both as a
   safety feature to protect against runaway apps and because cryptlib was
   never designed to function as a high-volume server application.  If
   necessary this can be changed to dynamically expand the pool size in the
   same way that the kernel dynamically expands its object table */

#define SOCKETPOOL_SIZE		256

typedef struct {
	SOCKET netSocket;		/* Socket handle */
	int refCount;			/* Reference count for the socket */
	int iChecksum;			/* Family, interface, and port */
	BYTE iData[ 32 ];		/*	info for server socket */
	int iDataLen;
	} SOCKET_INFO;

static SOCKET_INFO *socketInfo;
static const SOCKET_INFO SOCKET_INFO_TEMPLATE = \
				{ INVALID_SOCKET, 0, 0, { 0 }, 0 };

/* Initialise and shut down the socket pool */

static int initSocketPool( void )
	{
	int i;

	/* Allocate and clear the socket pool */
	if( ( socketInfo = \
			clAlloc( "initSocketPool", SOCKETPOOL_SIZE * \
									   sizeof( SOCKET_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		socketInfo[ i ] = SOCKET_INFO_TEMPLATE;

	return( CRYPT_OK );
	}

static void endSocketPool( void )
	{
	clFree( "endSocketPool", socketInfo );
	}

/* Create/add and and remove a socket to/from the pool.  The difference
   between creating and adding a socket is that newSocket() creates and
   adds a completely new socket while addSocket() adds an externally-
   created (via accept()) socket */

static int newSocket( SOCKET *newSocketPtr, struct addrinfo *addrInfoPtr,
					  const BOOLEAN isServer )
	{
	SOCKET netSocket;
	int i;

	/* Clear return value */
	*newSocketPtr = INVALID_SOCKET;

	enterMutex( MUTEX_SOCKETPOOL );

	/* If this is a server socket (i.e. one bound to a specific interface and
	   port), check to see whether there's already a socket bound here and if
	   there is, return the existing socket rather than creating a new one.
	   This check isn't currently totally foolproof since it compares some
	   nonessential fields that may differ for otherwise identical sockets
	   (it's difficult to do this in a clean manner because the comparison
	   becomes very protocol- and implementation- specific).  A workaround
	   would be to check whether the sin_family is AF_INET or AF_INET6 and
	   perform an appropriate situation-specific comparison, but this will
	   break the nice portability that was added by the reorganisation of
	   socket functions for IPv6 */
	if( isServer )
		{
		const int iCheck = checksumData( addrInfoPtr->ai_addr,
										 addrInfoPtr->ai_addrlen );

		for( i = 0; i < SOCKETPOOL_SIZE; i++ )
			if( socketInfo[ i ].iChecksum == iCheck && \
				socketInfo[ i ].iDataLen == addrInfoPtr->ai_addrlen && \
				!memcmp( socketInfo[ i ].iData, addrInfoPtr->ai_addr,
						 addrInfoPtr->ai_addrlen ) )
				{
				socketInfo[ i ].refCount++;
				*newSocketPtr = socketInfo[ i ].netSocket;
				exitMutex( MUTEX_SOCKETPOOL );

				/* The socket already exists, don't perform any further
				   initialisation with it */
				return( CRYPT_OK );
				}
		}

	/* Create a new socket entry */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket == INVALID_SOCKET )
			break;
	if( i == SOCKETPOOL_SIZE )
		{
		exitMutex( MUTEX_SOCKETPOOL );
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );	/* Should never happen */
		}
	if( isBadSocket( netSocket = socket( addrInfoPtr->ai_family,
										 addrInfoPtr->ai_socktype, 0 ) ) )
		{
		exitMutex( MUTEX_SOCKETPOOL );
		return( CRYPT_ERROR_OPEN );
		}
	socketInfo[ i ].netSocket = netSocket;
	if( isServer )
		{
		/* Remember the details for this socket so that we can detect another
		   attempt to bind to it */
		assert( addrInfoPtr->ai_addrlen <= 32 );
		socketInfo[ i ].iChecksum = checksumData( addrInfoPtr->ai_addr,
												  addrInfoPtr->ai_addrlen );
		memcpy( socketInfo[ i ].iData, addrInfoPtr->ai_addr,
				addrInfoPtr->ai_addrlen );
		socketInfo[ i ].iDataLen = addrInfoPtr->ai_addrlen;
		}
	socketInfo[ i ].refCount = 0;
	*newSocketPtr = netSocket;

	/* If we're creating a new server socket we can't unlock the socket info
	   yet because we need to bind it to a port before we do anything else
	   with it.  If we were to unlock the socket info, another thread could
	   perform an accept() on the incompletely set up socket, so we return
	   with the socket info still locked.  When the caller has finished
	   setting it up, they'll call newSocketDone() to signal that the socket
	   is ready for use */
	if( isServer )
		return( OK_SPECIAL );

	exitMutex( MUTEX_SOCKETPOOL );

	return( CRYPT_OK );
	}

static void newSocketDone( void )
	{
	/* The caller has finished setting up a new server socket, unlock the
	   socket info to allow others to access it */
	exitMutex( MUTEX_SOCKETPOOL );
	}

static int addSocket( const SOCKET netSocket )
	{
	int i;

	enterMutex( MUTEX_SOCKETPOOL );

	/* Add an existing socket entry */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket == INVALID_SOCKET )
			break;
	if( i == SOCKETPOOL_SIZE )
		{
		exitMutex( MUTEX_SOCKETPOOL );
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );	/* Should never happen */
		}
	socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
	socketInfo[ i ].netSocket = netSocket;

	exitMutex( MUTEX_SOCKETPOOL );

	return( CRYPT_OK );
	}

static void deleteSocket( const SOCKET netSocket )
	{
	int i;

	enterMutex( MUTEX_SOCKETPOOL );

	/* Find the entry for this socket in the pool.  There may not be one
	   present if the pool has received a shutdown signal and closed all
	   network sockets, so if we don't find it we exit normally */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket == netSocket )
			break;
	if( i == SOCKETPOOL_SIZE )
		{
		exitMutex( MUTEX_SOCKETPOOL );
		return;
		}

	/* Decrement the socket's reference count */
	socketInfo[ i ].refCount--;
	if( socketInfo[ i ].refCount < 0 )
		{
		/* If the reference count has reached zero, close the socket
		   and delete the pool entry */
		closesocket( socketInfo[ i ].netSocket );
		socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
		}

	exitMutex( MUTEX_SOCKETPOOL );
	}

/* Force all objects waiting on sockets to exit by closing their sockets.
   This is the only way to cause them to terminate, since an object waiting
   on a socket is marked as busy by the cryptlib kernel (and in fact will be
   blocked inside the OS out of reach of even the cryptlib kernel).
   Alternatively, the user can provide their own socket externally and close
   it from the outside, which will unblock the thread waiting on it.

   A somewhat less drastic alternative to closing the socket is to use
   shutdown(), but the behaviour of this is somewhat imlementation-specific.
   For example under Slowaris 5.x trying to shutdown a listening socket (to
   unlock a thread blocking in accept()) returns ENOTCONN, so the shutdown
   requires setting up a dummy connection to the socket to be shut down
   before it can actually be shut down.  Trying to shut down a thread blocked
   in connect() is more or less impossible under Slowaris 5.x.  Other systems
   are more flexible, but there's not enough consistency to rely on this */

void netSignalShutdown( void )
	{
	int i;

	enterMutex( MUTEX_SOCKETPOOL );

	/* For each open socket, close it and set its reference count to zero */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket != INVALID_SOCKET )
			{
			closesocket( socketInfo[ i ].netSocket );
			socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
			}

	exitMutex( MUTEX_SOCKETPOOL );
	}

/****************************************************************************
*																			*
*							Network Socket Interface						*
*																			*
****************************************************************************/

/* Open and close a connection to a remote server.  This function performs
   that most amazing of all things, the nonblocking connect.  This is
   currently done in order to allow a shorter timeout than the default
   fortnight or so but it also allows for two-phase connects in which we
   start the connect operation, perform further processing (e.g. signing and
   encrypting data prior to sending it over the connected socket) and then
   complete the connect before the first read or write.  Currently we just
   use a wrapper that performs the two back-to-back as a single operation,
   so it only functions as a timeout-management mechanism */

static int preOpenSocket( STREAM *stream, const char *server,
						  const int serverPort )
	{
	SOCKET netSocket;
	struct addrinfo *addrInfoPtr, *addrInfoCursor;
	BOOLEAN nonBlockWarning = FALSE;
	int port = serverPort, socketStatus, status;

	/* Clear return value */
	stream->netSocket = CRYPT_ERROR;

	/* Set up addressing information */
	status = getAddressInfo( stream, &addrInfoPtr, server, port, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Create a socket, make it nonblocking, and start the connect to the
	   remote server, falling back through alternative addresses if the
	   connect fails.  Since this is a nonblocking connect it could still
	   fail during the second phase where we can no longer try to recover
	   by falling back to an alternative address, but it's better than just
	   giving up after the first address we try */
	for( addrInfoCursor = addrInfoPtr; addrInfoCursor != NULL;
		 addrInfoCursor = addrInfoCursor->ai_next )
		{
		status = newSocket( &netSocket, addrInfoCursor, FALSE );
		if( cryptStatusError( status ) )
			{
			/* We need to get the socket error code now because further
			   calls to functions such as freeaddrinfo() will overwrite
			   the global error value before we can read it later on */
			socketStatus = getErrorCode();
			continue;
			}
		setSocketNonblocking( netSocket );
		status = connect( netSocket, addrInfoCursor->ai_addr,
						  addrInfoCursor->ai_addrlen );
		nonBlockWarning = isNonblockWarning();
		if( status >= 0 || nonBlockWarning )
			/* We've got a successfully-started connect, exit */
			break;
		socketStatus = getErrorCode();	/* Remember socket error code */
		deleteSocket( netSocket );
		}
	freeaddrinfo( addrInfoPtr );
	if( status < 0 && !nonBlockWarning )
		{
		/* There was an error condition other than a notification that the
		   operation hasn't completed yet */
		status = mapError( stream, socketErrorInfo, socketStatus,
						   CRYPT_ERROR_OPEN );
		deleteSocket( netSocket );
		return( status );
		}
	if( status == 0 )
		{
		/* If we're connecting to a local host, the connect can complete
		   immediately rather than returning an in-progress status, in
		   which case we don't need to do anything else */
		stream->netSocket = netSocket;
		return( CRYPT_OK );
		}

	/* The connect is in progress, mark the stream as not-quite-ready */
/*	stream->xxx = yyy; */
	stream->netSocket = netSocket;

	return( CRYPT_OK );
	}

static int completeOpen( STREAM *stream )
	{
	struct timeval tv;
	fd_set readfds, writefds;
	static const int trueValue = 1;
	SIZE_TYPE intLength = sizeof( int );
	int value, status;

	/* Wait around until the connect completes.  Some select()'s limit the
	   size of the second count, so we set it to a maximum of 1 year's worth.
	   BeOS doesn't allow setting a timeout (that is, it doesn't allow
	   asynchronous connects), but it hardcodes in a timeout of about a
	   minute so we get a vaguely similar effect */
	FD_ZERO( &readfds );
	FD_ZERO( &writefds );
	FD_SET( stream->netSocket, &readfds );
	FD_SET( stream->netSocket, &writefds );
	tv.tv_sec = min( stream->timeout, 30000000L );
	tv.tv_usec = 0;
	status = select( stream->netSocket + 1, &readfds, &writefds, NULL, &tv );
	if( status == 0 || \
		!( FD_ISSET( stream->netSocket, &readfds ) || \
		   FD_ISSET( stream->netSocket, &writefds ) ) )
		{
		/* We timed out on the connect (status == 0) or we encountered an
		   error condition (the socket is neither readable nor writeable),
		   exit */
		status = getSocketError( stream, CRYPT_ERROR_OPEN );
		if( stream->errorCode == 0 )
			{
			/* Some implementations don't treat a soft timeout as an error
			   so we insert a timeout error code ourselves */
			stream->errorCode = TIMEOUT_ERROR;
			mapError( stream, socketErrorInfo, stream->errorCode,
					  CRYPT_UNUSED );
			}
		stream->transportDisconnectFunction( stream, TRUE );
		return( status );
		}

	/* The socket is readable or writeable, however this may be because of
	   an error (it's readable and writeable) or because everything's OK
	   (it's writeable) or because everything's OK and there's data waiting
	   (it's readable and writeable), so we have to see what the error
	   condition is for the socket to determine what's really happening.

	   This is a somewhat tricky area, other possibilities are calling recv()
	   with a length of zero bytes (returns an error if the connect failed),
	   calling connect() again (fails with EISCONN if the connect succeeded),
	   and calling getmsg( netSocket, NULL, NULL, &( flags = 0 ) ) (fails
	   with errno == EAGAIN or EWOULDBLOCK if the only error is that there's
	   nothing available yet) */
	status = getsockopt( stream->netSocket, SOL_SOCKET, SO_ERROR,
						 ( void * ) &value, &intLength );
	if( status == 0 )
		{
		/* Berkeley-derived implementation, error is in value variable */
		if( value != 0 )
			{
			status = mapError( stream, socketErrorInfo, value,
							   CRYPT_ERROR_OPEN );
			stream->transportDisconnectFunction( stream, TRUE );
			return( status );
			}
		}
	else
		/* Slowaris, error is in errno */
		if( isSocketError( status ) )
			{
			status = getSocketError( stream, CRYPT_ERROR_OPEN );
			stream->transportDisconnectFunction( stream, TRUE );
			return( status );
			}

	/* Turn off Nagle (since we do our own optimised TCP handling) and make
	   the socket blocking again.  This is necessary because with a
	   nonblocking socket Winsock will occasionally return 0 bytes from
	   recv() (a sign that the receiver has closed the connection) even
	   though the connection is still fully open, and in any case there's
	   no real need for a nonblocking socket since we have select() handling
	   timeouts/blocking for us */
	setsockopt( stream->netSocket, IPPROTO_TCP, TCP_NODELAY,
				( void * ) &trueValue, sizeof( int ) );
	setSocketBlocking( stream->netSocket );

	/* We've completed the connection, mark the stream as ready for use */
/*	stream->xxx = zzz; */
	return( CRYPT_OK );
	}

static int openServerSocket( STREAM *stream, const char *server, const int port )
	{
	SOCKET listenSocket, netSocket;
	SOCKADDR_STORAGE clientAddr;
	struct addrinfo *addrInfoPtr, *addrInfoCursor;
	char portBuf[ 32 ];
	static const int trueValue = 1;
	SIZE_TYPE clientAddrLen = sizeof( SOCKADDR_STORAGE );
	int socketStatus, status;

	/* Clear return value */
	stream->netSocket = CRYPT_ERROR;

	/* Set up addressing information.  If we're not binding to a specified
	   interface, we allow connections on any interface.  Note that, in
	   combination with SO_REUSEADDR and older, unpatched kernels, this
	   allows port hijacking by another process running on the same machine
	   that binds to the port with a more specific binding than "any" */
	status = getAddressInfo( stream, &addrInfoPtr, server, port, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Create a new server socket, falling back through alternative
	   interfaces if the initial socket creation fails.  This may seem less
	   necessary than for the client-side connect, but is in fact required
	   because getaddrinfo() usually preferentially provides an IPv6
	   interface even if there's no IPv6 configured for the system (see the
	   long comment in getAddressInfo() for more on this), so we have to
	   step through until we get to an IPv4 interface, or at least one that
	   we can listen on */
	for( addrInfoCursor = addrInfoPtr; addrInfoCursor != NULL;
		 addrInfoCursor = addrInfoCursor->ai_next )
		{
		status = newSocket( &listenSocket, addrInfoCursor, TRUE );
		if( status == CRYPT_OK )
			/* It's a second thread listening on an existing socket,
			   we're done */
			break;
		if( status != OK_SPECIAL )
			{
			/* There was a problem creating the socket, try again with
			   another interface.  We need to get the socket error code now
			   because further calls to functions such as freeaddrinfo()
			   will overwrite the global error value before we can read it
			   later on */
			socketStatus = getErrorCode();
			continue;
			}
		status = CRYPT_OK;

		/* This is a new socket, set SO_REUSEADDR to avoid TIME_WAIT
		   problems, and prepare to accept connections (nemo surdior est
		   quam is qui non audiet).  Note that BeOS can only bind to one
		   interface at a time, so if we're binding to INADDR_ANY under
		   BeOS we actually bind to the first interface we find */
		if( setsockopt( listenSocket, SOL_SOCKET, SO_REUSEADDR,
						( char * ) &trueValue, sizeof( int ) ) || \
			bind( listenSocket, addrInfoCursor->ai_addr,
				  addrInfoCursor->ai_addrlen ) || \
			listen( listenSocket, 5 ) )
			{
			socketStatus = getErrorCode();	/* Remember socket error code */
			deleteSocket( listenSocket );
			newSocketDone();
			continue;
			}

		/* We've finished initialising the socket, tell the socket pool
		   manager that it's safe to let others access the pool */
		newSocketDone();
		break;
		}
	freeaddrinfo( addrInfoPtr );
	if( cryptStatusError( status ) )
		/* There was an error setting up the socket, don't try anything
		   further */
		return( mapError( stream, socketErrorInfo, socketStatus,
						  CRYPT_ERROR_OPEN ) );

	/* Wait for a connection.  At the moment this always waits forever
	   (actually some select()'s limit the size of the second count, so we
	   set it to a maximum of 1 year's worth), but in the future we could
	   have a separate timeout value for accepting incoming connections
	   to mirror the connection-wait timeout for outgoing connections */
	do
		{
		struct timeval tv;
		fd_set readfds;

		FD_ZERO( &readfds );
		FD_SET( listenSocket, &readfds );
		tv.tv_sec = min( stream->timeout, 30000000L );
		tv.tv_usec = 0;
		status = select( listenSocket + 1, &readfds, NULL, NULL, &tv );
		if( status == 0 )
			/* The select() timed out, exit */
			return( setSocketError( stream, "Timeout on accept (select())",
									CRYPT_ERROR_TIMEOUT, FALSE ) );
		}
	while( isSocketError( status ) && isRestartableError() );
	if( isSocketError( status ) )
		return( getSocketError( stream, CRYPT_ERROR_OPEN ) );

	/* We have an incoming connection ready to go, accept it.  This should
	   always succeed because the select() has told us so, but we check it
	   just in case */
	netSocket = accept( listenSocket, ( struct sockaddr * ) &clientAddr,
						&clientAddrLen );
	if( isBadSocket( netSocket ) )
		{
		status = getSocketError( stream, CRYPT_ERROR_OPEN );
		deleteSocket( listenSocket );
		return( status );
		}

	/* Get the IP address of the connected client.  We could gets its full
	   name, but this can slow down connections because of the time it takes
	   to do the lookup and is less authoritative because of potential
	   spoofing.  In any case the caller can still look up the name if they
	   need it.

	   Some Windows implementations of getnameinfo() call down to
	   getservbyport() assuming that it will always succeed and therefore
	   leave the port/service arg unchanged when it doesn't, so the following
	   call must be made with the NI_NUMERICSERV flag specified (which it
	   would be anyway, cryptlib always treats the port as a numeric arg).
	   Oddly enough the macro version of this function in wspiapi.h used for
	   IPv4-only situations does get it correct */
	if( getnameinfo( ( const struct sockaddr * ) &clientAddr,
					 sizeof( struct sockaddr ), stream->clientAddress,
					 sizeof( stream->clientAddress ), portBuf, 32,
					 NI_NUMERICHOST | NI_NUMERICSERV ) == 0 )
		{
#ifdef EBCDIC_CHARS
		ebcdicToAscii( stream->clientAddress, strlen( stream->clientAddress ) );
		ebcdicToAscii( portBuf, strlen( portBuf ) );
#endif /* EBCDIC_CHARS */
		stream->clientPort = aToI( portBuf );
		}
	else
		{
		strcpy( stream->clientAddress, "<Unknown>" );
		stream->clientPort = 0;
		}

	/* We've got a new connection, add the socket to the pool.  Since this
	   was created externally to the pool, we don't use newSocket() to
	   create a new socket but only add the existing socket */
	status = addSocket( netSocket );
	if( cryptStatusError( status ) )
		{
		/* There was a problem adding the new socket, close it and exit.
		   We don't call deleteSocket() since it wasn't added to the pool,
		   instead we call closesocket() directly */
		closesocket( netSocket );
		return( setSocketError( stream, "Couldn't add socket to socket pool",
								status, FALSE ) );
		}
	stream->netSocket = netSocket;
	stream->listenSocket = listenSocket;

	/* Turn off Nagle, since we do our own optimised TCP handling */
	setsockopt( stream->netSocket, IPPROTO_TCP, TCP_NODELAY,
				( void * ) &trueValue, sizeof( int ) );

	return( CRYPT_OK );
	}

static int openSocketFunction( STREAM *stream, const char *server,
							   const int port )
	{
	int status;

	assert( port >= 22 );
	assert( ( stream->flags & STREAM_NFLAG_ISSERVER ) || server != NULL );

	/* If it's a server stream, open a listening socket */
	if( stream->flags & STREAM_NFLAG_ISSERVER )
		return( openServerSocket( stream, server, port ) );

	/* It's a client stream, perform a two-part nonblocking open.  Currently
	   the two portions are performed synchronously, in the future we can
	   interleave the two and perform general crypto processing (e.g. hash/
	   MAC context setup for SSL) while the open is completing */
	status = preOpenSocket( stream, server, port );
	if( cryptStatusOK( status ) )
		status = completeOpen( stream );
	assert( ( cryptStatusError( status ) && \
			  stream->netSocket == CRYPT_ERROR ) || \
			( cryptStatusOK( status ) && \
			  stream->netSocket != CRYPT_ERROR ) );
	return( status );
	}

static void closeSocketFunction( STREAM *stream,
								 const BOOLEAN fullDisconnect )
	{
	/* If it's a partial disconnect, close only the send side of the
	   channel */
	if( !fullDisconnect )
		{
		if( stream->netSocket != CRYPT_ERROR )
			shutdown( stream->netSocket, SHUT_WR );
		return;
		}

	/* If it's an open-on-demand HTTP stream then the socket isn't
	   necessarily open even if the stream was successfully connected, so
	   we only close it if necessary.  It's easier handling it at this level
	   than expecting the caller to distinguish between an opened-stream-but-
	   not-opened-socket and a conventional open stream */
	if( stream->netSocket != CRYPT_ERROR )
		deleteSocket( stream->netSocket );
	if( stream->listenSocket != CRYPT_ERROR )
		deleteSocket( stream->listenSocket );
	stream->netSocket = CRYPT_ERROR;
	}

/* Check an externally-supplied socket to make sure that it's set up as
   required by cryptlib */

static int checkSocketFunction( STREAM *stream )
	{
	int value;

	/* Check that we've been passed a valid network socket, and that it's
	   blocking */
	getSocketNonblockingStatus( stream->netSocket, value );
	if( isSocketError( value ) )
		return( getSocketError( stream, CRYPT_ARGERROR_NUM1 ) );
	if( value )
		return( setSocketError( stream, "Socket is non-blocking",
								CRYPT_ARGERROR_NUM1, TRUE ) );

	return( CRYPT_OK );
	}

/* Read and write data from and to a socket.  Because data can appear in
   bits and pieces when reading we have to implement timeout handling at two
   levels, once via select() and a second time as an overall timeout.  If we
   only used select() this could potentially stretch the overall timeout to
   (length * timeout) so we also perform a time check that leads to a worst-
   case timeout of (timeout-1 + timeout).

   In addition to the standard stream-based timeout, we can also be called
   with flags specifying explicit blocking behaviour (for a read where we
   know we're expecting a certain amount of data) or explicit nonblocking
   behaviour (for speculative reads to fill a buffer).  These flags are used
   by the buffered-read routines, which try and speculatively read as much
   data as possible to avoid the many small reads required by some
   protocols.

   Finally, if we're performing a blocking read (which is usually done when
   we're expecting a predetermined number of bytes), we dynamically adjust
   the timeout so that if data is streaming in at a steady rate, we don't
   abort the read just because there's more data to transfer than we can
   manage in the originally specified timeout interval */

static int readSocketFunction( STREAM *stream, BYTE *buffer,
							   const int length, const int flags )
	{
	const time_t startTime = getTime();
	BYTE *bufPtr = buffer;
	time_t timeout = ( flags & TRANSPORT_FLAG_NONBLOCKING ) ? 0 : \
					 ( flags & TRANSPORT_FLAG_BLOCKING ) ? \
						max( 30, stream->timeout ) : stream->timeout;
	int bytesToRead = length, byteCount = 0;

	assert( timeout >= 0 );
	while( bytesToRead > 0 && \
		   ( ( getTime() - startTime < timeout || timeout <= 0 ) ) )
		{
		struct timeval tv;
		fd_set readfds, exceptfds;
		int bytesRead, status;

		/* Set up the information needed to handle timeouts.  If there's no
		   timeout, we wait at least 1ms on the theory that it isn't
		   noticeable to the caller but ensures we at least get a chance to
		   get anything that may be pending.  The exact wait time depends
		   on the system, but usually it's quantised to the system timer
		   quantum.  This means that on Unix systems with a 1ms timer
		   resolution, the wait time is quantised on a 1ms boundary.  Under
		   Windows NT/2000/XP, it's quantised on a 10ms boundary (some
		   early NT systems had a granularity ranging from 7.5 - 15ms, but
		   all newer systems use 10ms) and for Win95/98/ME it's quantised
		   on a 55ms boundary.  In other words when performing a select()
		   on a Win95 box it'll either return immediately or wait some
		   multiple of 55ms, even with the time set to 1ms.

		   In theory we shouldn't have to reset either the fds or the
		   timeval each time through the loop since we're only waiting on
		   one descriptor so it's always set and the timeval is a const,
		   however some versions of Linux can update it if the select fails
		   due to an EINTR and/or if a file descriptor changes status (e.g.
		   due to data becoming available) so we reset it each time just to
		   be on the safe side */
		FD_ZERO( &readfds );
		FD_ZERO( &exceptfds );
		FD_SET( stream->netSocket, &readfds );
		FD_SET( stream->netSocket, &exceptfds );
		tv.tv_sec = timeout;
		tv.tv_usec = !timeout ? 1000 : 0;

		/* See if there's anything available */
		status = select( stream->netSocket + 1, &readfds, NULL, &exceptfds,
						 &tv );
		if( isSocketError( status ) )
			return( getSocketError( stream, CRYPT_ERROR_READ ) );
		if( FD_ISSET( stream->netSocket, &exceptfds ) )
			/* If there's an exception condition on a socket, exit.  This is
			   implementation-specific, traditionally under Unix this only
			   indicates the arrival of out-of-band data rather than any real
			   error condition, but in some cases it can be used to signal
			   errors.  In these cases we have to explicitly check for an
			   exception condition because some types of errors will result in
			   select() timing out waiting for readability, rather than
			   indicating an error */
			return( getSocketError( stream, CRYPT_ERROR_READ ) );
		if( status == 0 )
			{
			/* If it's a nonblocking read then the unavailability of data
			   isn't an error.  We may also already have received data from
			   a previous iteration of the loop */
			if( timeout <= 0 || byteCount > 0 )
				return( byteCount );

			/* The select() timed out, exit */
			return( setSocketError( stream, "Timeout on blocking read "
									"(select())", CRYPT_ERROR_TIMEOUT,
									FALSE ) );
			}
		assert( FD_ISSET( stream->netSocket, &readfds ) );

		/* We've got data waiting, read it */
		bytesRead = recv( stream->netSocket, bufPtr, bytesToRead, 0 );
		if( isSocketError( bytesRead ) )
			{
			/* If it's a restartable read (due to something like an
			   interrupted system call), retry the read */
			if( isRestartableError() )
				{
				assert( !"Restartable read, recv() indicated error" );
				continue;
				}

			/* There was a problem with the read */
			return( getSocketError( stream, CRYPT_ERROR_READ ) );
			}
		if( bytesRead == 0 )
			{
			/* Under some odd circumstances (typically implementation bugs),
			   recv() can return zero bytes without an EOF condition being
			   present, even though it should return an error status if this
			   happens (this could also happen under very old SysV
			   implementations using O_NDELAY for nonblocking I/O).  To
			   catch this, we check for a restartable read due to something
			   like an interrupted system call and retry the read if it is */
			if( isRestartableError() )
				{
				assert( !"Restartable read, recv() indicated no error" );
				continue;
				}

			/* "It said its piece, and then it sodded off" - Baldrick,
			   Blackadder's Christmas Carol */
			bytesToRead = 0;
			break;
			}
		bufPtr += bytesRead;
		bytesToRead -= bytesRead;
		byteCount += bytesRead;

		/* If this is a blocking read and we've been moving data at a
		   reasonable rate (~1K/s) and we're about to time out, adjust the
		   timeout to give us a bit more time.  This is an adaptive process
		   that grants us more time for the read if data is flowing at
		   a reasonable rate, but ensures that we don't hang around forever
		   if data is trickling in at a few bytes a second */
		if( ( flags & TRANSPORT_FLAG_BLOCKING ) && \
			( byteCount / timeout ) >= 1000 && \
			( getTime() - startTime ) > ( timeout - 5 ) )
			timeout += 5;
		}
	if( length > 0 && byteCount <= 0 )
		/* We didn't get anything because the other side closed the
		   connection.  We report this is a read-complete status rather than
		   a read error since it isn't necessarily a real error */
		return( setSocketError( stream, "No data was read because the remote "
								"system closed the connection (recv() == 0)",
								CRYPT_ERROR_COMPLETE, TRUE ) );

	return( byteCount );
	}

static int writeSocketFunction( STREAM *stream, const BYTE *buffer,
								const int length, const int flags )
	{
	int status;

	/* Send data to the remote system.  As with the receive-data code, we
	   have to work around a large number of quirks and socket implementation
	   bugs.  Some very old Winsock stacks (Win3.x and early Win95 era) would
	   almost always indicate that a socket was writeable even when it wasn't.
	   Even older (mid-1980s) Berkeley-derived implementations could return
	   EWOULDBLOCK on a blocking socket if they couldn't get required mbufs,
	   so that even if select() indicated that the socket was writeable, an
	   actual attempt to write would return an error since there were no
	   mbufs available.  Under Win95, select() can fail to block on a non-
	   blocking socket, so that the send() returns EWOULDBLOCK.  One
	   possible reason (related to the mbuf problem) is that another thread
	   may grab memory between the select() and the send() so that there's
	   no buffer space available when send() needs it (although this should
	   return WSAENOBUFS rather than WSAEWOULDBLOCK).  There's also a known
	   bug in Win95 (and possible Win98 as well, Q177346) under which a
	   select() indicates writeability but send() returns EWOULDBLOCK.
	   Another select() after the send() then causes select() to realise the
	   socket is non-writeable.  Finally, in some cases send() can return an
	   error but WSAGetLastError() indicates there's no error, so we treat
	   it as noise and try again */
	do
		{
#if 0	/* This doesn't really do much except make the code more brittle in
		   the presence of select() bugs */
		fd_set writefds, exceptfds;
		struct timeval tv;

		FD_ZERO( &writefds );
		FD_ZERO( &exceptfds );
		FD_SET( stream->netSocket, &writefds );
		FD_SET( stream->netSocket, &exceptfds );
		tv.tv_sec = stream->timeout;
		tv.tv_usec = 0;

		/* Wait for the go-ahead to write.  This isn't really necessary for a
		   blocking socket, but we do it both to handle sockets
		   implementation bugs and to provide a timeout facility in case
		   something goes drastically wrong somewhere */
		status = select( stream->netSocket + 1, NULL, &writefds, &exceptfds,
						 &tv );
		if( isSocketError( status ) )
			return( getSocketError( stream, CRYPT_ERROR_WRITE ) );
		if( FD_ISSET( stream->netSocket, &exceptfds ) )
			/* If there's an error condition on a socket, exit.  We have to
			   explicitly check for this since some types of errors will
			   result in select() timing out waiting for writeability, rather
			   than indicating an error */
			return( getSocketError( stream, CRYPT_ERROR_READ ) );
		if( status == 0 )
			/* The select() timed out, exit */
			return( setSocketError( stream, "Timeout on write (select())",
									CRYPT_ERROR_READ, FALSE ) );
		assert( FD_ISSET( stream->netSocket, &writefds ) );
#endif /* 0 */

		/* Write the data */
		status = send( stream->netSocket, buffer, length, MSG_NOSIGNAL );
		if( isSocketError( status ) )
			{
			/* If it's a restartable write due to something like an
			   interrupted system call (or a sockets bug), retry the
			   write */
			if( isRestartableError() )
				{
				assert( !"Restartable write, send() indicated error" );
				continue;
				}

#ifdef __WINDOWS__
			/* If it's a Winsock bug, treat it as a restartable write */
			if( WSAGetLastError() < WSABASEERR )
				{
				assert( !"send() failed but WSAGetLastError() indicated no "
						"error, ignoring" );
				continue;
				}
#endif /* __WINDOWS__ */

			return( getSocketError( stream, CRYPT_ERROR_WRITE ) );
			}
		if( status < length )
			{
			char message[ 128 ];

			sPrintf( message, "Only sent %d of %d bytes (send() == %d)",
					 status, length, status );
			return( setSocketError( stream, message, CRYPT_ERROR_WRITE,
									TRUE ) );
			}
		}
	while( isSocketError( status ) );

	return( CRYPT_OK );
	}

int setAccessMethodTCP( STREAM *stream )
	{
	/* Set the access method pointers */
	stream->transportConnectFunction = openSocketFunction;
	stream->transportDisconnectFunction = closeSocketFunction;
	stream->transportReadFunction = readSocketFunction;
	stream->transportWriteFunction = writeSocketFunction;
	stream->transportOKFunction = transportOKFunction;
	stream->transportCheckFunction = checkSocketFunction;

	return( CRYPT_OK );
	}
#endif /* USE_TCP */
