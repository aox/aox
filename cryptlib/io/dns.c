/****************************************************************************
*																			*
*						cryptlib DNS Interface Routines						*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
  #include "tcp.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "stream.h"
  #include "tcp.h"
#else
  #include "crypt.h"
  #include "io/stream.h"
  #include "io/tcp.h"
#endif /* Compiler-specific includes */

#ifdef USE_TCP

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   libraries */

#if ( defined( sun ) && OSVERSION > 4 )
#undef htonl	/* Slowaris has defines that conflict with our ones */
#undef htons
#undef ntohl
#undef ntohs
#endif /* Slowaris */

static INSTANCE_HANDLE hDNS;

typedef void ( SOCKET_API *FREEADDRINFO )( struct addrinfo *ai );
typedef int ( SOCKET_API *GETADDRINFO )( const char *nodename,
										 const char *servname,
										 const struct addrinfo *hints,
										 struct addrinfo **res );
typedef struct hostent FAR * ( SOCKET_API *GETHOSTBYNAME )( const char FAR *name );
typedef struct hostent FAR * ( SOCKET_API *GETHOSTNAME )( char FAR * name,
														  int namelen );
typedef int ( SOCKET_API *GETNAMEINFO )( const struct sockaddr *sa,
										 SIZE_TYPE salen, char *node,
										 SIZE_TYPE nodelen, char *service,
										 SIZE_TYPE servicelen, int flags );
typedef u_long ( SOCKET_API *HTONL )( u_long hostlong );
typedef u_short ( SOCKET_API *HTONS )( u_short hostshort );
typedef unsigned long ( SOCKET_API *INET_ADDR )( const char FAR *cp );
typedef char FAR * ( SOCKET_API *INET_NTOA )( struct in_addr in );
typedef u_long ( SOCKET_API *NTOHL )( u_long netlong );
typedef u_short ( SOCKET_API *NTOHS )( u_short netshort );
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
typedef int ( SOCKET_API *WSAGETLASTERROR )( void );

static FREEADDRINFO pfreeaddrinfo = NULL;
static GETADDRINFO pgetaddrinfo = NULL;
static GETHOSTBYNAME pgethostbyname = NULL;
static GETHOSTNAME pgethostname = NULL;
static GETNAMEINFO pgetnameinfo = NULL;
static HTONL phtonl = NULL;
static HTONS phtons = NULL;
static INET_ADDR pinet_addr = NULL;
static INET_NTOA pinet_ntoa = NULL;
static NTOHL pntohl = NULL;
static NTOHS pntohs = NULL;
static DNSQUERY pDnsQuery = NULL;
static DNSQUERYCONFIG pDnsQueryConfig = NULL;
static DNSRECORDLISTFREE pDnsRecordListFree = NULL;
static WSAGETLASTERROR pWSAGetLastError = NULL;

#define freeaddrinfo		pfreeaddrinfo
#define getaddrinfo			pgetaddrinfo
#define gethostbyname		pgethostbyname
#define gethostname			pgethostname
#define getnameinfo			pgetnameinfo
#define htonl				phtonl
#define htons				phtons
#define inet_addr			pinet_addr
#define inet_ntoa			pinet_ntoa
#define ntohl				pntohl
#define ntohs				pntohs
#define DnsQuery			pDnsQuery
#define DnsQueryConfig		pDnsQueryConfig
#define DnsRecordListFree	pDnsRecordListFree
#ifndef WSAGetLastError
  /* In some environments WSAGetLastError() is a macro that maps to
     GetLastError() */
  #define WSAGetLastError	pWSAGetLastError
  #define DYNLOAD_WSAGETLASTERROR
#endif /* WSAGetLastError */

static int SOCKET_API my_getaddrinfo( const char *nodename, 
									  const char *servname,
									  const struct addrinfo *hints,
									  struct addrinfo **res );
static void SOCKET_API my_freeaddrinfo( struct addrinfo *ai );
static int SOCKET_API my_getnameinfo( const struct sockaddr *sa, 
									  SIZE_TYPE salen, char *node, 
									  SIZE_TYPE nodelen, char *service,
									  SIZE_TYPE servicelen, int flags );

int initDNS( INSTANCE_HANDLE hTCP, INSTANCE_HANDLE hAddr )
	{
	/* Get the required TCP/IP functions */
	gethostbyname = ( GETHOSTBYNAME ) DynamicBind( hTCP, TEXT( "gethostbyname" ) );
	gethostname = ( GETHOSTNAME ) DynamicBind( hTCP, TEXT( "gethostname" ) );
	htonl = ( HTONL ) DynamicBind( hTCP, TEXT( "htonl" ) );
	htons = ( HTONS ) DynamicBind( hTCP, TEXT( "htons" ) );
	inet_addr = ( INET_ADDR ) DynamicBind( hTCP, TEXT( "inet_addr" ) );
	inet_ntoa = ( INET_NTOA ) DynamicBind( hTCP, TEXT( "inet_ntoa" ) );
	ntohl = ( NTOHL ) DynamicBind( hTCP, TEXT( "ntohl" ) );
	ntohs = ( NTOHS ) DynamicBind( hTCP, TEXT( "ntohs" ) );
  #ifdef DYNLOAD_WSAGETLASTERROR
	WSAGetLastError = ( WSAGETLASTERROR ) DynamicBind( hTCP, TEXT( "WSAGetLastError" ) );
  #endif /* DYNLOAD_WSAGETLASTERROR */
	if( gethostbyname == NULL || gethostname == NULL || htonl == NULL || \
		htons == NULL || inet_addr == NULL || inet_ntoa == NULL || \
		ntohl == NULL || ntohs == NULL )
		return( CRYPT_ERROR );

	/* Set up the IPv6-style name/address functions */
	if( hAddr != NULL_INSTANCE )
		{
		freeaddrinfo = ( FREEADDRINFO ) DynamicBind( hAddr, TEXT( "freeaddrinfo" ) );
		getaddrinfo = ( GETADDRINFO ) DynamicBind( hAddr, TEXT( "getaddrinfo" ) );
		getnameinfo = ( GETNAMEINFO ) DynamicBind( hAddr, TEXT( "getnameinfo" ) );
		if( freeaddrinfo == NULL || getaddrinfo == NULL || \
			getnameinfo == NULL )
			return( CRYPT_ERROR );
		}
	else
		{
		/* If we couldn't dynamically bind the IPv6 name/address functions,
		   use a local emulation */
		getaddrinfo = my_getaddrinfo;
		freeaddrinfo = my_freeaddrinfo;
		getnameinfo = my_getnameinfo;
		}

	/* Get the required DNS functions if they're available */
#if defined( __WIN16__ )
	hDNS = NULL_INSTANCE;
#elif defined( __WIN32__ )
	hDNS = DynamicLoad( "dnsapi.dll" );
#elif defined( __WINCE__ )
	hDNS = hTCP;
#endif /* Win16/Win32/WinCE */
	if( hDNS != NULL_INSTANCE )
		{
		DnsQuery = ( DNSQUERY ) DynamicBind( hDNS, TEXT( "DnsQuery_A" ) );
		DnsQueryConfig = ( DNSQUERYCONFIG ) DynamicBind( hDNS, TEXT( "DnsQueryConfig" ) );
		DnsRecordListFree = ( DNSRECORDLISTFREE ) DynamicBind( hDNS, TEXT( "DnsRecordListFree" ) );
		if( ( DnsQuery == NULL || DnsQueryConfig == NULL || \
			  DnsRecordListFree == NULL ) && hDNS != hTCP )
			{
			DynamicUnload( hDNS );
			hDNS = NULL_INSTANCE;
			return( CRYPT_ERROR );
			}
		}
	
	return( CRYPT_OK );
	}

void endDNS( INSTANCE_HANDLE hTCP )
	{
	if( hDNS != NULL_INSTANCE && hDNS != hTCP )
		DynamicUnload( hDNS );
	hDNS = NULL_INSTANCE;
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		IPv6 Emulation								*
*																			*
****************************************************************************/

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

	/* Set the port and address information.  In general we'd copy the
	   address to the sockAddrPtr->sin_addr.s_addr member, however on
	   Crays, which don't have 32-bit data types, this is a 32-bit 
	   bitfield, so we have to use the encapsulating struct */
	sockAddrPtr->sin_family = AF_INET;
	sockAddrPtr->sin_port = htons( ( in_port_t ) port );
	memcpy( &sockAddrPtr->sin_addr, address, IP_ADDR_SIZE );
	*addrInfoPtrPtr = addrInfoPtr;
	return( 0 );
	}

static int SOCKET_API my_getaddrinfo( const char *nodename, 
									  const char *servname,
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

static void SOCKET_API my_freeaddrinfo( struct addrinfo *ai )
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

static int SOCKET_API my_getnameinfo( const struct sockaddr *sa, 
									  SIZE_TYPE salen, char *node, 
									  SIZE_TYPE nodelen, char *service,
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

/****************************************************************************
*																			*
*						 		DNS SRV Interface							*
*																			*
****************************************************************************/

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
#ifdef __WINCE__
	char fqdnBuffer[ MAX_URL_SIZE + 1 ], *fqdnPtr = fqdnBuffer;
#else
	char *fqdnPtr;
#endif /* Win32 vs. WinCE */

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
#ifdef __WINCE__
	unicodeToAscii( fqdnBuffer, pDns->Data.PTR.pNameHost,
					wcslen( pDns->Data.PTR.pNameHost ) );
#else
	fqdnPtr = pDns->Data.PTR.pNameHost;
#endif /* Win32 vs. WinCE */
	convertToSrv( cachedFQDN, fqdnPtr );
	DnsRecordListFree( pDns, DnsFreeRecordList );

	/* Remember the value that we just found to lighten the load on the
	   resolver when we perform repeat queries */
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
	   NATing and the use of private networks, but at least we can try */
	if( !strCompareZ( name, "[Autodetect]" ) )
		{
		const int status = getSrvFQDN( stream, hostName );
		if( cryptStatusError( status ) )
			return( status );
		name = hostName;
		}

	/* Perform a DNS SRV lookup to find the host info.  SRV has basic load-
	   balancing facilities, but for now we just use the highest-priority
	   host that we find (it's rarely-enough used that we'll be lucky to 
	   find SRV info, let alone any load-balancing setup) */
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
#ifdef __WINCE__
	if( pDnsInfo == NULL || \
		wcslen( pDnsInfo->Data.SRV.pNameTarget ) > MAX_URL_SIZE - 1 )
#else
	if( pDnsInfo == NULL || \
		strlen( pDnsInfo->Data.SRV.pNameTarget ) > MAX_URL_SIZE - 1 )
#endif /* Win32 vs. WinCE */

		{
		DnsRecordListFree( pDns, DnsFreeRecordList );
		return( setSocketError( stream, "Invalid DNS SRV entry for host",
								CRYPT_ERROR_NOTFOUND, TRUE ) );
		}

	/* Copy over the host info for this SRV record */
#ifdef __WINCE__
	nameLength = wcslen( pDnsInfo->Data.SRV.pNameTarget ) + 1;
	unicodeToAscii( hostName, pDnsInfo->Data.SRV.pNameTarget, nameLength );
#else
	nameLength = strlen( pDnsInfo->Data.SRV.pNameTarget ) + 1;
	memcpy( hostName, pDnsInfo->Data.SRV.pNameTarget, nameLength );
#endif /* Win32 vs. WinCE */
	*hostPort = pDnsInfo->Data.SRV.wPort;

	/* Clean up */
	DnsRecordListFree( pDns, DnsFreeRecordList );
	return( CRYPT_OK );
	}

#elif defined( __UNIX__ ) && \
	  !( defined( __CYGWIN__) || ( defined( sun ) && OSVERSION <= 5 ) || \
		 defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) )

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
	   NATing and the use of private networks, but at least we can try */
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
	   for now we just use the highest-priority host that we find (it's 
	   rarely-enough used that we'll be lucky to find SRV info, let alone 
	   any load-balancing setup) */
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
   can do to handle automatic host detection.  Setting localPort as a side-
   effect is necessary because the #define otherwise no-ops it out, leading
   to declared-but-not-used warnings from some compilers */

#define findHostInfo( stream, nameBuffer, localPort, name )	\
		CRYPT_ERROR_NOTFOUND; *( localPort ) = -1

#endif /* OS-specific host detection */

/****************************************************************************
*																			*
*						 		General DNS Interface						*
*																			*
****************************************************************************/

/* Get a host's IP address */

int getAddressInfo( STREAM *stream, struct addrinfo **addrInfoPtrPtr,
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
	   than the more sensible "look for any address".  The reason why this 
	   is a problem is because getaddrinfo() ends up looking for unnecessary 
	   IPv6 addresses, either by returning IPv6 addresses when the system 
	   doesn't do IPv6 or spending a lot of time groping around for IPv6 
	   stuff and/or further unnecessary addresses when it's already got what 
	   it needs.  This is made worse by confusion over implementation 
	   details, for example early implementations of getaddrinfo() in glibc 
	   would always try an AAAA lookup even on an IPv4-only system/network, 
	   resulting in long delays as the resolver timed out and fell back to a 
	   straight A lookup.  There was some disagreement over whether this was 
	   right or wrong, and how to fix it (IPv6 purists who never noticed the 
	   problem seemed to think that it was right, everyone else thought that 
	   it was wrong).  Variations of this problem exist, e.g. if an IPv4 
	   address is in /etc/hosts and DNS is down, the resolver will still 
	   spend ages (several minutes in some cases) groping around for an IPv6 
	   address before it finally gives up and falls back to what it already 
	   knows from /etc/hosts.  Switching the hint from AF_UNSPEC to AF_INET 
	   bypasses this problem, but has the downside of disabling IPv6 use.

	   This problem was partially fixed post-RFC 2553 by adding the
	   AI_ADDRCONFIG flag, which tells getaddrinfo() to only do AAAA queries
	   if the system has at least one IPv6 source address configured, and
	   the same for A and IPv4 (in other words it applies some common sense,
	   which is how it should have behaved in the first place).
	   Unfortunately this flag isn't very widely supported yet, so it usually
	   ends up being no-op'd out by the auto-config.
	   
	   Bounds Checker may crash in the getaddrinfo() call if maximum checking
	   is enabled.  To fix this, set the checking level to normal rather than
	   maximum */
	memset( &hints, 0, sizeof( struct addrinfo ) );
	sPrintf( portBuffer, "%d", port );
	hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
	if( isServer )
		/* If it's a server, set the AI_PASSIVE flag so that if the
		   interface that we're binding to isn't explicitly specified we get
		   any interface */
		hints.ai_flags |= AI_PASSIVE;
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if( getaddrinfo( name, portBuffer, &hints, addrInfoPtrPtr ) )
		return( getHostError( stream, CRYPT_ERROR_OPEN ) );
	return( CRYPT_OK );
	}

void freeAddressInfo( struct addrinfo *addrInfoPtr )
	{
	freeaddrinfo( addrInfoPtr );
	}

void getNameInfo( const struct sockaddr *sockAddr, char *address, 
				  const int addressMaxLen, int *port )
	{
	char portBuf[ 32 ];

	/* Clear return values */
	strcpy( address, "<Unknown>" );
	*port = 0;

	/* Some Windows implementations of getnameinfo() call down to
	   getservbyport() assuming that it will always succeed and therefore
	   leave the port/service arg unchanged when it doesn't, so the following
	   call must be made with the NI_NUMERICSERV flag specified (which it
	   would be anyway, cryptlib always treats the port as a numeric arg).
	   Oddly enough the macro version of this function in wspiapi.h used for
	   IPv4-only situations does get it correct */
	if( getnameinfo( sockAddr, sizeof( struct sockaddr ), address, 
					 addressMaxLen, portBuf, 32, 
					 NI_NUMERICHOST | NI_NUMERICSERV ) == 0 )
		{
#ifdef EBCDIC_CHARS
		ebcdicToAscii( address, strlen( address ) );
		ebcdicToAscii( portBuf, strlen( portBuf ) );
#endif /* EBCDIC_CHARS */
		*port = aToI( portBuf );
		}
	}
#endif /* USE_TCP */
