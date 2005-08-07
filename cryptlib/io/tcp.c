/****************************************************************************
*																			*
*						cryptlib TCP/IP Interface Routines					*
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

/* Forward declarations for socket pool functions */

static int initSocketPool( void );
static void endSocketPool( void );

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   libraries */

static INSTANCE_HANDLE hTCP, hIPv6;

typedef SOCKET ( SOCKET_API *ACCEPT )( SOCKET s, struct sockaddr *addr,
									   int *addrlen );
typedef int ( SOCKET_API *BIND )( SOCKET s, const struct sockaddr FAR *addr,
								  int namelen );
typedef int ( SOCKET_API *CONNECT )( SOCKET s, const struct sockaddr *name,
									 int namelen );
typedef int ( SOCKET_API *GETSOCKOPT )( SOCKET s, int level, int optname,
										char *optval, int FAR *optlen );
typedef int ( SOCKET_API *LISTEN )( SOCKET s, int backlog );
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
#endif /* __WINDOWS__ */
static ACCEPT paccept = NULL;
static BIND pbind = NULL;
static CONNECT pconnect = NULL;
static GETSOCKOPT pgetsockopt = NULL;
static LISTEN plisten = NULL;
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
#endif /* __WINDOWS__ */
#if ( defined( sun ) && OSVERSION > 4 )
  static int *h_errnoPtr;

  #undef getHostErrorCode
  #define getHostErrorCode()	*h_errnoPtr
#endif /* Slowaris */

#define accept				paccept
#define bind				pbind
#define connect				pconnect
#define getsockopt			pgetsockopt
#define listen				plisten
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
#ifndef WSAGetLastError
  /* In some environments WSAGetLastError() is a macro that maps to
     GetLastError() */
  #define WSAGetLastError	pWSAGetLastError
  #define DYNLOAD_WSAGETLASTERROR
#endif /* WSAGetLastError */
#define WSAStartup			pWSAStartup
#endif /* __WINDOWS__ */

/* Dynamically load and unload any necessary TCP/IP libraries.  Under Windows
   the dynamic loading is complicated by the existence of Winsock 1 vs.
   Winsock 2, all recent systems use Winsock 2 but we allow for Winsock 1 as 
   well just in case */

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#define TCP_LIBNAME			"winsock.dll"
  #elif defined( __WIN32__ )
	#define TCP_LIBNAME			TEXT( "ws2_32.dll" )
	#define WINSOCK_OLD_LIBNAME	TEXT( "wsock32.dll" )
  #elif defined( __WINCE__ )
	#define TCP_LIBNAME			TEXT( "ws2.dll" )
  #else
	#error Unknown Windows variant encountered
  #endif /* Win16/Win32/WinCE */
#else
  #define TCP_LIBNAME			"libsocket.so"
  #define TEXT( x )				x
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
	int status;
#endif /* __WINDOWS__ */

	/* Obtain a handle to the modules containing the TCP/IP functions */
#ifdef __WINDOWS__
	hTCP = hIPv6 = NULL_INSTANCE;
  #if defined( __WIN16__ )
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hTCP = DynamicLoad( TCP_LIBNAME );
	SetErrorMode( errorMode );
	if( hTCP < HINSTANCE_ERROR )
		{
		hTCP = NULL_INSTANCE;
		return( CRYPT_ERROR );
		}
  #elif defined( __WIN32__ )
	if( ( hTCP = DynamicLoad( TCP_LIBNAME ) ) == NULL_INSTANCE && \
		( hTCP = DynamicLoad( WINSOCK_OLD_LIBNAME ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
	if( DynamicBind( hTCP, "getaddrinfo" ) != NULL )
		ip6inWinsock = TRUE;
	else
		/* Newer releases of Windows put the IPv6 functions in the Winsock 2
		   library, older (non-IPv6-enabled) releases had it available as an
		   experimental add-on using the IPv6 Technology Preview library */
		hIPv6 = DynamicLoad( "wship6.dll" );
  #elif defined( __WINCE__ )
	if( ( hTCP = DynamicLoad( TCP_LIBNAME ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
	if( DynamicBind( hTCP, TEXT( "getaddrinfo" ) ) != NULL )
		ip6inWinsock = TRUE;
  #endif /* Win16/Win32/WinCE */
#else
	if( ( hTCP = DynamicLoad( TCP_LIBNAME ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
#endif /* OS-specific dynamic load */

	/* Now get pointers to the functions */
	accept = ( ACCEPT ) DynamicBind( hTCP, TEXT( "accept" ) );
	bind = ( BIND ) DynamicBind( hTCP, TEXT( "bind" ) );
	connect = ( CONNECT ) DynamicBind( hTCP, TEXT( "connect" ) );
	getsockopt = ( GETSOCKOPT ) DynamicBind( hTCP, TEXT( "getsockopt" ) );
	listen = ( LISTEN ) DynamicBind( hTCP, TEXT( "listen" ) );
	recv = ( RECV ) DynamicBind( hTCP, TEXT( "recv" ) );
	select = ( SELECT ) DynamicBind( hTCP, TEXT( "select" ) );
	send = ( SEND ) DynamicBind( hTCP, TEXT( "send" ) );
	setsockopt = ( SETSOCKOPT ) DynamicBind( hTCP, TEXT( "setsockopt" ) );
	shutdown = ( SHUTDOWN ) DynamicBind( hTCP, TEXT( "shutdown" ) );
	socket = ( SOCKETFN ) DynamicBind( hTCP, TEXT( "socket" ) );
#ifdef __WINDOWS__
	closesocket = ( CLOSESOCKET ) DynamicBind( hTCP, TEXT( "closesocket" ) );
	__WSAFDIsSet = ( FDISSETFN ) DynamicBind( hTCP, TEXT( "__WSAFDIsSet" ) );
	ioctlsocket = ( IOCTLSOCKET ) DynamicBind( hTCP, TEXT( "ioctlsocket" ) );
	WSACleanup = ( WSACLEANUP ) DynamicBind( hTCP, TEXT( "WSACleanup" ) );
  #ifdef DYNLOAD_WSAGETLASTERROR
	WSAGetLastError = ( WSAGETLASTERROR ) DynamicBind( hTCP, TEXT( "WSAGetLastError" ) );
  #endif /* DYNLOAD_WSAGETLASTERROR */
	WSAStartup = ( WSASTARTUP ) DynamicBind( hTCP, TEXT( "WSAStartup" ) );
	if( ip6inWinsock || hIPv6 != NULL_INSTANCE )
		status = initDNS( hTCP, ip6inWinsock ? hTCP : hIPv6 );
	else
		status = initDNS( hTCP, NULL_INSTANCE );
	if( cryptStatusError( status ) )
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
#endif /* __WINDOWS__ */
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
		getsockopt == NULL || listen == NULL || recv == NULL || \
		select == NULL || send == NULL || setsockopt == NULL || \
		shutdown == NULL || socket == NULL )
		{
		endDNS( hTCP );
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
		if( hIPv6 != NULL_INSTANCE )
			{
			DynamicUnload( hIPv6 );
			hIPv6 = NULL_INSTANCE;
			}
		return( CRYPT_ERROR );
		}

#ifdef __WINDOWS__
	if( closesocket == NULL || __WSAFDIsSet == NULL || \
		ioctlsocket == NULL || WSACleanup == NULL || 
  #ifdef DYNLOAD_WSAGETLASTERROR
		WSAGetLastError == NULL || 
  #endif /* DYNLOAD_WSAGETLASTERROR */
		WSAStartup == NULL || \
		( WSAStartup( 2, &wsaData ) && WSAStartup( 1, &wsaData ) ) )
		{
		endDNS( hTCP );
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
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
	/* Clean up the socket pool state information */
	endSocketPool();

	endDNS( hTCP );
	if( hIPv6 != NULL_INSTANCE )
		DynamicUnload( hIPv6 );
	if( hTCP != NULL_INSTANCE )
		{
#ifdef __WINDOWS__
		/* Wipe the Sheets Afterwards and Cleanup */
		WSACleanup();
#endif /* __WINDOWS__ */
		DynamicUnload( hTCP );
		}
	hTCP = hIPv6 = NULL_INSTANCE;
	}

/* Return the status of the network interface */

static BOOLEAN transportOKFunction( void )
	{
	return( hTCP != NULL_INSTANCE ? TRUE : FALSE );
	}
#else

int netInitTCP( void )
	{
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
		/* This assumes that stderr is open, i.e. that we're not a daemon.
		   This should be the case, at least during the development/debugging
		   stage */
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
	/* Clean up the socket pool state information */
	endSocketPool();

#ifdef __SCO_VERSION__
	signal( SIGIO, SIG_DFL );
#endif /* UnixWare/SCO */
	}

static BOOLEAN transportOKFunction( void )
	{
#if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
	static BOOLEAN transportOK = FALSE;

	if( !transportOK )
		{
		SOCKET netSocket;

		/* If the networking subsystem isn't enabled, attempting any network
		   operations will return ENOENT (which isn't a normal return code, 
		   but is the least inappropriate thing to return).  In order to 
		   check this before we get deep into the networking code, we create
		   a test socket here to make sure that everything is OK.  If the 
		   network transport is unavailable, we re-try each time we're 
		   called in case it's been enabled in the meantime */
		if( !isBadSocket( netSocket = socket( PF_INET, SOCK_STREAM, 0 ) ) )
			{
			closesocket( netSocket );
			transportOK = TRUE;
			}
		}
	return( transportOK );
#else
	return( TRUE );
#endif /* OS-specific socket availability check */
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map of common error codes to strings.  The error code supplied by the 
   caller is usually used as the return status code, however if a more 
   specific error code than the default is available it's specified via the 
   cryptSpecificCode member */

typedef struct {
	const int errorCode;		/* Native error code */
	const int cryptSpecificCode;/* Specific cryptlib error code */
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
	{ WSANO_ADDRESS,  CRYPT_OK, FALSE,
		"WSANO_ADDRESS: No address record available for this name" },
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
#if !( defined( __PALMOS__ ) || defined( __SYMBIAN32__ ) )
	{ ECONNABORTED, CRYPT_OK, TRUE,
		"ECONNABORTED: Software caused connection abort" },
#endif /* PalmOS || Symbian OS */
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
	{ NO_DATA, CRYPT_ERROR_NOTFOUND, TRUE,
		"NO_DATA: Valid name, no data record of requested type" },
	{ TRY_AGAIN,  CRYPT_OK, FALSE,
		"TRY_AGAIN: Local server did not receive a response from an "
		"authoritative server" },
	{ CRYPT_ERROR }
	};
#endif /* System-specific socket error codes */

/* Get and set the low-level error information from a socket- and host-
   lookup-based error */

static int mapError( STREAM *stream, const SOCKETERROR_INFO *errorInfo, 
					 int status )
	{
	int i;

	*stream->errorMessage = '\0';
	for( i = 0; errorInfo[ i ].errorCode != CRYPT_ERROR; i++ )
		if( errorInfo[ i ].errorCode == stream->errorCode )
			{
			strcpy( stream->errorMessage, errorInfo[ i ].errorString );
			if( errorInfo[ i ].cryptSpecificCode != CRYPT_OK )
				/* There's a more specific error code than the generic one
				   that we've been given available, use that instead */
				status = errorInfo[ i ].cryptSpecificCode;
			if( errorInfo[ i ].isFatal )
				/* It's a fatal error, make it persistent for the stream */
				stream->status = status;
			break;
			}
	return( status );
	}

int getSocketError( STREAM *stream, const int status )
	{
	/* Get the low-level error code and map it to an error string if
	   possible */
	stream->errorCode = getErrorCode();
	return( mapError( stream, socketErrorInfo, status ) );
	}

int getHostError( STREAM *stream, const int status )
	{
	/* Get the low-level error code and map it to an error string if
	   possible */
	stream->errorCode = getHostErrorCode();
	return( mapError( stream, hostErrorInfo, status ) );
	}

int setSocketError( STREAM *stream, const char *errorMessage,
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

	/* If we're checking for writeability, the best that we can do is to 
	   always report the socket as writeable.  Since the socket is a 
	   blocking socket, the data will (eventually) get written */
	if( read_bits == NULL && write_bits != NULL )
		{
		if( exception_bits != NULL )
			FD_ZERO( exception_bits );
		return( 1 );
		}

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
   this whether you want to or not)) and because when a thread is blocked in
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

   For now we limit the socket pool to a maximum of 256 sockets (16 in
   resource-constrained environments) both as a safety feature to protect 
   against runaway apps and because cryptlib was never designed to function 
   as a high-volume server application.  If necessary this can be changed to 
   dynamically expand the socket pool in the same way that the kernel 
   dynamically expands its object table */

#ifdef CONFIG_CONSERVE_MEMORY
  #define SOCKETPOOL_SIZE		16
#else
  #define SOCKETPOOL_SIZE		256
#endif /* CONFIG_CONSERVE_MEMORY */

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

/* Create/add and remove a socket to/from the pool.  The difference between 
   creating and adding a socket is that newSocket() creates and adds a 
   completely new socket while addSocket() adds an externally-created (via 
   accept()) socket */

static int newSocket( SOCKET *newSocketPtr, struct addrinfo *addrInfoPtr,
					  const BOOLEAN isServer )
	{
	SOCKET netSocket;
	int i;

	/* Clear return value */
	*newSocketPtr = INVALID_SOCKET;

	krnlEnterMutex( MUTEX_SOCKETPOOL );

	/* If this is a server socket (i.e. one bound to a specific interface and
	   port), check to see whether there's already a socket bound here and if
	   there is, return the existing socket rather than creating a new one.
	   This check isn't currently totally foolproof since it compares some
	   nonessential fields that may differ for otherwise identical sockets
	   (it's difficult to do this in a clean manner because the comparison
	   becomes very protocol- and implementation-specific).  A workaround
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
				krnlExitMutex( MUTEX_SOCKETPOOL );

				/* The socket already exists, don't perform any further
				   initialisation with it */
				return( CRYPT_OK );
				}
		}

	/* Create a new socket entry */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		{
		/* Check whether this is a zombie socket that we couldn't close 
		   earlier, usually due to written data being left in the TCP/IP
		   stack.  As a result it's probably trapped in the TIME_WAIT
		   state, so we periodically try and close it to free up the 
		   resource */
		if( socketInfo[ i ].refCount <= 0 && \
			socketInfo[ i ].netSocket != INVALID_SOCKET )
			{
			int status;

			status = closesocket( socketInfo[ i ].netSocket );
			if( !isSocketError( status ) )
				socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
			}

		if( socketInfo[ i ].netSocket == INVALID_SOCKET )
			break;
		}
	if( i >= SOCKETPOOL_SIZE )
		{
		krnlExitMutex( MUTEX_SOCKETPOOL );
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );	/* Should never happen */
		}
	if( isBadSocket( netSocket = socket( addrInfoPtr->ai_family,
										 addrInfoPtr->ai_socktype, 0 ) ) )
		{
		krnlExitMutex( MUTEX_SOCKETPOOL );
		return( CRYPT_ERROR_OPEN );
		}
	socketInfo[ i ].netSocket = netSocket;
	if( isServer )
		{
		const int addrInfoSize = min( addrInfoPtr->ai_addrlen, 32 );

		/* Remember the details for this socket so that we can detect another
		   attempt to bind to it */
		assert( addrInfoPtr->ai_addrlen <= 32 );
		socketInfo[ i ].iChecksum = checksumData( addrInfoPtr->ai_addr,
												  addrInfoPtr->ai_addrlen );
		memcpy( socketInfo[ i ].iData, addrInfoPtr->ai_addr,
				addrInfoSize );
		socketInfo[ i ].iDataLen = addrInfoSize;
		}
	socketInfo[ i ].refCount = 1;
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

	krnlExitMutex( MUTEX_SOCKETPOOL );

	return( CRYPT_OK );
	}

static void newSocketDone( void )
	{
	/* The caller has finished setting up a new server socket, unlock the
	   socket info to allow others to access it */
	krnlExitMutex( MUTEX_SOCKETPOOL );
	}

static int addSocket( const SOCKET netSocket )
	{
	int i;

	krnlEnterMutex( MUTEX_SOCKETPOOL );

	/* Add an existing socket entry */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket == INVALID_SOCKET )
			break;
	if( i >= SOCKETPOOL_SIZE )
		{
		krnlExitMutex( MUTEX_SOCKETPOOL );
		assert( NOTREACHED );
		return( CRYPT_ERROR_OVERFLOW );	/* Should never happen */
		}
	socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
	socketInfo[ i ].netSocket = netSocket;
	socketInfo[ i ].refCount = 1;

	krnlExitMutex( MUTEX_SOCKETPOOL );

	return( CRYPT_OK );
	}

static void deleteSocket( const SOCKET netSocket )
	{
	int i;

	krnlEnterMutex( MUTEX_SOCKETPOOL );

	/* Find the entry for this socket in the pool.  There may not be one
	   present if the pool has received a shutdown signal and closed all
	   network sockets, so if we don't find it we exit normally */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket == netSocket )
			break;
	if( i >= SOCKETPOOL_SIZE )
		{
		krnlExitMutex( MUTEX_SOCKETPOOL );
		return;
		}
	assert( socketInfo[ i ].refCount > 0 );

	/* Decrement the socket's reference count */
	socketInfo[ i ].refCount--;
	if( socketInfo[ i ].refCount <= 0 )
		{
		int status;

		/* If the reference count has reached zero, close the socket
		   and delete the pool entry */
		status = closesocket( socketInfo[ i ].netSocket );
		if( isSocketError( status ) )
			{
			/* There was a problem closing the socket, mark it as not-
			   present for matching purposes but keep its entry active so
			   that we'll periodically try and close it when we search the
			   socket pool for these slots, and again when we close down */
			socketInfo[ i ].iChecksum = 0;
			memset( socketInfo[ i ].iData, 0, 
					sizeof( socketInfo[ i ].iData ) );
			socketInfo[ i ].iDataLen = 0;

			assert( NOTREACHED );
			}
		else
			socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
		}

	krnlExitMutex( MUTEX_SOCKETPOOL );
	}

/* Force all objects waiting on sockets to exit by closing their sockets.
   This is the only way to cause them to terminate, since an object waiting
   on a socket is marked as busy by the cryptlib kernel (and in fact will be
   blocked inside the OS out of reach of even the cryptlib kernel).
   Alternatively, the user can provide their own socket externally and close
   it from the outside, which will unblock the thread waiting on it.

   A somewhat less drastic alternative to closing the socket is to use
   shutdown(), but the behaviour of this is somewhat implementation-specific.
   For example under Slowaris 5.x trying to shutdown a listening socket (to
   unlock a thread blocking in accept()) returns ENOTCONN, so the shutdown
   requires setting up a dummy connection to the socket to be shut down
   before it can actually be shut down.  Trying to shut down a thread blocked
   in connect() is more or less impossible under Slowaris 5.x.  Other systems
   are more flexible, but there's not enough consistency to rely on this */

void netSignalShutdown( void )
	{
	int i;

	krnlEnterMutex( MUTEX_SOCKETPOOL );

	/* For each open socket, close it and set its reference count to zero */
	for( i = 0; i < SOCKETPOOL_SIZE; i++ )
		if( socketInfo[ i ].netSocket != INVALID_SOCKET )
			{
			closesocket( socketInfo[ i ].netSocket );
			socketInfo[ i ] = SOCKET_INFO_TEMPLATE;
			}

	krnlExitMutex( MUTEX_SOCKETPOOL );
	}

/****************************************************************************
*																			*
*							Network Socket Interface						*
*																			*
****************************************************************************/

/* Wait for I/O to become possible on a socket */

typedef enum { IOWAIT_READ, IOWAIT_WRITE, IOWAIT_CONNECT, 
			   IOWAIT_ACCEPT } IOWAIT_TYPE;

static int ioWait( STREAM *stream, const time_t timeout, 
				   const int currentByteCount, const IOWAIT_TYPE type )
	{
	static const struct {
		const int status;
		const char *errorString;
		} errorInfo[] = {
		{ CRYPT_ERROR_READ, "read" },
		{ CRYPT_ERROR_WRITE, "write" },
		{ CRYPT_ERROR_OPEN, "connect" },
		{ CRYPT_ERROR_OPEN, "accept" },
		{ CRYPT_ERROR_OPEN, "unknown" }
		};
	const time_t startTime = getTime();
	struct timeval tv;
	fd_set readfds, writefds, exceptfds;
	fd_set *readFDPtr = ( type == IOWAIT_READ || \
						  type == IOWAIT_CONNECT || \
						  type == IOWAIT_ACCEPT ) ? &readfds : NULL;
	fd_set *writeFDPtr = ( type == IOWAIT_WRITE || \
						   type == IOWAIT_CONNECT ) ? &writefds : NULL;
	int status;

	/* Set up the information needed to handle timeouts and wait on the 
	   socket.  If there's no timeout, we wait at least 5ms on the theory 
	   that it isn't noticeable to the caller but ensures that we at least 
	   get a chance to get anything that may be pending.
	   
	   The exact wait time depends on the system, but usually it's quantised 
	   to the system timer quantum.  This means that on Unix systems with a 
	   1ms timer resolution, the wait time is quantised on a 1ms boundary.  
	   Under Windows NT/2000/XP, it's quantised on a 10ms boundary (some 
	   early NT systems had a granularity ranging from 7.5 - 15ms, but all 
	   newer systems use 10ms) and for Win95/98/ME it's quantised on a 55ms 
	   boundary.  In other words when performing a select() on a Win95 box 
	   it'll either return immediately or wait some multiple of 55ms, even 
	   with the time set to 1ms.

	   In theory we shouldn't have to reset either the fds or the timeval 
	   each time through the loop since we're only waiting on one descriptor 
	   so it's always set and the timeval is a const, however some versions 
	   of Linux can update it if the select fails due to an EINTR (which is 
	   the exact reason why we'd be going through the loop a second time) 
	   and/or if a file descriptor changes status (e.g. due to data becoming 
	   available) so we have to reset it each time to be on the safe side.
	   
	   The wait on connect is a slightly special case, the socket will 
	   become writeable if the connect succeeds normally, but both readable 
	   and writeable if there's an error on the socket or if there's data
	   already waiting on the connection (i.e. it arrives as part of the 
	   connect).  It's up to the caller to check for these conditions */
	do
		{
		if( readFDPtr != NULL )
			{
			FD_ZERO( readFDPtr );
			FD_SET( stream->netSocket, readFDPtr );
			}
		if( writeFDPtr != NULL )
			{
			FD_ZERO( writeFDPtr );
			FD_SET( stream->netSocket, writeFDPtr );
			}
		FD_ZERO( &exceptfds );
		FD_SET( stream->netSocket, &exceptfds );
		tv.tv_sec = timeout;
		tv.tv_usec = ( timeout <= 0 ) ? 5000 : 0;

		/* See if we can perform the I/O */
		status = select( stream->netSocket + 1, readFDPtr, writeFDPtr, 
						 &exceptfds, &tv );

		/* If there's a problem and it's not something transient like an 
		   interrupted system call, exit.  For a transient problem, we just 
		   retry the select until the overall timeout expires */
		if( isSocketError( status ) && !isRestartableError() )
			return( getSocketError( stream, errorInfo[ type ].status ) );
		}
	while( isSocketError( status ) && ( getTime() - startTime ) < timeout );

	/* If the wait timed out, either explicitly in the select (status == 0)
	   or implicitly in the wait loop (isSocketError()), report it as a 
	   select() timeout error */
	if( status == 0 || isSocketError( status ) )
		{
		char errorMessage[ 128 ];

		/* If we've already received data from a previous I/O, it counts as
		   the transferred byte count even though we timed out this time 
		   round */
		if( currentByteCount > 0 )
			return( currentByteCount );

		/* If it's a nonblocking wait (usually used as a poll to determine 
		   whether I/O is possible) then a timeout isn't an error */
		if( timeout <= 0 )
			return( OK_SPECIAL );

		/* The select() timed out, exit */
		sPrintf( errorMessage, "Timeout on %s (select()) after %d seconds",
				 errorInfo[ type ].errorString, timeout );
		return( setSocketError( stream, errorMessage, CRYPT_ERROR_TIMEOUT, 
								FALSE ) );
		}

#if 0	/* 12/6/04 Shouldn't be necessary any more since to get to this 
		   point the socket has to be either readable or writeable or 
		   subject to an exception condition, which is handled below */
	/* If we encountered an error condition on a connect (the socket is 
	   neither readable nor writeable), exit */
	if( ( type == IOWAIT_CONNECT ) && \
		!( FD_ISSET( stream->netSocket, &readfds ) || \
		   FD_ISSET( stream->netSocket, &writefds ) ) )
		{
		assert( FD_ISSET( stream->netSocket, &exceptfds ) );

		status = getSocketError( stream, CRYPT_ERROR_OPEN );
		if( stream->errorCode == 0 )
			{
			/* Some implementations don't treat a soft timeout as an error, 
			   and at least one (Tandem) returns EINPROGRESS rather than 
			   ETIMEDOUT, so we insert a timeout error code ourselves */
			stream->errorCode = TIMEOUT_ERROR;
			mapError( stream, socketErrorInfo, CRYPT_UNUSED );
			}
		return( status );
		}
#endif /* 0 */

	/* If there's an exception condition on a socket, exit.  This is
	   implementation-specific, traditionally under Unix this only indicates 
	   the arrival of out-of-band data rather than any real error condition, 
	   but in some cases it can be used to signal errors.  In these cases we 
	   have to explicitly check for an exception condition because some 
	   types of errors will result in select() timing out waiting for 
	   readability, rather than indicating an error.  In addition for OOB 
	   data we could just ignore the notification (which happens 
	   automatically with the default setting of SO_OOBINLINE = false and a 
	   socket owner to receive SIGURG's not set, the OOB data byte just 
	   languishes in a side-buffer), however we shouldn't be receiving OOB 
	   data so we treat it as an error */
	if( FD_ISSET( stream->netSocket, &exceptfds ) )
		{
		status = getSocketError( stream, errorInfo[ type ].status );
		if( stream->errorCode == 0 )
			{
			/* If there's a (supposed) exception condition present but no
			   error information available then this may be a mis-handled
			   select() timeout.  This can happen under Winsock under 
			   certain circumstances, and seems to be related to another 
			   app performing network I/O at the same time as we do the
			   wait.  Non-Winsock cases can occur because some 
			   implementations don't treat a soft timeout as an error, and 
			   at least one (Tandem) returns EINPROGRESS rather than 
			   ETIMEDOUT, so we insert a timeout error code ourselves */
			stream->errorCode = TIMEOUT_ERROR;
			mapError( stream, socketErrorInfo, CRYPT_UNUSED );
			}
		return( status );
		}

	/* The socket is read for reading or writing */
	assert( status > 0 );
	assert( ( type == IOWAIT_READ && \
			  FD_ISSET( stream->netSocket, &readfds ) ) || \
			( type == IOWAIT_WRITE && \
			  FD_ISSET( stream->netSocket, &writefds ) ) || \
			( type == IOWAIT_CONNECT && \
			  ( FD_ISSET( stream->netSocket, &readfds ) || \
				FD_ISSET( stream->netSocket, &writefds ) ) ) || \
			( type == IOWAIT_ACCEPT ) );
	return( CRYPT_OK );
	}

/* Open a connection to a remote server/wait for a connection from a remote 
   client.  The connection-open function performs that most amazing of all 
   things, the nonblocking connect.  This is currently done in order to 
   allow a shorter timeout than the default fortnight or so but it also 
   allows for two-phase connects in which we start the connect operation, 
   perform further processing (e.g. signing and encrypting data prior to 
   sending it over the connected socket) and then complete the connect 
   before the first read or write.  Currently we just use a wrapper that 
   performs the two back-to-back as a single operation, so it only functions 
   as a timeout-management mechanism */

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
	freeAddressInfo( addrInfoPtr );
	if( status < 0 && !nonBlockWarning )
		{
		/* There was an error condition other than a notification that the
		   operation hasn't completed yet */
		status = mapError( stream, socketErrorInfo, CRYPT_ERROR_OPEN );
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
	static const int trueValue = 1;
	SIZE_TYPE intLength = sizeof( int );
	int value, status;

	/* Wait around until the connect completes.  Some select()s limit the
	   size of the second count, so we set it to a maximum of 1 year's worth.
	   BeOS doesn't allow setting a timeout (that is, it doesn't allow
	   asynchronous connects), but it hardcodes in a timeout of about a
	   minute so we get a vaguely similar effect */
	status = ioWait( stream, min( stream->timeout, 30000000L ), 0, 
					 IOWAIT_CONNECT );
	if( cryptStatusError( status ) )
		{
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
			status = mapError( stream, socketErrorInfo, CRYPT_ERROR_OPEN );
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
	   recv() (a sign that the receiver has closed the connection, see the 
	   comment in readSocketFunction()) even though the connection is still 
	   fully open, and in any case there's no real need for a nonblocking 
	   socket since we have select() handling timeouts/blocking for us */
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
		   BeOS we actually bind to the first interface that we find */
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
	freeAddressInfo( addrInfoPtr );
	if( cryptStatusError( status ) )
		/* There was an error setting up the socket, don't try anything
		   further */
		return( mapError( stream, socketErrorInfo, CRYPT_ERROR_OPEN ) );

	/* Wait for a connection.  At the moment this always waits forever
	   (actually some select()'s limit the size of the second count, so we
	   set it to a maximum of 1 year's worth), but in the future we could
	   have a separate timeout value for accepting incoming connections to 
	   mirror the connection-wait timeout for outgoing connections.
	   
	   Because of the way that accept works, the socket that we eventually 
	   and up with isn't the one that we listen on, but we have to 
	   temporarily make it the one associated with the stream in order for 
	   ioWait() to work */
	stream->netSocket = listenSocket;
	status = ioWait( stream, min( stream->timeout, 30000000L ), 0, 
					 IOWAIT_ACCEPT );
	stream->netSocket = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		return( status );

	/* We have an incoming connection ready to go, accept it.  There's a
	   potential complication here in that if a client connects and then
	   immediately sends a RST after the TCP handshake has completed, 
	   ioWait() will return with an indication that there's an incoming
	   connection ready to go, but the following accept(), if it's called
	   after the RST has arrived, will block waiting for the next incoming
	   connection.  This is rather unlikely in practice, but could occur
	   as part of a DoS by setting the SO_LINGER time to 0 and disconnecting
	   immediately.  This has the effect of turning the accept() with 
	   timeout into an indefinite-wait accept().
	   
	   To get around this, we make the socket temporarily non-blocking, so 
	   that accept() returns an error if the client has closed the 
	   connection.  The exact error varies, BSD implementations handle the
	   error internally and return to the accept() while SVR4 
	   implementations return either EPROTO (older, pre-Posix behaviour) or
	   ECONNABORTED (newer Posix-compliant behaviour, since EPROTO is also
	   used for other protocol-related errors).
	   
	   Since BSD implementations hide the problem, they wouldn't normally 
	   return an error, however by temporarily making the socket non-
	   blocking we force it to return an EWOULDBLOCK if this situation 
	   occurs.  Since this could lead to a misleading returned error, we
	   intercept it and substitute a custom error string.  Note that when
	   we make the listen socket blocking again, we also have to make the 
	   newly-created ephemeral socket blocking, since it inherits its 
	   attributes from the listen socket */
	setSocketNonblocking( listenSocket );
	netSocket = accept( listenSocket, ( struct sockaddr * ) &clientAddr,
						&clientAddrLen );
	if( isBadSocket( netSocket ) )
		{
		if( isNonblockWarning() )
			status = setSocketError( stream, "Remote system closed the "
									 "connection after completing the TCP "
									 "handshake", CRYPT_ERROR_OPEN, TRUE );
		else
			status = getSocketError( stream, CRYPT_ERROR_OPEN );
		setSocketBlocking( listenSocket );
		deleteSocket( listenSocket );
		return( status );
		}
	setSocketBlocking( listenSocket );
	setSocketBlocking( netSocket );

	/* Get the IP address of the connected client.  We could get its full
	   name, but this can slow down connections because of the time that it 
	   takes to do the lookup and is less authoritative because of potential
	   spoofing.  In any case the caller can still look up the name if they
	   need it */
	getNameInfo( ( const struct sockaddr * ) &clientAddr,
				 stream->clientAddress, sizeof( stream->clientAddress ),
				 &stream->clientPort );

	/* We've got a new connection, add the socket to the pool.  Since this
	   was created external to the pool we don't use newSocket() to create a 
	   new socket but only add the existing socket */
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
		{
		const int savedTimeout = stream->timeout;

		/* Timeouts for server sockets are actually three-level rather than
		   the usual two-level model, there's an initial (pre-connect) 
		   timeout while we wait for an incoming connection to arrive, and 
		   then we go to the usual session connect vs. session read/write 
		   timeout mechanism.  To handle the pre-connect phase we set an 
		   (effectively infinite) timeout at this point to ensure that the 
		   server always waits forever for an incoming connection to 
		   appear */
		stream->timeout = INT_MAX - 1;
		status = openServerSocket( stream, server, port );
		stream->timeout = savedTimeout;
		return( status );
		}

	/* It's a client stream, perform a two-part nonblocking open.  Currently
	   the two portions are performed back-to-back, in the future we can
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

/* Close a connection.  Safely handling closes is extremely difficult due to
   a combination of the way TCP/IP (and TCP stacks) work and various bugs 
   and quirks in implementations.  After a close (and particularly if short-
   timeout non-blocking writes are used), there can still be data left in 
   TCP send buffers, and also as unacknowledged segments on the network.  At
   this point there's no easy way for the TCP stack to know how long it 
   should hang around trying to get the data out and waiting for acks to come
   back.  If it doesn't wait long enough, it'll end up discarding unsent 
   data.  If it waits too long, it could potentially wait forever in the 
   presence of network outages or crashed peers.  What's worse, since the 
   socket is now closed, there's no way to report any problems that may occur 
   to the caller.

   We try and handle this with a combination of shutdown() and close(), but 
   due to implementation bugs/quirks and the TCP stack issues above this 
   doesn't work all of the time.  The details get very implementation-
   specific, for example with glibc the manpage says that setting SO_LINGER 
   causes shutdown() not to return until queued messages are sent (which is 
   wrong, and non non-glibc implementations like PHUX and Solaris 
   specifically point out that only close() is affected), but that 
   shutdown() discards unsent data.  glibc in turn is dependent on the 
   kernel it's running on top of, under Linux shutdown() returns immediately 
   but data is still sent regardless of the SO_LINGER setting.
   
   BSD Net/2 and later (which many stacks are derived from, including non-
   Unix systems like OS/2) returned immediately from a close() but still 
   sent queued data on a best-effort basis.  With SO_LINGER set and a zero 
   timeout the close was abortive (which Linux also implemented starting 
   with the 2.4 kernel), and with a non-zero timeout it would wait until all 
   the data was sent, which meant that it could block almost indefinitely 
   (minutes or even hours, this is the worst-case behaviour mentioned 
   above).  This was finally fixed in 4.4BSD (although a lot of 4.3BSD-
   derived stacks ended up with the indefinite-wait behaviour), but even 
   then there was some confusion as to whether the wait time was in machine-
   specific ticks or seconds (Posix finally declared it to be seconds).  
   Under Winsock, close() simply discards queued data while shutdown() has 
   the same effect as under Linux, sending enqueued data asynchronously 
   regardless of the SO_LINGER setting.
	   
   This is a real mess to sort out safely, the best that we can do is to 
   perform a shutdown() followed later by a close().  Messing with SO_LINGER 
   is too risky, something like performing an ioWait() doesn't work either 
   since it just results in whoever initiated the shutdown being blocked for 
   the I/O wait time, and waiting for a recv() of 0 bytes isn't safe because 
   the higher-level code may need to read back a shutdown ack from the other 
   side, which a recv() performed here would interfere with.  Under Windows 
   we could handle it by waiting for an FD_CLOSE to be posted, but this 
   requires the use of a window handle which we don't have */

static void closeSocketFunction( STREAM *stream,
								 const BOOLEAN fullDisconnect )
	{
	/* If it's a partial disconnect, close only the send side of the channel.  
	   The send-side close can help with ensuring that all data queued for 
	   transmission is sent */
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
	stream->netSocket = stream->listenSocket = CRYPT_ERROR;
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
   levels, once via ioWait() and a second time as an overall timeout.  If we
   only used ioWait() this could potentially stretch the overall timeout to
   (length * timeout) so we also perform a time check that leads to a worst-
   case timeout of (timeout-1 + timeout).  This is the same as the 
   implementation of SO_SND/RCVTIMEO in Berkeley-derived implementations,
   where the timeout value is actually an interval timer rather than a
   absolute timer.

   In addition to the standard stream-based timeout, we can also be called
   with flags specifying explicit blocking behaviour (for a read where we
   know that we're expecting a certain amount of data) or explicit 
   nonblocking behaviour (for speculative reads to fill a buffer).  These 
   flags are used by the buffered-read routines, which try and speculatively 
   read as much data as possible to avoid the many small reads required by 
   some protocols.  We don't do the blocking read using MSG_WAITALL since 
   this can (potentially) block forever if not all of the data arrives.

   Finally, if we're performing a blocking read (which is usually done when
   we're expecting a predetermined number of bytes), we dynamically adjust
   the timeout so that if data is streaming in at a steady rate, we don't
   abort the read just because there's more data to transfer than we can
   manage in the originally specified timeout interval.

   Handling of return values is as follows:

	timeout		byteCount		return
	-------		---------		------
		0			0				0
		0		  > 0			byteCount
	  > 0			0			CRYPT_ERROR_TIMEOUT
	  > 0		  > 0			byteCount

   At the sread()/swrite() level if the partial-read/write flags aren't set 
   for the stream, a byteCount < length is also converted to a 
   CRYPTO_ERROR_TIMEOUT */

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
		int bytesRead, status;

		/* Wait for data to become available */
		status = ioWait( stream, timeout, byteCount, IOWAIT_READ );
		if( status != CRYPT_OK )
			return( ( status == OK_SPECIAL ) ? 0 : status );

		/* We've got data waiting, read it */
		bytesRead = recv( stream->netSocket, bufPtr, bytesToRead, 0 );
		if( isSocketError( bytesRead ) )
			{
			/* If it's a restartable read due to something like an
			   interrupted system call, retry the read */
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
			/* Under some odd circumstances (Winsock bugs when using non-
			   blocking sockets, or calling select() with a timeout of 0), 
			   recv() can return zero bytes without an EOF condition being 
			   present, even though it should return an error status if this 
			   happens (this could also happen under very old SysV 
			   implementations using O_NDELAY for nonblocking I/O).  To try 
			   and catch this, we check for a restartable read due to 
			   something like an interrupted system call and retry the read 
			   if it is.  Unfortunately this doesn't catch the Winsock zero-
			   delay bug, but it may catch problems in other implementations.
			   The real culprit here is the design flaw in recv(), which 
			   uses a valid bytes-received value to indicate an out-of-band 
			   condition that should be reported via an error code ("There's 
			   nowt wrong wi' owt what mithen clutterbucks don't barley 
			   grummit")
			if( isRestartableError() )
				{
				assert( !"Restartable read, recv() indicated no error" );
				continue;
				} */

			/* Once this Winsock bug hits, we've fallen and can't get up any 
			   more.  WSAGetLastError() reports no error, select() reports 
			   data available for reading, and recv() reports zero bytes 
			   read.  If the following is used, the code will loop endlessly 
			   waiting for data that can never be read */
#if 0
			getSocketError( stream, CRYPT_ERROR_READ );
			status = ioWait( stream, 0, 0, IOWAIT_READ );
			if( cryptStatusOK( status ) )
				continue;
#endif /* 0 */

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
	const time_t startTime = getTime();
	const BYTE *bufPtr = buffer;
	time_t timeout = ( flags & TRANSPORT_FLAG_NONBLOCKING ) ? 0 : \
					 ( flags & TRANSPORT_FLAG_BLOCKING ) ? \
						max( 30, stream->timeout ) : stream->timeout;
	int bytesToWrite = length, byteCount = 0;

	/* Send data to the remote system.  As with the receive-data code, we
	   have to work around a large number of quirks and socket 
	   implementation bugs, although most of the systems that exhibited 
	   these are now extinct, or close to it.  Some very old Winsock stacks 
	   (Win3.x and early Win95 era) would almost always indicate that a 
	   socket was writeable even when it wasn't.  Even older (mid-1980s) 
	   Berkeley-derived implementations could return EWOULDBLOCK on a 
	   blocking socket if they couldn't get required mbufs, so that even if 
	   select() indicated that the socket was writeable, an actual attempt 
	   to write would return an error since there were no mbufs available.  
	   Under Win95, select() can fail to block on a non-blocking socket, so 
	   that the send() returns EWOULDBLOCK.  One possible reason (related to 
	   the mbuf problem) is that another thread may grab memory between the 
	   select() and the send() so that there's no buffer space available 
	   when send() needs it (although this should return WSAENOBUFS rather 
	   than WSAEWOULDBLOCK).  There's also a known bug in Win95 (and 
	   possibly Win98 as well, Q177346) under which a select() indicates 
	   writeability but send() returns EWOULDBLOCK.  Another select() after 
	   the send() then causes select() to realise the socket is non-
	   writeable.  Finally, in some cases send() can return an error but 
	   WSAGetLastError() indicates there's no error, so we treat it as noise 
	   and try again */
	assert( timeout >= 0 );
	while( bytesToWrite > 0 && \
		   ( ( getTime() - startTime < timeout || timeout <= 0 ) ) )
		{
		int bytesWritten, status;

		/* Wait for the socket to become available */
		status = ioWait( stream, timeout, byteCount, IOWAIT_WRITE );
		if( status != CRYPT_OK )
			return( ( status == OK_SPECIAL ) ? 0 : status );

		/* Write the data */
		bytesWritten = send( stream->netSocket, bufPtr, bytesToWrite, 
							 MSG_NOSIGNAL );
		if( isSocketError( bytesWritten ) )
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

			/* There was a problem with the write */
			return( getSocketError( stream, CRYPT_ERROR_WRITE ) );
			}
		bufPtr += bytesWritten;
		bytesToWrite -= bytesWritten;
		byteCount += bytesWritten;
		}

	return( byteCount );
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
