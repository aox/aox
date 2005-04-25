/****************************************************************************
*																			*
*						STREAM Class Constants and Structures				*
*						  Copyright Peter Gutmann 1993-2004					*
*																			*
****************************************************************************/

#ifndef _STREAM_DEFINED

#define _STREAM_DEFINED

#if defined( INC_ALL )
  #include "crypt.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */
#if defined( __WIN32__ ) || defined( __WINCE__ )
  /* Includes are always handled via the normal system includes */
#elif defined( __UNIX__ ) || defined( __BEOS__ ) || defined( __XMK__ )
  #include <unistd.h>		/* For lseek() codes */
#elif defined( __MAC__ )
  #include <Files.h>
#elif defined( __PALMOS__ )
  #include <VFSMgr.h>
#elif !defined( CONFIG_NO_STDIO )
  #include <stdio.h>
#endif /* System-specific file I/O headers */

/****************************************************************************
*																			*
*								STREAM Constants							*
*																			*
****************************************************************************/

/* The stream types */

typedef enum {
	STREAM_TYPE_NONE,					/* No stream type */
	STREAM_TYPE_NULL,					/* Null stream (/dev/nul) */
	STREAM_TYPE_MEMORY,					/* Memory stream */
	STREAM_TYPE_FILE,					/* File stream */
	STREAM_TYPE_NETWORK,				/* Network stream */
	STREAM_TYPE_LAST					/* Last possible stream type */
	} STREAM_TYPE;

/* General-purpose stream flags.  The PARTIALREAD flag is used for network 
   reads to handle timeouts and for file streams when we don't know the full 
   extent of a file stream, when it's set and we ask for a read of n bytes 
   and there isn't sufficient data present in the file to satisfy the 
   request the stream code returns 0...n bytes rather than an underflow error.
   The PARTIALWRITE flag is used for network streams when performing bulk 
   data transfers, in this case the write may time out and can be restarted
   later rather than returning a timeout error */

#define STREAM_FLAG_READONLY	0x0001	/* Read-only stream */
#define STREAM_FLAG_PARTIALREAD 0x0002	/* Allow read of less than req.amount */
#define STREAM_FLAG_PARTIALWRITE 0x0004	/* Allow write of less than req.amount */
#define STREAM_FLAG_MASK		0x0007	/* Mask for general-purpose flags */

/* File stream flags */

#define STREAM_FFLAG_DIRTY		0x0010	/* Stream contains unwritten data */
#define STREAM_FFLAG_EOF		0x0020	/* EOF reached on stream */
#define STREAM_FFLAG_POSCHANGED	0x0040	/* File stream position has changed */
#define STREAM_FFLAG_POSCHANGED_NOSKIP 0x0080	/* New stream pos.is in following block */
#define STREAM_FFLAG_MMAPPED	0x0100	/* File stream is memory-mapped */
#define STREAM_FFLAG_MASK		( 0x01F0 | STREAM_FLAG_MASK )	
										/* Mask for file-only flags */

/* Network stream flags.  The ENCAPS flag indicates that the protocol is 
   running over a lower encapsulation layer that provides additional packet
   control information, typically packet size and flow control information.
   If this flag is set, the lower-level read code overrides some error 
   handling that normally takes place at a higher level.  For example if a 
   read of n bytes is requested and the encapsulation layer reports that 
   only m bytes, m < n is present, this isn't treated as a read/timeout 
   error */

#define STREAM_NFLAG_ISSERVER	0x01000	/* Stream is server rather than client */
#define STREAM_NFLAG_USERSOCKET	0x02000	/* Network socket was supplied by user */
#define STREAM_NFLAG_HTTP10		0x04000	/* HTTP 1.0 stream */
#define STREAM_NFLAG_HTTPPROXY	0x08000	/* Use HTTP proxy format for requests */
#define STREAM_NFLAG_IDEMPOTENT	0x10000	/* Allow idempotent HTTP queries only */
#define STREAM_NFLAG_LASTMSG	0x20000	/* Last message in exchange */
#define STREAM_NFLAG_ENCAPS		0x40000	/* Network transport is encapsulated */
#define STREAM_NFLAG_MASK		( 0x7F000 | STREAM_FLAG_MASK )
										/* Mask for network-only flags */

/* Network transport-specific flags.  The flush flag is used in writes to
   flush data in the stream, the blocking/nonblocking flags are used to
   override the stream default behaviour on reads */

#define TRANSPORT_FLAG_NONE		0x00	/* No transport flag */
#define TRANSPORT_FLAG_FLUSH	0x01	/* Flush data on write */
#define TRANSPORT_FLAG_NONBLOCKING 0x02	/* Explicitly perform nonblocking read */
#define TRANSPORT_FLAG_BLOCKING	0x04	/* Explicitly perform blocking read */

/* Occasionally we want to connect a memory stream to a fixed-length buffer
   whose size is (by definition) big enough for the data it needs to hold, 
   but of an unknown length (this is currently only used in keyex.c when 
   writing a wrapped key to an output buffer and in sign.c when writing a 
   signature to an output buffer, in both cases with data passed in by the
   user through the cryptlib 2.0-era legacy functions).  Using the following 
   as the length will avoid various checks on the input length */

/* #define STREAMSIZE_UNKNOWN	-1 */

/* When we're reading data of unknown size from an external source, we may
   need to dynamically increase the I/O buffer size during the read.  The 
   following callback function is used to increase the I/O buffer size */

typedef int ( *CALLBACKFUNCTION )( void *callbackParams, void **bufPtr, \
								   const int bufSize );

/* Access/option flags for the file stream open call.  The exclusive access
   flag locks the file so that other threads/processes can't open it until
   the current thread/process closes it.  This flag is implicitly set if the
   file R/W bits are FILE_WRITE, which creates a new file.  The difference
   between the private and sensitive flags is that some data may be private
   for a given user but not sensitive (e.g.config info) while other data may
   be private and sensitive (e.g.private keys).  The sensitive flag only has
   an effect on special systems where data can be committed to secure
   storage, since there's usually a very limited amount of this available we
   only use it for sensitive data but not generic private data */

#define FILE_READ			0x01	/* Open file for read access */
#define FILE_WRITE			0x02	/* Open file for write access */
#define FILE_EXCLUSIVE_ACCESS 0x04	/* Don't allow others access */
#define FILE_PRIVATE		0x08	/* Set ACL's to allow owner access only */
#define FILE_SENSITIVE		0x10	/* Use secure storage if available */
#define FILE_RW_MASK		0x03	/* Mask for R/W bits */

/* Options for the build-path call */

typedef enum {
	BUILDPATH_NONE,					/* No option type */
	BUILDPATH_CREATEPATH,			/* Get path to config file, create if nec.*/
	BUILDPATH_GETPATH,				/* Get path to config file */
	BUILDPATH_RNDSEEDFILE,			/* Get path to random seed file */
	BUILDPATH_LAST					/* Last valid option type */
	} BUILDPATH_OPTION_TYPE;

/* Stream IOCTL types */

typedef enum {
	STREAM_IOCTL_NONE,				/* No IOCTL type */
	STREAM_IOCTL_IOBUFFER,			/* Working buffer for file streams */
	STREAM_IOCTL_PARTIALREAD,		/* Allow read of less than req.amount */
	STREAM_IOCTL_PARTIALWRITE,		/* Allow write of less then req.amount */
	STREAM_IOCTL_READTIMEOUT,		/* Network read timeout */
	STREAM_IOCTL_WRITETIMEOUT,		/* Network write timeout */
	STREAM_IOCTL_HANDSHAKECOMPLETE,	/* Toggle handshake vs.data timeout */
	STREAM_IOCTL_CONNSTATE,			/* Connection state (open/closed) */
	STREAM_IOCTL_GETCLIENTNAME,		/* Get client name */
	STREAM_IOCTL_GETCLIENTPORT,		/* Get client port */
	STREAM_IOCTL_CONTENTTYPE,		/* HTTP content type */
	STREAM_IOCTL_QUERY,				/* HTTP query portion of URL */
	STREAM_IOCTL_IDEMPOTENT,		/* Allow idempotent HTTP queries only */
	STREAM_IOCTL_LASTMESSAGE,		/* CMP last message in transaction */
	STREAM_IOCTL_CALLBACKFUNCTION,	/* Callback function address */
	STREAM_IOCTL_CALLBACKPARAMS,	/* Callback function parameters */
	STREAM_IOCTL_CLOSESENDCHANNEL,	/* Close send side of channel */
	STREAM_IOCTL_LAST				/* Last possible IOCTL type */
	} STREAM_IOCTL_TYPE;

/* Stream network protocol types.  The difference between PROTOCOL_HTTP and
   PROTOCOL_HTTP_TRANSACTION is that the former is a read-only stream that
   performs a (transparent) GET followed by a read of the response while the
   latter is a read/write stream which expects a write that performs a POST
   followed by a read that fetches the response */

typedef enum {
	STREAM_PROTOCOL_NONE,			/* No protocol type */
	STREAM_PROTOCOL_TCPIP,			/* TCP/IP */
	STREAM_PROTOCOL_HTTP,			/* HTTP fetch */
	STREAM_PROTOCOL_HTTP_TRANSACTION,/* HTTP POST+fetch */
	STREAM_PROTOCOL_CMP,			/* TCP/IP with CMP packets */
	STREAM_PROTOCOL_LAST			/* Last possible protocol type */
	} STREAM_PROTOCOL_TYPE;

/* The size of the I/O buffer used to read/write data from/to streams backed 
   by persistent files.  These are allocated on-demand on the stack, so they
   shouldn't be made too big.  In addition since they may corespond directly
   to underlying storage media blocks (e.g. disk sectors or flash memory
   segments) they shouldn't be made smaller than the underlying blocksize
   either.  Finally, they should be a power of two (this isn't a strict
   requirement of the code, but is in a good idea in general because of 
   storage media constraints) */

#ifdef CONFIG_CONSERVE_MEMORY
  #define STREAM_BUFSIZE	512
#else
  #define STREAM_BUFSIZE	4096
#endif /* CONFIG_CONSERVE_MEMORY */

/****************************************************************************
*																			*
*							STREAM Class Structures							*
*																			*
****************************************************************************/

/* The STREAM data type */

typedef struct ST {
	/* General information for the stream */
	STREAM_TYPE type;			/* The stream type */
	int flags;					/* Stream flags */
	int status;					/* Current stream status (clib error code) */

	/* Information for memory I/O */
	BYTE *buffer;				/* Buffer to R/W to */
	int bufSize;				/* Total size of buffer */
	int bufPos;					/* Current position in buffer */
	int bufEnd;					/* Last buffer position with valid data */

	/* Information for file I/O */
	int bufCount;				/* File position quantised by buffer size */
#if defined( __WIN32__ ) || defined( __WINCE__ )
	HANDLE hFile;				/* Backing file for the stream */
#elif defined( __AMX__ ) || defined( __BEOS__ ) || defined( __ECOS__ ) || \
	  defined( __RTEMS__ ) || defined( __SYMBIAN32__ ) || \
	  defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	  defined( __UNIX__ ) || defined( __VXWORKS__ ) || defined( __XMK__ )
	int fd;						/* Backing file for the stream */
#elif defined( __MAC__ )
	short refNum;				/* File stream reference number */
	FSSpec fsspec;				/* File system specification */
#elif defined( __PALMOS__ )
	FileRef fileRef;			/* File reference number */
#elif defined( CONFIG_NO_STDIO )
  #if defined( __IBM4758__ )
	char name[ 8 + 1 ];			/* Data item associated with stream */
	BOOLEAN isSensitive;		/* Whether stream contains sensitive data */
  #elif defined( __VMCMS__ )
	char name[ FILENAME_MAX ];	/* Data item associated with stream */
  #endif /* Nonstandard I/O enviroments */
#else
	FILE *filePtr;				/* The file associated with this stream */
#endif /* System-specific file I/O information */

#ifdef USE_TCP
	/* Information for network I/O.  The server FQDN is held in dynamically-
	   allocated storage, the optional path for HTTP is a pointer into the
	   host string at the appropriate location.  For a server, the
	   listenSocket is the (possibly shared) common socket that the server
	   is listening on, the netSocket is the ephemeral socket used for
	   communications.  The timeout value depends on whether the stream is
	   in the connect/handshake phase or the data transfer phase.  The 
	   handshake phase is logically treated as part of the connect phase 
	   even though from the stream point of view it's part of the data 
	   transfer phase.  Initially the stream timeout is set to the connect
	   timeout and the saved timeout is set to the data transfer timeout.  
	   Once the connect/handshake has completed, the stream timeout is set 
	   to the saved data transfer timeout and the saved timeout is cleared */
	STREAM_PROTOCOL_TYPE protocol;/* Network protocol type */
	CRYPT_SESSION iTransportSession;/* cryptlib session as transport layer */
	char *host, *path;
	int port;					/* Host name, path on host, and port */
	int netSocket, listenSocket;/* Network socket */
	int timeout, savedTimeout;	/* Network comms timeout */
	char clientAddress[ 32 ];	/* Client IP address (dotted-decimal) */
	int clientPort;				/* Client port */

	/* Network streams require separate read/write buffers for packet
	   assembly/disassembly */
	BYTE *writeBuffer;			/* Write buffer */
	int writeBufSize;			/* Total size of buffer */
	int writeBufEnd;			/* Last buffer position with valid data */

	/* Network I/O access functions.  The general read and write functions
	   are for the higher-level network access routines such as HTTP and CMP
	   I/O, the transport I/O functions are for transport-level I/O that 
	   sits below the general I/O.  Finally, there's an intermediate function
	   that adds speculative read-ahead buffering to the transport-level 
	   read to improve performance for higher-level protocols like HTTP that
	   have to read a byte at a time in some places */
	int ( *writeFunction )( struct ST *stream, const void *buffer,
							const int length );
	int ( *readFunction )( struct ST *stream, void *buffer, int length );
	int ( *transportConnectFunction )( struct ST *stream, const char *server,
									   const int port );
	void ( *transportDisconnectFunction )( struct ST *stream, 
										   const BOOLEAN fullDisconnect );
	int ( *transportReadFunction )( struct ST *stream, BYTE *buffer,
									const int length, const int flags );
	int ( *transportWriteFunction )( struct ST *stream, const BYTE *buffer,
									 const int length, const int flags );
	BOOLEAN ( *transportOKFunction )( void );
	int ( *transportCheckFunction )( struct ST *stream );
	int ( *bufferedTransportReadFunction )( struct ST *stream, BYTE *buffer,
											const int length, 
											const int flags );
	int ( *bufferedTransportWriteFunction )( struct ST *stream, 
											 const BYTE *buffer,
											 const int length, 
											 const int flags );

	/* Protocol-specific infomation for network I/O */
	char contentType[ CRYPT_MAX_TEXTSIZE + 1 ];	/* HTTP content type */
	char *query;				/* HTTP query URI portion */
	int queryLen;
	CALLBACKFUNCTION callbackFunction;
	void *callbackParams;		/* Callback to change I/O buffer size */

	/* Last-error information returned from lower-level code.  Unlike its
	   use in high-level objects like keysets and devices, we dynamically
	   allocate the error message storage since it's only used for network
	   streams and would lead to a lot of wasted memory in memory streams,
	   which are used constantly throughout cryptlib */
	int errorCode;
	char *errorMessage;
#endif /* USE_TCP */
	} STREAM;

/* Parsed URL information */

typedef enum { URL_TYPE_NONE, URL_TYPE_HTTP, URL_TYPE_HTTPS, URL_TYPE_SSH,
			   URL_TYPE_CMP, URL_TYPE_TSP, URL_TYPE_LAST } URL_TYPE;

typedef struct {
	URL_TYPE type;
	const char *schema, *userInfo, *host, *location;
	int schemaLen, userInfoLen, hostLen, locationLen;
	int port;
	} URL_INFO;

/* Information required when connecting a network stream.  There are so many
   parameters required that we pack them into a struct to keep the interface
   more manageable */

typedef enum {
	NET_OPTION_NONE,			/* No connect option type */
	NET_OPTION_HOSTNAME,		/* Use host/interface name + port */
	NET_OPTION_TRANSPORTSESSION,/* Use network transport session */
	NET_OPTION_NETWORKSOCKET,	/* Use user-supplied network socket */
	NET_OPTION_NETWORKSOCKET_DUMMY,	/* Dummy open to check socket OK */
	NET_OPTION_LAST				/* Last possible connect option type */
	} NET_OPTION_TYPE;

typedef struct {
	/* Network link information, either a remote host and port, a pre-
	   connected network socket, or a cryptlib transport session */
	const char *name;
	int nameLength;
	int port;					/* Host info */
	int networkSocket;			/* Pre-connected network socket */
	CRYPT_SESSION iCryptSession;/* cryptlib transport session */

	/* Auxiliary information: Owning user object, network status 
	   information, general option type */
	CRYPT_USER iUserObject;		/* Owning user object */
	int timeout, connectTimeout;/* Connect and data xfer.timeouts */
	NET_OPTION_TYPE options;	/* Connect options */
	} NET_CONNECT_INFO;

#define initNetConnectInfo( netConnectInfo, netUserObject, netTimeout, \
							netConnectTimeout, netOption ) \
	{ \
	memset( netConnectInfo, 0, sizeof( NET_CONNECT_INFO ) ); \
	( netConnectInfo )->networkSocket = CRYPT_ERROR; \
	( netConnectInfo )->iCryptSession = CRYPT_ERROR; \
	( netConnectInfo )->iUserObject = netUserObject; \
	( netConnectInfo )->timeout = netTimeout; \
	( netConnectInfo )->connectTimeout = netConnectTimeout; \
	( netConnectInfo )->options = netOption; \
	}

/****************************************************************************
*																			*
*							Stream Function Prototypes						*
*																			*
****************************************************************************/

/* Functions corresponding to traditional/stdio-type I/O.  Apart from the
   convenience factor, the use of a macro for stell() also lets it 
   automatically adjust itself to int vs. long data types */

int sputc( STREAM *stream, const int ch );
int sgetc( STREAM *stream );
int sread( STREAM *stream, void *buffer, const int length );
int swrite( STREAM *stream, const void *buffer, const int length );
int sflush( STREAM *stream );
int sseek( STREAM *stream, const long position );
#define stell( stream )	\
		( ( ( stream )->bufCount * ( stream )->bufSize ) + ( stream )->bufPos )
int sioctl( STREAM *stream, const STREAM_IOCTL_TYPE type, void *data,
			const int dataLen );

/* Nonstandard functions: Skip a number of bytes in a stream, peek at the
   next value in the stream */

int sSkip( STREAM *stream, const long offset );
int sPeek( STREAM *stream );

/* Inquire as to the health of a stream */

#define sGetStatus( stream )		( stream )->status
#define sStatusOK( stream )			cryptStatusOK( ( stream )->status )

/* Set/clear user-defined error state for the stream.  The reason for the
   slightly convoluted code in sSetError() is because a conventional if
   statement would cause problems with dangling elses.  In addition this
   construct allows the expression to have a value, so it can be used in
   return statements (a common usage) */

#define sSetError( stream, error )	\
		( stream )->status = ( ( ( stream )->status == CRYPT_OK ) ? \
								 ( error ) : ( stream )->status )
#define sClearError( stream )		( stream )->status = CRYPT_OK

/* Return after setting extended error information for the stream.  We use a 
   macro to make it match the standard return statement, the slightly unusual
   form is required to handle the fact that the helper function is a varargs
   function */

int retExtStreamFn( STREAM *stream, const int status, const char *format, ... );
#define retExtStream	return retExtStreamFn

/* Stream query functions to determine whether a stream is a null stream or
   a memory-mapped file stream.  This is used to short-circuit unnecessary 
   data transfers in higher-level code where writing to a null stream is 
   used to determine overall data sizes and when we can eliminate extra
   buffer allocation if all data is available in memory */

#define sIsNullStream( stream )		( ( stream )->type == STREAM_TYPE_NULL )
#define sIsMemMappedStream( stream ) \
		( ( ( stream )->type == STREAM_TYPE_FILE ) && \
		  ( ( stream )->flags & STREAM_FFLAG_MMAPPED ) )

/* Determine the total size of a memory stream, the amount of data left to be
   read, and return a pointer to the current position in a streams internal
   memory buffer.  The latter is used by some routines that need to process
   data in a stream buffer after it's been written to the wire format */

#define sMemBufSize( stream )	( ( stream )->bufSize )
#define sMemDataLeft( stream )	( ( ( stream )->type == STREAM_TYPE_NULL ) ? 0 : \
								  ( stream )->bufSize - ( stream )->bufPos )
#define sMemBufPtr( stream )	( ( ( stream )->type == STREAM_TYPE_NULL ) ? NULL : \
								  ( stream )->buffer + ( stream )->bufPos )

/* Functions to work with memory streams */

int sMemOpen( STREAM *stream, void *buffer, const int length );
int sMemClose( STREAM *stream );
int sMemConnect( STREAM *stream, const void *buffer, const int length );
int sMemDisconnect( STREAM *stream );

/* Functions to work with file streams */

int sFileOpen( STREAM *stream, const char *fileName, const int mode );
int sFileClose( STREAM *stream );

/* Convert a file stream to a memory stream */

int sFileToMemStream( STREAM *memStream, STREAM *fileStream,
					  void **bufPtrPtr, const int length );

/* Functions to work with network streams */

int sNetParseURL( URL_INFO *urlInfo, const char *url, const int urlLen );
int sNetConnect( STREAM *stream, const STREAM_PROTOCOL_TYPE protocol,
				 const NET_CONNECT_INFO *connectInfo, char *errorMessage, 
				 int *errorCode );
int sNetListen( STREAM *stream, const STREAM_PROTOCOL_TYPE protocol,
				const NET_CONNECT_INFO *connectInfo, char *errorMessage,
				int *errorCode );
int sNetDisconnect( STREAM *stream );
void sNetGetErrorInfo( STREAM *stream, char *errorString, int *errorCode );

/* Special-case file I/O calls */

BOOLEAN fileReadonly( const char *fileName );
void fileClearToEOF( const STREAM *stream );
void fileErase( const char *fileName );
void fileBuildCryptlibPath( char *path, const char *fileName,
							const BUILDPATH_OPTION_TYPE option );

/* Initialisation/shutdown functions for network stream interfaces */

#ifdef USE_TCP
  int netInitTCP( void );
  void netSignalShutdown( void );
  void netEndTCP( void );
#else
  #define netInitTCP()						CRYPT_OK
  #define netSignalShutdown()
  #define netEndTCP()
#endif /* NET_TCP */

/* Prototypes for network mapping functions */

#ifdef USE_TCP
  int setAccessMethodTCP( STREAM *stream );
  int setStreamLayerHTTP( STREAM *stream );
  int setStreamLayerCMP( STREAM *stream );
#endif /* USE_TCP */
#endif /* _STREAM_DEFINED */
