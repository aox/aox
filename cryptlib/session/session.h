/****************************************************************************
*																			*
*						Secure Session Routines Header File					*
*						 Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#ifndef _SES_DEFINED

#define _SES_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../misc/stream.h"
  #else
	#include "misc/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* Session information flags.  The sendClosed flag indicates that the remote
   system has closed its receive channel, which means that no more data can
   be sent to it.  It does not however mean that no more data can be
   received on our receive channel.  The isSecure flag indicates that the 
   session has passed the initial handshake stage and all data is now being
   encrypted/MACd/whatever.  The isCryptlib flag indicates that the peer is
   also running cryptlib, which means that we can apply cryptlib-specific
   optimistions and security enhancements.  The encoding flags indicate that
   the user name and password are stored in cryptlib XXXXX-XXXXX-... style
   encoding and need to be converted to binary form before use.  The 
   changenotify values indicate that when changes are made to the indicated
   attribute (normally handled at the general session level), the changes
   are reflected down to the protocol-specific code for protocol-specific
   handling */

#define SESSION_NONE				0x000	/* No session flags */
#define SESSION_ISOPEN				0x001	/* Session is active */
#define SESSION_SENDCLOSED			0x002	/* Send channel is closed */
#define SESSION_ISSERVER			0x004	/* Session is server session */
#define SESSION_ISSECURE			0x008	/* Session has entered secure state */
#define SESSION_ISCRYPTLIB			0x010	/* Peer is running cryptlib */
#define SESSION_ISHTTPTRANSPORT		0x020	/* Session using HTTP transport */
#define SESSION_ISPNPPKI			0x040	/* Session is PnP PKI-capable */
#define SESSION_ISENCODEDUSERID		0x080	/* User ID uses XXX-XXX encoding */
#define SESSION_ISENCODEDPW			0x100	/* Password uses XXX-XXX encoding */
#define SESSION_USEALTTRANSPORT		0x200	/* Use alternative to HTTP xport */
#define SESSION_CHANGENOTIFY_USERID	0x400	/* Notify session of userID change */
#define SESSION_CHANGENOTIFY_PASSWD	0x800	/* Notify session of passwd change */

/* Needed-information flags used by protocol-specific handlers to indicate
   that the caller must set the given attributes in the session information
   before the session can be activated.  This allows it to be checked at the
   general cryptses.c level rather than at the per-protocol level.
   
   Some session types have private keys optional but if present they must 
   meet certain requirements, this is indicated by omitting the presence-
   check SESSION_NEEDS_PRIVATEKEY but specifying one or more of the 
   SESSION_NEEDS_PRIVKEYxxx options */

#define SESSION_NEEDS_USERID		0x0001	/* Must have userID */
#define SESSION_NEEDS_PASSWORD		0x0002	/* Must have password */
#define SESSION_NEEDS_PRIVATEKEY	0x0004	/* Must have private key */
#define SESSION_NEEDS_PRIVKEYCRYPT	0x0008	/* Priv.key must have cert */
#define SESSION_NEEDS_PRIVKEYSIGN	0x0010	/* Priv.key must have sig.capabil.*/
#define SESSION_NEEDS_PRIVKEYCERT	0x0020	/* Priv.key must have crypt capabil.*/
#define SESSION_NEEDS_PRIVKEYCACERT	0x0040	/* Priv key must have CA cert */
#define SESSION_NEEDS_KEYORPASSWORD	0x0080	/* PW can be used in place of privK */
#define SESSION_NEEDS_REQUEST		0x0100	/* Must have request obj.*/
#define SESSION_NEEDS_KEYSET		0x0200	/* Must have cert keyset */
#define SESSION_NEEDS_CERTSTORE		0x0400	/* Keyset must be cert store */

/* When reading packets for a secure session protocol, we need to 
   communicate read state information which is more complex than the usual 
   length or error code.  The following values modify the standard return
   value (either a positive or zero byte count or a negative error value) 
   with additional context-specific information */

typedef enum {
	READINFO_NONE,						/* No special handling */
	READINFO_HEADERPAYLOAD,				/* Header read got some payload data */
	READINFO_NOOP,						/* Packet was no-op, try again */
	READINFO_PARTIAL,					/* Partial packet, try again */
	READINFO_FATAL,						/* Treat errors as fatal */
	READINFO_LAST						/* Last possible read info */
	} READSTATE_INFO;

/* Protocol-specific information for each session */

typedef struct {
	STREAM_PROTOCOL_TYPE type;			/* Protocol type */
	char *uriType;						/* Protocol URI type (e.g. "cmp://") */
	int port;							/* Protocol port */
	} ALTPROTOCOL_INFO;

typedef struct {
	/* Information required for all sessions: Whether this is a secure
	   session or request/response protocol, protocol-specific flags, the
	   default port for the protocol, flags for attributes required before
	   the session can be activated, the default protocol version and lowest
	   and highest allowed versions, and the transport-protocol client and 
	   server content-types */
	BOOLEAN isReqResp;					/* Whether session is req/resp session */
	int flags;							/* Protocol flags */
	int port;							/* Default port */
	int clientReqAttrFlags, serverReqAttrFlags; /* Required attributes */
	int version, minVersion, maxVersion;/* Protocol version/subtype */
	const char *clientContentType, *serverContentType;
										/* HTTP content-type */

	/* Session type-specific information: The send and receive buffer size,
	   the alternative transport protocol for request/response sessions if
	   HTTP isn't being used, the minimum allowed size for the server's
	   private key */
	int bufSize;						/* Send/receive buffer sizes */
	int sendBufStartOfs, sendBufMaxPos;	/* Payload data start and end */
	const ALTPROTOCOL_INFO *altProtocolInfo; /* Alternative xport protocol */
	int requiredPrivateKeySize;			/* Min.allowed size for private key */
	} PROTOCOL_INFO;

/* A value to initialise the session type-specific buffer size values to
   default settings for request/response protocols */

#define BUFFER_SIZE_DEFAULT		0, 0, 0

/* The structure that stores the information on a session */

typedef struct SI {
	/* Control and status information */
	CRYPT_SESSION_TYPE type;			/* Session type */
	const PROTOCOL_INFO *protocolInfo;	/* Session subtype information */
	int version;						/* Protocol version/subtype */
	CRYPT_ALGO_TYPE cryptAlgo;			/* Negotiated encryption algo */
	CRYPT_ALGO_TYPE integrityAlgo;		/* Negotiated integrity prot.algo */
	int flags, protocolFlags;			/* Session info, protocol-specific flags */

	/* When we add generic attributes to the session, we occasionally need to
	   perform protocol-specific checking of the attributes being added.  The
	   following values are used to tell the generic cryptses.c code which
	   checks need to be performed */
	int clientReqAttrFlags, serverReqAttrFlags; /* Required attributes */
	int requiredPasswordStatus;			/* Password info OK if > 0 */

	/* The overall session status.  If we run into a nonrecoverable error
	   (which for the encrypted session types means just about anything,
	   once we lose sync we're toast) we remember the status here so that
	   any further attempts to work with the session will return this
	   status.  Since an error on one side of the channel (e.g. bad data on
	   read) doesn't necessarily affect the operation of the other side, we
	   keep track of the two sides independantly, and only set the error
	   state for both sides for network-related errors.

	   In many cases there'll still be data in the internal buffer that the
	   user can read without triggering an error response so before we set
	   the error state we set the pending error state and only move the
	   pending state into the current state once all data still present in
	   the buffer has been read */
	int readErrorState, writeErrorState;/* Current error state */
	int pendingErrorState;				/* Error state when buffer emptied */

	/* Data buffer information.  In protocols that consist of single
	   messages sent back and forth only the receive buffer is used for
	   sending and receiving data, this buffer is somewhat more flexible
	   since it's associated with extra variables for handling the current
	   position in the buffer (bufPos) vs.the total amount of data present
	   (bufEnd) */
	BYTE *sendBuffer, *receiveBuffer;	/* Data buffer */
	int sendBufSize, receiveBufSize;	/* Total buffer size */
	int sendBufPos, receiveBufPos;		/* Current position in buffer */
	int sendBufStartOfs, receiveBufStartOfs; /* Space for header in buffer */
	int receiveBufEnd;					/* Total data in buffer */

	/* When reading encrypted data packets we typically end up with a partial
	   packet in the read buffer that we can't process until the remainder
	   arrives, the following variables holds the eventual length of the
	   pending data packet, the amount of data at the start of the packet
	   that has already been MACd and decrypted (for protocols that require
	   processing of the packet header which is normally discarded as out-of-
	   band data), and the amount of data remaining to be read */
	int pendingPacketLength;			/* Lending of pending data packet */
	int pendingPacketPartialLength;		/* Length of data already processed */
	int pendingPacketRemaining;			/* Bytes remaining to be read */

	/* Unlike payload data, the packet header can't be read in sectiosn but
	   must be read atomically since all of the header information needs to
	   be processed at once.  The following value is usually zero, if it's
	   nonzero it records how much of the header has been read so far */
	int partialHeaderLength;			/* Header bytes read so far */

	/* The session generally has various ephemeral contexts associated with
	   it, some short-term (e.g.public-key contexts used to establish the
	   session) and some long-term (e.g.encryption contexts used to perform
	   bulk data encryption).  These contexts are ephemeral ones that are
	   created as part of the session, long-term ones (e.g.signature keys
	   used for authentication) are held elsewhere */
	CRYPT_CONTEXT iKeyexCryptContext;	/* Key exchange encryption */
	CRYPT_CONTEXT iKeyexAuthContext;	/* Key exchange authentication */
	CRYPT_CONTEXT iCryptInContext, iCryptOutContext;
										/* In/outgoing data encryption */
	CRYPT_CONTEXT iAuthInContext, iAuthOutContext;
										/* In/outgoing auth/integrity */
	CRYPT_CERTIFICATE iCertRequest, iCertResponse;
										/* Cert request/response */
	int cryptBlocksize, authBlocksize;	/* Block size of crypt, auth.algos */

	/* Other session state information.  The incoming and outgoing packet
	   sequence number, for detecting insertion/deletion attacks */
	long readSeqNo, writeSeqNo;			/* Packet sequence number */

	/* User name and password, key fingerprint, and private key, which are
	   required to authenticate the client or server in some protocols */
	char userName[ CRYPT_MAX_TEXTSIZE ], password[ CRYPT_MAX_TEXTSIZE ];
	int userNameLength, passwordLength;	/* Username and password */
	BYTE keyFingerprint[ CRYPT_MAX_HASHSIZE ];
	int keyFingerprintSize;				/* Server key fingerprint (hash) */
	CRYPT_CONTEXT privateKey;			/* Authentication private key */

	/* Certificate store for cert management protocols like OCSP and CMP
	   and private-key keyset for PnP PKI protocols */
	CRYPT_KEYSET cryptKeyset;			/* Certificate store */
	CRYPT_HANDLE privKeyset;			/* Private-key keyset/device */

	/* SSL protocol-specific information.  The SSL MAC read/write secrets
	   are required because SSL 3.0 uses a proto-HMAC that isn't handled
	   by cryptlib.  We leave the data in normal memory because it's only
	   usable for an active attack which means recovering it from swap
	   afterwards isn't a problem */
	BYTE sslMacReadSecret[ CRYPT_MAX_HASHSIZE ],
		 sslMacWriteSecret[ CRYPT_MAX_HASHSIZE ];	/* Proto-HMAC keys */
	int sslSessionCacheID;				/* Session cache ID for this session */

	/* SSH protocol-specific information.  The type and pad length are
	   extracted from the packet header during header processing */
	int sshPacketType, sshPadLength;	/* Packet type and padding length */
	char sshSubsystem[ CRYPT_MAX_TEXTSIZE ];
	int sshSubsystemLength;				/* Requested subsystem */
	char sshPortForward[ CRYPT_MAX_TEXTSIZE ];
	int sshPortForwardLength;			/* Requested port forwarding */
	long sshChannel;					/* Data channel ID */
	long sshWindowCount;				/* Bytes sent since window reset */

	/* TSP protocol-specific information.  The message imprint (hash)
	   algorithm and hash value */
	CRYPT_ALGO_TYPE tspImprintAlgo;		/* Imprint (hash) algorithm */
	BYTE tspImprint[ CRYPT_MAX_HASHSIZE ];
	int tspImprintSize;					/* Message imprint (hash) */

	/* CMP protocol-specific information.  The PKI user info, saved MAC 
	   context from a previous transaction (if any), and request subtype */
	CRYPT_CERTIFICATE cmpUserInfo;		/* PKI user info */
	CRYPT_CONTEXT cmpSavedMacContext;	/* MAC context from prev.trans */
	int cmpRequestType;					/* CMP request subtype */

	/* Network connection information */
	CRYPT_SESSION transportSession;		/* Transport mechanism */
	int networkSocket;					/* User-supplied network socket */
	int timeout, connectTimeout;		/* Connect and data xfer.timeouts */
	STREAM stream;						/* Network I/O stream */
	char serverName[ MAX_URL_SIZE + 1 ];/* Server name and port */
	int serverPort;
	char clientName[ MAX_URL_SIZE + 1 ];/* Client name and port */
	int clientPort;

	/* Last-error information.  To help developers in debugging, we store
	   the error code and error text (if available) */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE + 1 ];

	/* Pointers to session access methods.  Stateful sessions use the read/
	   write functions, stateless ones use the transact function */
	void ( *shutdownFunction )( struct SI *sessionInfoPtr );
	int ( *connectFunction )( struct SI *sessionInfoPtr );
	int ( *getAttributeFunction )( struct SI *sessionInfoPtr, void *data,
								   const CRYPT_ATTRIBUTE_TYPE type );
	int ( *setAttributeFunction )( struct SI *sessionInfoPtr, const void *data,
								   const CRYPT_ATTRIBUTE_TYPE type );
	int ( *checkAttributeFunction )( struct SI *sessionInfoPtr,
									 const CRYPT_HANDLE cryptHandle,
									 const CRYPT_ATTRIBUTE_TYPE type );
	int ( *transactFunction )( struct SI *sessionInfoPtr );
	int ( *readHeaderFunction )( struct SI *sessionInfoPtr,
								 READSTATE_INFO *readInfo );
	int ( *processBodyFunction )( struct SI *sessionInfoPtr,
								  READSTATE_INFO *readInfo );
	int ( *writeDataFunction )( struct SI *sessionInfoPtr );

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle and the handle of the user who owns this object.
	   The former is used when sending messages to the object when only the
	   xxx_INFO is available, the latter is used to avoid having to fetch the
	   same information from the system object table */
	CRYPT_HANDLE objectHandle;
	CRYPT_USER ownerHandle;
	} SESSION_INFO;

/* Prototypes for various utility functions in cryptses.c.  retExt() returns 
   after setting extended error information for the session.  We use a macro 
   to make it match the standard return statement, the slightly unusual form 
   is required to handle the fact that the helper function is a varargs
   function.  readFixedHeader() performs an atomic read of the fixed portion
   of a secure data session packet header.  read/writePkiDatagram() read and
   write a PKI (ASN.1-encoded) message.  initSessionNetConnectInfo() is an
   extended form of the STREAM-level initNetConnectInfo() that initialises the
   connect info using the session object data */

int retExtFnSession( SESSION_INFO *sessionInfoPtr, const int status, 
					 const char *format, ... );
#define retExt	return retExtFnSession
int readFixedHeader( SESSION_INFO *sessionInfoPtr, const int headerSize );
int readPkiDatagram( SESSION_INFO *sessionInfoPtr );
int writePkiDatagram( SESSION_INFO *sessionInfoPtr );
void initSessionNetConnectInfo( const SESSION_INFO *sessionInfoPtr,
								NET_CONNECT_INFO *connectInfo );

/* Prototypes for session mapping functions */

#ifdef USE_CMP
  int setAccessMethodCMP( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodCMP( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_CMP */
#ifdef USE_RTCS
  int setAccessMethodRTCS( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodRTCS( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_RTCS */
#ifdef USE_OCSP
  int setAccessMethodOCSP( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodOCSP( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_OCSP */
#ifdef USE_SCEP
  int setAccessMethodSCEP( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodSCEP( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_SCEP */
#if defined( USE_SSH1 ) || defined( USE_SSH2 )
  int setAccessMethodSSH( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodSSH( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_SSH1 || USE_SSH2 */
#ifdef USE_SSL
  int setAccessMethodSSL( SESSION_INFO *sessionInfoPtr );
  int initSessionCache( void );
  void endSessionCache( void );
#else
  #define setAccessMethodSSL( x )	CRYPT_ARGERROR_NUM1
  #define initSessionCache()		CRYPT_OK
  #define endSessionCache()
#endif /* USE_SSL */
#ifdef USE_TSP
  int setAccessMethodTSP( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodTSP( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_TCP */
#endif /* _SES_DEFINED */
