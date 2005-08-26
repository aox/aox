/****************************************************************************
*																			*
*						Secure Session Routines Header File					*
*						 Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#ifndef _SES_DEFINED

#define _SES_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../io/stream.h"
  #else
	#include "io/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/****************************************************************************
*																			*
*							Session Types and Constants						*
*																			*
****************************************************************************/

/* Session information flags.  These are:

	SESSION_ISOPEN: The session is active.

	SESSION_PARTIALOPEN: The session is partially active pending 
			confirmation of credentials such as a username and password
			or certificate.  This means that the session remains in the
			handshake state, with the handshake being completed once the 
			credentials have been confirmed.

	SESSION_SENDCLOSED: The remote system has closed its receive channel, 
			which means that no more data can be sent to it.  This does not 
			however mean that no more data can be received on our receive 
			channel.

	SESSION_NOREPORTERROR: Don't update the extended error information if
			an error occurs, since this has already been set.  This is
			typically used when performing shutdown actions in response to
			a protocol error, when a network error such as the other side
			closing the connection would overwrite the details of the
			error that caused the shutdown to be performed.

	SESSION_ISSERVER: The session is a server session.

	SESSION_ISSECURE_READ:  The read/write channel is in the secure state, 
	SESSION_ISSECURE_WRITE: for secure data transport sessions.  In other
			words the session has passed the initial handshake stage and all 
			data is now being encrypted/MACd/whatever.

	SESSION_ISCRYPTLIB: The peer is also running cryptlib, which means that 
			we can apply cryptlib-specific optimistions and security 
			enhancements.

	SESSION_ISHTTPTRANSPORT: The session is using HTTP transport, for 
			request/response sessions.

	SESSION_USEALTTRANSPORT: The protocol usually uses HTTP but also 
			supports an alternative transport type, which should be used 
			in place of HTTP.
	
	SESSION_USEHTTPTUNNEL: The protocol is (potentially) tunneled over an 
			HTTP proxy.  In other words if CRYPT_OPTION_NET_HTTP_PROXY is
			set, the protocol talks through an HTTP proxy rather than a
			direct connection */

#define SESSION_NONE				0x0000	/* No session flags */
#define SESSION_ISOPEN				0x0001	/* Session is active */
#define SESSION_PARTIALOPEN			0x0002	/* Session is partially active */
#define SESSION_SENDCLOSED			0x0004	/* Send channel is closed */
#define SESSION_NOREPORTERROR		0x0008	/* Don't report network-level errors */
#define SESSION_ISSERVER			0x0010	/* Session is server session */
#define SESSION_ISSECURE_READ		0x0020	/* Session read ch.in secure state */
#define SESSION_ISSECURE_WRITE		0x0040	/* Session write ch.in secure state */
#define SESSION_ISCRYPTLIB			0x0080	/* Peer is running cryptlib */
#define SESSION_ISHTTPTRANSPORT		0x0100	/* Session using HTTP transport */
#define SESSION_USEHTTPTUNNEL		0x0200	/* Session uses HTTP tunnel */
#define SESSION_USEALTTRANSPORT		0x0400	/* Use alternative to HTTP xport */

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
#define SESSION_NEEDS_CERTSOURCE	0x0800	/* Keyset must be R/O non-certstore */

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

/****************************************************************************
*																			*
*								Session Structures							*
*																			*
****************************************************************************/

/* Protocol-specific information for each session.  The alt.protocol info can
   be used when a secondary transport protocol is available (e.g. HTTP tunnel
   for SSL), if the URI type matches then the alt.protocol type, port, and
   protocol flags are used, the mask is used to mask out existing flags and
   the new flags value is used to set replacement flags */

typedef struct {
	const STREAM_PROTOCOL_TYPE type;	/* Protocol type */
	const char *uriType;				/* Protocol URI type (e.g. "cmp://") */
	const int port;						/* Protocol port */
	const int oldFlagsMask;				/* Mask for current protocol flags */
	const int newFlags;					/* Replacement flags */
	} ALTPROTOCOL_INFO;

typedef struct {
	/* Information required for all sessions: Whether this is a secure
	   session or request/response protocol, protocol-specific flags, the
	   default port for the protocol, flags for attributes required before
	   the session can be activated, the default protocol version and lowest
	   and highest allowed versions, and the transport-protocol client and 
	   server content-types */
	const BOOLEAN isReqResp;			/* Whether session is req/resp session */
	const int flags;					/* Protocol flags */
	const int port;						/* Default port */
	const int clientReqAttrFlags, serverReqAttrFlags; /* Required attributes */
	const int version, minVersion, maxVersion;/* Protocol version/subtype */
	const char *clientContentType, *serverContentType;
										/* HTTP content-type */

	/* Session type-specific information: The send and receive buffer size,
	   the alternative transport protocol for request/response sessions if
	   HTTP isn't being used, the minimum allowed size for the server's
	   private key */
	const int bufSize;					/* Send/receive buffer sizes */
	const int sendBufStartOfs;			/* Payload data start */
	const int maxPacketSize;			/* Maximum packet (payload data) size */
	const ALTPROTOCOL_INFO *altProtocolInfo; /* Alternative xport protocol */
	const int requiredPrivateKeySize;	/* Min.allowed size for private key */
	} PROTOCOL_INFO;

/* A value to initialise the session type-specific buffer size values to
   default settings for request/response protocols */

#define BUFFER_SIZE_DEFAULT		0, 0, 0

/* Attribute flags.  These are:

	ATTR_FLAG_ENCODEDVALUE: The attribute value is stored in cryptlib 
			XXXXX-XXXXX-... style encoding and needs to be converted to 
			binary form before use.
	
	ATTR_FLAG_MULTIVALUED: Multiple instances of the attribute are
			permitted.  This complements ATTR_FLAG_OVERWRITE in that
			instead of overwriting the single existing instance, another
			instance is created.
	
	ATTR_FLAG_COMPOSITE: Composite attribute containing sub-attribute
			data in the in the { value, valueLength } buffer.  The
			attribute cursor can be moved within the attribute using
			the internal virtual cursor.
			
	ATTR_FLAG_CURSORMOVED: The attribute (group) cursor has moved, so
			the virtual cursor within the attribute needs to be reset
			the next time that it's referenced.  This is used with
			composite attributes, whose internal structure is opaque
			to the general session code */

#define ATTR_FLAG_NONE			0x00	/* No attribute flag */
#define ATTR_FLAG_ENCODEDVALUE	0x01	/* Value uses XXX-XXX encoding */
#define ATTR_FLAG_MULTIVALUED	0x02	/* Multiple instances permitted */
#define ATTR_FLAG_COMPOSITE		0x04	/* Composite attribute */
#define ATTR_FLAG_CURSORMOVED	0x08	/* Attribute virtual cursor reset */

/* The helper function used to access session subtype-specific internal
   attributes within an attribute list entry */

struct AL;	/* Forward declaration for attribute-list access function */

typedef int ( *ATTRACCESSFUNCTION )( struct AL *attributeListPtr,
									 const ATTR_TYPE attrGetType );

/* An attribute list used to store session-related attributes such as 
   user names, passwords, and public keys.  Since some of these can be
   composite attributes (with information stored in the { value, 
   valueLength } buffer), we implement a virtual cursor that points to the 
   currently-selected sub-attribute within the composite attribute */

typedef struct AL {
	/* Identification and other information for this attribute */
	CRYPT_ATTRIBUTE_TYPE attribute;		/* Attribute type */
	ATTRACCESSFUNCTION accessFunction;	/* Internal attribute access fn.*/
	int flags;							/* Attribute data flags */

	/* The data payload for this attribute.  If it's numeric data such as 
	   a small integer or context, we store it in the intValue member.  If 
	   it's a string or composite attribute data, we store it in the 
	   variable-length buffer */
	long intValue;						/* Integer value for simple types */
	void *value;						/* Attribute value */
	int valueLength;					/* Attribute value length */

	/* The previous and next list element in the linked list of elements */
	struct AL *prev, *next;				/* Prev, next item in the list */

	/* Variable-length storage for the attribute data */
	DECLARE_VARSTRUCT_VARS;
	} ATTRIBUTE_LIST;

/* Deferred response information.  When we get a request, we may be in the 
   middle of assembling or sending a data packet, so the response has to be 
   deferred until after the data packet has been completed and sent.  The
   following structure is used to hold the response data until the send
   channel is clear */

#define SSH_MAX_RESPONSESIZE	16		/* 2 * channelNo + 2 * param */

typedef struct {
	int type;							/* Response type */
	BYTE data[ SSH_MAX_RESPONSESIZE ];	/* Encoded response data */
	int dataLen;
	} SSH_RESPONSE_INFO;

/* The internal fields in a session that hold data for the various session
   types */

typedef struct {
	/* Session state information */
	int sessionCacheID;					/* Session cache ID for this session */
	int ivSize;							/* Explicit IV size for TLS 1.1 */

	/* The incoming and outgoing packet sequence number, for detecting 
	   insertion/deletion attacks */
	long readSeqNo, writeSeqNo;

	/* The SSL MAC read/write secrets are required because SSL 3.0 uses a 
	   proto-HMAC that isn't handled by cryptlib.  We leave the data in 
	   normal memory because it's only usable for an active attack, which 
	   means that recovering it from swap afterwards isn't a problem */
	BYTE macReadSecret[ CRYPT_MAX_HASHSIZE ];
	BYTE macWriteSecret[ CRYPT_MAX_HASHSIZE ];
	} SSL_INFO;

typedef struct {
	/* The packet type and padding length, which are extracted from the 
	   packet header during header processing */
	int packetType, padLength;

	/* The incoming and outgoing packet sequence number, for detecting 
	   insertion/deletion attacks */
	long readSeqNo, writeSeqNo;

	/* Per-channel state information */
	int currReadChannel, currWriteChannel; /* Current active R/W channels */
	int nextChannelNo;					/* Next SSH channel no.to use */
	int channelIndex;					/* Current cryptlib unique channel ID */

	/* Deferred response data, used to enqueue responses when unwritten data 
	   remains in the send buffer */
	SSH_RESPONSE_INFO response;

	/* Whether an SSH user authentication packet has been read ready for the
	   server to act on */
	BOOLEAN authRead;
	} SSH_INFO;

typedef struct {
	/* The message imprint (hash) algorithm and hash value */
	CRYPT_ALGO_TYPE imprintAlgo;
	BYTE imprint[ CRYPT_MAX_HASHSIZE ];
	int imprintSize;
	} TSP_INFO;

typedef struct {
	/* CMP request subtype, user info and protocol flags */
	int requestType;					/* CMP request subtype */
	CRYPT_CERTIFICATE userInfo;			/* PKI user info */
	int flags;							/* Protocl flags */

	/* The saved MAC context from a previous transaction (if any) */
	CRYPT_CONTEXT savedMacContext;		/* MAC context from prev.trans */
	} CMP_INFO;

/* Defines to make access to the union fields less messy */

#define sessionSSH		sessionInfo.sshInfo
#define sessionSSL		sessionInfo.sslInfo
#define sessionTSP		sessionInfo.tspInfo
#define sessionCMP		sessionInfo.cmpInfo

/* The structure that stores the information on a session */

typedef struct SI {
	/* Control and status information */
	CRYPT_SESSION_TYPE type;			/* Session type */
	const PROTOCOL_INFO *protocolInfo;	/* Session subtype information */
	int version;						/* Protocol version/subtype */
	CRYPT_ALGO_TYPE cryptAlgo;			/* Negotiated encryption algo */
	CRYPT_ALGO_TYPE integrityAlgo;		/* Negotiated integrity prot.algo */
	int flags, protocolFlags;			/* Session info, protocol-specific flags */
	int authResponse;					/* Response to user-auth request */

	/* Session type-specific information */
	union {
		SSL_INFO *sslInfo;
		SSH_INFO *sshInfo;
		TSP_INFO *tspInfo;
		CMP_INFO *cmpInfo;
		} sessionInfo;

	/* When we add generic attributes to the session, we occasionally need to
	   perform protocol-specific checking of the attributes being added.  The
	   following values are used to tell the generic cryptses.c code which
	   checks need to be performed */
	int clientReqAttrFlags, serverReqAttrFlags; /* Required attributes */

	/* The overall session status.  If we run into a nonrecoverable error
	   (which for the encrypted session types means just about anything,
	   once we lose sync we're toast) we remember the status here so that
	   any further attempts to work with the session will return this
	   status.  Since an error on one side of the channel (e.g. bad data on
	   read) doesn't necessarily affect the operation of the other side, we
	   keep track of the two sides independantly, and only set the error
	   state for both sides for network-related errors.

	   In many cases there'll still be data in the internal buffer that the
	   user can read/write without triggering an error response so before we 
	   set the error state we set the pending error state and only move the
	   pending state into the current state once all data still present in
	   the buffer has been read */
	int readErrorState, writeErrorState;/* Current error state */
	int pendingReadErrorState, pendingWriteErrorState;
										/* Error state when buffer emptied */

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
	int maxPacketSize;					/* Maximum packet (payload data) size */

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

	/* Unlike payload data, the packet header can't be read in sections but
	   must be read atomically since all of the header information needs to
	   be processed at once.  The following value is usually zero, if it's
	   nonzero it records how much of the header has been read so far */
	int partialHeaderLength;			/* Header bytes read so far */

	/* When sending data we can also end up with partially-processed packets
	   in the send buffer, but for sending we prevent further packets from
	   being added until the current one is flushed.  To handle this all we
	   need is a simple high-water-mark indicator that indicates the start 
	   position of any yet-to-be-written data */
	BOOLEAN partialWrite;				/* Unwritten data remains in buffer */
	int sendBufPartialBufPos;			/* Progress point of partial write */

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

	/* The private key, which is required to authenticate the client or 
	   server in some protocols */
	CRYPT_CONTEXT privateKey;			/* Authentication private key */

	/* Certificate store for cert management protocols like OCSP and CMP
	   and private-key keyset for PnP PKI protocols */
	CRYPT_KEYSET cryptKeyset;			/* Certificate store */
	CRYPT_HANDLE privKeyset;			/* Private-key keyset/device */

	/* Session-related attributes such as username and password */
	ATTRIBUTE_LIST *attributeList, *attributeListCurrent;

	/* Network connection information.  The reason why the client and server
	   info require separate storage is that (on the server) we may be 
	   binding to a specific interface (requiring a server name) and we need
	   to record where the remote system's connection is coming from 
	   (requiring a client name) */
	CRYPT_SESSION transportSession;		/* Transport mechanism */
	int networkSocket;					/* User-supplied network socket */
	int readTimeout, writeTimeout, connectTimeout;
										/* Connect and data xfer.timeouts */
	STREAM stream;						/* Network I/O stream */

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
	int ( *preparePacketFunction )( struct SI *sessionInfoPtr );

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle and the handle of the user who owns this object.
	   The former is used when sending messages to the object when only the
	   xxx_INFO is available, the latter is used to avoid having to fetch the
	   same information from the system object table */
	CRYPT_HANDLE objectHandle;
	CRYPT_USER ownerHandle;

	/* Variable-length storage for the type-specific data */
	DECLARE_VARSTRUCT_VARS;
	} SESSION_INFO;

/****************************************************************************
*																			*
*								Session Functions							*
*																			*
****************************************************************************/

/* Prototypes for utility functions in cryptses.c.  retExt() returns after 
   setting extended error information for the session.  We use a macro to 
   make it match the standard return statement, the slightly unusual form is 
   required to handle the fact that the helper function is a varargs 
   function.
   
   In addition to the standard retExt() we also have an extended-form version
   of the function that takes an additional parameter, a handle to an object
   that may provide additional error information.  This is used when (for
   example) an operation references a keyset, where the keyset also contains
   extended error information */

int retExtFnSession( SESSION_INFO *sessionInfoPtr, const int status, 
					 const char *format, ... );
#define retExt	return retExtFnSession

int retExtExFnSession( SESSION_INFO *sessionInfoPtr, 
					   const int status, const CRYPT_HANDLE extErrorObject, 
					   const char *format, ... );
#define retExtEx	return retExtExFnSession

/* Session attribute management functions */

int addSessionAttribute( ATTRIBUTE_LIST **listHeadPtr,
						 const CRYPT_ATTRIBUTE_TYPE attributeType,
						 const void *data, const int dataLength );
int addSessionAttributeEx( ATTRIBUTE_LIST **listHeadPtr,
						   const CRYPT_ATTRIBUTE_TYPE attributeType,
						   const void *data, const int dataLength,
						   const ATTRACCESSFUNCTION accessFunction, 
						   const int flags );
int updateSessionAttribute( ATTRIBUTE_LIST **listHeadPtr,
							const CRYPT_ATTRIBUTE_TYPE attributeType,
							const void *data, const int dataLength,
							const int dataMaxLength, const int flags );
const ATTRIBUTE_LIST *findSessionAttribute( const ATTRIBUTE_LIST *attributeListPtr,
											const CRYPT_ATTRIBUTE_TYPE attributeType );
void resetSessionAttribute( ATTRIBUTE_LIST *attributeListPtr,
							const CRYPT_ATTRIBUTE_TYPE attributeType );
void deleteSessionAttribute( ATTRIBUTE_LIST **attributeListHead,
							 ATTRIBUTE_LIST *attributeListPtr );

/* Prototypes for functions in session.c */

int initSessionIO( SESSION_INFO *sessionInfoPtr );
void initSessionNetConnectInfo( const SESSION_INFO *sessionInfoPtr,
								NET_CONNECT_INFO *connectInfo );
int activateSession( SESSION_INFO *sessionInfoPtr );
int getSessionData( SESSION_INFO *sessionInfoPtr, void *data, 
					const int length, int *bytesCopied );
int putSessionData( SESSION_INFO *sessionInfoPtr, const void *data,
					const int length, int *bytesCopied );
int readFixedHeader( SESSION_INFO *sessionInfoPtr, const int headerSize );
int readPkiDatagram( SESSION_INFO *sessionInfoPtr );
int writePkiDatagram( SESSION_INFO *sessionInfoPtr );
int sendCloseNotification( SESSION_INFO *sessionInfoPtr,
						   const void *data, const int length );

/* Prototypes for session mapping functions */

#ifdef USE_CERTSTORE
  int setAccessMethodCertstore( SESSION_INFO *sessionInfoPtr );
#else
  #define setAccessMethodCertstore( x )	CRYPT_ARGERROR_NUM1
#endif /* USE_CERTSTORE */
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
