/****************************************************************************
*																			*
*						SSL v3/TLS Definitions Header File					*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#ifndef _SSL_DEFINED

#define _SSL_DEFINED

/* Default SSL port */

#define SSL_PORT					443

/* SSL constants */

#define ID_SIZE						1	/* ID byte */
#define UINT16_SIZE					2	/* 16 bits */
#define LENGTH_SIZE					3	/* 24 bits */
#define SEQNO_SIZE					8	/* 64 bits */
#define VERSIONINFO_SIZE			2	/* 0x03, 0x0n */
#define ALERTINFO_SIZE				2	/* level + description */
#define SSL_HEADER_SIZE				5	/* Type, version, length */
#define SSL_NONCE_SIZE				32	/* Size of client/svr nonce */
#define SSL_SECRET_SIZE				48	/* Size of premaster/master secret */
#define MD5MAC_SIZE					16	/* Size of MD5 proto-HMAC/dual hash */
#define SHA1MAC_SIZE				20	/* Size of SHA-1 proto-HMAC/dual hash */
#define TLS_HASHEDMAC_SIZE			12	/* Size of TLS PRF( MD5 + SHA1 ) */
#define SESSIONID_SIZE				16	/* Size of session ID */
#define MAX_SESSIONID_SIZE			32	/* Max.allowed session ID size */
#define MAX_KEYBLOCK_SIZE			( ( 20 + 32 + 16 ) * 2 )/* HMAC-SHA1 + AES */
#define MIN_PACKET_SIZE				4	/* Minimum SSL packet size */
#define MAX_PACKET_SIZE				16384	/* Maximum SSL packet size */

/* The number of entries in the SSL session cache and the maximum amount of 
   time that an entry is retained in the cache.  Note that when changing the
   SESSIONCACHE_SIZE value you need to also change MAX_ALLOC_SIZE in 
   sec_mem.c to allow the allocation of such large amounts of secure 
   memory */

#if defined( CONFIG_CONSERVE_MEMORY )
  #define SESSIONCACHE_SIZE			128
#else
  #define SESSIONCACHE_SIZE			1024
#endif /* CONFIG_CONSERVE_MEMORY */
#define SESSIONCACHE_TIMEOUT		3600

/* SSL packet/buffer size information.  The extra packet size is somewhat 
   large because it can contains the packet header (5 bytes), IV (0/8/16 
   bytes), MAC (16/20 bytes), and cipher block padding (up to 256 bytes) */

#define EXTRA_PACKET_SIZE			512	

/* By default, cryptlib uses RSA key transport, which is supported by all 
   servers.  It's also possible to use DH key agreement, however this isn't
   supported by all servers (particularly Microsoft ones) and has a 
   considerably higher cryptographic overhead than RSA, requiring a DH 
   (pseudo-)private key operation on both client and server as well as a 
   standard RSA private-key operation on the server.  To use DH cipher 
   suites in preference to RSA ones, uncomment the following */

/* #define PREFER_DH_SUITES */

/* SSL protocol-specific flags that augment the general session flags.  The 
   alert-sent flag is required because we're required to send a close alert 
   when shutting down to prevent a truncation attack, however lower-level 
   code may have already sent an alert so we have to remember not to send it 
   twice */

#define SSL_PFLAG_NONE				0x0	/* No protocol-specific flags */
#define SSL_PFLAG_ALERTSENT			0x1	/* Close alert sent */

/* SSL message types */

#define SSL_MSG_CHANGE_CIPHER_SPEC	20
#define SSL_MSG_ALERT				21
#define SSL_MSG_HANDSHAKE			22
#define SSL_MSG_APPLICATION_DATA	23

#define SSL_MSG_FIRST				20
#define SSL_MSG_LAST				23

/* Special-case expected packet-type values that are passed to 
   readPacketSSL() to handle situations where more than one packet type is 
   valid.  The first handshake packet from the client or server is treated 
   specially in that both the version number info is taken from this packet,
   and the packet itself may have to be treated specially because although
   the client handshake is supposed to be a v3 handshake, the first 
   handshake packet is often a hacked v2 one with forwards-compatibility 
   kludges */

#define SSL_MSG_FIRST_HANDSHAKE		0xFF
#define SSL_MSG_V2HANDSHAKE			0x80

/* SSL handshake message subtypes */

#define SSL_HAND_CLIENT_HELLO		0x01
#define SSL_HAND_SERVER_HELLO		0x02
#define SSL_HAND_CERTIFICATE		0x0B
#define SSL_HAND_SERVER_KEYEXCHANGE	0x0C
#define SSL_HAND_SERVER_CERTREQUEST	0x0D
#define SSL_HAND_SERVER_HELLODONE	0x0E
#define SSL_HAND_CLIENT_CERTVERIFY	0x0F
#define SSL_HAND_CLIENT_KEYEXCHANGE	0x10
#define SSL_HAND_FINISHED			0x14

/* SSL alert levels and types */

#define SSL_ALERTLEVEL_WARNING				1
#define SSL_ALERTLEVEL_FATAL				2

#define SSL_ALERT_CLOSE_NOTIFY				0
#define SSL_ALERT_UNEXPECTED_MESSAGE		10
#define SSL_ALERT_BAD_RECORD_MAC			20
#define TLS_ALERT_DECRYPTION_FAILED			21
#define TLS_ALERT_RECORD_OVERFLOW			22
#define SSL_ALERT_DECOMPRESSION_FAILURE		30
#define SSL_ALERT_HANDSHAKE_FAILURE			40
#define SSL_ALERT_NO_CERTIFICATE			41
#define SSL_ALERT_BAD_CERTIFICATE			42
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE	43
#define SSL_ALERT_CERTIFICATE_REVOKED		44
#define SSL_ALERT_CERTIFICATE_EXPIRED		45
#define SSL_ALERT_CERTIFICATE_UNKNOWN		46
#define SSL_ALERT_ILLEGAL_PARAMETER			47
#define TLS_ALERT_UNKNOWN_CA				48
#define TLS_ALERT_ACCESS_DENIED				49
#define TLS_ALERT_DECODE_ERROR				50
#define TLS_ALERT_DECRYPT_ERROR				51
#define TLS_ALERT_EXPORT_RESTRICTION		60
#define TLS_ALERT_PROTOCOL_VERSION			70
#define TLS_ALERT_INSUFFICIENT_SECURITY		71
#define TLS_ALERT_INTERNAL_ERROR			80
#define TLS_ALERT_USER_CANCELLED			90
#define TLS_ALERT_NO_RENEGOTIATION			100
#define TLS_ALERT_UNSUPPORTED_EXTENSION		110
#define TLS_ALERT_CERTIFICATE_UNOBTAINABLE	111
#define TLS_ALERT_UNRECOGNIZED_NAME			112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE 114
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY		115

/* SSL cipher suites */

typedef enum {
	/* SSLv3 cipher suites (0-10) */
	SSL_NULL_WITH_NULL, SSL_RSA_WITH_NULL_MD5, SSL_RSA_WITH_NULL_SHA,
	SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL_RSA_WITH_RC4_128_MD5,
	SSL_RSA_WITH_RC4_128_SHA, SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSL_RSA_WITH_IDEA_CBC_SHA, SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSL_RSA_WITH_DES_CBC_SHA, SSL_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) DH cipher suites (11-22) */
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_DSS_WITH_DES_CBC_SHA,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_RSA_WITH_DES_CBC_SHA, TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_WITH_DES_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) anon-DH cipher suites (23-27) */
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, TLS_DH_anon_WITH_RC4_128_MD5,
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_anon_WITH_DES_CBC_SHA,
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) reserved cipher suites (28-29, used for Fortezza in
	   SSLv3) */
	TLS_reserved_1, TLS_reserved_2,

	/* TLS with Kerberos (RFC 2712) suites (30-43) */
	TLS_KRB5_WITH_DES_CBC_SHA, TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
	TLS_KRB5_WITH_RC4_128_SHA, TLS_KRB5_WITH_IDEA_CBC_SHA,
	TLS_KRB5_WITH_DES_CBC_MD5, TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
	TLS_KRB5_WITH_RC4_128_MD5, TLS_KRB5_WITH_IDEA_CBC_MD5,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA, TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, TLS_KRB5_EXPORT_WITH_RC4_40_MD5,

	/* Unknown suites (44-46) */

	/* TLS (post-2246) cipher suites (47-58) */
	TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F, TLS_DH_DSS_WITH_AES_128_CBC_SHA,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DH_anon_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DH_DSS_WITH_AES_256_CBC_SHA,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DH_anon_WITH_AES_256_CBC_SHA,

	/* Unknown suites (59-137) */

	/* TLS-PSK cipher suites (138-149) */
	TLS_PSK_WITH_RC4_128_SHA = 138, TLS_PSK_WITH_3DES_EDE_CBC_SHA, 
	TLS_PSK_WITH_AES_128_CBC_SHA, TLS_PSK_WITH_AES_256_CBC_SHA, 
	TLS_DHE_PSK_WITH_RC4_128_SHA, TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA, TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_RSA_PSK_WITH_RC4_128_SHA, TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA, TLS_RSA_PSK_WITH_AES_256_CBC_SHA,

	SSL_LAST 
	} SSL_CIPHERSUITE_TYPE;

/* TLS extension types */

typedef enum {
	TLS_EXT_SERVER_NAME, TLS_EXT_MAX_FRAGMENT_LENTH,
	TLS_EXT_CLIENT_CERTIFICATE_URL, TLS_EXT_TRUSTED_CA_KEYS,
	TLS_EXT_TRUNCATED_HMAC, TLS_EXT_STATUS_REQUEST, TLS_EXT_LAST
	} TLS_EXT_TYPE;

/* SSL and TLS major and minor version numbers */

#define SSL_MAJOR_VERSION		3
#define SSL_MINOR_VERSION_SSL	0
#define SSL_MINOR_VERSION_TLS	1
#define SSL_MINOR_VERSION_TLS11	2

/* SSL sender label values for the finished message MAC */

#define SSL_SENDER_CLIENTLABEL	"CLNT"
#define SSL_SENDER_SERVERLABEL	"SRVR"
#define SSL_SENDERLABEL_SIZE	4

/* Fixed-format message templates for SSL, TLS 1.0, and TLS 1.1.  The second
   subscript is a worst-case, unfortunately this is the only way we can
   statically initialise a two-dimensional array of chars */

typedef BYTE SSL_MESSAGE_TEMPLATE[ 3 ][ 8 ];

/* SSL handshake state information.  This is passed around various
   subfunctions that handle individual parts of the handshake */

typedef struct SL {
	/* Client and server proto-HMAC/dual-hash contexts */
	CRYPT_CONTEXT clientMD5context, clientSHA1context;
	CRYPT_CONTEXT serverMD5context, serverSHA1context;

	/* Client and server nonces and session ID */
	BYTE clientNonce[ SSL_NONCE_SIZE + 8 ];
	BYTE serverNonce[ SSL_NONCE_SIZE + 8 ];
	BYTE sessionID[ MAX_SESSIONID_SIZE + 8 ];
	int sessionIDlength;

	/* Premaster/master secret */
	BYTE premasterSecret[ CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE + 8 ];
	int premasterSecretSize;

	/* Encryption/security info */
	CRYPT_CONTEXT dhContext;	/* DH ctx.if DHE is being used */
	int cipherSuite;			/* Selected cipher suite */
	CRYPT_ALGO_TYPE keyexAlgo, authAlgo;/* Selected cipher suite algos */
	int cryptKeysize;			/* Size of session key */
	BOOLEAN serverSigKey;		/* Server sig.key can auth.DH exchange */

	/* Other info */
	int clientOfferedVersion;	/* Prot.vers.originally offered by client */
	BOOLEAN isSSLv2;			/* Client hello is SSLv2 */
	BOOLEAN hasExtensions;		/* Hello has TLS extensions */

	/* The packet data stream.  Since SSL can encapsulate multiple handshake
	   packets within a single SSL packet, the stream has to be persistent
	   across the different handshake functions to allow the continuation of
	   packets */
	STREAM stream;				/* Packet data stream */

	/* Function pointers to handshaking functions.  These are set up as 
	   required depending on whether the session is client or server */
	int ( *beginHandshake )( SESSION_INFO *sessionInfoPtr,
							 struct SL *handshakeInfo );
	int ( *exchangeKeys )( SESSION_INFO *sessionInfoPtr,
						   struct SL *handshakeInfo );
	} SSL_HANDSHAKE_INFO;

/* Session cache management functions */

int findSessionCacheEntryID( const void *sessionID, 
							 const int sessionIDlength );
int addSessionCacheEntry( const void *sessionID, const int sessionIDlength, 
						  const void *masterSecret, 
						  const int masterSecretLength, 
						  const BOOLEAN isFixedEntry );
void deleteSessionCacheEntry( const int uniqueID );

/* Prototypes for functions in ssl.c */

int readUint24( STREAM *stream );
int writeUint24( STREAM *stream, const int length );
int processHelloSSL( SESSION_INFO *sessionInfoPtr, 
					 SSL_HANDSHAKE_INFO *handshakeInfo, 
					 STREAM *stream, const BOOLEAN isServer );
int readSSLCertChain( SESSION_INFO *sessionInfoPtr, 
					  SSL_HANDSHAKE_INFO *handshakeInfo, STREAM *stream,
					  CRYPT_CERTIFICATE *iCertChain, 
					  const BOOLEAN isServer );
int writeSSLCertChain( SESSION_INFO *sessionInfoPtr, STREAM *stream );
int checkPacketHeaderSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream );
int checkHSPacketHeader( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						 const int packetType, const int minSize );
int processVersionInfo( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						int *clientVersion );
	/* Only needed for legacy SSLv2 support */
int processCipherSuite( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo, 
						STREAM *stream, const int noSuites );

/* Prototypes for functions in ssl_rw.c */

int unwrapPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
					 const int packetType );
int readPacketSSL( SESSION_INFO *sessionInfoPtr,
				   SSL_HANDSHAKE_INFO *handshakeInfo, const int packetType );
int refreshHSStream( SESSION_INFO *sessionInfoPtr, 
					 SSL_HANDSHAKE_INFO *handshakeInfo );
int wrapPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
				   const int offset );
int sendPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
				   const BOOLEAN sendOnly );
void openPacketStreamSSL( STREAM *stream, const SESSION_INFO *sessionInfoPtr, 
						  const int bufferSize, const int packetType );
int continuePacketStreamSSL( STREAM *stream, 
							 const SESSION_INFO *sessionInfoPtr, 
							 const int packetType );
int completePacketStreamSSL( STREAM *stream, const int offset );
int continueHSPacketStream( STREAM *stream, const int packetType );
int completeHSPacketStream( STREAM *stream, const int offset );
int processAlert( SESSION_INFO *sessionInfoPtr, const void *header, 
				  const int headerLength );
void sendCloseAlert( SESSION_INFO *sessionInfoPtr, 
					 const BOOLEAN alertReceived );
void sendHandshakeFailAlert( SESSION_INFO *sessionInfoPtr );

/* Prototypes for functions in ssl_cry.c */

int initSecurityContextsSSL( SESSION_INFO *sessionInfoPtr );
void destroySecurityContextsSSL( SESSION_INFO *sessionInfoPtr );
int initHandshakeCryptInfo( SSL_HANDSHAKE_INFO *handshakeInfo );
int destroyHandshakeCryptInfo( SSL_HANDSHAKE_INFO *handshakeInfo );
int initDHcontextSSL( CRYPT_CONTEXT *iCryptContext, const void *keyData, 
					  const int keyDataLength );
int createSharedPremasterSecret( void *premasterSecret, 
								 int *premasterSecretLength,
								 const SESSION_INFO *sessionInfoPtr );
int wrapPremasterSecret( SESSION_INFO *sessionInfoPtr, 
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 void *data, int *dataLength );
int unwrapPremasterSecret( SESSION_INFO *sessionInfoPtr, 
						   SSL_HANDSHAKE_INFO *handshakeInfo,
						   const void *data, const int dataLength );
int premasterToMaster( const SESSION_INFO *sessionInfoPtr, 
					   const SSL_HANDSHAKE_INFO *handshakeInfo, 
					   void *masterSecret, const int masterSecretLength );
int masterToKeys( const SESSION_INFO *sessionInfoPtr, 
				  const SSL_HANDSHAKE_INFO *handshakeInfo, 
				  const void *masterSecret, const int masterSecretLength,
				  void *keyBlock, const int keyBlockLength );
int loadKeys( SESSION_INFO *sessionInfoPtr, 
			  const SSL_HANDSHAKE_INFO *handshakeInfo, 
			  const BOOLEAN isClient, const void *keyBlock );
int loadExplicitIV( SESSION_INFO *sessionInfoPtr, STREAM *stream );
int encryptData( const SESSION_INFO *sessionInfoPtr, BYTE *data,
				 const int dataLength );
int decryptData( SESSION_INFO *sessionInfoPtr, BYTE *data,
				 const int dataLength );
int dualMacData( const SSL_HANDSHAKE_INFO *handshakeInfo, 
				 const STREAM *stream, const BOOLEAN isRawData );
int completeSSLDualMAC( const CRYPT_CONTEXT md5context,
						const CRYPT_CONTEXT sha1context, BYTE *hashValues, 
						const char *label, const BYTE *masterSecret );
int completeTLSHashedMAC( const CRYPT_CONTEXT md5context,
						  const CRYPT_CONTEXT sha1context, BYTE *hashValues, 
						  const char *label, const BYTE *masterSecret );
int macDataSSL( SESSION_INFO *sessionInfoPtr, const void *data,
				const int dataLength, const int type, const BOOLEAN isRead, 
				const BOOLEAN noReportError );
int macDataTLS( SESSION_INFO *sessionInfoPtr, const void *data,
				const int dataLength, const int type, const BOOLEAN isRead, 
				const BOOLEAN noReportError );
int createCertVerify( const SESSION_INFO *sessionInfoPtr,
					  const SSL_HANDSHAKE_INFO *handshakeInfo,
					  STREAM *stream );
int checkCertVerify( const SESSION_INFO *sessionInfoPtr,
					 const SSL_HANDSHAKE_INFO *handshakeInfo,
					 STREAM *stream, const int sigLength );
int createKeyexSignature( SESSION_INFO *sessionInfoPtr, 
						  SSL_HANDSHAKE_INFO *handshakeInfo,
						  STREAM *stream, const void *keyData, 
						  const int keyDataLength );
int checkKeyexSignature( SESSION_INFO *sessionInfoPtr, 
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 STREAM *stream, const void *keyData, 
						 const int keyDataLength );

/* Prototypes for session mapping functions */

void initSSLclientProcessing( SSL_HANDSHAKE_INFO *handshakeInfo );
void initSSLserverProcessing( SSL_HANDSHAKE_INFO *handshakeInfo );

#endif /* _SSL_DEFINED */
