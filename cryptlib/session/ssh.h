/****************************************************************************
*																			*
*						SSHv1/SSHv2 Definitions Header File					*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#ifndef _SSH_DEFINED

#define _SSH_DEFINED

/* Default SSH port */

#define SSH_PORT				22

/* Various SSH constants */

#define ID_SIZE					1	/* ID byte */
#define LENGTH_SIZE				4	/* Size of packet length field */
#define UINT_SIZE				4	/* Size of integer value */
#define PADLENGTH_SIZE			1	/* Size of padding length field */
#define BOOLEAN_SIZE			1	/* Size of boolean value */

#define SSH1_COOKIE_SIZE		8	/* Size of SSHv1 cookie */
#define SSH1_HEADER_SIZE		5	/* Size of SSHv1 packet header */
#define SSH1_CRC_SIZE			4	/* Size of CRC value */
#define SSH1_MPI_LENGTH_SIZE	2	/* Size of MPI length field */
#define SSH1_SESSIONID_SIZE		16	/* Size of SSHv1 session ID */
#define SSH1_SECRET_SIZE		32	/* Size of SSHv1 shared secret */
#define SSH1_CHALLENGE_SIZE		32	/* Size of SSHv1 RSA auth.challenge */
#define SSH1_RESPONSE_SIZE		16	/* Size of SSHv1 RSA auth.response */

#define SSH2_COOKIE_SIZE		16	/* Size of SSHv2 cookie */
#define SSH2_HEADER_SIZE		5	/* Size of SSHv2 packet header */
#define SSH2_MIN_ALGOID_SIZE	4	/* Size of shortest SSHv2 algo.name */
#define SSH2_MIN_PADLENGTH_SIZE	4	/* Minimum amount of padding for packets */
#define SSH2_PAYLOAD_HEADER_SIZE 9	/* Size of SSHv2 inner payload header */
#define SSH2_FIXED_KEY_SIZE		16	/* Size of SSHv2 fixed-size keys */
#define SSH2_DEFAULT_KEYSIZE	128	/* Size of SSHv2 default DH key */

/* SSH packet/buffer size information */

#define MAX_PACKET_SIZE			262144L
#define EXTRA_PACKET_SIZE		64
#define DEFAULT_PACKET_SIZE		16384
#define MAX_WINDOW_SIZE			0x7FFFFFFFL

/* SSH protocol-specific flags that augment the general session flags */

#define SSH_PFLAG_NONE			0x00/* No protocol-specific flags */
#define SSH_PFLAG_HMACKEYSIZE	0x01/* Peer is using short HMAC keys */
#define SSH_PFLAG_SIGFORMAT		0x02/* Peer omits sig.algo name */
#define SSH_PFLAG_NOHASHSECRET	0x04/* Peer omits secret in key derive */
#define SSH_PFLAG_NOHASHLENGTH	0x08/* Peer omits length in exchge.hash */
#define SSH_PFLAG_WINDOWBUG		0x10/* Peer requires unnec.window-adjusts */
#define SSH_PFLAG_TEXTDIAGS		0x20/* Peer dumps text diagnostics on error */
#define SSH_PFLAG_CHANNELCLOSED	0x40/* Peer has closed the channel */

/* Various data sizes used for read-ahead and buffering.  The minimum SSH
   packet size is used to determine how much data we can read when reading
   a packet header, the SSHv2 header remainder size is how much data we've
   got left once we've extracted just the length but no other data, the
   SSHv2 remainder size is how much data we've got left once we've
   extracted all fixed information values, and the SSHv1 maximum header size
   is used to determine how much space we need to reserve at the start of
   the buffer when encoding SSHv1's variable-length data packets (SSHv2 has
   a fixed header size so this isn't a problem any more) */

#define MIN_PACKET_SIZE			16
#define SSH2_HEADER_REMAINDER_SIZE \
								( MIN_PACKET_SIZE - LENGTH_SIZE )
#define SSH2_PACKET_REMAINDER_SIZE \
								( SSH2_HEADER_REMAINDER_SIZE - \
									( ID_SIZE + PADLENGTH_SIZE ) )
#define SSH1_MAX_HEADER_SIZE	( LENGTH_SIZE + 8 + ID_SIZE + LENGTH_SIZE )

/* SSH ID information */

#define SSH_ID					"SSH-"		/* Start of SSH ID */
#define SSH_ID_SIZE				4	/* Size of SSH ID */
#define SSH_VERSION_SIZE		4	/* Size of SSH version */
#define SSH_ID_MAX_SIZE			255	/* Max.size of SSHv2 ID string */
#define SSH1_ID_STRING			"SSH-1.5-cryptlib"
#define SSH2_ID_STRING			"SSH-2.0-cryptlib"	/* cryptlib SSH ID strings */

/* SSHv1 packet types */

#define SSH1_MSG_DISCONNECT		1	/* Disconnect session */
#define SSH1_SMSG_PUBLIC_KEY	2	/* Server public key */
#define SSH1_CMSG_SESSION_KEY	3	/* Encrypted session key */
#define SSH1_CMSG_USER			4	/* User name */
#define SSH1_CMSG_AUTH_RSA		6	/* RSA public key */
#define SSH1_SMSG_AUTH_RSA_CHALLENGE 7	/* RSA challenge from server */
#define SSH1_CMSG_AUTH_RSA_RESPONSE 8	/* RSA response from client */
#define SSH1_CMSG_AUTH_PASSWORD	9	/* Password */
#define SSH1_CMSG_REQUEST_PTY	10	/* Request a pty */
#define SSH1_CMSG_EXEC_SHELL	12	/* Request a shell */
#define SSH1_CMSG_EXEC_CMD		13	/* Request command execution */
#define SSH1_SMSG_SUCCESS		14	/* Success status message */
#define SSH1_SMSG_FAILURE		15	/* Failure status message */
#define SSH1_CMSG_STDIN_DATA	16	/* Data from client stdin */
#define SSH1_SMSG_STDOUT_DATA	17	/* Data from server stdout */
#define SSH1_SMSG_EXITSTATUS	20	/* Exit status of command run on server */
#define SSH1_MSG_IGNORE			32	/* No-op */
#define SSH1_CMSG_EXIT_CONFIRMATION 33 /* Client response to server exitstatus */
#define SSH1_MSG_DEBUG			36	/* Debugging/informational message */
#define SSH1_CMSG_MAX_PACKET_SIZE 38	/* Maximum data packet size */

/* Further SSHv1 packet types that aren't used but which we need to
   recognise */

#define SSH1_CMSG_PORT_FORWARD_REQUEST		28
#define SSH1_CMSG_AGENT_REQUEST_FORWARDING	30
#define SSH1_CMSG_X11_REQUEST_FORWARDING	34
#define SSH1_CMSG_REQUEST_COMPRESSION		37

/* SSHv2 packet types.  There is some overlap with SSHv1, but an annoying
   number of messages have the same name but different values.  Note also
   that the keyex (static DH keys) and keyex_gex (ephemeral DH keys) message
   types overlap */

#define SSH2_MSG_DISCONNECT		1	/* Disconnect session */
#define SSH2_MSG_IGNORE			2	/* No-op */
#define SSH2_MSG_DEBUG			4	/* No-op */
#define SSH2_MSG_SERVICE_REQUEST 5	/* Request authentiction */
#define SSH2_MSG_SERVICE_ACCEPT	6	/* Acknowledge request */
#define SSH2_MSG_KEXINIT		20	/* Hello */
#define SSH2_MSG_NEWKEYS		21	/* Change cipherspec */
#define SSH2_MSG_KEXDH_INIT		30	/* DH, phase 1 */
#define SSH2_MSG_KEXDH_REPLY	31	/* DH, phase 2 */
#define SSH2_MSG_KEXDH_GEX_REQUEST 30 /* Ephem.DH key request */
#define SSH2_MSG_KEXDH_GEX_GROUP 31	/* Ephem.DH key response */
#define SSH2_MSG_KEXDH_GEX_INIT	32	/* Ephem.DH, phase 1 */
#define SSH2_MSG_KEXDH_GEX_REPLY 33	/* Ephem.DH, phase 2 */
#define SSH2_MSG_KEXDH_GEX_REQUEST_NEW 34 /* Ephem.DH key request */
#define SSH2_MSG_USERAUTH_REQUEST 50 /* Request authentication */
#define SSH2_MSG_USERAUTH_FAILURE 51 /* Authentication failed */
#define SSH2_MSG_USERAUTH_SUCCESS 52 /* Authentication succeeded */
#define SSH2_MSG_USERAUTH_BANNER 53	/* No-op */
#define SSH2_MSG_GLOBAL_REQUEST	80	/* Perform a global ioctl */
#define SSH2_MSG_GLOBAL_SUCCESS	81	/* Global request succeeded */
#define SSH2_MSG_GLOBAL_FAILURE	82	/* Global request failed */
#define	SSH2_MSG_CHANNEL_OPEN	90	/* Open a channel over an SSH link */
#define	SSH2_MSG_CHANNEL_OPEN_CONFIRMATION 91	/* Channel open succeeded */
#define	SSH2_MSG_CHANNEL_WINDOW_ADJUST 93	/* No-op */
#define SSH2_MSG_CHANNEL_DATA	94	/* Data */
#define SSH2_MSG_CHANNEL_EXTENDED_DATA 95	/* Out-of-band data */
#define SSH2_MSG_CHANNEL_EOF	96	/* EOF */
#define SSH2_MSG_CHANNEL_CLOSE	97	/* Close the channel */
#define SSH2_MSG_CHANNEL_REQUEST 98	/* Perform a channel ioctl */
#define SSH2_MSG_CHANNEL_SUCCESS 99	/* Channel request succeeded */
#define SSH2_MSG_CHANNEL_FAILURE 100/* Channel request failed */

/* Special-case expected-packet-type values that are passed to 
   readPacketSSHx() to handle situations where more than one return value is 
   valid.  CMSG_USER can return failure meaning "no password" even if 
   there's no actual failure, CMSG_AUTH_PASSWORD can return SMSG_FAILURE 
   which indicates a wrong password used iff it's a response to the client 
   sending a password, and MSG_USERAUTH_REQUEST can similarly return a 
   failure or success response.

   In addition to these types there's a "any" type which is used during the
   setup negotiation which will accept any (non-error) packet type and return
   the type as the return code */

#define SSH1_MSG_SPECIAL_USEROPT	500	/* Value to handle SSHv1 user name */
#define SSH1_MSG_SPECIAL_PWOPT		501	/* Value to handle SSHv1 password */
#define SSH1_MSG_SPECIAL_RSAOPT		502	/* Value to handle SSHv1 RSA challenge */
#define SSH1_MSG_SPECIAL_ANY		503	/* Any SSHv1 packet type */
#define SSH2_MSG_SPECIAL_USERAUTH	504	/* Value to handle SSHv2 combined auth.*/
#define SSH2_MSG_SPECIAL_REQUEST	505	/* Value to handle SSHv2 global/channel req.*/

/* SSHv1 cipher types */

#define SSH1_CIPHER_NONE		0	/* No encryption */
#define SSH1_CIPHER_IDEA		1	/* IDEA/CFB */
#define SSH1_CIPHER_DES			2	/* DES/CBC */
#define SSH1_CIPHER_3DES		3	/* 3DES/inner-CBC (nonstandard) */
#define SSH1_CIPHER_TSS			4	/* Deprecated */
#define SSH1_CIPHER_RC4			5	/* RC4 */
#define SSH1_CIPHER_BLOWFISH	6	/* Blowfish */
#define SSH1_CIPHER_CRIPPLED	7	/* Reserved, from ssh 1.2.x source */

/* SSHv1 authentication types */

#define SSH1_AUTH_RHOSTS		1	/* .rhosts or /etc/hosts.equiv */
#define SSH1_AUTH_RSA			2	/* RSA challenge-response */
#define SSH1_AUTH_PASSWORD		3	/* Password */
#define SSH1_AUTH_RHOSTS_RSA	4	/* .rhosts with RSA challenge-response */
#define SSH1_AUTH_TIS			5	/* TIS authsrv */
#define SSH1_AUTH_KERBEROS		6	/* Kerberos */
#define SSH1_PASS_KERBEROS_TGT	7	/* Kerberos TGT-passing */

/* SSHv2 disconnection codes */

#define SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT		1
#define SSH2_DISCONNECT_PROTOCOL_ERROR					2
#define SSH2_DISCONNECT_KEY_EXCHANGE_FAILED				3
#define SSH2_DISCONNECT_RESERVED						4
#define SSH2_DISCONNECT_MAC_ERROR						5
#define SSH2_DISCONNECT_COMPRESSION_ERROR				6
#define SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE			7
#define SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	8
#define SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE			9
#define SSH2_DISCONNECT_CONNECTION_LOST					10
#define SSH2_DISCONNECT_BY_APPLICATION					11
#define SSH2_DISCONNECT_TOO_MANY_CONNECTIONS			12
#define SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER			13
#define SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14
#define SSH2_DISCONNECT_ILLEGAL_USER_NAME				15

/* Mapping of SSHv2 algorithm names to cryptlib algorithm IDs, in preferred
   algorithm order */

typedef struct {
	const char *name;						/* Algorithm name */
	const CRYPT_ALGO_TYPE algo;				/* Algorithm ID */
	} ALGO_STRING_INFO;

/* SSH handshake state information.  This is passed around various
   subfunctions that handle individual parts of the handshake */

typedef struct SH {
	/* SSHv1 session state information/SSHv2 exchange hash */
	BYTE cookie[ SSH2_COOKIE_SIZE ];		/* Anti-spoofing cookie */
	BYTE sessionID[ CRYPT_MAX_HASHSIZE ];	/* Session ID/exchange hash */
	int sessionIDlength;
	CRYPT_CONTEXT iExchangeHashcontext;		/* Hash of exchanged info */

	/* Information needed to compute the session ID.  SSHv1 requires the
	   host and server key modulus, SSHv2 requires the client DH value
	   (along with various other things, but these are hashed inline).
	   The SSHv2 values are in MPI-encoded form, so we need to reserve a
	   little extra room for the length and leading zero-padding.  Since the
	   data fields are rather large and also disjoint, we alias one to the
	   other */
	BYTE hostModulus[ CRYPT_MAX_PKCSIZE + 16 ];
	BYTE serverModulus[ CRYPT_MAX_PKCSIZE + 16 ];
	int hostModulusLength, serverModulusLength;
	#define clientKeyexValue		hostModulus
	#define serverKeyexValue		serverModulus
	#define clientKeyexValueLength	hostModulusLength
	#define serverKeyexValueLength	serverModulusLength

	/* Encryption algorithm and key information */
	CRYPT_ALGO_TYPE pubkeyAlgo;				/* Host signature algo */
	BYTE secretValue[ CRYPT_MAX_PKCSIZE ];	/* Shared secret value */
	int secretValueLength;

	/* Short-term server key (SSHv1) or DH key agreement context (SSHv2),
	   and the client requested DH key size for the SSHv2 key exchange.
	   Alongside the actual key size, we also store the original encoded
	   form, which has to be hashed as part of the exchange hash.  The 
	   long-term host key is stored as the session info iKeyexCryptContext 
	   for the client and privateKey for the server */
	CRYPT_CONTEXT iServerCryptContext;
	int serverKeySize, requestedServerKeySize;
	BYTE encodedReqKeySizes[ UINT_SIZE * 3 ];
	int encodedReqKeySizesLength;

	/* Tables mapping SSHv2 algorithm names to cryptlib algorithm IDs.  
	   These are declared once in ssh2.c and referred to here via pointers 
	   to allow them to be static const, which is necessary in some
	   environments to get them into the read-only segment */
	const FAR_BSS ALGO_STRING_INFO *algoStringPubkeyTbl, 
								   *algoStringUserauthentTbl;

	/* Function pointers to handshaking functions.  These are set up as 
	   required depending on whether the protocol being used is v1 or v2, 
	   and the session is client or server */
	int ( *beginHandshake )( SESSION_INFO *sessionInfoPtr,
							 struct SH *handshakeInfo );
	int ( *exchangeKeys )( SESSION_INFO *sessionInfoPtr,
						   struct SH *handshakeInfo );
	int ( *completeHandshake )( SESSION_INFO *sessionInfoPtr,
								struct SH *handshakeInfo );
	} SSH_HANDSHAKE_INFO;

/* Prototypes for functions in ssh.c */

int initSecurityContexts( SESSION_INFO *sessionInfoPtr );
int encodeString( BYTE *buffer, const BYTE *string, const int stringLength );

/* Prototypes for functions in ssh2.c */

int initSecurityInfo( SESSION_INFO *sessionInfoPtr,
					  SSH_HANDSHAKE_INFO *handshakeInfo );
int getAlgoID( const ALGO_STRING_INFO *algoInfo, CRYPT_ALGO_TYPE *algo, 
			   const CRYPT_ALGO_TYPE preferredAlgo, const BYTE *string, 
			   const int maxLength, void *errorInfo );
int putAlgoID( BYTE **bufPtrPtr, const CRYPT_ALGO_TYPE algo );
int initDHcontext( CRYPT_CONTEXT *iCryptContext, int *keySize, 
				   const void *keyData, const int keyDataLength,
				   const int requestedKeySize );
int hashAsString( const CRYPT_CONTEXT iHashContext,
				  const BYTE *data, const int dataLength );
int hashAsMPI( const CRYPT_CONTEXT iHashContext, const BYTE *data, 
			   const int dataLength );
int encodeMPI( BYTE *buffer, const BYTE *value,
			   const int valueLength );
int completeKeyex( SESSION_INFO *sessionInfoPtr, 
				   SSH_HANDSHAKE_INFO *handshakeInfo, 
				   const BOOLEAN isServer );
int wrapPacket( SESSION_INFO *sessionInfoPtr, BYTE *bufPtr,
				const int dataLength );
int sendPacketSSH2( SESSION_INFO *sessionInfoPtr, const int dataLength,
					const BOOLEAN sendOnly );
int readPacketSSH2( SESSION_INFO *sessionInfoPtr, int expectedType );
int processHello( SESSION_INFO *sessionInfoPtr, 
				  SSH_HANDSHAKE_INFO *handshakeInfo, int *serverKeyexLength,
				  const BOOLEAN isServer );
int processRequest( SESSION_INFO *sessionInfoPtr, const BYTE *data,
					const int dataLength );

/* Prototypes for functions in ssh2_svr.c */

int getAddressAndPort( SESSION_INFO *sessionInfoPtr, const BYTE *data,
					   const int dataLength );
int processChannelOpen( SESSION_INFO *sessionInfoPtr, const BYTE *data,
						const int dataLength );

/* Prototypes for session mapping functions */

void initSSH1processing( SESSION_INFO *sessionInfoPtr,
						 SSH_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN isServer );
void initSSH2processing( SESSION_INFO *sessionInfoPtr,
						 SSH_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN isServer );
void initSSH2clientProcessing( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo );
void initSSH2serverProcessing( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo );

#ifndef USE_SSH1
  #define initSSH1processing	initSSH2processing
#endif /* USE_SSH1 */
#ifndef USE_SSH2
  #define initSSH2processing	initSSH1processing
#endif /* USE_SSH2 */
#endif /* _SSH_DEFINED */
