/****************************************************************************
*																			*
*						cryptlib SSHv2 Session Management					*
*						Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssh.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../session/session.h"
  #include "../session/ssh.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH2

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Generate/check an SSHv2 key fingerprint.  This is simply an MD5 hash of
   the server's key/certificate data */

static int processKeyFingerprint( SESSION_INFO *sessionInfoPtr,
								  const void *keyData,
								  const int keyDataLength )
	{
	HASHFUNCTION hashFunction;
	BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
	int hashSize;

	getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashSize );
	hashFunction( NULL, fingerPrint, keyData, keyDataLength, HASH_ALL );
	if( sessionInfoPtr->keyFingerprintSize > 0 )
		{
		/* In the unlikely event that the user has passed us an SHA-1
		   fingerprint (which isn't allowed by the spec, but no doubt
		   someone out there's using it based on the fact that the SSH
		   architecture draft suggests an SHA-1 fingerprint while the SSH
		   fingerprint draft requires an MD5 fingerprint), calculate that
		   instead */
		if( sessionInfoPtr->keyFingerprintSize == 20 )
			{
			getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
			hashFunction( NULL, fingerPrint, keyData, keyDataLength,
						  HASH_ALL );
			}

		/* There's an existing fingerprint value, make sure that it matches
		   what we just calculated */
		if( memcmp( sessionInfoPtr->keyFingerprint, fingerPrint, hashSize ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"Server key fingerprint doesn't match requested "
					"fingerprint" );
		}
	else
		{
		/* Remember the value for the caller */
		memcpy( sessionInfoPtr->keyFingerprint, fingerPrint, hashSize );
		sessionInfoPtr->keyFingerprintSize = hashSize;
		}
	return( CRYPT_OK );
	}

/* Create a request for the appropriate type of service, either encrypted-
   telnet, SFTP, or port forwarding */

static int createOpenRequest( SESSION_INFO *sessionInfoPtr, 
							  BYTE *buffer )
	{
	BYTE *bufPtr = buffer + SSH2_HEADER_SIZE;
	int length, status;

	/* If the user has requested the use of a custom subsystem (and at the
	   moment the only one that's likely to be used is SFTP), request this 
	   from the server */
	if( sessionInfoPtr->sshSubsystemLength > 0 )
		{
		/*	...
			byte	type = SSH2_MSG_CHANNEL_REQUEST
			uint32	recipient_channel = 0
			string	request_name = "subsystem"
			boolean	want_reply = FALSE
			string	subsystem_name */
		*bufPtr++ = SSH2_MSG_CHANNEL_REQUEST;
		mputLong( bufPtr, 0 );
		bufPtr += encodeString( bufPtr, "subsystem", 0 );
		*bufPtr++ = 0;
		bufPtr += encodeString( bufPtr, sessionInfoPtr->sshSubsystem,
								sessionInfoPtr->sshSubsystemLength );
		return( wrapPacket( sessionInfoPtr, buffer,
							bufPtr - ( buffer + SSH2_HEADER_SIZE ) ) );
		}

	/* If the user has requested port-forwarding, request this from the 
	   server */
	if( sessionInfoPtr->sshPortForwardLength > 0 )
		{
		URL_INFO urlInfo;

		/*	...
			byte	type = SSH_MSG_GLOBAL_REQUEST
			string	request_name = "tcpip-forward"
			boolean	want_reply
			string	address_to_bind (e.g. "0.0.0.0")
			uint32	port_to_bind

		  The exact details of what we should send at this stage of the 
		  handshake are a bit unclear.  Most implementations go through the 
		  standard channel open process to provide a general control channel 
		  and then specify the port-forwarding in addition to this (see 
		  processChannelOpen() for the hoops we have to jump through to 
		  handle this).  This double-open can cause problems with some 
		  applications hanging off the tunnel because they may see the 
		  output from opening the channel and starting a shell as tunnelled 
		  data and get confused by it.  The safest option seems to be to 
		  only open the forwarded channel, without opening a (mostly 
		  redundant) control channel */
		sNetParseURL( &urlInfo, sessionInfoPtr->sshPortForward, 
					  sessionInfoPtr->sshPortForwardLength );
		bufPtr = buffer + SSH2_HEADER_SIZE;
		*bufPtr++ = SSH2_MSG_GLOBAL_REQUEST;
		bufPtr += encodeString( bufPtr, "tcpip-forward", 0 );
		*bufPtr++ = 0;
		bufPtr += encodeString( bufPtr, urlInfo.host, urlInfo.hostLen );
		mputLong( bufPtr, urlInfo.port );
		return( wrapPacket( sessionInfoPtr, buffer,
							bufPtr - ( buffer + SSH2_HEADER_SIZE ) ) );
		}

	/* It's a standard channel open:
		...
		byte	type = SSH2_MSG_CHANNEL_REQUEST
		uint32	recipient_channel = 0
		string	request_name = "pty-req"
		boolean	want_reply = FALSE
		string	TERM_environment_variable = "vt100"
		uint32	cols = 80
		uint32	rows = 24
		uint32	pixel_width = 0
		uint32	pixel_height = 0
		string	tty_mode_info = ""
		... */
	*bufPtr++ = SSH2_MSG_CHANNEL_REQUEST;
	mputLong( bufPtr, 0 );
	bufPtr += encodeString( bufPtr, "pty-req", 0 );
	*bufPtr++ = 0;
	bufPtr += encodeString( bufPtr, "vt100", 0 );/* Generic */
	mputLong( bufPtr, 80 );
	mputLong( bufPtr, 24 );				/* 24 x 80 */
	mputLong( bufPtr, 0 );
	mputLong( bufPtr, 0 );				/* No graphics capabilities */
	bufPtr += encodeString( bufPtr, "", 0 );/* No special TTY modes */
	status = length = wrapPacket( sessionInfoPtr, buffer,
								  bufPtr - ( buffer + SSH2_HEADER_SIZE ) );
	if( cryptStatusError( status ) )
		return( status );

	/*	...
		byte	type = SSH2_MSG_CHANNEL_REQUEST
		uint32	recipient_channel = 0
		string	request_name = "shell"
		boolean	want_reply = FALSE

	   This final request, once sent, moves the server into interactive 
	   session mode, if we're talking to a standard Unix server implementing 
	   a remote shell we could read the stdout data response from starting 
	   the shell but this may not be the case so we leave the response for 
	   the user to process explicitly */
	bufPtr = buffer + length + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_CHANNEL_REQUEST;
	mputLong( bufPtr, 0 );
	bufPtr += encodeString( bufPtr, "shell", 0 );
	*bufPtr++ = 0;
	status = wrapPacket( sessionInfoPtr, buffer + length,
						 bufPtr - ( buffer + length + SSH2_HEADER_SIZE ) );
	return( cryptStatusError( status ) ? status : length + status );
	}

/****************************************************************************
*																			*
*						Client-side Connect Functions						*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the server */

static int beginClientHandshake( SESSION_INFO *sessionInfoPtr,
								 SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	KEYAGREE_PARAMS keyAgreeParams;
	RESOURCE_DATA msgData;
	BYTE *bufPtr;
	int length, length2, serverKeyexLength, clientKeyexLength;
	int mpiLength, status;

	/* The higher-level code has already read the server session info, send
	   back our own version info (SSHv2 uses a CR and LF as terminator,
	   which differs from SSHv1) */
	length = strlen( SSH2_ID_STRING );
	memcpy( sessionInfoPtr->sendBuffer, SSH2_ID_STRING "\r\n", length + 2 );
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer,
					 length + 2 );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}

	/* SSHv2 hashes parts of the handshake messages for integrity-protection
	   purposes, so we hash the ID strings (first our client string, then the
	   server string that we read previously) encoded as SSH string values */
	hashAsString( handshakeInfo->iExchangeHashcontext, SSH2_ID_STRING,
				  length );
	hashAsString( handshakeInfo->iExchangeHashcontext,
				  sessionInfoPtr->receiveBuffer,
				  strlen( sessionInfoPtr->receiveBuffer ) );

	/* While we wait for the server to digest our version info and send
	   back its response, we can create the context with the DH key and
	   perform phase 1 of the DH key agreement process */
	status = initDHcontext( &handshakeInfo->iServerCryptContext,
							&handshakeInfo->serverKeySize, NULL, 0,
							CRYPT_USE_DEFAULT );
	if( cryptStatusOK( status ) )
		{
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Process the server hello */
	status = processHello( sessionInfoPtr, handshakeInfo, 
						   &serverKeyexLength, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the client hello and DH phase 1 keyex packet:

		byte		type = SSH2_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms = DH
		string		pubkey algorithms
		string		client_crypto algorithms
		string		server_crypto algorithms
		string		client_mac algorithms
		string		server_mac algorithms
		string		client_compression algorithms = "none"
		string		server_compression algorithms = "none"
		string		client_language = {}
		string		server_language = {}
		boolean		first_keyex_packet_follows = FALSE
		uint32		reserved = 0
		...

	   The SSH spec leaves the order in which things happen ambiguous, in 
	   order to save a whole round trip it has provisions for both sides
	   shouting at each other and then a complex interlock process where
	   bits of the initial exchange can be discarded and retried if necessary.
	   This is ugly and error-prone, so what we do is wait for the server
	   hello (already done earlier), choose known-good algorithms, and then
	   send the client hello immediately followed by the client keyex.  
	   Since we wait for the server to speak first, we can choose parameters 
	   that are accepted the first time.  In theory this means that we can 
	   set keyex_follows to true (since a correct keyex packet always 
	   follows the hello), however because of the nondeterministic initial 
	   exchange the spec requires that a (guessed) keyex be discarded by the 
	   server if the hello doesn't match (even if the keyex does):
	   
		svr: hello
		client: matched hello, keyex
		svr: (discard keyex)

	   To avoid this problem, we set keyex_follows to false to make it clear
	   to the server that the keyex is the real thing and shouldn't be 
	   discarded */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_KEXINIT;
	setMessageData( &msgData, bufPtr, SSH2_COOKIE_SIZE );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
					 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	bufPtr += SSH2_COOKIE_SIZE;
	if( handshakeInfo->requestedServerKeySize > 0 )
		bufPtr += encodeString( bufPtr, "diffie-hellman-group-exchange-sha1", 
								0 );
	else
		putAlgoID( &bufPtr, CRYPT_ALGO_DH );
	putAlgoID( &bufPtr, handshakeInfo->pubkeyAlgo );
	putAlgoID( &bufPtr, sessionInfoPtr->cryptAlgo );
	putAlgoID( &bufPtr, sessionInfoPtr->cryptAlgo );
	putAlgoID( &bufPtr, sessionInfoPtr->integrityAlgo );
	putAlgoID( &bufPtr, sessionInfoPtr->integrityAlgo );
	putAlgoID( &bufPtr, CRYPT_ALGO_NONE );
	putAlgoID( &bufPtr, CRYPT_ALGO_NONE );
	mputLong( bufPtr, 0 );	/* No language tag */
	mputLong( bufPtr, 0 );
	*bufPtr++ = 0;			/* Tell the server not to discard the packet */
	mputLong( bufPtr, 0 );	/* Reserved */
	clientKeyexLength = ( int ) ( bufPtr - \
							( sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE ) );
	status = length = wrapPacket( sessionInfoPtr,
							sessionInfoPtr->sendBuffer, clientKeyexLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the client and server hello messages.  We have to do this now 
	   (rather than deferring it until we're waiting on network traffic from
	   the server) because they may get overwritten by the keyex negotiation 
	   if we're using a non-builtin DH key value */
	hashAsString( handshakeInfo->iExchangeHashcontext,
				  sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE,
				  clientKeyexLength );
	status = hashAsString( handshakeInfo->iExchangeHashcontext,
						   sessionInfoPtr->receiveBuffer, serverKeyexLength );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using a non-builtin DH key value, request the keyex key from 
	   the server */
	if( handshakeInfo->requestedServerKeySize > 0 )
		{
		BYTE *dataStartPtr;
		const int extraLength = LENGTH_SIZE + ( LENGTH_SIZE + 6 );

		/*	...
			byte	type = SSH2_MSG_KEXDH_GEX_REQUEST
			uint32	keySize = 1024
	
		   There is an alternative format that allows the client to specify 
		   a range of key sizes:
		   
			byte	type = SSH2_MSG_KEXDH_GEX_REQUEST_NEW
			uint32	minSize = 1024 - 16
			uint32	preferredSize = 1024
			uint32	maxSize = 1024 + 16

		   but few implementations currently seem to support this, with some 
		   servers just dropping the connection without any error response if 
		   they encounter the newer packet type */
		bufPtr = dataStartPtr = sessionInfoPtr->sendBuffer + length + \
								SSH2_HEADER_SIZE;
#if 1
		*bufPtr++ = SSH2_MSG_KEXDH_GEX_REQUEST;
		mputLong( bufPtr, bytesToBits( SSH2_DEFAULT_KEYSIZE ) );
		status = length2 = wrapPacket( sessionInfoPtr,
								sessionInfoPtr->sendBuffer + length,
								ID_SIZE + UINT_SIZE );
#else
		*bufPtr++ = SSH2_MSG_KEXDH_GEX_REQUEST_NEW;
		mputLong( bufPtr, 1024 );
		mputLong( bufPtr, bytesToBits( SSH2_DEFAULT_KEYSIZE ) );
		mputLong( bufPtr, bytesToBits( CRYPT_MAX_PKCSIZE ) );
		status = length2 = wrapPacket( sessionInfoPtr,
								sessionInfoPtr->sendBuffer + length,
								ID_SIZE + ( 3 * UINT_SIZE ) );
#endif /* 1 */
		if( !cryptStatusError( status ) )
			status = sendPacketSSH2( sessionInfoPtr, length + length2, 
									 TRUE );
		if( cryptStatusError( status ) )
			return( status );

		/* Remember the encoded key size info for later when we generate
		   the exchange hash */
#if 1
		memcpy( handshakeInfo->encodedReqKeySizes, dataStartPtr + 1,
				UINT_SIZE );
		handshakeInfo->encodedReqKeySizesLength = UINT_SIZE;
#else
		memcpy( handshakeInfo->encodedReqKeySizes, dataStartPtr + 1,
				3 * UINT_SIZE );
		handshakeInfo->encodedReqKeySizesLength = 3 * UINT_SIZE;
#endif /* 1 */

		/* Process the ephemeral DH key:

			byte	type = SSH2_MSG_KEXDH_GEX_GROUP
			mpint	p
			mpint	g */
		length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_KEXDH_GEX_GROUP );
		if( cryptStatusError( length ) )
			return( length );
		bufPtr = dataStartPtr = sessionInfoPtr->receiveBuffer + ID_SIZE;
		length -= ID_SIZE;
		if( length < ( LENGTH_SIZE + bitsToBytes( MIN_PKCSIZE_BITS ) ) + \
					 ( LENGTH_SIZE + 1 ) || \
			length > ( ( LENGTH_SIZE + CRYPT_MAX_PKCSIZE ) * 2 ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid DH ephemeral key packet length %d",
					length );

		/* Since this phase of the key negotiation exchanges raw key 
		   components rather than the standard SSH public-key format, we 
		   have to rewrite the raw key components into a standard SSH key so 
		   that we can import it:

			string	"ssh-dh"
			mpint	p
			mpint	g */
		memmove( bufPtr + extraLength, bufPtr, length );
		mputLong( bufPtr, ( extraLength - LENGTH_SIZE ) + length );
		encodeString( bufPtr, "ssh-dh", 0 );

		/* Destroy the existing static DH key, load the new one, and
		   re-perform phase 1 of the DH key agreement process */
		krnlSendNotifier( handshakeInfo->iServerCryptContext, 
						  IMESSAGE_DECREFCOUNT );
		status = initDHcontext( &handshakeInfo->iServerCryptContext,
								&handshakeInfo->serverKeySize, 
								dataStartPtr, extraLength + length,
								CRYPT_UNUSED );
		if( cryptStatusOK( status ) )
			{
			memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
			status = krnlSendMessage( handshakeInfo->iServerCryptContext,
									  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
									  sizeof( KEYAGREE_PARAMS ) );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* We've already sent the client hello as part of the keyex 
		   negotiation so there's no need to bundle it with the client
		   keyex, reset the start position in the send buffer */
		length = 0;
		}

	/*	...
		byte	type = SSH2_MSG_KEXDH_INIT / SSH2_MSG_KEXDH_GEX_INIT
		mpint	y */
	bufPtr = sessionInfoPtr->sendBuffer + length + SSH2_HEADER_SIZE;
	*bufPtr++ = ( handshakeInfo->requestedServerKeySize > 0 ) ? \
				SSH2_MSG_KEXDH_GEX_INIT : SSH2_MSG_KEXDH_INIT;
	mpiLength = encodeMPI( bufPtr, keyAgreeParams.publicValue,
						   keyAgreeParams.publicValueLen );
	status = length2 = wrapPacket( sessionInfoPtr,
							sessionInfoPtr->sendBuffer + length,
							ID_SIZE + mpiLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Save the MPI-encoded client DH keyex value for later, when we need to
	   hash it */
	memcpy( handshakeInfo->clientKeyexValue,
			sessionInfoPtr->sendBuffer + length + SSH2_HEADER_SIZE + ID_SIZE,
			mpiLength );
	handshakeInfo->clientKeyexValueLength = mpiLength;

	/* Send the whole mess to the server.  Since SSH, unlike SSL, requires
	   that each packet in a multi-packet group be wrapped as a separate
	   packet, we have to first assemble the packets via wrapPacket() and
	   then send them in a group via sendPacket() with the send-only
	   flag set */
	status = sendPacketSSH2( sessionInfoPtr, length + length2, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up PKC info while we wait for the server to process our 
	   response */
	setMessageCreateObjectInfo( &createInfo, handshakeInfo->pubkeyAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		sessionInfoPtr->iKeyexAuthContext = createInfo.cryptHandle;
	return( status );
	}

/* Exchange keys with the server */

static int exchangeClientKeys( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_ALGO_TYPE pubkeyAlgo;
	RESOURCE_DATA msgData;
	BYTE *bufPtr, *dataStartPtr;
	int length, dataLength, stringLength, status;

	/* Process the DH phase 2 keyex packet:

		byte		type = SSH2_MSG_KEXDH_REPLY / SSH2_MSG_KEXDH_GEX_REPLY
		string		server key/certificate
			string	"ssh-rsa"	"ssh-dss"
			mpint	e			p
			mpint	n			q
			mpint				g
			mpint				y
		mpint		y'
		string		signature of handshake data
			string	"ssh-rsa"	"ssh-dss"
			string	signature	signature

	   First, we read and hash the server key/certificate.  Since this is
	   already encoded as an SSH string, we can hash it directly */
	length = readPacketSSH2( sessionInfoPtr, 
					( handshakeInfo->requestedServerKeySize > 0 ) ? \
					SSH2_MSG_KEXDH_GEX_REPLY : SSH2_MSG_KEXDH_REPLY );
	if( cryptStatusError( length ) )
		return( length );
	bufPtr = dataStartPtr = sessionInfoPtr->receiveBuffer + ID_SIZE;
	dataLength = ( int ) mgetLong( bufPtr );	/* Server key size */
	length -= ID_SIZE + LENGTH_SIZE + dataLength;
	if( length < ( LENGTH_SIZE + bitsToBytes( MIN_PKCSIZE_BITS ) ) + \
				 LENGTH_SIZE + ( LENGTH_SIZE + 7 ) + ( LENGTH_SIZE + 40 ) || \
		dataLength < ( LENGTH_SIZE + 7 ) + ( LENGTH_SIZE + 1 ) + \
					 ( LENGTH_SIZE + bitsToBytes( MIN_PKCSIZE_BITS ) ) || \
		dataLength > ( LENGTH_SIZE + 7 ) + \
					 ( ( LENGTH_SIZE + CRYPT_MAX_PKCSIZE ) * 4 ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 packet length %d, data length %d",
				length, dataLength );
	stringLength = getAlgoID( handshakeInfo->algoStringPubkeyTbl,
							  &pubkeyAlgo, CRYPT_ALGO_NONE, bufPtr,
							  dataLength, sessionInfoPtr );
	if( cryptStatusError( stringLength ) )
		return( stringLength );
	if( pubkeyAlgo != handshakeInfo->pubkeyAlgo )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 public key algorithm %d, expected %d",
				pubkeyAlgo, handshakeInfo->pubkeyAlgo );
	setMessageData( &msgData, dataStartPtr, LENGTH_SIZE + dataLength );
	status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_KEY_SSH2 );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, cryptArgError( status ) ? \
				CRYPT_ERROR_BADDATA : status, 
				"Invalid server key/certificate" );
	status = krnlSendMessage( handshakeInfo->iExchangeHashcontext,
							  IMESSAGE_CTX_HASH, dataStartPtr,
							  LENGTH_SIZE + dataLength );
	if( cryptStatusOK( status ) )
		status = processKeyFingerprint( sessionInfoPtr,
										dataStartPtr + LENGTH_SIZE,
										dataLength );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr += dataLength;

	/* Then we read the server DH keyex value and complete the DH key
	   agreement */
	dataStartPtr = bufPtr;
	dataLength = ( int ) mgetLong( bufPtr );	/* DH keyex value size */
	length -= LENGTH_SIZE + dataLength;
	if( length < LENGTH_SIZE + ( LENGTH_SIZE + 7 ) + ( LENGTH_SIZE + 40 ) || \
		dataLength < bitsToBytes( MIN_PKCSIZE_BITS ) || \
		dataLength > 4 + CRYPT_MAX_PKCSIZE )	/* +4 for zero-pad */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid DH phase 2 keyex value length %d, packet length "
				"%d", dataLength, length );
	bufPtr += dataLength;
	memcpy( handshakeInfo->serverKeyexValue, dataStartPtr,
			LENGTH_SIZE + dataLength );
	handshakeInfo->serverKeyexValueLength = LENGTH_SIZE + dataLength;
	status = completeKeyex( sessionInfoPtr, handshakeInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Some implementations incorrectly format the signature packet, 
	   omitting the algorithm name and signature blob length for DSA sigs 
	   (that is, they just encode two 20-byte values instead of a properly-
	   formatted signature):

			  Right							  Wrong
		string		signature data		string		signature data
			string	"ssh-dss"						signature
			string	signature

	   If we're talking to one of these versions, we check to see whether 
	   the packet is correctly formatted and if it isn't rewrite it into the 
	   correct format so that we can verify the signature.  This check 
	   requires that the signature format be one of the SSHv2 standard 
	   types, but since we can't (by definition) handle proprietary formats 
	   this isn't a problem */
	if( ( sessionInfoPtr->protocolFlags & SSH_PFLAG_SIGFORMAT ) && \
		( pubkeyAlgo == CRYPT_ALGO_DSA ) && \
		( memcmp( bufPtr + LENGTH_SIZE + LENGTH_SIZE, "ssh-", 4 ) && \
		  memcmp( bufPtr + LENGTH_SIZE + LENGTH_SIZE, "x509v3-", 7 ) && \
		  memcmp( bufPtr + LENGTH_SIZE + LENGTH_SIZE, "spki-", 5 ) && \
		  memcmp( bufPtr + LENGTH_SIZE + LENGTH_SIZE, "pgp-", 4 ) ) )
		{
		BYTE *sigInfoPtr = bufPtr;
		const int extraLength = putAlgoID( NULL, CRYPT_ALGO_DSA ) + \
								LENGTH_SIZE;

		/* Make sure that the rewritten packet still fits into the buffer */
		if( ( bufPtr - sessionInfoPtr->receiveBuffer ) + length + extraLength >= \
			sessionInfoPtr->receiveBufSize )
			retExt( sessionInfoPtr, CRYPT_ERROR_OVERFLOW,
					"Invalid DH phase 2 keyex value length %d, need extra %d "
					"bytes", length, extraLength );

		/* Rewrite the packet to fix up the overall length at the start and 
		   insert the algorithm name and signature length */
		memmove( sigInfoPtr + extraLength, sigInfoPtr, length );
		mputLong( sigInfoPtr, extraLength + length );
		putAlgoID( &sigInfoPtr, pubkeyAlgo );
		mputLong( sigInfoPtr, length );
		}

	/* Finally, verify the server's signature on the exchange hash */
	status = iCryptCheckSignatureEx( bufPtr, length, CRYPT_IFORMAT_SSH,
							sessionInfoPtr->iKeyexAuthContext,
							handshakeInfo->iExchangeHashcontext, NULL );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Bad handshake data signature" );

	/* We don't need the hash context any more, get rid of it */
	krnlSendNotifier( handshakeInfo->iExchangeHashcontext,
					  IMESSAGE_DECREFCOUNT );
	handshakeInfo->iExchangeHashcontext = CRYPT_ERROR;

	return( CRYPT_OK );
	}

/* Complete the handshake with the server */

static int completeClientHandshake( SESSION_INFO *sessionInfoPtr,
									SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	BYTE *bufPtr;
	int length, totalLength, status;

	/* Set up the security information required for the session */
	status = initSecurityInfo( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Wait for the server's change cipherspec message */
	status = readPacketSSH2( sessionInfoPtr, SSH2_MSG_NEWKEYS );
	if( cryptStatusError( status ) )
		return( status );

	/* Build our change cipherspec message and request authentication with
	   the server:

		byte	type = SSH2_MSG_NEWKEYS
		... */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_NEWKEYS;
	status = totalLength = wrapPacket( sessionInfoPtr,
									   sessionInfoPtr->sendBuffer, ID_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* We've sent the change cipherspec message, from now on all data is
	   encrypted and MAC'ed */
	sessionInfoPtr->flags |= SESSION_ISSECURE;

	/*	...
		byte	type = SSH2_MSG_SERVICE_REQUEST
		string	service_name = "ssh-userauth" */
	bufPtr = sessionInfoPtr->sendBuffer + totalLength + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_SERVICE_REQUEST;
	length = encodeString( bufPtr, "ssh-userauth", 0 );
	status = length = wrapPacket( sessionInfoPtr,
								  sessionInfoPtr->sendBuffer + totalLength,
								  ID_SIZE + length );
	if( cryptStatusError( status ) )
		return( status );

	/* Send the whole mess to the server.  For some reason SSHv2 requires 
	   the use of two authentication messages, an "I'm about to 
	   authenticate" packet and an "I'm authenticating" packet, so we have 
	   to perform the authentication in two parts.  SSL at this point uses a 
	   Finished message in which the client and server do a mutual proof-of-
	   possession of encryption and MAC keys via a pipeline-stalling message 
	   that prevents any further (sensitive) data from being exchanged until 
	   the PoP has concluded (the SSL Finished also authenticates the 
	   handshake messages).  The signed exchange hash from the server proves 
	   to the client that the server knows the master secret, but not 
	   necessarily that the client and server share encryption and MAC keys.  
	   Without this mutual PoP, the client could potentially end up sending 
	   passwords to the server using an incorrect (and potentially weak) key 
	   if it's messed up and derived the key incorrectly.  Although mutual 
	   PoP isn't a design goal of the SSH handshake, we do it anyway (as far 
	   as we can without a proper Finished message), although this introduces 
	   a pipeline stall at this point 

	   The spec in fact says that after a key exchange with implicit server
	   authentication the client has to wait for the server to send a 
	   service-accept packet before continuing, however it never explains 
	   what implicit (and, by extension, explicit) server authentication 
	   actually are.  This text is a leftover from an extremely early SSH 
	   draft in which the only keyex mechanism was "double-encrypting-sha", 
	   a mechanism that required a pipeline stall at this point because the 
	   client wasn't able to authenticate the server until it received the 
	   first encrypted/MAC'ed message from it.  In theory to extricate 
	   ourselves from the confusion due to the missing definition we could
	   define "implicit authentication" to be "Something completely 
	   different from what we're doing here", which means that we could send 
	   the two packets together without having to wait for the server, but 
	   it's probably better to use SSL-tyle Finished semantics at this point
	   even if it adds an extra RTT delay */
	status = sendPacketSSH2( sessionInfoPtr, totalLength + length, TRUE );
	if( cryptStatusOK( status ) )
		status = readPacketSSH2( sessionInfoPtr, SSH2_MSG_SERVICE_ACCEPT );
	if( cryptStatusError( status ) )
		return( status );

	/*	byte	type = SSH2_MSG_USERAUTH_REQUEST
		string	user_name
		string	service_name = "ssh-connection"
		... 

	   The way in which we handle authentication here isn't totally 
	   appropriate since we assume that the user knows the appropriate form
	   of authentication to use.  If they're ambiguous and supply both a
	   password and a private key and the server only accepts PKC-based
	   authentication, this will always preferentially choose password-based
	   authentication.  The way around this is to send an auth-request with
	   a method-type of "none" to see what the server wants, but the only 
	   thing cryptlib can do (since it's non-interactive during the
	   handshake phase) is disconnect, tell the user what went wrong, and try
	   again.  The current mechanism does this anyway, so we don't gain much
	   by adding this question-and-answer facility */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_USERAUTH_REQUEST;
	bufPtr += encodeString( bufPtr, sessionInfoPtr->userName,
							sessionInfoPtr->userNameLength );
	bufPtr += encodeString( bufPtr, "ssh-connection", 0 );
	if( sessionInfoPtr->passwordLength > 0 )
		{
		/*	...
			string	method-name = "password"
			boolean	FALSE
			string	password */
		bufPtr += encodeString( bufPtr, "password", 0 );
		*bufPtr++ = 0;
		bufPtr += encodeString( bufPtr, sessionInfoPtr->password,
								sessionInfoPtr->passwordLength );
		}
	else
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;
		RESOURCE_DATA msgData;
		int sigLength;

		/*	...
			string	method-name = "publickey"
			boolean	TRUE
			string		client certificate
				string	"ssh-rsa"	"ssh-dss"
				mpint	e			p
				mpint	n			q
				mpint				g
				mpint				y
			string		client signature
				string	"ssh-rsa"	"ssh-dss"
				string	signature	signature */
		bufPtr += encodeString( bufPtr, "publickey", 0 );
		*bufPtr++ = 1;
		setMessageData( &msgData, bufPtr,
						LENGTH_SIZE + ( LENGTH_SIZE + 7 ) + \
						( ( LENGTH_SIZE + CRYPT_MAX_PKCSIZE ) * 4 ) );
		status = krnlSendMessage( sessionInfoPtr->privateKey,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSH2 );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr += msgData.length;

		/* Sign the authentication request data:

			string		exchange hash
			[ user_auth_request packet payload up to signature start ] */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		if( !( sessionInfoPtr->protocolFlags & SSH_PFLAG_NOHASHLENGTH ) )
			{
			BYTE header[ 8 ], *headerPtr = header;

			/* Some implementations erroneously omit the length when hashing
			    the exchange hash */
			mputLong( headerPtr, handshakeInfo->sessionIDlength );
			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							 header, LENGTH_SIZE );
			}
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
						 handshakeInfo->sessionID,
						 handshakeInfo->sessionIDlength );
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
						 sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE,
						 bufPtr - ( sessionInfoPtr->sendBuffer + \
									SSH2_HEADER_SIZE ) );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
								  "", 0 );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		status = iCryptCreateSignatureEx( bufPtr, &sigLength,
						sessionInfoPtr->sendBufSize - \
							( ( bufPtr - sessionInfoPtr->sendBuffer ) + 128 ),
						CRYPT_IFORMAT_SSH, sessionInfoPtr->privateKey,
						createInfo.cryptHandle, CRYPT_UNUSED, CRYPT_UNUSED );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr += sigLength;
		}
	status = length = wrapPacket( sessionInfoPtr,
								  sessionInfoPtr->sendBuffer,
								  bufPtr - ( sessionInfoPtr->sendBuffer + \
											 SSH2_HEADER_SIZE ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Send the authentication info to the server and wait for the server's 
	   ack of the authentication */
	status = sendPacketSSH2( sessionInfoPtr, length, TRUE );
	if( cryptStatusOK( status ) )
		status = readPacketSSH2( sessionInfoPtr, SSH2_MSG_SPECIAL_USERAUTH );
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		CRYPT_ALGO_TYPE authentAlgo;
		int stringLength;

		/* The authentication failed, pick apart the response to see if we 
		   can return more meaningful error info:

			byte	type = SSH2_MSG_USERAUTH_FAILURE
			string	available_auth_types
			boolean	partial_success

		  God knows how the partial_success flag is really meant to be 
		  applied (there are a whole pile of odd conditions surrounding 
		  changed passwords and similar issues), according to the spec it 
		  means that the authentication was successful, however the packet 
		  type indicates that the authentication failed and something else is 
		  needed.  This whole section of the protocol winds up in an 
		  extremely complex state machine with all sorts of special-case 
		  conditionsm, several of which require manual intervention by the
		  user.  It's easiest to not even try and handle this stuff */
		bufPtr = sessionInfoPtr->receiveBuffer + ID_SIZE;
		length = ( int ) mgetLong( bufPtr );
		stringLength = getAlgoID( handshakeInfo->algoStringUserauthentTbl, 
								  &authentAlgo, CRYPT_ALGO_DES, 
								  sessionInfoPtr->receiveBuffer + ID_SIZE, 
								  length + UINT_SIZE, sessionInfoPtr );
		if( cryptStatusError( stringLength ) )
			{
			/* If the problem is due to lack of a compatible algorithm, make
			   the error message a bit more specific to tell the user that we
			   got through most of the handshake but failed at the 
			   authentication stage */
			if( stringLength == CRYPT_ERROR_NOTAVAIL )
				retExt( sessionInfoPtr, CRYPT_ERROR_NOTAVAIL,
						"Remote system supports neither password nor "
						"public-key authentication" );
			return( stringLength );
			}
		if( sessionInfoPtr->passwordLength > 0 )
			{
			/* If we used a password and the server wants a PKC, report the 
			   error as a missing private key.  RSA in this case is a 
			   placeholder that means "any public-key algorithm", it could
			   just as well end up as DSA once we send the data */
			if( authentAlgo == CRYPT_ALGO_RSA )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				retExt( sessionInfoPtr, CRYPT_ERROR_NOTINITED,
						"Server requested public-key authentication but "
						"only a password was available" );
				}
			}
		else
			/* If we used a PKC and the server wants a password, report the 
			   error as a missing password.  DES in this case is a 
			   placeholder for passwords, since there's no cryptlib ID for
			   them */
			if( authentAlgo == CRYPT_ALGO_DES )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				retExt( sessionInfoPtr, CRYPT_ERROR_NOTINITED,
						"Server requested password authentication but "
						"only a public/private key was available" );
				}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've finally made it through all the formalities (post proelia 
	   praemia), open a channel of the requested type:

		byte	type = SSH2_MSG_CHANNEL_OPEN
		string	channel_type = "session"
		uint32	sender_channel = 0
		uint32	initial_window_size = MAX_WINDOW_SIZE
		uint32	max_packet_size = bufSize
		...

	   The use of security protocol-level flow control when there's already
	   a far better, heavily analysed and field-tested network protocol-
	   level flow control mechanism is just stupid.  All it does is create
	   performance problems where throughput can be reduced by as much as an
	   order of magnitude due to SSH's "flow-control" getting in the way 
	   (Putty even has an FAQ entry "Why is SFTP so much slower than scp?", 
	   for which the correct answer should be "It's the SSH-level flow-
	   control braindamage").  For this reason cryptlib always advertises a 
	   maximum window size (effectively disabling the SSH-level flow 
	   control) and lets the network stack and network hardware take care of 
	   flow control, as it should */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_CHANNEL_OPEN;
	bufPtr += encodeString( bufPtr, "session", 0 );
	mputLong( bufPtr, 0 );
	length = sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE;
	mputLong( bufPtr, MAX_WINDOW_SIZE );
	mputLong( bufPtr, length );
	status = totalLength = wrapPacket( sessionInfoPtr,
							sessionInfoPtr->sendBuffer,
							bufPtr - ( sessionInfoPtr->sendBuffer + \
									   SSH2_HEADER_SIZE ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Create a request for the appropriate type of service, either 
	   encrypted-telnet, SFTP, or port forwarding */
	status = createOpenRequest( sessionInfoPtr, 
								sessionInfoPtr->sendBuffer + totalLength );
	if( cryptStatusError( status ) )
		return( status );
	totalLength += status;

	/* Send the whole mess to the server, again as separate packets, and wait
	   for the server's ack of the channel open request and channel request.
	   As with the authentication, we have to send two packets to do the work
	   of one.

	   The SSHv2 spec doesn't really explain the semantics of the server's
	   response to the channel open command, in particular whether the
	   returned data size parameters are merely a confirmation of the
	   client's requested values or whether the server is allowed to further
	   modify them to suit its own requirements (or perhaps one is for send
	   and the other for receive?).  In the absence of any further guidance,
	   we just ignore the returned values, which seems to work for all
	   deployed servers */
	status = sendPacketSSH2( sessionInfoPtr, totalLength, TRUE );
	if( cryptStatusOK( status ) )
		status = readPacketSSH2( sessionInfoPtr,
								 SSH2_MSG_CHANNEL_OPEN_CONFIRMATION );
	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSH2clientProcessing( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	handshakeInfo->beginHandshake = beginClientHandshake;
	handshakeInfo->exchangeKeys = exchangeClientKeys;
	handshakeInfo->completeHandshake = completeClientHandshake;
	}
#endif /* SSH2 */
