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

/* SSHv2 algorithm names sent to client, in preferred algorithm order.  
   Since we have a fixed algorithm for our public key (determined by the key
   type), we only send a single value for this that's evaluated at runtime,
   so there's no list for this defined.
   
   Note that these tables must match the algoStringXXXTbl values in ssh2.c */

static const FAR_BSS CRYPT_ALGO_TYPE algoKeyexList[] = {
	CRYPT_ALGO_DH, CRYPT_ALGO_NONE };
static const FAR_BSS char *algoStringCoprList = "none";
static const FAR_BSS CRYPT_ALGO_TYPE algoEncrList[] = {
	/* We can't list AES as an option because the peer can pick up anything
	   it wants from the list as its preferred choice, which means that if 
	   we're talking to any non-cryptlib implementation they always go for 
	   AES even though it doesn't currently have the provenance of 3DES.
	   Once AES passes the five-year test this option can be enabled */
	CRYPT_ALGO_3DES, /*CRYPT_ALGO_AES,*/ CRYPT_ALGO_BLOWFISH, 
	CRYPT_ALGO_CAST, CRYPT_ALGO_IDEA, CRYPT_ALGO_RC4, CRYPT_ALGO_NONE };
static const FAR_BSS CRYPT_ALGO_TYPE algoMACList[] = { 
	CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_MD5, CRYPT_ALGO_NONE };
static const FAR_BSS char *algoStringUserauthentList = "password";

/* Encode a list of available algorithms */

static int putAlgoList( BYTE **bufPtrPtr, const CRYPT_ALGO_TYPE algoList[] )
	{
	static const FAR_BSS ALGO_STRING_INFO algoStringMapTbl[] = {
		{ "ssh-rsa", CRYPT_ALGO_RSA },
		{ "ssh-dss", CRYPT_ALGO_DSA },
		{ "3des-cbc", CRYPT_ALGO_3DES },
		{ "aes128-cbc", CRYPT_ALGO_AES },
		{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
		{ "cast128-cbc", CRYPT_ALGO_CAST },
		{ "idea-cbc", CRYPT_ALGO_IDEA },
		{ "arcfour", CRYPT_ALGO_RC4 },
		{ "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
		{ "diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
		{ "hmac-sha1", CRYPT_ALGO_HMAC_SHA },
		{ "hmac-md5", CRYPT_ALGO_HMAC_MD5 },
		{ "none", CRYPT_ALGO_NONE },
		};
	const char *availableAlgos[ 16 ];
	int noAlgos = 0, length = 0, algoIndex;

	/* Walk down the list of algorithms remembering the encoded name of each 
	   one that's available for use */
	for( algoIndex = 0; algoList[ algoIndex ] != CRYPT_ALGO_NONE; algoIndex++ )
		if( algoAvailable( algoList[ algoIndex ] ) )
			{
			int i;

			for( i = 0; algoStringMapTbl[ i ].algo != CRYPT_ALGO_NONE && \
						algoStringMapTbl[ i ].algo != algoList[ algoIndex ]; i++ );
			assert( algoStringMapTbl[ i ].algo != CRYPT_ALGO_NONE );
			availableAlgos[ noAlgos++ ] = algoStringMapTbl[ i ].name;
			length += strlen( algoStringMapTbl[ i ].name );
			if( noAlgos > 1 )
				length++;			/* Room for comma delimiter */
			}

	/* Encode the list of available algorithms into a comma-separated string */
	if( bufPtrPtr != NULL )
		{
		BYTE *bufPtr = *bufPtrPtr;

		mputLong( bufPtr, length );
		for( algoIndex = 0; algoIndex < noAlgos; algoIndex++ )
			{
			const int algoLen = strlen( availableAlgos[ algoIndex ] );

			if( algoIndex > 0 )
				*bufPtr++ = ',';	/* Add comma delimiter */
			memcpy( bufPtr, availableAlgos[ algoIndex ], algoLen );
			bufPtr += algoLen;
			}

		*bufPtrPtr = bufPtr;
		}
	return( LENGTH_SIZE + length );
	}

/* Process a channel open */

int getAddressAndPort( SESSION_INFO *sessionInfoPtr, const BYTE *data,
					   const int dataLength )
	{
	char portBuffer[ 16 ];
	long port;
	int length = dataLength, stringLength, portLength;

	/* Get the host and port and convert it into string form for the user to 
	   read:

		string	host
		uint32	port */
	stringLength = ( int ) mgetLong( data );
	if( stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE - 4 || \
		length < ( LENGTH_SIZE + stringLength ) + UINT_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid port forwarding host name length %d", 
				stringLength );
	memcpy( sessionInfoPtr->sshPortForward, data, stringLength );
	data += stringLength;
	port = mgetLong( data );
	length -= ( LENGTH_SIZE + stringLength ) + UINT_SIZE;
	portBuffer[ 0 ] = ':';
	portLength = sprintf( portBuffer + 1, "%ld", port ) + 1;
	if( stringLength + portLength <= CRYPT_MAX_TEXTSIZE )
		{
		memcpy( sessionInfoPtr->sshPortForward + stringLength,
				portBuffer, portLength );
		stringLength += portLength;
		}
	sessionInfoPtr->sshPortForwardLength = stringLength;
	return( CRYPT_OK );
	}

int processChannelOpen( SESSION_INFO *sessionInfoPtr, const BYTE *data,
						const int dataLength )
	{
	BYTE *bufPtr;
	BOOLEAN isPortForwarding = FALSE;
	long maxPacketSize;
	int length = dataLength, stringLength;

	/* Read the channel open request.  The ID byte has already been read by
	   the caller:

	  [	byte	type = SSH2_MSG_CHANNEL_OPEN ]
		string	channel_type = "session" | "direct-tcpip"
		uint32	sender_channel
		uint32	initial_window_size
		uint32	max_packet_size
	  [ string	host_to_connect		- For port-forwarding
		uint32	port_to_connect
		string	originator_IP_address
		uint32	originator_port ]
	
	   Some clients open a standard (non-forwarded) channel when they connect
	   for general comms and then later open a forwarded channel when client 
	   -> server forwarding is being used and a forwarded connection arrives, 
	   we interpret this to mean that the forwarded channel should supersede 
	   the original non-forwarded one, performed by simply copying the new 
	   channel info over the top of the existing info */
	stringLength = ( int ) mgetLong( data );
	if( stringLength <= 0 || \
		length < ( LENGTH_SIZE + stringLength ) + \
				 UINT_SIZE + UINT_SIZE + UINT_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid channel open packet length %d, string length %d",
				length, stringLength );
	if( stringLength != 7 || memcmp( data, "session", 7 ) )
		{
		/* It's not a normal channel open, see if the caller is trying to
		   do port forwarding */
		if( stringLength != 12 || memcmp( data, "direct-tcpip", 12 ) )
			{
			char stringBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];

			/* It's something else, report it as an error */
			stringLength = min( stringLength, CRYPT_MAX_TEXTSIZE );
			memcpy( stringBuffer, data, stringLength );
			stringBuffer[ stringLength ] = '\0';
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid channel open channel type '%'", stringBuffer );
			}
		isPortForwarding = TRUE;
		}
	data += stringLength;
	length -= ( LENGTH_SIZE + stringLength );
	sessionInfoPtr->sshChannel = mgetLong( data );
	data += UINT_SIZE;					/* Skip window size */
	length -= UINT_SIZE + UINT_SIZE;
	sessionInfoPtr->sshWindowCount = 0;	/* New window, reset count */
	maxPacketSize = mgetLong( data );
	if( maxPacketSize < 16 || maxPacketSize > 0x100000L )
		/* General sanity check to make sure that the packet size is in the 
		   range 16 bytes ... 16MB */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid maximum packet size %d", maxPacketSize );
	length -= UINT_SIZE;
	if( isPortForwarding )
		{
		int status;

		/* Get the source and destination host information */
		if( length < ( LENGTH_SIZE + 1 ) + UINT_SIZE + \
					 ( LENGTH_SIZE + 1 ) + UINT_SIZE )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid port forwarding channel open data length %d", 
					length );
		status = getAddressAndPort( sessionInfoPtr, data, length );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* If it's a straight channel open, there shouldn't be any more 
		   data */
		if( length != 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid additional %d data bytes in channel open", 
					length );

	/* Send back the open confirmation:

		byte	type = SSH2_MSG_CHANNEL_OPEN_CONFIRMATION
		uint32	recipient_channel = prev. sender_channel
		uint32	sender_channel
		uint32	initial_window_size = MAX_WINDOW_SIZE
		uint32	max_packet_size = bufSize

	   The SSHv2 spec doesn't really explain the semantics of the server's 
	   response to the channel open command, in particular whether the 
	   returned data size parameters are merely a confirmation of the 
	   client's requested values or whether the server is allowed to further 
	   modify them to suit its own requirements (or perhaps one is for send 
	   and the other for receive?).  In the absence of any further guidance, 
	   we try and comply with a client's request for smaller data 
	   quantities, but also return a smaller-than-requested data size value 
	   if they ask for too much data.

	   See the comments in the client-handshake code for the reason for the 
	   window size */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;
	mputLong( bufPtr, sessionInfoPtr->sshChannel );		/* Recip.channel */
	mputLong( bufPtr, sessionInfoPtr->sshChannel );		/* Sender channel */
	mputLong( bufPtr, MAX_WINDOW_SIZE );				/* Window size */
	maxPacketSize = min( maxPacketSize, \
						 sessionInfoPtr->receiveBufSize - EXTRA_PACKET_SIZE );
	mputLong( bufPtr, maxPacketSize );
	return( sendPacketSSH2( sessionInfoPtr,
				bufPtr - ( sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE ),
				FALSE ) );
	}

/****************************************************************************
*																			*
*							Server-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the client */

static int beginServerHandshake( SESSION_INFO *sessionInfoPtr,
								 SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	static const FAR_BSS ALGO_STRING_INFO algoStringPubkeyRSATbl[] = {
		{ "ssh-rsa", CRYPT_ALGO_RSA },
		{ NULL, CRYPT_ALGO_NONE }
		};
	static const FAR_BSS ALGO_STRING_INFO algoStringPubkeyDSATbl[] = {
		{ "ssh-dss", CRYPT_ALGO_DSA },
		{ NULL, CRYPT_ALGO_NONE }
		};
	RESOURCE_DATA msgData;
	BYTE *bufPtr;
	int length, serverKeyexLength, clientKeyexLength, status;

	/* Get the public-key algorithm that we'll be advertising to the client 
	   and set the algorithm table used for processing the client hello to 
	   only match the one that we're offering */
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_GETATTRIBUTE,
							  &handshakeInfo->pubkeyAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	switch( handshakeInfo->pubkeyAlgo )
		{
		case CRYPT_ALGO_RSA:
			handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyRSATbl;
			break;

		case CRYPT_ALGO_DSA:
			handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyDSATbl;
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
		}

	/* SSHv2 hashes parts of the handshake messages for integrity-protection
	   purposes, so we hash the ID strings (first the client string that we
	   read previously, then our server string) encoded as SSH string
	   values */
	hashAsString( handshakeInfo->iExchangeHashcontext,
				  sessionInfoPtr->receiveBuffer,
				  strlen( sessionInfoPtr->receiveBuffer ) );
	hashAsString( handshakeInfo->iExchangeHashcontext, SSH2_ID_STRING,
				  strlen( SSH2_ID_STRING ) );

	/* Send the server hello packet:

		byte		type = SSH2_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms
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

	   The SSH spec leaves the order in which things happen ambiguous, in 
	   order to save a while round trip it has provisions for both sides 
	   shouting at each other and then a complex interlock process where
	   bits of the initial exchange can be discarded and retried if necessary.
	   This is ugly and error-prone.  The client code solves this by waiting
	   for the server hello, choosing known-good algorithms, and then sending
	   the client hello immediately followed by the client key exchange data.
	   Since it waits for the server to speak first, it can choose parameters
	   that are accepted the first time.

	   Unfortunately, this doesn't work if we're the server, since we'd end
	   up waiting for the client to speak first while it waits for us to
	   speak first, so we have to send the server hello in order to prevent
	   deadlock.  This works fine with almost all clients tested, which take
	   the same approach and wait for the server to speak first.  The message
	   flow is then:

		server hello;
		client hello;
		client keyex;
		server keyex;
	   
	   One exception to this is the F-Secure client, which has the client 
	   speak first, choosing as its preference the incompletely specified
	   "x509v3-sign-dss" format (see the comment in exchangeServerKeys()
	   below) that we can't use since no-one's quite sure what the format is.  
	   In this case the message flow is:

		server hello;
		client hello;
		client keyex1;
		client keyex2;
		server keyex;

	   This is handled by having the code that reads the client hello return 
	   OK_SPECIAL to indicate that the next packet should be skipped.  An 
	   alternative (and simpler) strategy would be to always throw away the 
	   F-Secure client's first keyex, since it's using an algorithm choice 
	   that's impossible to use */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_KEXINIT;
	setMessageData( &msgData, bufPtr, SSH2_COOKIE_SIZE );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
					 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	bufPtr += SSH2_COOKIE_SIZE;
	putAlgoList( &bufPtr, algoKeyexList );
	putAlgoID( &bufPtr, handshakeInfo->pubkeyAlgo );
	putAlgoList( &bufPtr, algoEncrList );
	putAlgoList( &bufPtr, algoEncrList );
	putAlgoList( &bufPtr, algoMACList );
	putAlgoList( &bufPtr, algoMACList );
	bufPtr += encodeString( bufPtr, algoStringCoprList, 0 );
	bufPtr += encodeString( bufPtr, algoStringCoprList, 0 );
	mputLong( bufPtr, 0 );		/* No language tag */
	mputLong( bufPtr, 0 );
	*bufPtr++ = 0;				/* Don't try and guess the keyex */
	mputLong( bufPtr, 0 );		/* Reserved */
	serverKeyexLength = ( int ) \
			( bufPtr - ( sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE ) );
	status = sendPacketSSH2( sessionInfoPtr, serverKeyexLength, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* While we wait for the client to digest our hello and send back its
	   response, create the context with the DH key */
	status = initDHcontext( &handshakeInfo->iServerCryptContext,
							&handshakeInfo->serverKeySize, NULL, 0,
							CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the client hello packet */
	status = processHello( sessionInfoPtr, handshakeInfo, 
						   &clientKeyexLength, TRUE );
	if( status == OK_SPECIAL )
		/* There's an incorrectly-guessed keyex following the client 
		   hello, skip it */
		status = readPacketSSH2( sessionInfoPtr, 
						( handshakeInfo->requestedServerKeySize > 0 ) ? \
						SSH2_MSG_KEXDH_GEX_INIT : SSH2_MSG_KEXDH_INIT );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the client and server hello messages */
	hashAsString( handshakeInfo->iExchangeHashcontext,
				  sessionInfoPtr->receiveBuffer, clientKeyexLength );
	status = hashAsString( handshakeInfo->iExchangeHashcontext,
						   sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE,
						   serverKeyexLength );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using a nonstandard DH key value, negotiate a new key with 
	   the client */
	if( handshakeInfo->requestedServerKeySize > 0 )
		{
		BOOLEAN isExtReq = FALSE;
		const int extraLength = LENGTH_SIZE + ( LENGTH_SIZE + 6 );
		int keySize;

		/* Get the keyex key request from the client.  Portions of the the 
		   request info are hashed later on as part of the exchange hash, so
		   we have to save a copy for then.  Note that we save the original
		   encoded form, because some clients send non-integral lengths that 
		   don't survive the conversion from bits to bytes */
		length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_KEXDH_GEX_REQUEST );
		if( cryptStatusError( length ) )
			return( length );
		bufPtr = sessionInfoPtr->receiveBuffer;
		if( *bufPtr++ == SSH2_MSG_KEXDH_GEX_REQUEST_NEW )
			{
			/* It's a { min_length, length, max_length } sequence, save a 
			   copy and get the length value */
			memcpy( handshakeInfo->encodedReqKeySizes, bufPtr, UINT_SIZE * 3 );
			handshakeInfo->encodedReqKeySizesLength = UINT_SIZE * 3;
			bufPtr += UINT_SIZE;
			keySize = ( int ) mgetLong( bufPtr );
			bufPtr += UINT_SIZE;
			}
		else
			{
			/* It's a straight length, save a copy and get the length 
			   value */
			memcpy( handshakeInfo->encodedReqKeySizes, bufPtr, UINT_SIZE );
			handshakeInfo->encodedReqKeySizesLength = UINT_SIZE;
			keySize = ( int ) mgetLong( bufPtr );
			}
		if( keySize < MIN_PKCSIZE_BITS || \
			keySize > bytesToBits( CRYPT_MAX_PKCSIZE ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Client requested invalid ephemeral DH key size %d bits",
					keySize );
		handshakeInfo->requestedServerKeySize = bitsToBytes( keySize );

		/* If the requested key size differs too much from the built-in 
		   default one, destroy the existing default DH key and load a new 
		   one of the appropriate size.  Things get quite confusing here
		   because the spec is a schizophrenic mix of two different 
		   documents, one that specifies the behaviour for the original 
		   message format which uses a single length value and a second one 
		   that specifies the behaviour for the { min, n, max } combination.  
		   The range option was added as an attempted fix for 
		   implementations that couldn't handle the single size option, but
		   the real problem is that the server knows what key sizes are
		   appropriate but the client has to make the choice, without any
		   indication of what the server can actually handle.  Because of
		   this the spec (in its n-only mindset, which also applies to the 
		   min/n/max version since it's the same document) contains assorted 
		   weasel-words that allow the server to choose any key size it 
		   feels like if the client sends a range indication that's 
		   inappropriate.  Although the spec ends up saying that the server
		   can do anything it feels like ("The server should return the 
		   smallest group it knows that is larger than the size the client 
		   requested.  If the server does not know a group that is larger 
		   than the client request, then it SHOULD return the largest group 
		   it knows"), we use a least-upper-bound interpretation of the
		   above, mostly because we store a range of fixed keys of different
		   sizes and can always find something reasonably close to any 
		   (sensible) requested length */
		if( handshakeInfo->requestedServerKeySize < \
										SSH2_DEFAULT_KEYSIZE - 16 || \
			handshakeInfo->requestedServerKeySize > \
										SSH2_DEFAULT_KEYSIZE + 16 )
			{
			krnlSendNotifier( handshakeInfo->iServerCryptContext, 
							  IMESSAGE_DECREFCOUNT );
			status = initDHcontext( &handshakeInfo->iServerCryptContext,
									&handshakeInfo->serverKeySize, NULL, 0,
									handshakeInfo->requestedServerKeySize );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Send the DH key values to the client:

			byte	type = SSH2_MSG_KEXDH_GEX_GROUP
			mpint	p
			mpint	g
		
		   Since this phase of the key negotiation exchanges raw key 
		   components rather than the standard SSH public-key format, we 
		   have to rewrite the public key before we can send it to the 
		   client */
		bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
		*bufPtr++ = SSH2_MSG_KEXDH_GEX_GROUP;
		setMessageData( &msgData, bufPtr, 128 + ( CRYPT_MAX_PKCSIZE * 2 ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSH2 );
		if( cryptStatusError( status ) )
			return( status );
		length = msgData.length - extraLength;
		memmove( bufPtr, bufPtr + extraLength, length );
		status = sendPacketSSH2( sessionInfoPtr, ID_SIZE + length, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the client keyex:

		byte	type = SSH2_MSG_KEXDH_INIT / SSH2_MSG_KEXDH_GEX_INIT
		mpint	y */
	length = readPacketSSH2( sessionInfoPtr, 
							 ( handshakeInfo->requestedServerKeySize > 0 ) ? \
								SSH2_MSG_KEXDH_GEX_INIT : SSH2_MSG_KEXDH_INIT );
	if( cryptStatusError( length ) )
		return( length );
	bufPtr = sessionInfoPtr->receiveBuffer + ID_SIZE;
	clientKeyexLength = ( int ) mgetLong( bufPtr );
	if( length != ID_SIZE + LENGTH_SIZE + clientKeyexLength || \
		clientKeyexLength < handshakeInfo->serverKeySize - 8 || \
		clientKeyexLength > handshakeInfo->serverKeySize + 1 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid client keyex packet length %d, keyex length %d",
				length, clientKeyexLength );
	memcpy( handshakeInfo->clientKeyexValue, bufPtr - LENGTH_SIZE,
			LENGTH_SIZE + clientKeyexLength );
	handshakeInfo->clientKeyexValueLength = LENGTH_SIZE + clientKeyexLength;
	return( CRYPT_OK );
	}

/* Exchange keys with the client */

static int exchangeServerKeys( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	RESOURCE_DATA msgData;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	int length, length2, sigLength, status;

	/* Create the server DH value */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( handshakeInfo->iServerCryptContext,
							  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the DH phase 2 keyex packet:

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
		...

	   The specification also makes provision for using X.509 and PGP keys,
	   but only so far as to say that keys and signatures are in "X.509 DER"
	   and "PGP" formats, neither of which actually explain what it is
	   that's sent or signed (and no-one on the SSH list can agree on what
	   they're supposed to look like), so we can't use either of them */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = handshakeInfo->requestedServerKeySize ? \
				SSH2_MSG_KEXDH_GEX_REPLY : SSH2_MSG_KEXDH_REPLY;
	setMessageData( &msgData, bufPtr, 128 + ( CRYPT_MAX_PKCSIZE * 4 ) );
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_KEY_SSH2 );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( handshakeInfo->iExchangeHashcontext, IMESSAGE_CTX_HASH,
					 bufPtr, msgData.length );
	bufPtr += msgData.length;
	handshakeInfo->serverKeyexValueLength = \
					encodeMPI( handshakeInfo->serverKeyexValue, 
							   keyAgreeParams.publicValue,
							   keyAgreeParams.publicValueLen );
	memcpy( bufPtr, handshakeInfo->serverKeyexValue, 
			handshakeInfo->serverKeyexValueLength );
	bufPtr += handshakeInfo->serverKeyexValueLength;

	/* Complete phase 2 of the DH key agreement process to obtain the shared
	   secret value */
	status = completeKeyex( sessionInfoPtr, handshakeInfo, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Sign the hash */
	status = iCryptCreateSignatureEx( bufPtr, &sigLength,
							min( sessionInfoPtr->sendBufSize - \
								 ( ( bufPtr - sessionInfoPtr->sendBuffer ) + 128 ),
								 DEFAULT_PACKET_SIZE ),
							CRYPT_IFORMAT_SSH, sessionInfoPtr->privateKey,
							handshakeInfo->iExchangeHashcontext,
							CRYPT_UNUSED, CRYPT_UNUSED );
	krnlSendNotifier( handshakeInfo->iExchangeHashcontext,
					  IMESSAGE_DECREFCOUNT );
	handshakeInfo->iExchangeHashcontext = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		return( status );
	bufPtr += sigLength;
	status = length = wrapPacket( sessionInfoPtr, sessionInfoPtr->sendBuffer,
				bufPtr - ( sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Build our change cipherspec message and send the whole mess through
	   to the client:

		...
		byte	type = SSH2_MSG_NEWKEYS */
	bufPtr = sessionInfoPtr->sendBuffer + length;
	bufPtr[ SSH2_HEADER_SIZE ] = SSH2_MSG_NEWKEYS;
	status = length2 = wrapPacket( sessionInfoPtr, bufPtr, ID_SIZE );
	if( !cryptStatusError( status ) )
		status = sendPacketSSH2( sessionInfoPtr, length + length2, TRUE );
	return( status );
	}

/* Complete the handshake with the client */

static int completeServerHandshake( SESSION_INFO *sessionInfoPtr,
									SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	BYTE *bufPtr;
	int length, stringLength, status;

	/* Set up the security information required for the session */
	status = initSecurityInfo( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Wait for the client's change cipherspec message */
	status = readPacketSSH2( sessionInfoPtr, SSH2_MSG_NEWKEYS );
	if( cryptStatusError( status ) )
		return( status );

	/* We've sent the change cipherspec message, from now on all data is
	   encrypted and MAC'ed */
	sessionInfoPtr->flags |= SESSION_ISSECURE;

	/* Wait for the client's authentication packets.  For some reason SSHv2
	   requires the use of two authentication messages, an "I'm about to
	   authenticate" packet and an "I'm authenticating" packet.  First we 
	   handle the "I'm about to authenticate":

		byte	type = SSH2_MSG_SERVICE_REQUEST
		string	service_name = "ssh-userauth"

		byte	type = SSH2_MSG_SERVICE_ACCEPT
		string	service_name = "ssh-userauth" */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_SERVICE_REQUEST );
	if( cryptStatusError( length ) )
		return( length );
	bufPtr = sessionInfoPtr->receiveBuffer + ID_SIZE;
	stringLength = ( int ) mgetLong( bufPtr );
	if( length != ID_SIZE + LENGTH_SIZE + stringLength || \
		stringLength != 12 || memcmp( bufPtr, "ssh-userauth", 12 ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid service request packet length %d, string length "
				"%d", length, stringLength );
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr++ = SSH2_MSG_SERVICE_ACCEPT;
	length = encodeString( bufPtr, "ssh-userauth", 0 );
	status = sendPacketSSH2( sessionInfoPtr, ID_SIZE + length, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Wait for the second part of the authentication:

		byte	type = SSH2_MSG_USERAUTH_REQUEST
		string	user_name
		string	service_name = "ssh-connection"
		string	method_name = "none" | "password"
		[ boolean	FALSE ]
		[ string	password ]

	   The client can send a method-type of "none" to indicate that it'd
	   like the server to return a list of allowed authentication types, if
	   we get a packet of this kind we return our allowed types list.  Unlike
	   SSHv1, SSHv2 properly identifies public keys, however because of its
	   complexity (several more states added to the state machine because of
	   SSHv2's propensity for carrying out any negotiation it performs in
	   little bits and pieces) we don't support this form of authentication 
	   until someone specifically requests it */
	while( cryptStatusOK( status ) )
		{
		length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_USERAUTH_REQUEST );
		if( cryptStatusError( length ) )
			return( length );
		bufPtr = sessionInfoPtr->receiveBuffer + ID_SIZE;
		stringLength = ( int ) mgetLong( bufPtr );
		if( length < ID_SIZE + ( LENGTH_SIZE + stringLength ) + \
					 ( LENGTH_SIZE + 14 ) + ( LENGTH_SIZE + 4 ) || \
			stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid user auth packet length %d, string length %d",
					length, stringLength );
		memcpy( sessionInfoPtr->userName, bufPtr, stringLength );
		sessionInfoPtr->userNameLength = stringLength;
		bufPtr += stringLength;
		length -= ID_SIZE + ( LENGTH_SIZE + stringLength );
		stringLength = ( int ) mgetLong( bufPtr );
		if( stringLength != 14 || memcmp( bufPtr, "ssh-connection", 14 ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid user auth service string length %d",
					stringLength );
		bufPtr += stringLength;
		length -= ( LENGTH_SIZE + stringLength );
		stringLength = ( int ) mgetLong( bufPtr );
		if( length < LENGTH_SIZE + stringLength )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid user auth method length %d, string length %d",
					length, stringLength );

		/* If the client wants a list of supported authentication mechanisms,
		   tell them what we allow and await further input:

			byte	type = SSH2_MSG_USERAUTH_FAILURE
			string	allowed_authent
			boolean	partial_success = FALSE */
		if( stringLength == 4 && !memcmp( bufPtr, "none", 4 ) )
			{
			bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
			*bufPtr++ = SSH2_MSG_USERAUTH_FAILURE;
			length = encodeString( bufPtr, algoStringUserauthentList, 0 );
			bufPtr[ length ] = 0;
			status = sendPacketSSH2( sessionInfoPtr, ID_SIZE + length + \
													 BOOLEAN_SIZE, FALSE );
			continue;
			}

		/* The only other permitted type is password authentication */
		if( stringLength != 8 || memcmp( bufPtr, "password", 8 ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid user auth method name, string length %d", 
					stringLength );
		break;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We got authentication info, save it for the caller to check */
	bufPtr += stringLength + BOOLEAN_SIZE;
	length -= LENGTH_SIZE + stringLength + BOOLEAN_SIZE;
	stringLength = ( int ) mgetLong( bufPtr );
	if( length != LENGTH_SIZE + stringLength || \
		stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid user auth payload length %d, string length %d",
				length, stringLength );
	memcpy( sessionInfoPtr->password, bufPtr, stringLength );
	sessionInfoPtr->passwordLength = stringLength;

	/* Acknowledge the authentication:
	
		byte	type = SSH2_MSG_USERAUTH_SUCCESS */
	bufPtr = sessionInfoPtr->sendBuffer + SSH2_HEADER_SIZE;
	*bufPtr = SSH2_MSG_USERAUTH_SUCCESS;
	status = sendPacketSSH2( sessionInfoPtr, ID_SIZE, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Handle the channel open */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_CHANNEL_OPEN );
	if( cryptStatusError( length ) )
		return( length );
	status = processChannelOpen( sessionInfoPtr, 
								 sessionInfoPtr->receiveBuffer + ID_SIZE, 
								 length - ID_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Process any further junk that the caller may throw at us until we get 
	   a request that we can handle */
	while( !cryptStatusError( status = length = \
				readPacketSSH2( sessionInfoPtr, SSH2_MSG_SPECIAL_REQUEST ) ) )
		{
		status = processRequest( sessionInfoPtr, 
								 sessionInfoPtr->receiveBuffer + ID_SIZE, 
								 length - ID_SIZE );
		if( cryptStatusError( status ) )
			return( ( status == OK_SPECIAL ) ? CRYPT_OK : status );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSH2serverProcessing( SESSION_INFO *sessionInfoPtr,
							   SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	handshakeInfo->beginHandshake = beginServerHandshake;
	handshakeInfo->exchangeKeys = exchangeServerKeys;
	handshakeInfo->completeHandshake = completeServerHandshake;
	}
#endif /* SSH2 */
