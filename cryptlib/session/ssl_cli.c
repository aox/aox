/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Client Management					*
*					   Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Encode a list of available algorithms.  Some buggy older versions of IIS 
   that only support crippled crypto drop the connection when they see a 
   client hello advertising strong crypto, rather than sending an alert as 
   they should.  To work around this, we advertise a dummy cipher suite 
   SSL_RSA_EXPORT_WITH_RC4_40_MD5 as a canary to force IIS to send back a 
   response that we can then turn into an error message.  The need to do 
   this is somewhat unfortunate since it will appear to an observer that 
   cryptlib will use crippled crypto, but there's no other way to detect the 
   buggy IIS apart from completely restarting the session activation at the 
   session level with crippled-crypto advertised in the restarted session */

static int writeCipherSuiteList( STREAM *stream, const BOOLEAN usePSK )
	{
	const static struct {
		const CRYPT_ALGO_TYPE cryptAlgo;
		const int cipherSuite;
		} cipherSuiteList[] = {
		{ CRYPT_ALGO_3DES, TLS_PSK_WITH_3DES_EDE_CBC_SHA }, 
		{ CRYPT_ALGO_AES, TLS_PSK_WITH_AES_256_CBC_SHA }, 
		{ CRYPT_ALGO_AES, TLS_PSK_WITH_AES_128_CBC_SHA }, 
		{ CRYPT_ALGO_RC4, TLS_PSK_WITH_RC4_128_SHA }, 
#ifdef PREFER_DH_SUITES
		{ CRYPT_ALGO_3DES, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_DHE_RSA_WITH_AES_256_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_DHE_RSA_WITH_AES_128_CBC_SHA },
		{ CRYPT_ALGO_3DES, SSL_RSA_WITH_3DES_EDE_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_RSA_WITH_AES_256_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_RSA_WITH_AES_128_CBC_SHA },
#else
		{ CRYPT_ALGO_3DES, SSL_RSA_WITH_3DES_EDE_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_RSA_WITH_AES_256_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_RSA_WITH_AES_128_CBC_SHA },
		{ CRYPT_ALGO_3DES, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_DHE_RSA_WITH_AES_256_CBC_SHA },
		{ CRYPT_ALGO_AES, TLS_DHE_RSA_WITH_AES_128_CBC_SHA },
#endif /* PREFER_DH_SUITES */
		{ CRYPT_ALGO_IDEA, SSL_RSA_WITH_IDEA_CBC_SHA },
		{ CRYPT_ALGO_RC4, SSL_RSA_WITH_RC4_128_SHA },
		{ CRYPT_ALGO_RC4, SSL_RSA_WITH_RC4_128_MD5 },
		{ CRYPT_ALGO_DES, SSL_RSA_WITH_DES_CBC_SHA },
		{ CRYPT_ALGO_DES, TLS_DHE_RSA_WITH_DES_CBC_SHA },
		{ CRYPT_ALGO_SHA, SSL_RSA_EXPORT_WITH_RC4_40_MD5 },	/* Canary */
		{ CRYPT_ALGO_NONE, SSL_NULL_WITH_NULL }
		};
	int availableSuites[ 32 ], cipherSuiteCount = 0, suiteIndex = 0, status;

	/* Walk down the list of algorithms (and the corresponding cipher 
	   suites) remembering each one that's available for use */
	while( cipherSuiteList[ suiteIndex ].cryptAlgo != CRYPT_ALGO_NONE && \
		   cipherSuiteCount < 32 )
		{
		const CRYPT_ALGO_TYPE cryptAlgo = \
								cipherSuiteList[ suiteIndex ].cryptAlgo;

		if( !usePSK && \
			cipherSuiteList[ suiteIndex ].cipherSuite >= TLS_PSK_WITH_RC4_128_SHA )
			{
			/* It's a PSK suite but we're not using a PSK handshake, skip 
			   it */
			suiteIndex++;
			continue;
			}
		if( !algoAvailable( cipherSuiteList[ suiteIndex ].cryptAlgo ) )
			{
			while( cipherSuiteList[ suiteIndex ].cryptAlgo == cryptAlgo )
				suiteIndex++;
			continue;
			}
		while( cipherSuiteList[ suiteIndex ].cryptAlgo == cryptAlgo && \
			   cipherSuiteCount < 32 )
			availableSuites[ cipherSuiteCount++ ] = \
						cipherSuiteList[ suiteIndex++ ].cipherSuite;
		}
	assert( cipherSuiteCount < 32 );

	/* Encode the list of available cipher suites */
	status = writeUint16( stream, cipherSuiteCount * UINT16_SIZE );
	for( suiteIndex = 0; \
		 cryptStatusOK( status ) && suiteIndex < cipherSuiteCount; \
		 suiteIndex++ )
		status = writeUint16( stream, availableSuites[ suiteIndex ] );

	return( status );
	}

/* Make sure that the server URL matches the value in the returned 
   certificate.  This code isn't currently called because it's not certain 
   what the best way is to report this to the user is, and more importantly 
   because there are quite a few servers out there where the server name 
   doesn't match what's in the cert but for which the user will just click 
   "OK" anyway even if we can tunnel a warning indication back to them, so
   we leave it to the caller to perform whatever checking and take whatever
   action they consider necessary */

#if 0

static int checkURL( SESSION_INFO *sessionInfoPtr )
	{
	RESOURCE_DATA msgData;
	char hostName[ MAX_URL_SIZE ];
	const int serverNameLength = strlen( sessionInfoPtr->serverName );
	int hostNameLength, splatPos = CRYPT_ERROR, postSplatLen, i, status;

	/* Read the server name specification from the server's cert */
	setMessageData( &msgData, hostName, MAX_URL_SIZE );
	status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_DNSNAME );
	if( cryptStatusError( status ) )
		status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Couldn't read server name from server certificate" );
	hostNameLength = msgData.length;

	/* Look for a splat in the host name spec */
	for( i = 0; i < hostNameLength; i++ )
		if( hostName[ i ] == '*' )
			{
			if( splatPos != CRYPT_ERROR )
				/* Can't have more than one splat in a host name */
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Server name in certificate contains more than one "
						"wildcard" );
			splatPos = i;
			}

	/* If there's no wildcarding, perform a direct match */
	if( splatPos == CRYPT_ERROR )
		{
		if( hostNameLength != serverNameLength || \
			strCompare( hostName, sessionInfoPtr->serverName,
						serverNameLength ) )
			/* Host doesn't match the name in the cert */
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Server name doesn't match name in server certificate" );

		return( CRYPT_OK );
		}

	/* Determine how much to match before and after the splat */
	postSplatLen = hostNameLength - splatPos - 1;
	if( postSplatLen + splatPos > serverNameLength )
		/* The fixed name spec text is longer than the server name, a match
		   can't be possible */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Server name doesn't match name in server certificate" );

	/* Check that the pre- and post-splat URL components match */
	if( splatPos > 0 && \
		strCompare( hostName, sessionInfoPtr->serverName, splatPos ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Server name doesn't match name in server certificate" );
	if( strCompare( hostName + splatPos + 1,
					sessionInfoPtr->serverName + serverNameLength - postSplatLen,
					postSplatLen ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Server name doesn't match name in server certificate" );

	return( CRYPT_OK );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Client-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the server */

int beginClientHandshake( SESSION_INFO *sessionInfoPtr, 
						  SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
#if 0	/* Old PSK mechanism */
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
#endif /* 0 */
	RESOURCE_DATA msgData;
	int packetOffset, length, status;

	/* Get the nonce that's used to randomise all crypto ops */
	setMessageData( &msgData, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the client hello packet:

		byte		ID = SSL_HAND_CLIENT_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		uint32		time			| Client nonce
		byte[28]	nonce			|
		byte		sessIDlen
		byte[]		sessID
		uint16		suiteLen
		uint16[]	suite
		byte		coprLen = 1
		byte[]		copr = { 0x00 } 
		[ uint16	extListLen		| RFC 3546
			byte	extType
			uint16	extLen
			byte[]	extData ] */
	openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
						 SSL_MSG_HANDSHAKE );
	packetOffset = continueHSPacketStream( stream, SSL_HAND_CLIENT_HELLO );
	sputc( stream, SSL_MAJOR_VERSION );
	sputc( stream, sessionInfoPtr->version );
	handshakeInfo->clientOfferedVersion = sessionInfoPtr->version;
	swrite( stream, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
#if 0	/* Old PSK mechanism */
	if( attributeListPtr != NULL )
		{
		BYTE buffer[ SESSIONID_SIZE + 8 ];

		/* If there's a user name present, we're "resuming" a session based 
		   on a shared secret, send the user name as the session ID */
		sputc( stream, SESSIONID_SIZE );
		memset( buffer, 0, SESSIONID_SIZE );
		memcpy( buffer, attributeListPtr->value, 
				min( attributeListPtr->valueLength, SESSIONID_SIZE ) );
		swrite( stream, buffer, SESSIONID_SIZE );
		}
	else
		sputc( stream, 0 );	/* No session ID */
#else
	sputc( stream, 0 );	/* No session ID */
#endif /* 0 */
	writeCipherSuiteList( stream, 
						  findSessionAttribute( sessionInfoPtr->attributeList,
												CRYPT_SESSINFO_USERNAME ) ? \
						  TRUE : FALSE );
	sputc( stream, 1 );		/* No compression */
	sputc( stream, 0 );
#if 0	/* TLS extension test code.  Since almost no clients/servers (except
		   maybe some obscure bits of code embedded in cellphones) do this,
		   we have to fake it ourselves for testing purpose.  In addition
		   the RFC rather optimistically expects implementations to handle
		   the presence of unexpected data at the end of the hello packet,
		   since this is often not the case (quite a few servers fail the 
		   handshake if extension data is present) we leave the following 
		   disabled by default */
	writeUint16( stream, UINT16_SIZE + UINT16_SIZE + 1 );
	writeUint16( stream, TLS_EXT_MAX_FRAGMENT_LENTH );
	writeUint16( stream, 1 );
	sputc( stream, 3 );
#endif /* 0 */
	completeHSPacketStream( stream, packetOffset );
	status = sendPacketSSL( sessionInfoPtr, stream, FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Perform the dual MAC'ing of the client hello in between the network 
	   ops where it's effectively free */
	dualMacData( handshakeInfo, stream, FALSE );
	sMemDisconnect( stream );

	/* Process the server hello */
	length = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_FIRST_HANDSHAKE );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	status = processHelloSSL( sessionInfoPtr, handshakeInfo, stream, FALSE );
#if 0	/* Old PSK mechanism */
	if( status == OK_SPECIAL )
		{
		/* It's a (pseudo-)resumed session using a pre-shared secret key, 
		   there's no more packets to read, disconnect the stream and create 
		   the master secret from the user-supplied password */
		sMemDisconnect( stream );
		status = createSharedMasterSecret( handshakeInfo->premasterSecret,
										   &handshakeInfo->premasterSecretSize,
										   sessionInfoPtr );
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status, 
					"Couldn't create SSL master secret from shared "
					"secret/password value" );
		return( OK_SPECIAL );
		}
#endif /* 0 */
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Exchange keys with the server */

int exchangeClientKeys( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	BOOLEAN needClientCert = FALSE;
	int packetOffset, status;

	/* Process the optional server cert chain:

		byte		ID = SSL_HAND_CERTIFICATE
		uint24		len
		uint24		certLen			| 1...n certs ordered
		byte[]		cert			|   leaf -> root */
	if( handshakeInfo->authAlgo != CRYPT_ALGO_NONE )
		{
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		status = readSSLCertChain( sessionInfoPtr, handshakeInfo, 
							stream, &sessionInfoPtr->iKeyexCryptContext, 
							FALSE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/* Process the optional server keyex:

		byte		ID = SSL_HAND_SERVER_KEYEXCHANGE
		uint24		len
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
		uint16		signatureLen
		byte[]		signature */
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams;
		const void *keyData;
		int keyDataOffset, length;

		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		length = checkHSPacketHeader( sessionInfoPtr, stream, 
							SSL_HAND_SERVER_KEYEXCHANGE, 
							UINT16_SIZE + bitsToBytes( MIN_PKCSIZE_BITS ) + \
							UINT16_SIZE + 1 + \
							UINT16_SIZE + bitsToBytes( MIN_PKCSIZE_BITS ) + \
							UINT16_SIZE + bitsToBytes( MIN_PKCSIZE_BITS ) );
		if( cryptStatusError( length ) )
			{
			sMemDisconnect( stream );
			return( length );
			}

		/* Read the server DH key and DH public value */
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		keyData = sMemBufPtr( stream );
		keyDataOffset = stell( stream );
		readInteger16U( stream, NULL, NULL, bitsToBytes( MIN_PKCSIZE_BITS ),
						CRYPT_MAX_PKCSIZE );
		status = readInteger16U( stream, NULL, NULL, 1, CRYPT_MAX_PKCSIZE );
		if( cryptStatusOK( status ) )
			status = initDHcontextSSL( &handshakeInfo->dhContext, keyData, 
									   stell( stream ) - keyDataOffset );
		if( cryptStatusOK( status ) )
			status = readInteger16U( stream, keyAgreeParams.publicValue,
									 &keyAgreeParams.publicValueLen,
									 bitsToBytes( MIN_PKCSIZE_BITS ),
									 CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( sessionInfoPtr, cryptArgError( status ) ? \
					CRYPT_ERROR_BADDATA : status, 
					"Invalid server key agreement parameters" );
			}

		/* Check the server's signature on the DH parameters */
		status = checkKeyexSignature( sessionInfoPtr, handshakeInfo,
									  stream, keyData, 
									  stell( stream ) - keyDataOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( sessionInfoPtr, status, 
					"Bad server key agreement parameter signature" );
			}

		/* Perform phase 2 of the DH key agreement */
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}
		memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->premasterSecretSize = keyAgreeParams.wrappedKeyLen;
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}

	/* Process the optional server cert request:

		byte	ID = SSL_HAND_SERVER_CERTREQUEST
		uint24	len
		byte	certTypeLen
		byte[]	certType
		uint16	caNameListLen
			uint16	caNameLen
			byte[]	caName

	   We don't really care what's in the cert request packet since the 
	   contents are irrelevant, in a number of cases servers have been 
	   known to send out superfluous cert requests without the admins even 
	   knowning that they're doing it.  All we do here is perform a basic 
	   sanity check and remember that we may need to submit a cert later 
	   on.

	   Since we're about to peek ahead into the stream to see if we need to 
	   process a server cert request, we have to refresh the stream at this 
	   point in case the cert request wasn't bundled with the preceding 
	   packets */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sPeek( stream ) == SSL_HAND_SERVER_CERTREQUEST )
		{
		int length;

		/* Although the spec says that at least one CA name entry must be 
		   present, some implementations send a zero-length list, so we 
		   allow this as well.  The spec was changed in late TLS 1.1 drafts 
		   to reflect this practice */
		status = checkHSPacketHeader( sessionInfoPtr, stream, 
									  SSL_HAND_SERVER_CERTREQUEST, 
									  1 + 1 + UINT16_SIZE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		length = sgetc( stream );
		if( cryptStatusError( length ) || \
			length < 1 || cryptStatusError( sSkip( stream, length ) ) )
			{
			sMemDisconnect( stream );
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid cert request certificate type" );
			}
		length = readUint16( stream );
		if( cryptStatusError( length ) || \
			length < 0 || \
			( length > 0 && cryptStatusError( sSkip( stream, length ) ) ) )
			{
			sMemDisconnect( stream );
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid cert request CA name list" );
			}
		needClientCert = TRUE;
		}

	/* Process the server hello done:

		byte		ID = SSL_HAND_SERVER_HELLODONE
		uint24		len = 0 */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = checkHSPacketHeader( sessionInfoPtr, stream, 
								  SSL_HAND_SERVER_HELLODONE, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* If we need a client cert, build the client cert packet */
	openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
						 SSL_MSG_HANDSHAKE );
	if( needClientCert )
		{
		BOOLEAN sentResponse = FALSE;

		/* If we haven't got a cert available, tell the server.  SSL and TLS
		   differ here, SSL sends a no-certificate alert while TLS sends an
		   empty client cert packet, which is handled further on */
		if( sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY, 
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				{
				static const FAR_BSS BYTE noCertAlertSSLTemplate[] = {
					SSL_MSG_ALERT,							/* ID */
					SSL_MAJOR_VERSION, SSL_MINOR_VERSION_SSL,/* Version */
					0, 2,									/* Length */
					SSL_ALERTLEVEL_WARNING, SSL_ALERT_NO_CERTIFICATE
					};

				/* This is an alert-protocol message rather than a handshake
				   message, so we don't add it to the handshake packet stream
				   but write it directly to the network stream */
				swrite( &sessionInfoPtr->stream, noCertAlertSSLTemplate, 7 );
				sentResponse = TRUE;
				}

			/* The reaction to the lack of a cert is up to the server (some 
			   just request one anyway even though they can't do anything
			   with it), so from here on we just continue as if nothing had
			   happened */
			needClientCert = FALSE;
			}

		/* If we haven't sent a response yet, send it now */
		if( !sentResponse )
			{
			status = writeSSLCertChain( sessionInfoPtr, stream );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				return( status );
				}
			}
		}

	/* Build the client key exchange packet:

		byte		ID = SSL_HAND_CLIENT_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		yLen
		byte[]		y 
	   PSK:
		uint16		userIDLen
		byte[]		userID 
	   RSA:
	  [ uint16		encKeyLen - TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random ) */
	packetOffset = continueHSPacketStream( stream, 
										   SSL_HAND_CLIENT_KEYEXCHANGE );
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams;

		/* Perform phase 1 of the DH key agreement process */
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}
		writeInteger16U( stream, keyAgreeParams.publicValue, 
						 keyAgreeParams.publicValueLen );
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}
	else
		if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE )
			{
			const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );

			/* Create the shared premaster secret from the user password */
			status = createSharedPremasterSecret( \
									handshakeInfo->premasterSecret,
									&handshakeInfo->premasterSecretSize, 
									sessionInfoPtr );
			if( cryptStatusError( status ) )
				retExt( sessionInfoPtr, status, 
						"Couldn't create SSL master secret from shared "
						"secret/password value" );

			/* Write the PSK client identity */
			writeUint16( stream, attributeListPtr->valueLength );
			swrite( stream, attributeListPtr->value, 
					attributeListPtr->valueLength );
			}
		else
			{
			BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
			int wrappedKeyLength;

			status = wrapPremasterSecret( sessionInfoPtr, handshakeInfo,
										  wrappedKey, &wrappedKeyLength );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				return( status );
				}
			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				/* The original Netscape SSL implementation didn't provide a 
				   length for the encrypted key and everyone copied that so 
				   it became the de facto standard way to do it (Sic faciunt 
				   omnes.  The spec itself is ambiguous on the topic).  This 
				   was fixed in TLS (although the spec is still ambiguous) so 
				   the encoding differs slightly between SSL and TLS */
				swrite( stream, wrappedKey, wrappedKeyLength );
			else
				writeInteger16U( stream, wrappedKey, wrappedKeyLength );
			}
	completeHSPacketStream( stream, packetOffset );

	/* If we need to supply a client cert, send the signature generated with 
	   the cert to prove possession of the private key */
	if( needClientCert )
		{
		/* Write the packet header and drop in the signature data */
		packetOffset = continueHSPacketStream( stream, 
											   SSL_HAND_CLIENT_CERTVERIFY );
		status = createCertVerify( sessionInfoPtr, handshakeInfo, stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		completeHSPacketStream( stream, packetOffset );
		}

	/* Wrap and MAC the packet.  This is followed by the change cipherspec
	   packet so we don't send it at this point but leave it to be sent by
	   the shared handshake-completion code */
	status = completePacketStreamSSL( stream, 0 );
	dualMacData( handshakeInfo, stream, FALSE );
	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSLclientProcessing( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	handshakeInfo->beginHandshake = beginClientHandshake;
	handshakeInfo->exchangeKeys = exchangeClientKeys;
	}
#endif /* USE_SSL */
