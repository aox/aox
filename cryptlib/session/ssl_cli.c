/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Client Management					*
*					   Copyright Peter Gutmann 1998-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssl.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../session/session.h"
  #include "../session/ssl.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Most of the SSL packets have fixed formats, so we can construct them by
   copying in a constant template and setting up the variable fields.  The
   following templates are for various packet types */

#define SERVERHELLODONE_TEMPLATE_SIZE		4
#define NOCERTALERT_TEMPLATE_SIZE			7
#define NOCERT_TEMPLATE_SIZE				7

static const FAR_BSS BYTE serverHelloDoneTemplate[] = {
	SSL_HAND_SERVER_HELLODONE,				/* ID */
	0, 0, 0									/* Length */
	};
static const FAR_BSS BYTE noCertAlertSSLTemplate[] = {
	SSL_MSG_ALERT,							/* ID */
	SSL_MAJOR_VERSION, SSL_MINOR_VERSION_SSL,/* Version */
	0, 2,									/* Length */
	SSL_ALERTLEVEL_WARNING, SSL_ALERT_NO_CERTIFICATE
	};
static const FAR_BSS BYTE noCertTLSTemplate[] = {
	SSL_HAND_CERTIFICATE,					/* ID */
	0, 0, 3,								/* Length */
	0, 0, 0									/* Cert list length */
	};

/****************************************************************************
*																			*
*							Client-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the server */

int beginClientHandshake( SESSION_INFO *sessionInfoPtr, 
						  SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	RESOURCE_DATA msgData;
	BYTE *bufPtr, *bufMarkPtr, *lengthPtr;
	BOOLEAN resumedSession = FALSE;
	int length, sessionIDlength, cipherSuite, status;

	/* Build the client hello packet:

		byte		ID = 1
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
			byte[]	extData ]

	   Some buggy older versions of IIS that only support crippled crypto 
	   drop the connection when they see a client hello advertising strong
	   crypto, rather than sending an alert as they should.  To work around
	   this, we advertise a dummy cipher suite SSL_RSA_EXPORT_WITH_RC4_40_MD5 
	   as a canary to force IIS to send back a response that we can then turn
	   into an error message.  The need to do this is somewhat unfortunate
	   since it will appear to an observer that cryptlib will use crippled
	   crypto, but there's no other way to detect the buggy IIS apart from
	   completely restarting the session activation at the session level with
	   crippled-crypto advertised in the restarted session */
	setMessageData( &msgData, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
					 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	bufPtr = sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufStartOfs;
	*bufPtr++ = SSL_HAND_CLIENT_HELLO;
	*bufPtr++ = 0;
	lengthPtr = bufPtr;	/* Low 16 bits of length */
	bufPtr += LENGTH_SIZE - 1;
	*bufPtr++ = SSL_MAJOR_VERSION;
	*bufPtr++ = handshakeInfo->clientOfferedVersion = \
				sessionInfoPtr->version;
	memcpy( bufPtr, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	bufPtr += SSL_NONCE_SIZE;
	if( sessionInfoPtr->userNameLength > 0 )
		{
		/* If there's a user name present, we're "resuming" a session based 
		   on a shared secret, send the user name as the session ID */
		*bufPtr++ = SESSIONID_SIZE;
		memset( bufPtr, 0, SESSIONID_SIZE );
		memcpy( bufPtr, sessionInfoPtr->userName, 
				min( sessionInfoPtr->userNameLength, SESSIONID_SIZE ) );
		bufPtr += SESSIONID_SIZE;
		}
	else
		*bufPtr++ = '\0';		/* No session ID */
	bufMarkPtr = bufPtr;
	bufPtr += UINT16_SIZE;	/* Leave room for length */
	if( algoAvailable( CRYPT_ALGO_3DES ) )
		{ mputWord( bufPtr, SSL_RSA_WITH_3DES_EDE_CBC_SHA ); }
	if( algoAvailable( CRYPT_ALGO_AES ) )
		{
		mputWord( bufPtr, TLS_RSA_WITH_AES_128_CBC_SHA );
		mputWord( bufPtr, TLS_RSA_WITH_AES_256_CBC_SHA );
		}
	if( algoAvailable( CRYPT_ALGO_IDEA ) )
		{ mputWord( bufPtr, SSL_RSA_WITH_IDEA_CBC_SHA ); }
	if( algoAvailable( CRYPT_ALGO_RC4 ) )
		{
		mputWord( bufPtr, SSL_RSA_WITH_RC4_128_SHA );
		mputWord( bufPtr, SSL_RSA_WITH_RC4_128_MD5 );
		}
	if( algoAvailable( CRYPT_ALGO_DES ) )
		{ mputWord( bufPtr, SSL_RSA_WITH_DES_CBC_SHA ); }
	mputWord( bufPtr, SSL_RSA_EXPORT_WITH_RC4_40_MD5 );	/* Canary for broken servers */
	mputWord( bufMarkPtr, bufPtr - ( bufMarkPtr + UINT16_SIZE ) );
	*bufPtr++ = 1;						/* No compression */
	*bufPtr++ = 0;
#if 0	/* TLS extension test code.  Since no known clients/servers (except
		   maybe some obscure bits of code embedded in cellphones) do this,
		   we have to fake it ourselves for testing purpose.  In addition
		   the RFC rather optimistically expects implementations to handle
		   the presence of unexpected data at the end of the hello packet,
		   since this is rarely the case we leave the following disabled 
		   by default */
	mputWord( bufPtr, ID_SIZE + UINT16_SIZE + 1 );
	*bufPtr++ = TLS_EXT_MAX_FRAGMENT_LENTH;
	mputWord( bufPtr, 1 );
	*bufPtr++ = 3;
#endif /* 0 */
	length = bufPtr - \
			 ( sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufStartOfs );
	mputWord( lengthPtr, length - ( ID_SIZE + LENGTH_SIZE ) );
	wrapHandshakePacket( sessionInfoPtr->sendBuffer, length, 
						 sessionInfoPtr->version );

	/* Send the client hello to the server and read back and process the 
	   server's data (server hello, cert or key mgt. packets, and server 
	   done).  We perform the dual MAC'ing of the client hello in between the
	   network ops where it's effectively free */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer, 
					 sessionInfoPtr->sendBufStartOfs + length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream, 
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	dualMacData( handshakeInfo, sessionInfoPtr->sendBuffer + \
								sessionInfoPtr->sendBufStartOfs, length );
	status = readPacketSSL( sessionInfoPtr, handshakeInfo, 
							SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the server hello:

		byte		ID = 2
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		uint32		time			| Server nonce
		byte[28]	nonce			|
		byte		sessIDlen
		byte		sessID
		uint16		suite
		byte		copr = 0 */
	bufPtr = sessionInfoPtr->receiveBuffer;
	length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
								SSL_HAND_SERVER_HELLO, 
								VERSIONINFO_SIZE + SSL_NONCE_SIZE + 1 + \
									UINT16_SIZE + 1, SSL_MAJOR_VERSION );
	if( cryptStatusError( length ) )
		return( length );
	status = processVersionInfo( sessionInfoPtr, *bufPtr++ );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( handshakeInfo->serverNonce, bufPtr, SSL_NONCE_SIZE );
	bufPtr += SSL_NONCE_SIZE;
	sessionIDlength = *bufPtr++;
	if( sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid session ID length %d", sessionIDlength );
	if( length != VERSIONINFO_SIZE + SSL_NONCE_SIZE + \
				  ( 1 + sessionIDlength ) + UINT16_SIZE + 1 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid header data length %d", length );
	if( sessionIDlength == SESSIONID_SIZE )
		{
		BYTE sessionID[ SESSIONID_SIZE ];

		/* There's a session ID present, check to make sure that it matches 
		   the one we sent */
		memset( sessionID, 0, SESSIONID_SIZE );
		memcpy( sessionID, sessionInfoPtr->userName, 
				min( sessionInfoPtr->userNameLength, SESSIONID_SIZE ) );
		if( !memcmp( bufPtr, sessionID, SESSIONID_SIZE ) )
			{
			/* It's a resumed session, remember the session ID */
			memcpy( handshakeInfo->sessionID, sessionID, SESSIONID_SIZE );
			handshakeInfo->sessionIDlength = SESSIONID_SIZE;
			resumedSession = TRUE;

			/* Create the master secret from the user-supplied password */
			status = createSharedMasterSecret( handshakeInfo->premasterSecret,
											   sessionInfoPtr );
			if( cryptStatusError( status ) )
				retExt( sessionInfoPtr, status, 
						"Couldn't create SSL master secret from shared "
						"secret/password value" );
			}
		}
	bufPtr += sessionIDlength;
	cipherSuite = mgetWord( bufPtr );
	if( cipherSuite == SSL_RSA_EXPORT_WITH_RC4_40_MD5 )
		/* If we got back our method-of-last-resort cipher suite, the server
		   is incapable of handling non-crippled crypto.  Veni, vidi, volo in
		   domum redire */
		retExt( sessionInfoPtr, CRYPT_ERROR_NOSECURE,
				"Server rejected attempt to connect using non-crippled "
				"encryption" );
	status = initCiphersuiteInfo( sessionInfoPtr, handshakeInfo, 
								  cipherSuite );
	if( cryptStatusError( status ) )
		return( status );
	if( *bufPtr++ )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid compression algorithm suite %02X", 
				bufPtr[ -1 ] );

	return( resumedSession ? OK_SPECIAL : CRYPT_OK );
	}

/* Exchange keys with the server */

int exchangeClientKeys( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	BYTE certFingerprint[ CRYPT_MAX_HASHSIZE ];
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos, *lengthPtr;
	BOOLEAN needClientCert = FALSE;
	int length, chainLength, algorithm, status;

	/* Process the server cert chain:

		byte		ID = 0x0B
		uint24		len
		uint24		certLen			| 1...n certs ordered
		byte[]		cert			|   leaf -> root */
	if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
		{
		status = readPacketSSL( sessionInfoPtr, handshakeInfo,  
								SSL_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr = sessionInfoPtr->receiveBuffer;
		}		
	length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
								SSL_HAND_CERTIFICATE, 64, 0 );
	if( cryptStatusError( length ) )
		return( length );
	chainLength = mgetWord( bufPtr );
	if( chainLength < 64 || chainLength != length - LENGTH_SIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid server cert chain length %d", chainLength );

	/* Import the cert chain and get information on it.  This isn't a true 
	   cert chain (in the sense of being degenerate PKCS #7 SignedData) but 
	   a special-case SSL-encoded cert chain */
	setMessageCreateObjectIndirectInfo( &createInfo, bufPtr, chainLength,
										CRYPT_ICERTTYPE_SSL_CERTCHAIN );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT, &createInfo, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		/* There are sufficient numbers of broken certs around that if we 
		   run into a problem importing one we provide a custom error 
		   message telling the user to try again with a reduced compliance 
		   level */
		if( status == CRYPT_ERROR_BADDATA || status == CRYPT_ERROR_INVALID )
			retExt( sessionInfoPtr, status, 
					"Server provided a broken/invalid certificate, try again "
					"with a reduced level of certificate compliance "
					"checking" );
		}
	else
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_GETATTRIBUTE, &algorithm,
								  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, certFingerprint, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( createInfo.cryptHandle, 
							IMESSAGE_GETATTRIBUTE_S, &msgData, 
							( sessionInfoPtr->keyFingerprintSize == 16 ) ? \
							CRYPT_CERTINFO_FINGERPRINT_MD5 : \
							CRYPT_CERTINFO_FINGERPRINT_SHA );
		}
	if( cryptStatusError( status ) )
		return( status );
	bufPtr += chainLength;
	sessionInfoPtr->iKeyexCryptContext = createInfo.cryptHandle;

	/* Either compare the cert fingerprint to a supplied one or save it for 
	   the caller to examine */
	if( sessionInfoPtr->keyFingerprintSize > 0 )
		{
		/* The caller has supplied a cert fingerprint, compare it to the
		   received cert's fingerprint to make sure that we're talking to 
		   the right server */
		if( sessionInfoPtr->keyFingerprintSize != msgData.length || \
			memcmp( sessionInfoPtr->keyFingerprint, certFingerprint,
					msgData.length ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"Server key didn't match fingerprint" );
		}
	else
		{
		/* Remember the cert fingerprint in case the caller wants to check 
		   it */
		memcpy( sessionInfoPtr->keyFingerprint, certFingerprint, 
				msgData.length );
		sessionInfoPtr->keyFingerprintSize = msgData.length;
		}

	/* Make sure that we can perform the required operation using the key 
	   we've been given.  This performs a variety of checks alongside the 
	   obvious one, so it's a good general health check before we go any 
	   further.  If this fails, we convert the result to a wrong key error 
	   rather than a check failure */
	status = krnlSendMessage( createInfo.cryptHandle, 
							  IMESSAGE_CHECK, NULL,
							  isKeyxAlgo( algorithm ) ? \
								MESSAGE_CHECK_PKC_KA_IMPORT : \
								MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
				"Server returned a key incapable of being used for %s",
				isKeyxAlgo( algorithm ) ? "key agreement" : "key transport" );

	/* Process optional server cert request and server hello done:

		byte		ID = 0x0E
		uint24		len = 0 */
	if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
		{
		status = readPacketSSL( sessionInfoPtr, handshakeInfo,  
								SSL_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr = sessionInfoPtr->receiveBuffer;
		}		
	if( *bufPtr == SSL_HAND_SERVER_CERTREQUEST )
		{
		int certInfoLen;

		/* The server wants a client cert:

			byte	ID = 0x0D
			uint24	len
			byte	certTypeLen
			byte[]	certType
			uint16	caNameListLen
				uint16	caNameLen
				byte[]	caName

		   We don't really care what's in the cert request packet since the 
		   contents are irrelevant, and in many cases servers send out
		   superfluous cert requests without the admins even knowning that
		   they're doing it.  All we do here is perform a basic sanity check 
		   and remember that we may need to submit a cert later on.

		   Although the spec says that at least one CA name entry must be 
		   present, some implementations send a zero-length list, so we allow 
		   this as well.  The spec was changed in late TLS 1.1 drafts to
		   reflect this practice */
		length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
									SSL_HAND_SERVER_CERTREQUEST, 4, 
									CRYPT_UNUSED );
		if( cryptStatusError( length ) )
			return( length );
		certInfoLen = *bufPtr++;	/* certTypeLen */
		if( certInfoLen < 1 || certInfoLen > length - 1 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid cert request cert type length %d", 
					certInfoLen );
		bufPtr += certInfoLen;		/* Skip cert types */
		length -= 1 + certInfoLen;
		certInfoLen = mgetWord( bufPtr );
		if( certInfoLen < 0 || certInfoLen != length - UINT16_SIZE )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid cert request CA name list length %d", 
					certInfoLen );
		bufPtr += certInfoLen;
		needClientCert = TRUE;
		if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
			{
			status = readPacketSSL( sessionInfoPtr, handshakeInfo,  
									SSL_MSG_HANDSHAKE );
			if( cryptStatusError( status ) )
				return( status );
			bufPtr = sessionInfoPtr->receiveBuffer;
			}
		}
	if( sessionInfoPtr->receiveBufPos + SERVERHELLODONE_TEMPLATE_SIZE > \
			sessionInfoPtr->receiveBufEnd || \
		memcmp( bufPtr, serverHelloDoneTemplate, 
				SERVERHELLODONE_TEMPLATE_SIZE ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid server hello packet" );
	sessionInfoPtr->receiveBufPos += SERVERHELLODONE_TEMPLATE_SIZE;

	/* If we need a client cert, build the client cert packet */
	bufPtr = sessionInfoPtr->sendBuffer + sessionInfoPtr->sendBufStartOfs;
	if( needClientCert )
		{
		/* If we haven't got a cert available, tell the server.  SSL and TLS
		   differ here, SSL sends a no-certificate alert while TLS sends an
		   empty client cert packet */
		if( sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY, 
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				swrite( &sessionInfoPtr->stream, noCertAlertSSLTemplate, 
						NOCERTALERT_TEMPLATE_SIZE );
			else
				{
				memcpy( bufPtr, noCertTLSTemplate, NOCERT_TEMPLATE_SIZE );
				length = NOCERT_TEMPLATE_SIZE;
				bufPtr += NOCERT_TEMPLATE_SIZE;
				}

			/* The reaction to the lack of a cert is up to the server (some 
			   just request one anyway even though they can't do anything
			   with it), so from here on we just continue as if nothing had
			   happened */
			needClientCert = FALSE;
			}
		else
			{
			/* Write the client cert chain */
			status = length = writeSSLCertChain( sessionInfoPtr, bufPtr );
			if( cryptStatusError( status ) )
				return( status );
			bufPtr += status;
			}
		}
	else
		/* No client cert packet */
		length = 0;

	/* Build the client key exchange packet:

		byte		ID = 0x10
		uint24		len
	   RSA:
	  [ uint16		encKeyLen - TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random )
	   DH:
		uint16		yLen
		byte[]		y */
	*bufPtr++ = SSL_HAND_CLIENT_KEYEXCHANGE;
	*bufPtr++ = 0;
	lengthPtr = bufPtr;
	bufPtr += UINT16_SIZE;
	if( !isKeyxAlgo( algorithm ) )
		{
		if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
			bufPtr += UINT16_SIZE;	/* See comment below */

		/* Create the premaster secret and wrap it using the server's public 
		   key.  Note that the version that we advertise at this point is the
		   version originally offered by the client in its hello message, not
		   the version eventually negotiated for the connection.  This is 
		   designed to prevent rollback attacks */
		handshakeInfo->premasterSecret[ 0 ] = SSL_MAJOR_VERSION;
		handshakeInfo->premasterSecret[ 1 ] = handshakeInfo->clientOfferedVersion;
		setMessageData( &msgData, 
						handshakeInfo->premasterSecret + VERSIONINFO_SIZE, 
						SSL_SECRET_SIZE - VERSIONINFO_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM );
		if( cryptStatusError( status ) )
			return( status );
		setMechanismWrapInfo( &mechanismInfo, bufPtr, CRYPT_MAX_PKCSIZE, 
							  handshakeInfo->premasterSecret, SSL_SECRET_SIZE, 
							  CRYPT_UNUSED, sessionInfoPtr->iKeyexCryptContext, 
							  CRYPT_UNUSED );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
								  &mechanismInfo, MECHANISM_PKCS1_RAW );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr += mechanismInfo.wrappedDataLength;
		length += ID_SIZE + LENGTH_SIZE + mechanismInfo.wrappedDataLength;
		if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
			{
			/* The original Netscape SSL implementation didn't provide a 
			   length for the encrypted key and everyone copied that so it 
			   became the de facto standard way to do it (Sic faciunt omnes.  
			   The spec itself is ambiguous on the topic).  This was fixed 
			   in TLS (although the spec is still ambiguous) so the encoding 
			   differs slightly between SSL and TLS */
			mputWord( lengthPtr, UINT16_SIZE + mechanismInfo.wrappedDataLength );
			length += UINT16_SIZE;
			}
		mputWord( lengthPtr, mechanismInfo.wrappedDataLength );
		}
	else
		{
		KEYAGREE_PARAMS keyAgreeParams;

		/* Perform phase 2 of the DH key agreement.  This is in fact extra-
		   ordinarily complex since SSL allows for DH parameters to be 
		   exchanged in every imaginable manner, including raw DH parameters, 
		   a DH key signed by the server, a DH server cert, and just to top 
		   it all off as DH client info.  Since nothing actively uses DH, 
		   it's not even possible to determine which of the various options 
		   are likely to occur.  Because of this we go through the motions of
		   handling DH up to this point but leave the public value zeroed, if
		   anyone ever reports a live deployment that uses DH we can fetch
		   the data from the appropriate location and complete the key
		   agreement process */
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
#if 0
		memcpy( keyAgreeParams.publicValue, y, yLength );
		keyAgreeParams.publicValueLen = yLength;
#endif /* 0 */
		status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
								  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			return( status );
			}
		memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
				SSL_SECRET_SIZE );
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}

	/* If we need to supply a client cert, send the signature generated with 
	   the cert to prove possession of the private key */
	if( needClientCert )
		{
		int verifyInfoLength;

		/* Write the packet header and drop in the signature data */
		*bufPtr++ = SSL_HAND_CLIENT_CERTVERIFY;
		status = verifyInfoLength = \
			processCertVerify( sessionInfoPtr, handshakeInfo, 
							   bufPtr + LENGTH_SIZE, 0, 
							   min( sessionInfoPtr->sendBufSize - ( length + 256 ),
									MAX_PACKET_SIZE ) );
		if( cryptStatusError( status ) )
			return( status );
		*bufPtr++ = 0;
		mputWord( bufPtr, verifyInfoLength );
		length += ID_SIZE + LENGTH_SIZE + verifyInfoLength;
		}

	/* Send the client information to the server */
	wrapHandshakePacket( sessionInfoPtr->sendBuffer, length,
						 sessionInfoPtr->version );
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer, 
					 sessionInfoPtr->sendBufStartOfs + length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream, 
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	dualMacData( handshakeInfo, sessionInfoPtr->sendBuffer + \
								sessionInfoPtr->sendBufStartOfs, length );

	return( CRYPT_OK );
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
