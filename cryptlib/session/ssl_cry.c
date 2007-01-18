/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Crypto Routines						*
*					 Copyright Peter Gutmann 1998-2004						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

/* Proto-HMAC padding data */

#define PROTOHMAC_PAD1_VALUE	0x36
#define PROTOHMAC_PAD2_VALUE	0x5C
#define PROTOHMAC_PAD1			"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36"
#define PROTOHMAC_PAD2			"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Initialise and destroy the crypto information in the handshake state
   info */

int initHandshakeCryptInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	/* Clear the handshake info contexts */
	handshakeInfo->clientMD5context = \
		handshakeInfo->serverMD5context = \
			handshakeInfo->clientSHA1context = \
				handshakeInfo->serverSHA1context = \
					handshakeInfo->dhContext = CRYPT_ERROR;

	/* Create the MAC/dual-hash contexts for incoming and outgoing data.
	   SSL uses a pre-HMAC variant for which we can't use real HMAC but have
	   to construct it ourselves from MD5 and SHA-1, TLS uses a straight dual
	   hash and MACs that once a MAC key becomes available at the end of the
	   handshake */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->clientMD5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->serverMD5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->clientSHA1context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->serverSHA1context = createInfo.cryptHandle;
		return( CRYPT_OK );
		}

	/* One or more of the contexts couldn't be created, destroy all of the
	   contexts that have been created so far */
	destroyHandshakeCryptInfo( handshakeInfo );
	return( status );
	}

int destroyHandshakeCryptInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	if( handshakeInfo->clientMD5context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->clientMD5context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->serverMD5context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->serverMD5context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->clientSHA1context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->clientSHA1context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->serverSHA1context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->serverSHA1context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->dhContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->dhContext, IMESSAGE_DECREFCOUNT );

	return( CRYPT_OK );
	}

/* Initialise and destroy the security contexts */

int initSecurityContextsSSL( SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
	else
		/* One or more of the contexts couldn't be created, destroy all of
		   the contexts that have been created so far */
		destroySecurityContextsSSL( sessionInfoPtr );
	return( status );
	}

void destroySecurityContextsSSL( SESSION_INFO *sessionInfoPtr )
	{
	/* Destroy any active contexts */
	if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexCryptContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
		}
	}

/****************************************************************************
*																			*
*								Keying Functions							*
*																			*
****************************************************************************/

/* Load a DH key into a context, with the fixed value below being used for
   the SSL server.  The prime is the value 2^1024 - 2^960 - 1 +
   2^64 * { [2^894 pi] + 129093 }, from the Oakley spec (RFC 2412, other
   locations omit the q value).  Unfortunately the choice of q leads to
   horribly inefficient operations since it's 860 bits larger than it needs
   to be */

static const BYTE FAR_BSS dh1024SSL[] = {
	0x00, 0x80,		/* p */
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
		0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
		0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
		0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
		0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x01,		/* g */
		0x02
	};

int initDHcontextSSL( CRYPT_CONTEXT *iCryptContext, const void *keyData,
					  const int keyDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( ( keyData == NULL && keyDataLength == 0 ) || \
			isReadPtr( keyData, keyDataLength ) );

	*iCryptContext = CRYPT_ERROR;

	/* Create the DH context */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DH );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the context */
	setMessageData( &msgData, "TLS DH key", 10 );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusOK( status ) )
		{
		/* If we're being given externally-supplied DH key components, load
		   them, otherwise use the built-in key */
		if( keyData != NULL )
			{ setMessageData( &msgData, ( void * ) keyData,
							  keyDataLength ); }
		else
			{ setMessageData( &msgData, ( void * ) dh1024SSL,
							  sizeof( dh1024SSL ) ); }
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSL );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Create the master secret from a shared secret value, typically a
   password.  The expandSharedSecret function uses a slightly different
   coding style because it's taken directly from the RFC */

#if 0	/* Old PSK mechanism */

static void expandSharedSecret( BYTE *premaster_secret,
								const BYTE *shared_secret,
							    const int shared_secret_length )
	{
	int premaster_index;

	for( premaster_index = 0; premaster_index < 48; )
		{
		int i;

		premaster_secret[ premaster_index++ ] = shared_secret_length;
		for( i = 0; i < shared_secret_length && premaster_index < 48; i++ )
			premaster_secret[ premaster_index++ ] = shared_secret[ i ];
		}
	}

int createSharedMasterSecret( void *masterSecret, int *masterSecretLength,
							  const SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE premasterSecret[ SSL_SECRET_SIZE + 8 ];
	int status;

	/* Expand the shared secret to create the premaster secret */
	if( attributeListPtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		BYTE decodedValue[ 64 + 8 ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded password, decode it into its binary
		   value */
		decodedValueLength = decodePKIUserValue( decodedValue, 64,
											attributeListPtr->value,
											attributeListPtr->valueLength );
		if( cryptStatusError( decodedValueLength ) )
			{
			assert( NOTREACHED );
			return( decodedValueLength );
			}
		expandSharedSecret( premasterSecret, decodedValue,
							min( decodedValueLength, SSL_SECRET_SIZE ) );
		zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
		}
	else
		expandSharedSecret( premasterSecret, attributeListPtr->value,
							min( attributeListPtr->valueLength,
								 SSL_SECRET_SIZE ) );

	/* Create the master secret from the expanded user-supplied password.
	   Note that since the use of shared secrets is specified only for TLS,
	   we always use the TLS key derivation even if it's with the SSL
	   protocol */
	setMechanismDeriveInfo( &mechanismInfo,
							masterSecret, SSL_SECRET_SIZE,
							premasterSecret, SSL_SECRET_SIZE,
							CRYPT_USE_DEFAULT, "shared secret", 13, 1 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_DERIVE, &mechanismInfo,
							  MECHANISM_DERIVE_TLS );
	zeroise( premasterSecret, SSL_SECRET_SIZE );
	if( cryptStatusOK( status ) )
		*masterSecretLength = SSL_SECRET_SIZE;
	return( status );
	}
#else

int createSharedPremasterSecret( void *premasterSecret,
								 int *premasterSecretLength,
								 const ATTRIBUTE_LIST *attributeListPtr )
	{
	STREAM stream;
	BYTE zeroes[ CRYPT_MAX_TEXTSIZE + 8 ];

	assert( attributeListPtr->attributeID == CRYPT_SESSINFO_PASSWORD );

	/* Write the PSK-derived premaster secret value:

		uint16	otherSecretLen
		byte[]	otherSecret
		uint16	pskLen
		byte[]	psk

	   Because the TLS PRF splits the input into two halves, one half which
	   is processed by HMAC-MD5 and the other by HMAC-SHA1, it's necessary
	   to extend the PSK in some way to provide input to both halves of the
	   PRF.  In a rather dubious decision, the spec requires that the MD5
	   half be set to all zeroes, with only the SHA1 half being used.  To
	   achieve this, we write otherSecret as a number of zero bytes equal in
	   length to the password */
	memset( zeroes, 0, CRYPT_MAX_TEXTSIZE );
	sMemOpen( &stream, premasterSecret,
			  ( UINT16_SIZE + CRYPT_MAX_TEXTSIZE ) * 2 );
	if( attributeListPtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		BYTE decodedValue[ 64 + 8 ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded password, decode it into its binary
		   value */
		decodedValueLength = decodePKIUserValue( decodedValue, 64,
											attributeListPtr->value,
											attributeListPtr->valueLength );
		if( cryptStatusError( decodedValueLength ) )
			{
			assert( NOTREACHED );
			return( decodedValueLength );
			}
		writeUint16( &stream, decodedValueLength );
		swrite( &stream, zeroes, decodedValueLength );
		writeUint16( &stream, decodedValueLength );
		swrite( &stream, decodedValue, decodedValueLength );
		zeroise( decodedValue, decodedValueLength );
		}
	else
		{
		writeUint16( &stream, attributeListPtr->valueLength );
		swrite( &stream, zeroes, attributeListPtr->valueLength );
		writeUint16( &stream, attributeListPtr->valueLength );
		swrite( &stream, attributeListPtr->value,
				attributeListPtr->valueLength );
		}
	*premasterSecretLength = stell( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Wrap/unwrap the pre-master secret */

int wrapPremasterSecret( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 void *data, int *dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	int status;

	/* Clear return value */
	*dataLength = 0;

	/* Create the premaster secret and wrap it using the server's public
	   key.  Note that the version that we advertise at this point is the
	   version originally offered by the client in its hello message, not
	   the version eventually negotiated for the connection.  This is
	   designed to prevent rollback attacks (but see also the comment in
	   unwrapPremasterSecret() below) */
	handshakeInfo->premasterSecretSize = SSL_SECRET_SIZE;
	handshakeInfo->premasterSecret[ 0 ] = SSL_MAJOR_VERSION;
	handshakeInfo->premasterSecret[ 1 ] = handshakeInfo->clientOfferedVersion;
	setMessageData( &msgData,
					handshakeInfo->premasterSecret + VERSIONINFO_SIZE,
					handshakeInfo->premasterSecretSize - VERSIONINFO_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismWrapInfo( &mechanismInfo, data, CRYPT_MAX_PKCSIZE,
						  handshakeInfo->premasterSecret,
						  handshakeInfo->premasterSecretSize, CRYPT_UNUSED,
						  sessionInfoPtr->iKeyexCryptContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1_RAW );
	if( cryptStatusOK( status ) )
		*dataLength = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );

	return( status );
	}

int unwrapPremasterSecret( SESSION_INFO *sessionInfoPtr,
						   SSL_HANDSHAKE_INFO *handshakeInfo,
						   const void *data, const int dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	int status;

	/* Decrypt the encrypted premaster secret.  In theory we could
	   explicitly defend against Bleichenbacher-type attacks at this point
	   by setting the premaster secret to a pseudorandom value if we get a
	   bad data or (later) an incorrect version error and continuing as
	   normal, however the attack depends on the server returning
	   information required to pinpoint the cause of the failure and
	   cryptlib just returns a generic "failed" response for any handshake
	   failure, so this explicit defence isn't really necessary */
	handshakeInfo->premasterSecretSize = SSL_SECRET_SIZE;
	setMechanismWrapInfo( &mechanismInfo, ( void * ) data, dataLength,
						  handshakeInfo->premasterSecret,
						  handshakeInfo->premasterSecretSize, CRYPT_UNUSED,
						  sessionInfoPtr->privateKey, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1_RAW );
	if( cryptStatusOK( status ) && \
		mechanismInfo.keyDataLength != handshakeInfo->premasterSecretSize )
		status = CRYPT_ERROR_BADDATA;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that it looks OK.  Note that the version that we check for
	   at this point is the version originally offered by the client in its
	   hello message, not the version eventually negotiated for the
	   connection.  This is designed to prevent rollback attacks */
	if( handshakeInfo->premasterSecret[ 0 ] != SSL_MAJOR_VERSION || \
		handshakeInfo->premasterSecret[ 1 ] != handshakeInfo->clientOfferedVersion )
		{
		/* Microsoft braindamage, even the latest versions of MSIE still send
		   the wrong version number for the premaster secret (making it look
		   like a rollback attack), so if we're expecting 3.1 and get 3.0, it's
		   MSIE screwing up */
		if( handshakeInfo->premasterSecret[ 0 ] == SSL_MAJOR_VERSION && \
			handshakeInfo->premasterSecret[ 1 ] == SSL_MINOR_VERSION_SSL && \
			sessionInfoPtr->version == SSL_MINOR_VERSION_SSL && \
			handshakeInfo->clientOfferedVersion == SSL_MINOR_VERSION_TLS )
			strcpy( sessionInfoPtr->errorMessage,
					"Warning: Accepting invalid premaster secret version "
					"3.0 (MSIE bug)" );
		else
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid premaster secret version data 0x%02X 0x%02X, "
					"expected 0x03 0x%02X",
					handshakeInfo->premasterSecret[ 0 ],
					handshakeInfo->premasterSecret[ 1 ],
					handshakeInfo->clientOfferedVersion );
		}

	return( CRYPT_OK );
	}

/* Convert a pre-master secret to a master secret, and a master secret to
   keying material */

int premasterToMaster( const SESSION_INFO *sessionInfoPtr,
					   const SSL_HANDSHAKE_INFO *handshakeInfo,
					   void *masterSecret, const int masterSecretLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];

	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( nonceBuffer, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
		memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
				SSL_NONCE_SIZE );
		setMechanismDeriveInfo( &mechanismInfo, masterSecret,
								masterSecretLength,
								handshakeInfo->premasterSecret,
								handshakeInfo->premasterSecretSize,
								CRYPT_USE_DEFAULT, nonceBuffer,
								SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
		return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_SSL ) );
		}

	memcpy( nonceBuffer, "master secret", 13 );
	memcpy( nonceBuffer + 13, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + 13 + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	setMechanismDeriveInfo( &mechanismInfo, masterSecret, masterSecretLength,
							handshakeInfo->premasterSecret,
							handshakeInfo->premasterSecretSize,
							CRYPT_USE_DEFAULT, nonceBuffer,
							13 + SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

int masterToKeys( const SESSION_INFO *sessionInfoPtr,
				  const SSL_HANDSHAKE_INFO *handshakeInfo,
				  const void *masterSecret, const int masterSecretLength,
				  void *keyBlock, const int keyBlockLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];

	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( nonceBuffer, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
		memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->clientNonce,
				SSL_NONCE_SIZE );
		setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
								masterSecret, masterSecretLength, CRYPT_USE_DEFAULT,
								nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
		return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_SSL ) );
		}

	memcpy( nonceBuffer, "key expansion", 13 );
	memcpy( nonceBuffer + 13, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + 13 + SSL_NONCE_SIZE, handshakeInfo->clientNonce,
			SSL_NONCE_SIZE );
	setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
							masterSecret, masterSecretLength, CRYPT_USE_DEFAULT,
							nonceBuffer, 13 + SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

/* Load the SSL/TLS cryptovariables */

int loadKeys( SESSION_INFO *sessionInfoPtr,
			  const SSL_HANDSHAKE_INFO *handshakeInfo,
			  const BOOLEAN isClient, const void *keyBlock )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	BYTE *keyBlockPtr = ( BYTE * ) keyBlock;
	int status;

	/* Load the keys and secrets:

		( client_write_mac || server_write_mac || \
		  client_write_key || server_write_key || \
		  client_write_iv  || server_write_iv )

	   First, we load the MAC keys.  For TLS these are proper MAC keys, for
	   SSL we have to build the proto-HMAC ourselves from a straight hash
	   context so we store the raw cryptovariables rather than loading them
	   into a context */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( isClient ? sslInfo->macWriteSecret : sslInfo->macReadSecret,
				keyBlockPtr, sessionInfoPtr->authBlocksize );
		memcpy( isClient ? sslInfo->macReadSecret : sslInfo->macWriteSecret,
				keyBlockPtr + sessionInfoPtr->authBlocksize,
				sessionInfoPtr->authBlocksize );
		keyBlockPtr = keyBlockPtr + sessionInfoPtr->authBlocksize * 2;
		}
	else
		{
		setMessageData( &msgData, keyBlockPtr, sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthOutContext : \
										sessionInfoPtr->iAuthInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, keyBlockPtr + sessionInfoPtr->authBlocksize,
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthInContext: \
										sessionInfoPtr->iAuthOutContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			return( status );
		keyBlockPtr = keyBlockPtr + sessionInfoPtr->authBlocksize * 2;
		}

	/* Then we load the encryption keys */
	setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptOutContext : \
									sessionInfoPtr->iCryptInContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	keyBlockPtr += handshakeInfo->cryptKeysize;
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptInContext : \
									sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	keyBlockPtr += handshakeInfo->cryptKeysize;
	if( cryptStatusError( status ) )
		return( status );

	/* Finally we load the IVs if required.  This load is actually redundant
	   for TLS 1.1, which uses explicit IVs, but it's easier to just do it
	   anyway */
	if( isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		return( CRYPT_OK );	/* No IV, we're done */
	setMessageData( &msgData, keyBlockPtr,
					sessionInfoPtr->cryptBlocksize );
	krnlSendMessage( isClient ? sessionInfoPtr->iCryptOutContext : \
								sessionInfoPtr->iCryptInContext,
					 IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_CTXINFO_IV );
	keyBlockPtr += sessionInfoPtr->cryptBlocksize;
	setMessageData( &msgData, keyBlockPtr,
					sessionInfoPtr->cryptBlocksize );
	return( krnlSendMessage( isClient ? sessionInfoPtr->iCryptInContext : \
										sessionInfoPtr->iCryptOutContext,
							 IMESSAGE_SETATTRIBUTE_S, &msgData,
							 CRYPT_CTXINFO_IV ) );
	}

/* TLS versions greater than 1.0 prepend an explicit IV to the data, the
   following function loads this from the packet data stream */

int loadExplicitIV( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	MESSAGE_DATA msgData;
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];
	int status;

	/* Read and load the IV */
	status = sread( stream, iv, sessionInfoPtr->cryptBlocksize );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, iv, sessionInfoPtr->cryptBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Packet IV read/load failed" );

	/* The following alternate code, which decrypts and discards the first
	   block, can be used when we can't reload an IV during decryption */
#if 0
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, iv,
							  sessionInfoPtr->cryptBlocksize );
#endif /* 0 */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt Functions						*
*																			*
****************************************************************************/

/* Encrypt/decrypt a data block */

int encryptData( const SESSION_INFO *sessionInfoPtr, BYTE *data,
				 const int dataLength )
	{
	int length = dataLength, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength > 0 && dataLength <= MAX_PACKET_SIZE + 20 );
	assert( isWritePtr( data, dataLength ) );

	/* If it's a block cipher, we need to add end-of-block padding */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		BYTE *dataPadPtr = data + dataLength;
		const int padSize = ( sessionInfoPtr->cryptBlocksize - 1 ) - \
						    ( dataLength & ( sessionInfoPtr->cryptBlocksize - 1 ) );
		int i;

		/* Add the PKCS #5-style padding (PKCS #5 uses n, TLS uses n-1) */
		for( i = 0; i < padSize + 1; i++ )
			*dataPadPtr++ = padSize;
		length += padSize + 1;
		}

	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_CTX_ENCRYPT, data, length );
	return( cryptStatusError( status ) ? status : length );
	}

int decryptData( SESSION_INFO *sessionInfoPtr, BYTE *data,
				 const int dataLength )
	{
	int length = dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength > 0 && dataLength <= sessionInfoPtr->receiveBufEnd );
	assert( isWritePtr( data, dataLength ) );

	/* Decrypt the data */
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, data, length );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Packet decryption failed" );

	/* If it's a block cipher, we need to remove end-of-block padding.  Up
	   until TLS 1.1 the spec was silent about any requirement to check the
	   padding (and for SSLv3 it didn't specify the padding format at all)
	   so it's not really safe to reject an SSL message if we don't find the
	   correct padding because many SSL implementations didn't process the
	   padded space in any way, leaving it containing whatever was there
	   before (which can include old plaintext (!!)).  Almost all TLS
	   implementations get it right (even though in TLS 1.0 there was only a
	   requirement to generate, but not to check, the PKCS #5-style padding).
	   Because of this we only check the padding bytes if we're talking
	   TLS */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		const int padSize = data[ dataLength - 1 ];

		/* Make sure that the padding info looks OK.  TLS allows up to 256
		   bytes of padding (only GnuTLS actually seems to use this
		   capability though) so we can't check for a sensible (small)
		   padding length, however we can check this for SSL, which is good
		   because for that we can't check the padding itself */
		if( padSize < 0 || \
			( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL && \
			  padSize > sessionInfoPtr->cryptBlocksize - 1 ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid encryption padding value 0x%02X", padSize );
		length -= padSize + 1;
		if( length < 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Encryption padding adjustment value %d is greater "
					"than packet length %d", padSize, dataLength );

		/* Check for PKCS #5-type padding (PKCS #5 uses n, TLS uses n-1) if
		   necessary */
		if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
			{
			int i;

			for( i = 0; i < padSize; i++ )
				{
				if( data[ length + i ] != padSize )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid encryption padding byte 0x%02X at "
							"position %d, should be 0x%02X",
							data[ length + i ], length + i, padSize );
				}
			}
		}

	return( length );
	}

/****************************************************************************
*																			*
*								MAC Data Functions							*
*																			*
****************************************************************************/

/* Perform a MAC or dual MAC of a data block.  We have to provide special-
   case handling of zero-length blocks since some versions of OpenSSL send
   these as a kludge in SSL/TLS 1.0 to work around chosen-IV attacks */

int macDataSSL( SESSION_INFO *sessionInfoPtr, const void *data,
				const int dataLength, const int type, const BOOLEAN isRead,
				const BOOLEAN noReportError )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE buffer[ 128 + 8 ];
	const CRYPT_CONTEXT iHashContext = isRead ? \
			sessionInfoPtr->iAuthInContext : sessionInfoPtr->iAuthOutContext;
	const void *macSecret = isRead ? sslInfo->macReadSecret : \
									 sslInfo->macWriteSecret;
	const long seqNo = isRead ? sslInfo->readSeqNo++ : sslInfo->writeSeqNo++;
	const int padSize = \
			( sessionInfoPtr->integrityAlgo == CRYPT_ALGO_MD5 ) ? 48 : 40;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );
	assert( dataLength == 0 || isReadPtr( data, dataLength ) );

	/* Set up the sequence number and length data */
	memset( buffer, PROTOHMAC_PAD1_VALUE, padSize );
	sMemOpen( &stream, buffer + padSize, 128 - padSize );
	writeUint64( &stream, seqNo );
	sputc( &stream, type );
	writeUint16( &stream, dataLength );
	length = stell( &stream );
	sMemDisconnect( &stream );

	/* Reset the hash context and generate the inner portion of the MAC:

		hash( MAC_secret || pad1 || seq_num || type || length || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) macSecret,
					 sessionInfoPtr->authBlocksize );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
					 padSize + length );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data,
						 dataLength );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the inner hash value */
	memset( buffer, PROTOHMAC_PAD2_VALUE, padSize );
	setMessageData( &msgData, buffer + padSize, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the outer portion of the handshake message's MAC:

		hash( MAC_secret || pad2 || inner_hash ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) macSecret,
					 sessionInfoPtr->authBlocksize );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
					 padSize + msgData.length );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a read, compare the calculated MAC to the MAC present at the
	   end of the data */
	if( isRead )
		{
		setMessageData( &msgData, ( BYTE * ) data + dataLength,
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( iHashContext, IMESSAGE_COMPARE,
								  &msgData, MESSAGE_COMPARE_HASH );
		if( cryptStatusError( status ) )
			{
			/* If the error message has already been set at a higher level,
			   don't update the error info */
			if( noReportError )
				return( CRYPT_ERROR_SIGNATURE );

			retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
					"Bad message MAC for packet type %d, length %d",
					type, dataLength );
			}
		return( CRYPT_OK );
		}

	/* Set the MAC value at the end of the packet */
	setMessageData( &msgData, ( BYTE * ) data + dataLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	return( cryptStatusOK( status ) ? dataLength + msgData.length : status );
	}

int macDataTLS( SESSION_INFO *sessionInfoPtr, const void *data,
				const int dataLength, const int type, const BOOLEAN isRead,
				const BOOLEAN noReportError )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE buffer[ 64 + 8 ];
	const CRYPT_CONTEXT iHashContext = isRead ? \
			sessionInfoPtr->iAuthInContext : sessionInfoPtr->iAuthOutContext;
	const long seqNo = isRead ? sslInfo->readSeqNo++ : sslInfo->writeSeqNo++;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );
	assert( dataLength == 0 || isReadPtr( data, dataLength ) );

	/* Set up the sequence number, type, version, and length data */
	sMemOpen( &stream, buffer, 64 );
	writeUint64( &stream, seqNo );
	sputc( &stream, type );
	sputc( &stream, SSL_MAJOR_VERSION );
	sputc( &stream, sessionInfoPtr->version );
	writeUint16( &stream, dataLength );
	length = stell( &stream );
	sMemDisconnect( &stream );

	/* Reset the hash context and generate the MAC:

		HMAC( seq_num || type || version || length || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, length );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data,
						 dataLength );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a read, compare the calculated MAC to the MAC present at the
	   end of the data */
	if( isRead )
		{
		setMessageData( &msgData, ( BYTE * ) data + dataLength,
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( iHashContext, IMESSAGE_COMPARE,
								  &msgData, MESSAGE_COMPARE_HASH );
		if( cryptStatusError( status ) )
			{
			/* If the error message has already been set at a higher level,
			   don't update the error info */
			if( noReportError )
				return( CRYPT_ERROR_SIGNATURE );

			retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
					"Bad message MAC for packet type %d, length %d",
					type, dataLength );
			}
		return( CRYPT_OK );
		}

	/* Set the MAC value at the end of the packet */
	setMessageData( &msgData, ( BYTE * ) data + dataLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	return( cryptStatusOK( status ) ? dataLength + msgData.length : status );
	}

int dualMacData( const SSL_HANDSHAKE_INFO *handshakeInfo,
				 const STREAM *stream, const BOOLEAN isRawData )
	{
	const int dataLength = isRawData ? sMemDataLeft( stream ) : \
									   stell( stream ) - SSL_HEADER_SIZE;
	const void *data = isRawData ? sMemBufPtr( stream ) : \
								   sMemBufPtr( stream ) - dataLength;
	int status;

	assert( dataLength > 0 );

	status = krnlSendMessage( handshakeInfo->clientMD5context,
							  IMESSAGE_CTX_HASH, ( void * ) data,
							  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->clientSHA1context,
								  IMESSAGE_CTX_HASH, ( void * ) data,
								  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverMD5context,
								  IMESSAGE_CTX_HASH, ( void * ) data,
								  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverSHA1context,
								  IMESSAGE_CTX_HASH, ( void * ) data,
								  dataLength );
	return( status );
	}

/* Complete the dual MD5/SHA1 hash/MAC used in the finished message */

int completeSSLDualMAC( const CRYPT_CONTEXT md5context,
						const CRYPT_CONTEXT sha1context, BYTE *hashValues,
						const char *label, const BYTE *masterSecret )
	{
	MESSAGE_DATA msgData;
	int status;

	/* Generate the inner portion of the handshake message's MAC:

		hash( handshake_messages || cl/svr_label || master_secret || pad1 ).

	   Note that the SHA-1 pad size is 40 bytes and not 44 (to get a total
	   length of 64 bytes), this is due to an error in the spec */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, ( void * ) label,
					 SSL_SENDERLABEL_SIZE );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, ( void * ) label,
					 SSL_SENDERLABEL_SIZE );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 SSL_SECRET_SIZE );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 SSL_SECRET_SIZE );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 48 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 40 );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashValues, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashValues + MD5MAC_SIZE, SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Reset the hash contexts */
	krnlSendMessage( md5context, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( sha1context, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );

	/* Generate the outer portion of the handshake message's MAC:

		hash( master_secret || pad2 || inner_hash ) */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 SSL_SECRET_SIZE );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 SSL_SECRET_SIZE );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 48 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 40 );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, hashValues,
					 MD5MAC_SIZE );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, hashValues + MD5MAC_SIZE,
					 SHA1MAC_SIZE );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashValues, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashValues + MD5MAC_SIZE, SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	return( status );
	}

int completeTLSHashedMAC( const CRYPT_CONTEXT md5context,
						  const CRYPT_CONTEXT sha1context, BYTE *hashValues,
						  const char *label, const BYTE *masterSecret )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	const int labelLength = strlen( label );
	int status;

	memcpy( hashBuffer, label, labelLength );

	/* Complete the hashing and get the MD5 and SHA-1 hashes */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashBuffer + labelLength, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashBuffer + labelLength + MD5MAC_SIZE,
						SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the TLS check value.  This isn't really a hash or a MAC, but
	   is generated by feeding the MD5 and SHA1 hashes of the handshake
	   messages into the TLS key derivation (PRF) function and truncating
	   the result to 12 bytes (96 bits) for no adequately explored reason,
	   most probably it's IPsec cargo cult protocol design:

		TLS_PRF( label || MD5_hash || SHA1_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, TLS_HASHEDMAC_SIZE,
							( void * ) masterSecret, 48, CRYPT_USE_DEFAULT,
							hashBuffer, labelLength + MD5MAC_SIZE + SHA1MAC_SIZE, 1 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

/****************************************************************************
*																			*
*							Signature Functions								*
*																			*
****************************************************************************/

/* Create/check the signature on an SSL certificate verify message.
   SSLv3/TLS use a weird signature format that dual-MACs (SSLv3) or hashes
   (TLS) all of the handshake messages exchanged to date (SSLv3 additionally
   hashes in further data like the master secret), then signs them using
   nonstandard PKCS #1 RSA without the ASN.1 wrapper (that is, it uses the
   private key to encrypt the concatenated SHA-1 and MD5 MAC or hash of the
   handshake messages with PKCS #1 padding prepended), unless we're using
   DSA in which case it drops the MD5 MAC/hash and uses only the SHA-1 one.
   This is an incredible pain to support because it requires running a
   parallel hash of handshake messages that terminates before the main
   hashing does, further hashing/MAC'ing of additional data, and the use of
   weird nonstandard data formats and signature mechanisms that aren't
   normally supported by anything.  For example if the signing is to be done
   via a smart card then we can't use the standard PKCS #1 sig mechanism, we
   can't even use raw RSA and kludge the format together ourselves because
   some PKCS #11 implementations don't support the _X509 (raw) mechanism,
   what we have to do is tunnel the nonstandard sig.format info down through
   several cryptlib layers and then hope that the PKCS #11 implementation
   that we're using (a) supports this format and (b) gets it right.  Another
   problem (which only occurs for SSLv3) is that the MAC requires the use of
   the master secret, which isn't available for several hundred more lines
   of code, so we have to delay producing any more data packets until the
   master secret is available, which severely screws up the handshake
   processing flow.

   The chances of all of this working correctly are fairly low, and in any
   case there's no advantage to the weird mechanism and format used in
   SSL/TLS, all we actually need to do is sign the client and server nonces
   to ensure signature freshness.  Because of this what we actually do is
   just this, after which we create a standard PKCS #1 signature via the
   normal cryptlib mechanisms, which guarantees that it'll work with native
   cryptlib as well as any crypto hardware implementation.  Since client
   certs are hardly ever used and when they are it's in a closed environment,
   it's extremely unlikely that anyone will ever notice.  There'll be far
   more problems in trying to use the nonstandard SSL/TLS signature mechanism
   than there are with using a standard (but not-in-the-spec) one */

static CRYPT_CONTEXT createCertVerifyHash( const SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];
	int status;

	/* Hash the client and server nonces */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( nonceBuffer, "certificate verify", 18 );
	memcpy( nonceBuffer + 18, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + 18 + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 nonceBuffer, 18 + SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 nonceBuffer, 0 );

	return( createInfo.cryptHandle );
	}

int createCertVerify( const SESSION_INFO *sessionInfoPtr,
					  const SSL_HANDSHAKE_INFO *handshakeInfo,
					  STREAM *stream )
	{
	CRYPT_CONTEXT iHashContext;
	int length, status;

	/* Create the hash of the data to sign */
	iHashContext = createCertVerifyHash( handshakeInfo );
	if( cryptStatusError( iHashContext ) )
		return( iHashContext );

	/* Create the signature.  The reason for the min() part of the
	   expression is that iCryptCreateSignatureEx() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a 1MB send buffer */
	status = iCryptCreateSignatureEx( sMemBufPtr( stream ), &length,
									  min( sMemDataLeft( stream ), 16384 ),
									  CRYPT_FORMAT_CRYPTLIB,
									  sessionInfoPtr->privateKey,
									  iHashContext, CRYPT_UNUSED,
									  CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, length );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

int checkCertVerify( const SESSION_INFO *sessionInfoPtr,
					 const SSL_HANDSHAKE_INFO *handshakeInfo,
					 STREAM *stream, const int sigLength )
	{
	CRYPT_CONTEXT iHashContext;
	int status;

	assert( sigLength > MIN_CRYPT_OBJECTSIZE );

	/* Create the hash of the data to sign */
	iHashContext = createCertVerifyHash( handshakeInfo );
	if( cryptStatusError( iHashContext ) )
		return( iHashContext );

	/* Verify the signature.  The reason for the min() part of the
	   expression is that iCryptCheckSignatureEx() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a 1MB send buffer */
	status = iCryptCheckSignatureEx( sMemBufPtr( stream ),
									 min( sigLength, 16384 ),
									 CRYPT_FORMAT_CRYPTLIB,
									 sessionInfoPtr->iKeyexAuthContext,
									 iHashContext, NULL );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Create/check the signature on the server key data */

static int createKeyexHashes( const SSL_HANDSHAKE_INFO *handshakeInfo,
							  const void *keyData, const int keyDataLength,
							  CRYPT_CONTEXT *md5Context,
							  CRYPT_CONTEXT *shaContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];
	int status;

	/* Create the dual hash contexts */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	*md5Context = createInfo.cryptHandle;
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *md5Context, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*shaContext = createInfo.cryptHandle;

	/* Hash the client and server nonces and key data */
	memcpy( nonceBuffer, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
					 nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
					 nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
					 ( void * ) keyData, keyDataLength );
	krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
					 ( void * ) keyData, keyDataLength );
	krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
					 nonceBuffer, 0 );
	krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
					 nonceBuffer, 0 );

	return( CRYPT_OK );
	}

int createKeyexSignature( SESSION_INFO *sessionInfoPtr,
						  SSL_HANDSHAKE_INFO *handshakeInfo,
						  STREAM *stream, const void *keyData,
						  const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context, shaContext;
	int sigLength, status;

	/* Hash the data to be signed */
	status = createKeyexHashes( handshakeInfo, keyData, keyDataLength,
								&md5Context, &shaContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Sign the hashes.  The reason for the min() part of the expression is
	   that iCryptCreateSignatureEx() gets suspicious of very large buffer
	   sizes, for example when the user has specified the use of a 1MB send
	   buffer */
	status = iCryptCreateSignatureEx( sMemBufPtr( stream ), &sigLength,
							min( sMemDataLeft( stream ), 16384 ),
							CRYPT_IFORMAT_SSL, sessionInfoPtr->privateKey,
							md5Context, shaContext, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, sigLength );

	/* Clean up */
	krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

int checkKeyexSignature( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 STREAM *stream, const void *keyData,
						 const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context, shaContext;
	int status;

	/* Make sure that there's enough data present for at least a minimal-
	   length signature */
	if( sMemDataLeft( stream ) < bitsToBytes( MIN_PKCSIZE_BITS ) )
		return( CRYPT_ERROR_BADDATA );

	/* Hash the data to be signed */
	status = createKeyexHashes( handshakeInfo, keyData, keyDataLength,
								&md5Context, &shaContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the signature on the hashes.  The reason for the min() part of
	   the expression is that iCryptCreateSignatureEx() gets suspicious of
	   very large buffer sizes, for example when the user has specified the
	   use of a 1MB send buffer */
	status = iCryptCheckSignatureEx( sMemBufPtr( stream ),
									 min( sMemDataLeft( stream ), 16384 ),
									 CRYPT_IFORMAT_SSL,
									 sessionInfoPtr->iKeyexCryptContext,
									 md5Context, &shaContext );
	if( cryptStatusOK( status ) )
		status = readUniversal16( stream );

	/* Clean up */
	krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}
#endif /* USE_SSL */
