/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Session Management					*
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

#define CHANGECIPHERSPEC_TEMPLATE_SIZE		6
#define FINISHED_TEMPLATE_SIZE				4
#define CLOSEALERT_TEMPLATE_SIZE			7
#define HANDSHAKEFAILALERT_TEMPLATE_SIZE	7

static const FAR_BSS SSL_MESSAGE_TEMPLATE changeCipherSpecTemplate = {
	/*	byte		type = 20 (change cipherspec)
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1 */
	{ SSL_MSG_CHANGE_CIPHER_SPEC, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_SSL, 0, 1, 1 },
	{ SSL_MSG_CHANGE_CIPHER_SPEC, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_TLS, 0, 1, 1 },
	{ SSL_MSG_CHANGE_CIPHER_SPEC, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_TLS11, 0, 1, 1 }
	};
static const FAR_BSS SSL_MESSAGE_TEMPLATE finishedTemplate[] = {
	/*	byte		ID = 0x14
		uint24		len = 16 + 20 (SSL), 12 (TLS) */
	{ SSL_HAND_FINISHED, 0, 0, MD5MAC_SIZE + SHA1MAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	};
static const FAR_BSS SSL_MESSAGE_TEMPLATE closeAlertTemplate[] = {
	/*	byte		type = 21 (alert)
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 2
		byte		level = 1 (warning)
		byte		description = 0 (close_notify) */
	{ SSL_MSG_ALERT, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_SSL, 0, 2, 
	  SSL_ALERTLEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY },
	{ SSL_MSG_ALERT, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_TLS, 0, 2, 
	  SSL_ALERTLEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY },
	{ SSL_MSG_ALERT, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_TLS11, 0, 2, 
	  SSL_ALERTLEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY },
	};
static const FAR_BSS SSL_MESSAGE_TEMPLATE handshakeFailAlertTemplate[] = {
	/*	byte		type = 21 (alert)
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 2
		byte		level = 2 (fatal)
		byte		description = 40 (handshake_failure) */
	{ SSL_MSG_ALERT, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_SSL, 0, 2,
	  SSL_ALERTLEVEL_FATAL, SSL_ALERT_HANDSHAKE_FAILURE },
	{ SSL_MSG_ALERT, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_TLS, 0, 2,
	  SSL_ALERTLEVEL_FATAL, SSL_ALERT_HANDSHAKE_FAILURE },
	{ SSL_MSG_ALERT, SSL_MAJOR_VERSION, SSL_MINOR_VERSION_TLS11, 0, 2,
	  SSL_ALERTLEVEL_FATAL, SSL_ALERT_HANDSHAKE_FAILURE },
	};

/* Set up the information implied by an SSL cipher suite */

int initCiphersuiteInfo( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 const int cipherSuite )
	{
	const CRYPT_ALGO_TYPE integrityAlgoMD5 = \
					( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					CRYPT_ALGO_MD5 : CRYPT_ALGO_HMAC_MD5;
	const CRYPT_ALGO_TYPE integrityAlgoSHA = \
					( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					CRYPT_ALGO_SHA : CRYPT_ALGO_HMAC_SHA;

	if( cipherSuite == TLS_RSA_WITH_AES_128_CBC_SHA || \
		cipherSuite == TLS_RSA_WITH_AES_256_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_AES;
		sessionInfoPtr->integrityAlgo = integrityAlgoSHA;
		sessionInfoPtr->cryptBlocksize = 16;
		handshakeInfo->cryptKeysize = \
				( cipherSuite == TLS_RSA_WITH_AES_128_CBC_SHA ) ? 16 : 32;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_3DES_EDE_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_3DES;
		sessionInfoPtr->integrityAlgo = integrityAlgoSHA;
		sessionInfoPtr->cryptBlocksize = 8;
		handshakeInfo->cryptKeysize = 24;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_RC4_128_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_RC4;
		sessionInfoPtr->integrityAlgo = integrityAlgoSHA;
		sessionInfoPtr->cryptBlocksize = 1;
		handshakeInfo->cryptKeysize = 16;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_RC4_128_MD5 )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_RC4;
		sessionInfoPtr->integrityAlgo = integrityAlgoMD5;
		sessionInfoPtr->cryptBlocksize = 1;
		handshakeInfo->cryptKeysize = 16;
		sessionInfoPtr->authBlocksize = MD5MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_IDEA_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_IDEA;
		sessionInfoPtr->integrityAlgo = integrityAlgoSHA;
		sessionInfoPtr->cryptBlocksize = 8;
		handshakeInfo->cryptKeysize = 16;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_DES_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_DES;
		sessionInfoPtr->integrityAlgo = integrityAlgoSHA;
		sessionInfoPtr->cryptBlocksize = 8;
		handshakeInfo->cryptKeysize = 8;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}

	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Initialise and destroy the handshake state information */

static void destroyHandshakeInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
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

	zeroise( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) );
	}

static int initHandshakeInfo( SSL_HANDSHAKE_INFO *handshakeInfo,
							  const BOOLEAN isServer )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	/* Initialise the handshake state info values */
	memset( handshakeInfo, 0, sizeof( SSL_HANDSHAKE_INFO ) );
	handshakeInfo->clientMD5context = \
		handshakeInfo->serverMD5context = \
		handshakeInfo->clientSHA1context = \
		handshakeInfo->serverSHA1context = CRYPT_ERROR;
	if( isServer )
		initSSLserverProcessing( handshakeInfo );
	else
		initSSLclientProcessing( handshakeInfo );

	/* Create the MAC/dual-hash contexts for incoming and outgoing data.  
	   SSL uses a pre-HMAC variant for which we can't use real HMAC but have 
	   to construct it ourselves from MD5 and SHA-1, TLS uses a straight dual
	   hash and MACs that once a MAC key is available */
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

	/* One or more of the contexts couldn't be created, destroy all the
	   contexts that have been created so far */
	destroyHandshakeInfo( handshakeInfo );
	return( status );
	}

/* Initialise and destroy the security contexts */

static void destroySecurityContexts( SESSION_INFO *sessionInfoPtr )
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

static int initSecurityContexts( SESSION_INFO *sessionInfoPtr )
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
		/* One or more of the contexts couldn't be created, destroy all the
		   contexts that have been created so far */
		destroySecurityContexts( sessionInfoPtr );
	return( status );
	}

/* Create the master secret from a shared secret value, typically a 
   password.  The expandSharedSecret function uses a slightly different
   coding style because it's taken directly from the RFC */

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

int createSharedMasterSecret( BYTE *masterSecret, 
							  const SESSION_INFO *sessionInfoPtr )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE premasterSecret[ SSL_SECRET_SIZE ];
	int status;

	/* Expand the shared secret to create the premaster secret */
	if( sessionInfoPtr->flags & SESSION_ISENCODEDPW )
		{
		BYTE decodedValue[ CRYPT_MAX_TEXTSIZE ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded password, decode it into its binary 
		   value */
		decodedValueLength = decodePKIUserValue( decodedValue,
											sessionInfoPtr->password,
											sessionInfoPtr->passwordLength );
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
		expandSharedSecret( premasterSecret, sessionInfoPtr->password, 
							min( sessionInfoPtr->passwordLength, 
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
							  MECHANISM_TLS );
	zeroise( premasterSecret, SSL_SECRET_SIZE );
	return( status );
	}

/* Encrypt/decrypt a data block */

static int encryptData( const SESSION_INFO *sessionInfoPtr, BYTE *data,
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

static int decryptData( SESSION_INFO *sessionInfoPtr, BYTE *data,
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
				"Decryption of SSL packet failed" );

	/* If it's a block cipher, we need to remove end-of-block padding.  Up
	   until TLS 1.1 the spec was silent about any requirement to check the 
	   padding (and for SSLv3 it didn't specify the padding format at all) 
	   so it's not really safe to reject an SSL a message if we don't find 
	   the correct padding because many SSL implementations didn't process 
	   the padded space in any way, leaving it containing whatever was there 
	   before.  Almost all TLS implementations get it right (even though in
	   TLS 1.0 there was only a requirement to generate, but not to check, 
	   the PKCS #5-style padding).  Because of this we only check the 
	   padding bytes if we're talking TLS */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		const int padSize = data[ dataLength - 1 ];

		/* Make sure that the padding info looks OK.  TLS allows up to 256 
		   bytes of padding, but there are no known implementations that do 
		   this.  This is convenient because it allows us to quickly detect
		   most invalid decrypts */
		if( padSize < 0 || padSize > sessionInfoPtr->cryptBlocksize - 1 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid padding value 0x%02X", padSize );
		length -= padSize + 1;
		if( length < 0 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Padding adjustment value 0x%02X is greater than packet "
					"length %d", padSize, dataLength );

		/* Check for PKCS #5-type padding (PKCS #5 uses n, TLS uses n-1) if
		   necessary */
		if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
			{
			int i;

			for( i = 0; i < padSize; i++ )
				if( data[ length + i ] != padSize )
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid padding byte 0x%02X at position %d", 
							data[ length + i ], length + i );
			}
		}

	return( length );
	}

/* Perform a MAC or dual MAC of a data block.  We have to provide special-
   case handling of zero-length blocks since some versions of OpenSSL send
   these as a kludge to work around chosen-IV attacks */

static int macDataSSL( SESSION_INFO *sessionInfoPtr, const void *data,
					   const int dataLength, const int type,
					   const BOOLEAN isRead )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ 128 ], *bufPtr;
	BYTE *macPtr = isRead ? buffer : ( BYTE * ) data + dataLength;
	const CRYPT_CONTEXT iHashContext = isRead ? \
			sessionInfoPtr->iAuthInContext : sessionInfoPtr->iAuthOutContext;
	const void *macSecret = isRead ? \
			sessionInfoPtr->sslMacReadSecret : sessionInfoPtr->sslMacWriteSecret;
	const long seqNo = isRead ? \
			sessionInfoPtr->readSeqNo++ : sessionInfoPtr->writeSeqNo++;
	const int padSize = \
			( sessionInfoPtr->integrityAlgo == CRYPT_ALGO_MD5 ) ? 48 : 40;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );
	assert( isReadPtr( data, dataLength ) );

	/* Set up the sequence number and length data */
	memcpy( buffer, PROTOHMAC_PAD1, padSize );
	memset( buffer + padSize, 0, SEQNO_SIZE );
	bufPtr = buffer + padSize + 4;
	mputLong( bufPtr, seqNo );
	*bufPtr++ = type;
	mputWord( bufPtr, dataLength );

	/* Reset the hash context and generate the inner portion of the MAC:

		hash( MAC_secret || pad1 || seq_num || type || length || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) macSecret, 
					 sessionInfoPtr->authBlocksize );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 
					 padSize + SEQNO_SIZE + ID_SIZE + UINT16_SIZE );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data, 
						 dataLength );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the inner hash value */
	memcpy( buffer, PROTOHMAC_PAD2, padSize );
	setMessageData( &msgData, buffer + padSize, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the outer portion of the handshake message's MAC and get the
	   MAC value, which is either written to the end of the data (for a
	   write) or to a separate buffer (for a read):
		hash( MAC_secret || pad2 || inner_hash ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) macSecret, 
					 sessionInfoPtr->authBlocksize );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 
					 padSize + msgData.length );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, macPtr, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a read, compare the calculated MAC to the MAC present at the
	   end of the data */
	if( isRead )
		{
		if( memcmp( macPtr, ( BYTE * ) data + dataLength, msgData.length ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
					"Bad message MAC" );
		return( CRYPT_OK );
		}

	return( dataLength + msgData.length );
	}

static int macDataTLS( SESSION_INFO *sessionInfoPtr, const void *data,
					   const int dataLength, const int type,
					   const BOOLEAN isRead )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ 128 ], *bufPtr;
	BYTE *macPtr = isRead ? buffer : ( BYTE * ) data + dataLength;
	const CRYPT_CONTEXT iHashContext = isRead ? \
			sessionInfoPtr->iAuthInContext : sessionInfoPtr->iAuthOutContext;
	const long seqNo = isRead ? \
			sessionInfoPtr->readSeqNo++ : sessionInfoPtr->writeSeqNo++;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );
	assert( isReadPtr( data, dataLength ) );

	/* Set up the sequence number, type, version, and length data */
	memset( buffer, 0, SEQNO_SIZE );
	bufPtr = buffer + 4;
	mputLong( bufPtr, seqNo );
	*bufPtr++ = type;
	*bufPtr++ = SSL_MAJOR_VERSION;
	*bufPtr++ = SSL_MINOR_VERSION_TLS;
	mputWord( bufPtr, dataLength );

	/* Reset the hash context and generate the MAC, which is either written
	   to the end of the data (for a write) or to a separate buffer (for a
	   read):

		HMAC( seq_num || type || version || length || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 
					 SEQNO_SIZE + ID_SIZE + VERSIONINFO_SIZE + UINT16_SIZE );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data, 
						 dataLength );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, macPtr, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a read, compare the calculated MAC to the MAC present at the
	   end of the data */
	if( isRead )
		{
		if( memcmp( macPtr, ( BYTE * ) data + dataLength, msgData.length ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
					"Bad message MAC" );
		return( CRYPT_OK );
		}

	return( dataLength + msgData.length );
	}

int dualMacData( const SSL_HANDSHAKE_INFO *handshakeInfo, const void *data,
				 const int dataLength )
	{
	int status;

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

/* Wrap/unwrap an SSL data packet.  These functions process data as follows:

				------				MAC'd
		   =======================  Encrypted

	[ hdr | IV | data | MAC | pad ]	|
	|		   +------+				| Wrap, adds hdr, IV, MAC, pad,
	|			  |					| returns total length
   buffer		length 

	[ hdr | IV | data | MAC | pad ]	|
			   +------------------+	| Unwrap, removes MAC, pad, 
			   |		|			| returns data length
			 buffer	 length 

   Processing of the header and IV during unwrapping have already been 
   performed during the packet header read, so the two functions aren't
   quite isometric */

static int wrapData( SESSION_INFO *sessionInfoPtr, BYTE *buffer, 
					 const int length, const int type )
	{
	BYTE *bufPtr = buffer;
	const int ivSize = \
				( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV ) ? \
				sessionInfoPtr->cryptBlocksize : 0;
	int startOffset = sessionInfoPtr->sendBufStartOfs, dataLength;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( length >= 0 && length <= MAX_PACKET_SIZE );
	assert( isWritePtr( buffer, length ) );
	assert( startOffset >= SSL_HEADER_SIZE ); 

	/* MAC the payload */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		dataLength = macDataSSL( sessionInfoPtr, bufPtr + startOffset, 
								 length, type, FALSE );
	else
		dataLength = macDataTLS( sessionInfoPtr, bufPtr + startOffset, 
								 length, type, FALSE );
	if( cryptStatusError( dataLength ) )
		return( dataLength );

	/* If it's TLS 1.1 or newer and we're using a block cipher, prepend
	   the IV to the data */
	if( ivSize > 0 )
		{
		RESOURCE_DATA msgData;

		assert( startOffset >= SSL_HEADER_SIZE + ivSize ); 

		startOffset -= ivSize;
		setMessageData( &msgData, bufPtr + startOffset, ivSize );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		}

	/* Encrypt the payload */
	dataLength = encryptData( sessionInfoPtr, bufPtr + startOffset,
							  dataLength + ivSize );
	if( cryptStatusError( dataLength ) )
		return( dataLength );

	/* Add the packet wrapper */
	*bufPtr++ = type;
	*bufPtr++ = SSL_MAJOR_VERSION;
	*bufPtr++ = sessionInfoPtr->version;
	mputWord( bufPtr, dataLength );

	return( startOffset + dataLength );
	}

static int unwrapData( SESSION_INFO *sessionInfoPtr, BYTE *buffer,
					   const int length, const int type )
	{
	BOOLEAN badDecrypt = FALSE;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( length >= 0 && length <= MAX_PACKET_SIZE + 20 + \
									 sessionInfoPtr->cryptBlocksize );
	assert( isWritePtr( buffer, length ) );

	/* Make sure that the length is a multiple of the block cipher size */
	if( sessionInfoPtr->cryptBlocksize > 1 && \
		( length % sessionInfoPtr->cryptBlocksize ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet length %d relative to cipher block size %d", 
				length, sessionInfoPtr->cryptBlocksize );

	/* Decrypt the packet in the buffer.  We allow zero-length blocks (once
	   the padding is stripped) because some versions of OpenSSL send these 
	   as a kludge to work around chosen-IV attacks */
	dataLength = decryptData( sessionInfoPtr, buffer, length );
	if( cryptStatusError( dataLength ) )
		{
		/* If there's a padding error, don't exit immediately but record 
		   that there was a problem for after we've done the MAC'ing.  
		   Delaying the error reporting until then helps prevent timing 
		   attacks of the kind described by Brice Canvel, Alain Hiltgen,
		   Serge Vaudenay, and Martin Vuagnoux in "Password Interception 
		   in a SSL/TLS Channel", Crypto'03, LNCS No.2729, p.583.  These 
		   are close to impossible in most cases because we delay sending 
		   the close notify over a much longer period than the MAC vs.non-
		   MAC time difference and because it requires repeatedly connecting
		   with a fixed-format secret such as a password at the same location
		   in the packet (which MS Outlook manages to do, however), but we 
		   take this step anyway just to be safe */
		if( dataLength == CRYPT_ERROR_BADDATA )
			{
			badDecrypt = TRUE;
			dataLength = length;
			}
		else
			return( dataLength );
		}
	dataLength -= sessionInfoPtr->authBlocksize;
	if( dataLength < 0 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid data payload length %d", dataLength );

	/* MAC the decrypted data */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		status = macDataSSL( sessionInfoPtr, buffer, dataLength, type, TRUE );
	else
		status = macDataTLS( sessionInfoPtr, buffer, dataLength, type, TRUE );
	if( badDecrypt )
		/* Report the delayed decrypt error, held to this point to make 
		   timing attacks more difficult.  The extended error info will have
		   been overwritten by the error info from the MAC'ing code, but
		   either message is appropriate */
		return( CRYPT_ERROR_BADDATA );
	if( cryptStatusError( status ) )
		return( status );

	return( dataLength );
	}

/* Write an SSL cert chain:

	byte		ID = 0x0B
	uint24		len
	uint24		certListLen
	uint24		certLen			| 1...n certs ordered
	byte[]		cert			|   leaf -> root */

int writeSSLCertChain( SESSION_INFO *sessionInfoPtr, BYTE *buffer )
	{
	CRYPT_CERTIFICATE iCryptCert;
	BYTE *bufPtr = buffer, *lengthPtr;
	int length = 0, status;

	/* Write the packet header and leave room for the packet length and
	   cert list length */
	*bufPtr++ = SSL_HAND_CERTIFICATE;
	lengthPtr = bufPtr;
	bufPtr += LENGTH_SIZE + LENGTH_SIZE;	/* len + certListLen */

	/* Lock the cert chain for our exclusive use and select the leaf cert,
	   export each cert in turn until we reach the root, and unlock it again 
	   to allow others access */
	krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_GETDEPENDENT,
					 &iCryptCert, OBJECT_TYPE_CERTIFICATE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	do
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, bufPtr + LENGTH_SIZE,
						sessionInfoPtr->sendBufSize - \
						( bufPtr + LENGTH_SIZE - sessionInfoPtr->sendBuffer ) );
		status = krnlSendMessage( sessionInfoPtr->privateKey,
								  IMESSAGE_CRT_EXPORT, &msgData, 
								  CRYPT_CERTFORMAT_CERTIFICATE );
		*bufPtr++ = 0;
		mputWord( bufPtr, msgData.length );
		bufPtr += msgData.length;
		length += msgData.length + LENGTH_SIZE;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( sessionInfoPtr->privateKey,
							IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE, 
					 CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );

	/* Go back and add the overall packet length and cert chain length at the
	   start of the packet */
	*lengthPtr++ = 0;		/* len */
	mputWord( lengthPtr, length + LENGTH_SIZE );
	*lengthPtr++ = 0;		/* certListLen */
	mputWord( lengthPtr, length );

	return( ID_SIZE + LENGTH_SIZE + LENGTH_SIZE + length );
	}

/* Read/write an SSL certificate verify message:

	byte		ID = 0x0F
	uint24		len
	byte[]		signature

   SSLv3/TLS use a weird signature format that dual-MACs (SSLv3) or hashes
   (TLS) all of the handshake messages exchanged to date (SSLv3 additionally 
   hashes in further data like the master secret), then signs them using raw,
   non-PKCS #1 RSA (that is, it uses the private key to encrypt the
   concatenated SHA-1 and MD5 MAC or hash of the handshake messages), unless
   we're using DSA in which case it drops the MD5 MAC/hash and uses only the
   SHA-1 one.  This is an incredible pain to support because it requires
   running a parallel hash of handshake messages that terminates before the
   main hashing does, further hashing/MAC'ing of additional data and the use 
   of weird nonstandard data formats and signature mechanisms that aren't 
   normally supported by anything.  For example if the signing is to be done 
   via a smart card then we can't use the standard PKCS #1 sig, we can't 
   even use raw RSA and kludge the format together ourselves because some 
   PKCS #11 implementations don't support the _X509 (raw) mechanism, what we 
   have to do is tunnel the nonstandard sig.format info down through several 
   cryptlib layers and then hope that the PKCS #11 implementation we're using 
   (a) supports this format and (b) gets it right.  Another problem (which 
   only occurs for SSLv3) is that the MAC requires the use of the master 
   secret, which isn't available for several hundred more lines of code, so 
   we have to delay producing any more data packets until the master secret 
   is available, which severely screws up the handshake processing flow.

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

int processCertVerify( const SESSION_INFO *sessionInfoPtr,
					   const SSL_HANDSHAKE_INFO *handshakeInfo,
					   void *signature, const int signatureLength,
					   const int signatureMaxLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE ];
	int length, status;

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

	/* Create or verify the signature as appropriate */
	if( signatureLength )
		status = iCryptCheckSignatureEx( signature, signatureLength,
										 CRYPT_FORMAT_CRYPTLIB,
										 sessionInfoPtr->iKeyexAuthContext,
										 createInfo.cryptHandle, NULL );
	else
		status = iCryptCreateSignatureEx( signature, &length, 
										  signatureMaxLength,
										  CRYPT_FORMAT_CRYPTLIB,
										  sessionInfoPtr->privateKey,
										  createInfo.cryptHandle,
										  CRYPT_UNUSED, CRYPT_UNUSED );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( ( cryptStatusOK( status ) && !signatureLength ) ? \
			length : status );
	}

/* Process version information from a peer */

int processVersionInfo( SESSION_INFO *sessionInfoPtr, const int version )
	{
	switch( version )
		{
		case SSL_MINOR_VERSION_SSL:
			/* If the other side can't do TLS, fall back to SSL */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
				sessionInfoPtr->version = SSL_MINOR_VERSION_SSL;
			break;

		case SSL_MINOR_VERSION_TLS:
			/* If the other side can't do TLS 1.1, fall back to TLS 1.0 */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 )
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS;
			break;

		case SSL_MINOR_VERSION_TLS11:
			break;

		default:
			/* If we're the server and the client has offered a vaguely 
			   sensible version, fall back to the highest version we
			   support */
			if( ( sessionInfoPtr->flags && SESSION_ISSERVER ) && \
				version <= 5 )
				{
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS11;
				break;
				}

			/* It's nothing we can handle */
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid protocol version %d", version );
		}

	return( CRYPT_OK );
	}

/* Wrap a handshake packet, taking as input a data packet with a 5-byte gap
   at the start for the header and wrapping it up as appropriate in the
   SSL/TLS packet encapsulation

	byte		type = 22 (handshake)
	byte[2]		version = { 0x03, 0x0n }
	uint16		len */

void wrapHandshakePacket( void *data, const int length,
						  const int protocolVersion )
	{
	BYTE *dataPtr = data;

	/* Add the length and type at the start */
	*dataPtr++ = SSL_MSG_HANDSHAKE;
	*dataPtr++ = SSL_MAJOR_VERSION;
	*dataPtr++ = protocolVersion;
	mputWord( dataPtr, length );
	}

/* Send a close alert, with appropriate protection if necessary */

static void sendCloseAlert( SESSION_INFO *sessionInfoPtr, 
							const BOOLEAN alertReceived )
	{
	int status;

	/* Make sure that we only send a single close alert.  Normally we do 
	   this automatically on shutdown, but we may have already sent it 
	   earlier as part of an error-handler */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT )
		return;
	sessionInfoPtr->protocolFlags |= SSL_PFLAG_ALERTSENT;

	/* Send a close alert to tell the other side that we're going away */
	if( !( sessionInfoPtr->flags & SESSION_ISSECURE ) )
		status = swrite( &sessionInfoPtr->stream,
						 closeAlertTemplate[ sessionInfoPtr->version ],
						 CLOSEALERT_TEMPLATE_SIZE );
	else
		{
		BYTE buffer[ 256 ];

		buffer[ sessionInfoPtr->sendBufStartOfs ] = SSL_ALERTLEVEL_WARNING;
		buffer[ sessionInfoPtr->sendBufStartOfs + 1 ] = SSL_ALERT_CLOSE_NOTIFY;
		status = wrapData( sessionInfoPtr, buffer, 2, SSL_MSG_ALERT );
		if( !cryptStatusError( status ) )
			status = swrite( &sessionInfoPtr->stream, buffer, 
							 sessionInfoPtr->sendBufStartOfs + status );
		else
			/* We can't really do much with errors at this point, although 
			   we can throw an exception in the debug version to draw 
			   attention to the fact that there's a problem.  The one error
			   type that we don't complain about is an access permission 
			   problem, which can occur when cryptlib is shutting down, for 
			   example when the current thread is blocked waiting for 
			   network traffic and another thread shuts cryptlib down */
			if( status != CRYPT_ERROR_PERMISSION )
				assert( NOTREACHED );
		}
	if( cryptStatusError( status ) || alertReceived )
		return;

	/* Close the send side of the connection if it's a cryptlib-internal 
	   socket and (try and) read the response from the other side.  The 
	   former is needed by some implementations that want to see a FIN 
	   before they react to a shutdown notification, the latter to clear the 
	   line in case it's a persistent connection.  If it's a user-managed 
	   socket, we can't perform the partial close since this would affect the
	   state of the socket as seen by the user, since the need to see the FIN
	   is fairly rare we choose this as the less problematic of the two 
	   options */
	if( sessionInfoPtr->networkSocket == CRYPT_ERROR )
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_CLOSESENDCHANNEL, NULL, 0 );
	readPacketSSL( sessionInfoPtr, NULL, SSL_MSG_ALERT );
	}

/* Send a handshake failure alert.  This doesn't need any protection since
   it's always sent during the handshake phase */

static void sendHandshakeFailAlert( SESSION_INFO *sessionInfoPtr )
	{
	/* Make sure that we only send a single alert.  Normally we send a close
	   alert automatically on shutdown, but we may have already sent one
	   earlier as part of an error-handler */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT )
		return;
	sessionInfoPtr->protocolFlags |= SSL_PFLAG_ALERTSENT;

	/* Send the appropriate handshake failure alert */
	swrite( &sessionInfoPtr->stream, 
			handshakeFailAlertTemplate[ sessionInfoPtr->version ],
			HANDSHAKEFAILALERT_TEMPLATE_SIZE );
	}

/* Process an alert packet.  IIS often just drops the connection rather than 
   sending an alert when it encounters a problem (although we try and work
   around some of the known problems, e.g. by sending a canary in the client
   hello to force IIS to at least send back something rather than just 
   dropping the connection, see ssl_cli.c), so when communicating with IIS 
   the only error indication we sometimes get will be a "Connection closed 
   by remote host" rather than an SSL-level error message.  In addition when 
   it encounters an unknown cert, MSIE will complete the handshake and then 
   close the connection (via a proper close alert in this case rather than 
   just closing the connection), wait while the user clicks OK several 
   times, and then restart the connection via an SSL resume.  Netscape in 
   contrast just hopes that the session won't time out while waiting for the 
   user to click OK.  As a result, cryptlib sees a closed connection and 
   aborts the session setup process, requiring a second call to the session 
   setup to continue with the resumed session */

static int processAlert( SESSION_INFO *sessionInfoPtr, const int length )
	{
	const static struct {
		const int type;
		const char *message;
		const int cryptlibError;
		} alertInfo[] = {
		{ SSL_ALERT_CLOSE_NOTIFY, "Close notify", CRYPT_ERROR_COMPLETE },
		{ SSL_ALERT_UNEXPECTED_MESSAGE, "Unexpected message", CRYPT_ERROR_FAILED },
		{ SSL_ALERT_BAD_RECORD_MAC, "Bad record MAC", CRYPT_ERROR_SIGNATURE },
		{ TLS_ALERT_DECRYPTION_FAILED, "Decryption failed", CRYPT_ERROR_WRONGKEY },
		{ TLS_ALERT_RECORD_OVERFLOW, "Record overflow", CRYPT_ERROR_OVERFLOW },
		{ SSL_ALERT_DECOMPRESSION_FAILURE, "Decompression failure", CRYPT_ERROR_FAILED },
		{ SSL_ALERT_HANDSHAKE_FAILURE, "Handshake failure", CRYPT_ERROR_FAILED },
		{ SSL_ALERT_NO_CERTIFICATE, "No certificate", CRYPT_ERROR_PERMISSION },
		{ SSL_ALERT_BAD_CERTIFICATE, "Bad certificate", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_UNSUPPORTED_CERTIFICATE, "Unsupported certificate", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_REVOKED, "Certificate revoked", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_EXPIRED, "Certificate expired", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_UNKNOWN, "Certificate unknown", CRYPT_ERROR_INVALID },
		{ SSL_ALERT_ILLEGAL_PARAMETER, "Illegal parameter", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNKNOWN_CA, "Unknown CA", CRYPT_ERROR_INVALID },
		{ TLS_ALERT_ACCESS_DENIED, "Access denied", CRYPT_ERROR_PERMISSION },
		{ TLS_ALERT_DECODE_ERROR, "Decode error", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_DECRYPT_ERROR, "Decrypt error", CRYPT_ERROR_WRONGKEY },
		{ TLS_ALERT_EXPORT_RESTRICTION, "Export restriction", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_PROTOCOL_VERSION, "Protocol version", CRYPT_ERROR_NOTAVAIL },
		{ TLS_ALERT_INSUFFICIENT_SECURITY, "Insufficient security", CRYPT_ERROR_NOSECURE },
		{ TLS_ALERT_INTERNAL_ERROR, "Internal error", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_USER_CANCELLED, "User cancelled", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_NO_RENEGOTIATION, "No renegotiation", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNSUPPORTED_EXTENSION, "Unsupported_extension", CRYPT_ERROR_NOTAVAIL },
		{ TLS_ALERT_CERTIFICATE_UNOBTAINABLE, "Certificate_unobtainable", CRYPT_ERROR_NOTFOUND },
		{ TLS_ALERT_UNRECOGNIZED_NAME, "Unrecognized_name", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE, "Bad_certificate_status_response", CRYPT_ERROR_FAILED },
		{ TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE, "Bad_certificate_hash_value", CRYPT_ERROR_FAILED },
 		{ CRYPT_ERROR, NULL }
		};
	BYTE buffer[ 256 ];
	int type, i, status;

	assert( length > 0 && length < 256 );	/* Range already checked by caller */

	/* Get the alert packet and tell the other side that we're going away */
	status = sread( &sessionInfoPtr->stream, buffer, length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < length )
		{
		/* If we timed out before we could get all of the alert data, bail
		   out without trying to perform any further processing.  We're 
		   about to close the session anyway so there's no point in 
		   potentially stalling for ages trying to find a lost byte */
		sendCloseAlert( sessionInfoPtr, TRUE );
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT, 
				"Timed out reading alert message, got %d of %d bytes", 
				status, length );
		}
	sessionInfoPtr->receiveBufEnd = length;
	if( sessionInfoPtr->flags & SESSION_ISSECURE && \
		( length > ALERTINFO_SIZE || \
		  isStreamCipher( sessionInfoPtr->cryptAlgo ) ) )
		{
		/* We only try and decrypt if the alert info is big enough to be
		   encrypted, i.e. it contains the fixed-size data + padding.  This
		   situation can occur if there's an error moving from the
		   unencrypted to the encrypted state.  However, if it's a stream
		   cipher the ciphertext and plaintext are the same size so we always
		   have to try the decryption */
		status = unwrapData( sessionInfoPtr, buffer, length, SSL_MSG_ALERT );
		if( cryptStatusError( status ) )
			{
			sessionInfoPtr->flags |= SESSION_SENDCLOSED;
			return( status );
			}
		}
	sendCloseAlert( sessionInfoPtr, TRUE );
	sessionInfoPtr->flags |= SESSION_SENDCLOSED;

	/* Process the alert info.  In theory we should also make the session 
	   non-resumable if the other side goes away without sending a close 
	   alert, but this leads to too many problems with non-resumable 
	   sessions if we do it.  For example many protocols do their own end-of-
	   data indication (e.g. "Connection: close" in HTTP and BYE in SMTP) 
	   and so don't bother with a close alert.  In other cases 
	   implementations just drop the connection without sending a close 
	   alert, carried over from many early Unix protocols that used a 
	   connection close to signify end-of-data, which has caused problems 
	   ever since for newer protocols that want to keep the connection open.  
	   Others still send their alert and then immediately close the 
	   connection.  Because of this haphazard approach to closing 
	   connections, many implementations allow a session to be resumed even 
	   if no close alert is sent.  In order to be compatible with this 
	   behaviour, we do the same (thus perpetuating the problem).  If 
	   necessary this can be fixed by calling deleteSessionCacheEntry() if 
	   the connection is closed without a close alert being sent */
	if( buffer[ 0 ] != SSL_ALERTLEVEL_WARNING && \
		buffer[ 0 ] != SSL_ALERTLEVEL_FATAL )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid SSL alert level 0x%02X", buffer[ 0 ] );
	sessionInfoPtr->errorCode = type = buffer[ 1 ];
	for( i = 0; alertInfo[ i ].type != CRYPT_ERROR && \
				alertInfo[ i ].type != type; i++ );
	if( alertInfo[ i ].type == CRYPT_ERROR )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Unknown alert message type %d", type );
	strcpy( sessionInfoPtr->errorMessage,
			( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
				"Received SSL alert message: " : \
				"Received TLS alert message: " );
	strcat( sessionInfoPtr->errorMessage, alertInfo[ i ].message );
	return( alertInfo[ i ].cryptlibError );
	}

/* Read an SSL packet.  The readPacketSSL() portion is only used during the 
   handshake phase (the data transfer phase has its own read/write code) so 
   we can perform some special-case handling based on this */

static int readPacketHeader( SESSION_INFO *sessionInfoPtr, BOOLEAN *isFatal )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufEnd;
	int status;

	/* Read the SSL packet header data */
	status = readFixedHeader( sessionInfoPtr, 
							  sessionInfoPtr->receiveBufStartOfs );
	if( status <= 0 )
		return( status );
	assert( status == sessionInfoPtr->receiveBufStartOfs );

	/* Check for an SSL alert message */
	if( bufPtr[ 0 ] == SSL_MSG_ALERT )
		{
		int length, ch;

		if( isFatal != NULL )
			*isFatal = TRUE;
		bufPtr += ID_SIZE;
		if( *bufPtr++ != SSL_MAJOR_VERSION )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid SSL major version number 0x%02X in alert "
					"message", bufPtr[ -1 ] );
		ch = *bufPtr++;
		if( ch < SSL_MINOR_VERSION_SSL || ch > SSL_MINOR_VERSION_TLS11 )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid SSL minor version number 0x%02X in alert "
					"message", ch );
		length = mgetWord( bufPtr );
		if( sessionInfoPtr->flags & SESSION_ISSECURE )
			{
			if( length < ALERTINFO_SIZE || length > 128 )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid encrypted alert info size %d", length );

			/* If we're using explicit IVs, the first block constitutes the 
			   IV.  Load it into the context */
			if( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV )
				{
				RESOURCE_DATA msgData;

				setMessageData( &msgData, bufPtr, 
								sessionInfoPtr->cryptBlocksize );
				krnlSendMessage( sessionInfoPtr->iCryptInContext,
								 IMESSAGE_SETATTRIBUTE_S, &msgData, 
								 CRYPT_CTXINFO_IV );
				length -= sessionInfoPtr->cryptBlocksize;
				}
			}
		else
			if( length != ALERTINFO_SIZE )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid alert info size %d, should be %d", 
						length, ALERTINFO_SIZE );
		return( processAlert( sessionInfoPtr, length ) );
		}

	return( status );
	}

int readPacketSSL( SESSION_INFO *sessionInfoPtr,
				   SSL_HANDSHAKE_INFO *handshakeInfo, const int packetType )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufEnd;
	BOOLEAN isV2handshake = FALSE;
	int totalLength, effectiveTotalLength, type, version, status;

	/* Read and process the header.  We don't have to check for status == 0
	   (meaning no data was read) at this point since all reads during the
	   handshake phase are blocking reads */
	status = readPacketHeader( sessionInfoPtr, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Decode the SSL packet header:

			SSLv3/TLS						SSLv2
		byte	type					uint16	length code = { 0x80, len }
		byte[2]	vers = { 0x03, 0x0n }	byte	type = 1
		uint16	length					byte[2]	vers = { 0x03, 0x0n }
	  [ byte[]	iv	- TLS 1.1 ]

	   If the expected packet type is SSL_MSG_SPECIAL_HANDSHAKE the actual
	   type can be either an SSLv2 or SSLv3/TLS handshake, so we have to
	   check for either type being present */
	type = *bufPtr++;
	if( packetType == SSL_MSG_SPECIAL_HANDSHAKE )
		{
		if( type == SSL_MSG_V2HANDSHAKE )
			{
			/* It's an SSLv2 handshake from Netscape, handle it specially */
			isV2handshake = TRUE;
			totalLength = *bufPtr++;
			if( handshakeInfo != NULL )
				/* Due to the different ordering of header fields in SSLv2,
				   the type and version is regarded as part of the payload
				   that needs to be hashed, rather than the header as for
				   SSLv3 */
				dualMacData( handshakeInfo, bufPtr, 3 );
			if( *bufPtr++ != SSL_HAND_CLIENT_HELLO )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Unknown SSLv2 hello message type %d, should be %d", 
						bufPtr[ -1 ], SSL_HAND_CLIENT_HELLO );
			totalLength -= ID_SIZE + VERSIONINFO_SIZE;
			}
		else
			/* If it's not an SSLv2 handshake it has to be an SSLv3/TLS
			   handshake */
			if( type != SSL_MSG_HANDSHAKE )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Unknown SSL/TLS hello message type %d, should be %d", 
						type, SSL_MSG_HANDSHAKE );
		}
	else
		if( type != packetType )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Unknown SSL/TLS message type %d, should be %d", 
					type, packetType );
	if( *bufPtr++ != SSL_MAJOR_VERSION )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid SSL major version number %d", bufPtr[ -1 ] );
	version = *bufPtr++;
	if( version < SSL_MINOR_VERSION_SSL || \
		version > ( ( ( packetType == SSL_MSG_SPECIAL_HANDSHAKE ) ? \
					5 : SSL_MINOR_VERSION_TLS11 ) ) )
		/* If it's the first handshake packet we allow versions up to a 
		   hypothetical SSLv3.5 (which would be TLS 1.4), after that we 
		   should have fallen back to a version that we understand */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid SSL minor version number %d", version );
	if( !isV2handshake )
		{ totalLength = mgetWord( bufPtr ); }
	if( totalLength < 1 || totalLength > sessionInfoPtr->receiveBufSize || \
		( packetType != SSL_MSG_CHANGE_CIPHER_SPEC && \
		  totalLength < MIN_PACKET_SIZE ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet length %d", totalLength );
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE ) && \
		( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV ) )
		{
		/* If we're using an explicit IV, the IV data is counted as part of 
		   the header so we have to adjust the payload read for the data that 
		   we've already read */
		memmove( sessionInfoPtr->receiveBuffer, bufPtr, 
				 sessionInfoPtr->cryptBlocksize );
		bufPtr = sessionInfoPtr->receiveBuffer + \
				 sessionInfoPtr->cryptBlocksize;
		effectiveTotalLength = totalLength - sessionInfoPtr->cryptBlocksize;
		assert( effectiveTotalLength > 0 );
		}
	else
		{
		bufPtr = sessionInfoPtr->receiveBuffer;
		effectiveTotalLength = totalLength;
		}

	/* Read the payload packet(s) */
	status = sread( &sessionInfoPtr->stream, bufPtr, effectiveTotalLength );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( status < effectiveTotalLength )
		/* If we timed out during the handshake phase, treat it as a hard 
		   timeout error */
		retExt( sessionInfoPtr, CRYPT_ERROR_TIMEOUT,
				"Timeout during packet data read, only got %d of %d bytes", 
				status, totalLength );
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = totalLength;
	if( handshakeInfo != NULL )
		dualMacData( handshakeInfo, sessionInfoPtr->receiveBuffer,
					 totalLength );
	if( isV2handshake )
		{
		/* SSLv2 puts the version info in the header, so we have to move the
		   data up in the buffer and drop in the minor version to return it
		   to the caller, with the high bit set to ensure that it doesn't 
		   get confused with a normal SSL packet type */
		memmove( sessionInfoPtr->receiveBuffer + 1, 
				 sessionInfoPtr->receiveBuffer, totalLength );
		sessionInfoPtr->receiveBuffer[ 0 ] = version | 0x80;
		}
	return( CRYPT_OK );
	}

/* Check that the header of an SSL packet is in order:

	byte		ID = <type>
	uint24		len
	[ byte		opaque = <nextByte>] */

int checkPacketHeader( SESSION_INFO *sessionInfoPtr, BYTE **bufPtrPtr,
					   const int type, const int minSize, const int nextByte )
	{
	BYTE *bufPtr = *bufPtrPtr;
	int length;

	if( *bufPtr++ != type || *bufPtr++ != 0 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet header 0x%02X 0x%02X", *bufPtrPtr[ 0 ], 
				*bufPtrPtr[ 1 ] );
	length = mgetWord( bufPtr );
	if( length < minSize || length > MAX_PACKET_SIZE || \
		sessionInfoPtr->receiveBufPos + ID_SIZE + LENGTH_SIZE + length > \
			sessionInfoPtr->receiveBufEnd )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet length", length ); 
	if( nextByte != CRYPT_UNUSED && *bufPtr++ != nextByte )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet header data byte 0x%02X, expected 0x%02X", 
				bufPtr[ -1 ], nextByte ); 
	*bufPtrPtr = bufPtr;
	sessionInfoPtr->receiveBufPos = ID_SIZE + LENGTH_SIZE + length;
	return( length );
	}

/****************************************************************************
*																			*
*								Shared Connect Functions					*
*																			*
****************************************************************************/

/* Complete the dual MD5/SHA1 hash/MAC used in the finished message */

static int completeSSLDualMAC( const CRYPT_CONTEXT md5context,
							   const CRYPT_CONTEXT sha1context,
							   BYTE *hashValues, const char *label,
							   const BYTE *masterSecret )
	{
	RESOURCE_DATA msgData;
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

static int completeTLSHashedMAC( const CRYPT_CONTEXT md5context,
								 const CRYPT_CONTEXT sha1context,
								 BYTE *hashValues, const char *label,
								 const BYTE *masterSecret )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	BYTE hashBuffer[ 64 + CRYPT_MAX_HASHSIZE * 2 ];
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
	   the result to 12 bytes for no adequately explored reason, most 
	   probably it's IPsec cargo cult protocol design:

		TLS_PRF( label || MD5_hash || SHA1_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, TLS_HASHEDMAC_SIZE,
							( void * ) masterSecret, 48, CRYPT_USE_DEFAULT,
							hashBuffer, labelLength + MD5MAC_SIZE + SHA1MAC_SIZE, 1 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_TLS ) );
	}

/* Complete the handshake with the client or server.  The logic gets a bit
   complex here because the roles of the client and server are reversed if
   we're resuming a session:

		Normal					Resumed
	Client		Server		Client		Server
	------		------		------		------
	KeyEx  --->					   <---	Hello
	CCS	   --->					   <--- CCS
	Fin	   --->					   <--- Fin
		   <---	CCS			CCS	   --->
		   <---	Fin			Fin	   --->

   Because of this the handshake-completion step treats the two sides as
   initiator and responder rather than client and server.  The overall flow
   is then:

	dualMAC( initiator );
	if( !initiator )
		read initiator CCS;
	dualMAC( responder );
	send initiator/responder CCS;
	if( initiator )
		read responder CCS; */

static int readHandshakeCompletionData( SESSION_INFO *sessionInfoPtr,
										SSL_HANDSHAKE_INFO *handshakeInfo,
										const BYTE *hashValues )
	{
	BYTE *bufPtr;
	const int macValueLength = \
					( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					MD5MAC_SIZE + SHA1MAC_SIZE : TLS_HASHEDMAC_SIZE;
	int status, length;

	/* Process the other side's change cipher spec (we could do this more
	   simply via an sread() and memcmp() against a template but that
	   doesn't process alerts properly).  Since change cipherspec is its
	   own protocol, the packet data consists of only a '1' byte:

		byte		1
	
	   At this point we've sent our change cipher spec (so the send channel
	   is in the secure state) but haven't received the other side's one yet
	   so the receive channel isn't.  To handle this we need to temporarily 
	   turn off the secure-session flag to ensure that there's no security 
	   processing applied to the received message */
	sessionInfoPtr->flags &= ~SESSION_ISSECURE;
	status = readPacketSSL( sessionInfoPtr, NULL, 
							SSL_MSG_CHANGE_CIPHER_SPEC );
	sessionInfoPtr->flags |= SESSION_ISSECURE;
	if( cryptStatusError( status ) )
		return( status );
	bufPtr = sessionInfoPtr->receiveBuffer;
	if( *bufPtr++ != 1 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid change cipher spec payload, expected 0x01, got "
				"0x%02X", bufPtr[ -1 ] );

	/* Change cipher spec was the last message not subject to security 
	   encapsulation, if we're using explicit IVs the effective header size 
	   changes at this point because of the extra IV data so we update the 
	   receive buffer start offset to accomodate this */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV )
		sessionInfoPtr->receiveBufStartOfs += sessionInfoPtr->cryptBlocksize;

	/* Process the other side's finished.  Since this is the first chance that 
	   we have to test whether our crypto keys are set up correctly, we 
	   report problems with decryption or MAC'ing or a failure to find any 
	   recognisable header as a wrong key rather than bad data error:

			SSLv3						TLS
		byte		ID = 0x14		byte		ID = 0x14
		uint24		len				uint24		len
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	status = readPacketSSL( sessionInfoPtr, NULL, SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr = sessionInfoPtr->receiveBuffer;
	length = sessionInfoPtr->receiveBufEnd;
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV )
		{
#if 0
		/* If we're using explicit IVs, the first block constitutes the IV.
		   Decrypt it and discard it (alternate code used when we can't 
		   reload an IV during decryption) */
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_CTX_DECRYPT, bufPtr, 
								  sessionInfoPtr->cryptBlocksize );
#else
		RESOURCE_DATA msgData;

		/* If we're using explicit IVs, the first block constitutes the IV,
		   load it into the context.  We have to do this outside wrapData()
		   because the packet header and IV are usually read separately from
		   the packet payload and therefore aren't available to wrapData() */
		setMessageData( &msgData, bufPtr, sessionInfoPtr->cryptBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_IV );
#endif /* 0 */
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status, 
					"Decryption of SSL packet failed" );
		bufPtr += sessionInfoPtr->cryptBlocksize;
		length -= sessionInfoPtr->cryptBlocksize;
		}
	status = unwrapData( sessionInfoPtr, bufPtr, length, SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA || \
			status == CRYPT_ERROR_SIGNATURE )
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"Decrypted data was corrupt, probably due to incorrect "
					"encryption keys being negotiated during the handshake" );
		return( status );
		}
	length = checkPacketHeader( sessionInfoPtr, &bufPtr, 
								SSL_HAND_FINISHED, 
								min( MD5MAC_SIZE + SHA1MAC_SIZE, \
									 TLS_HASHEDMAC_SIZE ), 
								CRYPT_UNUSED );
	if( cryptStatusError( length ) )
		{
		if( length == CRYPT_ERROR_BADDATA )
			retExt( sessionInfoPtr, CRYPT_ERROR_WRONGKEY,
					"Bad message header, probably due to incorrect "
					"encryption keys being negotiated during the "
					"handshake" );
		return( length );
		}

	/* Make sure that the dual MAC/hashed MAC of all preceding messages is 
	   valid */
	if( length != macValueLength || \
		memcmp( bufPtr, hashValues, macValueLength ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE,
				"Bad handshake messages MAC, handshake messages were "
				"corrupted/modified" );

	return( CRYPT_OK );
	}

static int completeHandshake( SESSION_INFO *sessionInfoPtr,
							  SSL_HANDSHAKE_INFO *handshakeInfo,
							  const BOOLEAN isClient,
							  const BOOLEAN isResumedSession )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE ];
	BYTE masterSecret[ SSL_SECRET_SIZE ], keyBlock[ MAX_KEYBLOCK_SIZE ];
	BYTE initiatorHashes[ CRYPT_MAX_HASHSIZE * 2 ];
	BYTE responderHashes[ CRYPT_MAX_HASHSIZE * 2 ];
	BYTE *bufPtr, *keyBlockPtr;
	const BOOLEAN isInitiator = isResumedSession ? !isClient : isClient;
	int length, status;

	/* Create the security contexts required for the session */
	status = initSecurityContexts( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Convert the premaster secret into the master secret */
	if( !isResumedSession )
		{
		if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
			{
			memcpy( nonceBuffer, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
			memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
					SSL_NONCE_SIZE );
			setMechanismDeriveInfo( &mechanismInfo,
									masterSecret, SSL_SECRET_SIZE,
									handshakeInfo->premasterSecret, SSL_SECRET_SIZE,
									CRYPT_USE_DEFAULT, nonceBuffer,
									SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_DERIVE, &mechanismInfo, 
									  MECHANISM_SSL );
			}
		else
			{
			memcpy( nonceBuffer, "master secret", 13 );
			memcpy( nonceBuffer + 13, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
			memcpy( nonceBuffer + 13 + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
					SSL_NONCE_SIZE );
			setMechanismDeriveInfo( &mechanismInfo,
									masterSecret, SSL_SECRET_SIZE,
									handshakeInfo->premasterSecret, SSL_SECRET_SIZE,
									CRYPT_USE_DEFAULT, nonceBuffer,
									13 + SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_DERIVE, &mechanismInfo, 
									  MECHANISM_TLS );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Everything is OK so far, add the master secret to the session
		   cache */
		sessionInfoPtr->sslSessionCacheID = \
					addSessionCacheEntry( handshakeInfo->sessionID, 
										  handshakeInfo->sessionIDlength, 
										  masterSecret, FALSE );
		}
	else
		/* We've already got the master secret present from the session we're
		   resuming from, reuse that */
		memcpy( masterSecret, handshakeInfo->premasterSecret,
				SSL_SECRET_SIZE );

	/* Convert the master secret into keying material.  Unfortunately we
	   can't delete it yet because it's required to calculate the MAC for
	   the handshake messages */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( nonceBuffer, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
		memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->clientNonce,
				SSL_NONCE_SIZE );
		setMechanismDeriveInfo( &mechanismInfo, keyBlock, MAX_KEYBLOCK_SIZE,
								masterSecret, SSL_SECRET_SIZE, CRYPT_USE_DEFAULT,
								nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
								  &mechanismInfo, MECHANISM_SSL );
		}
	else
		{
		memcpy( nonceBuffer, "key expansion", 13 );
		memcpy( nonceBuffer + 13, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
		memcpy( nonceBuffer + 13 + SSL_NONCE_SIZE, handshakeInfo->clientNonce,
				SSL_NONCE_SIZE );
		setMechanismDeriveInfo( &mechanismInfo, keyBlock, MAX_KEYBLOCK_SIZE,
								masterSecret, SSL_SECRET_SIZE, CRYPT_USE_DEFAULT,
								nonceBuffer, 13 + SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
								  &mechanismInfo, MECHANISM_TLS );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Load the keys and secrets:

		( client_write_mac || server_write_mac || \
		  client_write_key || server_write_key || \
		  client_write_iv  || server_write_iv ) */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( isClient ? sessionInfoPtr->sslMacWriteSecret : \
						   sessionInfoPtr->sslMacReadSecret,
				keyBlock, sessionInfoPtr->authBlocksize );
		memcpy( isClient ? sessionInfoPtr->sslMacReadSecret : \
						   sessionInfoPtr->sslMacWriteSecret,
				keyBlock + sessionInfoPtr->authBlocksize,
				sessionInfoPtr->authBlocksize );
		keyBlockPtr = keyBlock + sessionInfoPtr->authBlocksize * 2;
		}
	else
		{
		setMessageData( &msgData, keyBlock, sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthOutContext : \
										sessionInfoPtr->iAuthInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, keyBlock + sessionInfoPtr->authBlocksize,
							sessionInfoPtr->authBlocksize );
			status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthInContext: \
										sessionInfoPtr->iAuthOutContext,
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_KEY );
			}
		keyBlockPtr = keyBlock + sessionInfoPtr->authBlocksize * 2;
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iCryptOutContext : \
										sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_KEY );
		keyBlockPtr += handshakeInfo->cryptKeysize;
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iCryptInContext : \
										sessionInfoPtr->iCryptOutContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_KEY );
		keyBlockPtr += handshakeInfo->cryptKeysize;
		}
	if( cryptStatusOK( status ) && \
		!isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		{
		setMessageData( &msgData, keyBlockPtr,
						sessionInfoPtr->cryptBlocksize );
		krnlSendMessage( isClient ? sessionInfoPtr->iCryptOutContext : \
									sessionInfoPtr->iCryptInContext,
						 IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_IV );
		keyBlockPtr += sessionInfoPtr->cryptBlocksize;
		setMessageData( &msgData, keyBlockPtr,
						sessionInfoPtr->cryptBlocksize );
		krnlSendMessage( isClient ? sessionInfoPtr->iCryptInContext : \
									sessionInfoPtr->iCryptOutContext,
						 IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_IV );
		}
	zeroise( keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		sessionInfoPtr->protocolFlags |= SSL_PFLAG_EXPLICITIV;

	/* Complete the dual-MAC hashing of the initiator-side messages and, if
	   we're the responder, check that the MACs match the ones supplied by
	   the initiator */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		status = completeSSLDualMAC( handshakeInfo->clientMD5context,
									 handshakeInfo->clientSHA1context,
									 initiatorHashes, SSL_SENDER_CLIENTLABEL,
									 masterSecret );
	else
		status = completeTLSHashedMAC( handshakeInfo->clientMD5context,
									   handshakeInfo->clientSHA1context,
									   initiatorHashes, "client finished",
									   masterSecret );
	if( cryptStatusOK( status ) && !isInitiator )
		status = readHandshakeCompletionData( sessionInfoPtr, handshakeInfo,
											  initiatorHashes );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Now that we have the initiator MACs, complete the dual-MAC hashing of
	   the responder-side messages and destroy the master secret.  We haven't
	   created the full message yet at this point so we manually hash the
	   individual pieces so that we can get rid of the master secret */
	krnlSendMessage( handshakeInfo->serverMD5context, IMESSAGE_CTX_HASH,
					 ( void * ) finishedTemplate[ sessionInfoPtr->version ],
					 FINISHED_TEMPLATE_SIZE );
	krnlSendMessage( handshakeInfo->serverSHA1context, IMESSAGE_CTX_HASH,
					 ( void * ) finishedTemplate[ sessionInfoPtr->version ],
					 FINISHED_TEMPLATE_SIZE );
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		krnlSendMessage( handshakeInfo->serverMD5context, IMESSAGE_CTX_HASH,
						 initiatorHashes, MD5MAC_SIZE + SHA1MAC_SIZE );
		krnlSendMessage( handshakeInfo->serverSHA1context, IMESSAGE_CTX_HASH,
						 initiatorHashes, MD5MAC_SIZE + SHA1MAC_SIZE );
		status = completeSSLDualMAC( handshakeInfo->serverMD5context,
									 handshakeInfo->serverSHA1context,
									 responderHashes, SSL_SENDER_SERVERLABEL,
									 masterSecret );
		}
	else
		{
		krnlSendMessage( handshakeInfo->serverMD5context, IMESSAGE_CTX_HASH,
						 initiatorHashes, TLS_HASHEDMAC_SIZE );
		krnlSendMessage( handshakeInfo->serverSHA1context, IMESSAGE_CTX_HASH,
						 initiatorHashes, TLS_HASHEDMAC_SIZE );
		status = completeTLSHashedMAC( handshakeInfo->serverMD5context,
									   handshakeInfo->serverSHA1context,
									   responderHashes, "server finished",
									   masterSecret );
		}
	zeroise( masterSecret, SSL_SECRET_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the change cipher spec packet:

		byte		type = 20 (change cipherspec)
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1

	   Note that change cipher spec is its own protocol, of which the '1' 
	   byte is the payload, so we're using SSL-level packet encoding rather 
	   than handshake protocol-level encoding */
	bufPtr = sessionInfoPtr->sendBuffer;
	memcpy( bufPtr,
			changeCipherSpecTemplate[ sessionInfoPtr->version ],
			CHANGECIPHERSPEC_TEMPLATE_SIZE );
	bufPtr += CHANGECIPHERSPEC_TEMPLATE_SIZE;
	sessionInfoPtr->flags |= SESSION_ISSECURE;

	/* Change cipher spec was the last message not subject to security 
	   encapsulation, if we're using TLS 1.1 with explicit IVs the effective
	   header size changes at this point because of the extra IV data so we 
	   update the receive buffer start offset to accomodate this */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV )
		sessionInfoPtr->sendBufStartOfs += sessionInfoPtr->cryptBlocksize;

	/* Build the finished packet.  The initiator sends the MAC of the
	   contents of every handshake packet before the finished packet, the
	   responder sends the MAC of the contents of every packet before its own
	   finished packet but including the MAC of the initiator's packet
	   contents:

			SSLv3						TLS
		byte		ID = 0x14		byte		ID = 0x14
		uint24		len				uint24		len
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	bufPtr += sessionInfoPtr->sendBufStartOfs;
	memcpy( bufPtr, finishedTemplate[ sessionInfoPtr->version ],
			FINISHED_TEMPLATE_SIZE );
	memcpy( bufPtr + FINISHED_TEMPLATE_SIZE,
			isInitiator ? initiatorHashes : responderHashes,
			( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
				MD5MAC_SIZE + SHA1MAC_SIZE : TLS_HASHEDMAC_SIZE );

	/* MAC, pad, and encrypt the payload */
#if 0
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		length = macDataSSL( sessionInfoPtr, bufPtr,
							 FINISHED_TEMPLATE_SIZE + MD5MAC_SIZE + SHA1MAC_SIZE,
							 SSL_MSG_HANDSHAKE, FALSE );
	else
		length = macDataTLS( sessionInfoPtr, bufPtr,
							 FINISHED_TEMPLATE_SIZE + TLS_HASHEDMAC_SIZE,
							 SSL_MSG_HANDSHAKE, FALSE );
	if( !cryptStatusError( length ) )
		length = encryptData( sessionInfoPtr, bufPtr, length );
	if( cryptStatusError( length ) )
		return( length );
	wrapHandshakePacket( sessionInfoPtr->sendBuffer + \
							CHANGECIPHERSPEC_TEMPLATE_SIZE,
						 length, sessionInfoPtr->version );
	length += sessionInfoPtr->sendBufStartOfs;
#else
	length = wrapData( sessionInfoPtr, 
				sessionInfoPtr->sendBuffer + CHANGECIPHERSPEC_TEMPLATE_SIZE, 
				( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					FINISHED_TEMPLATE_SIZE + MD5MAC_SIZE + SHA1MAC_SIZE : \
					FINISHED_TEMPLATE_SIZE + TLS_HASHEDMAC_SIZE, 
				SSL_MSG_HANDSHAKE );
	if( cryptStatusError( length ) )
		return( length );
#endif

	/* Send our change cipher spec and finished and, if we're the initator,
	   check that the MACs match the ones supplied by the responder */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer,
					 CHANGECIPHERSPEC_TEMPLATE_SIZE + length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  sessionInfoPtr->errorMessage,
						  &sessionInfoPtr->errorCode );
		return( status );
		}
	if( isInitiator )
		{
		status = readHandshakeCompletionData( sessionInfoPtr, handshakeInfo,
											  responderHashes );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Make sure that the server URL matches the value in the returned 
   certificate.  This code isn't currently called because it's not certain 
   what the best way is to report this to the user and more importantly 
   because there are quite a few servers out there where the server name 
   doesn't match what's in the cert but for which the user will just click 
   "OK" anyway even if we can tunnel a warning indication back to them, so
   we leave it to the caller to perform whatever checking and take whatever
   action they consider necessary */

#if 0

static int checkURL( SESSION_INFO *sessionInfoPtr )
	{
	RESOURCE_DATA msgData;
	char hostNameSpec[ MAX_URL_SIZE ];
	const int serverNameLength = strlen( sessionInfoPtr->serverName );
	int hostNameSpecLength, splatPos = CRYPT_ERROR, postSplatLen, i, status;

	/* Read the server name specification from the server's cert */
	setMessageData( &msgData, hostNameSpec, MAX_URL_SIZE );
	status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_DNSNAME );
	if( cryptStatusError( status ) )
		status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusError( status ) )
		return( status );
	hostNameSpecLength = msgData.length;

	/* Find the splat in the host name spec */
	for( i = 0; i < hostNameSpecLength; i++ )
		if( hostNameSpec[ i ] == '*' )
			{
			if( splatPos != CRYPT_ERROR )
				/* Can't have more than one splat in a host name */
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Certificate server name contains more than one "
						"wildcard" );
			splatPos = i;
			}

	/* If there's no wildcarding, perform a direct match */
	if( splatPos == CRYPT_ERROR )
		{
		if( hostNameSpecLength != serverNameLength || \
			strCompare( hostNameSpec, sessionInfoPtr->serverName,
						serverNameLength ) )
			/* Host doesn't match the name in the cert */
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Certificate server name doesn't match server name" );

		return( CRYPT_OK );
		}

	/* Determine how much to match before and after the splat */
	postSplatLen = hostNameSpecLength - splatPos - 1;
	if( postSplatLen + splatPos > serverNameLength )
		/* The fixed name spec text is longer than the server name, a match
		   can't be possible */
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Certificate name length exceeds server name length" );

	/* Check that the pre- and post-splat URL components match */
	if( splatPos > 0 && \
		strCompare( hostNameSpec, sessionInfoPtr->serverName, splatPos ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Certificate server name doesn't match server name" );
	if( strCompare( hostNameSpec + splatPos + 1,
					sessionInfoPtr->serverName + serverNameLength - postSplatLen,
					postSplatLen ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Certificate server name doesn't match server name" );

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Close a previously-opened SSL session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	sendCloseAlert( sessionInfoPtr, FALSE );

	sNetDisconnect( &sessionInfoPtr->stream );
	}

/* Connect to an SSL server/client */

static int abortStartup( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN cleanupSecContexts,
						 const int status )
	{
	sendHandshakeFailAlert( sessionInfoPtr );
	if( cleanupSecContexts )
		destroySecurityContexts( sessionInfoPtr );
	if( handshakeInfo != NULL )
		destroyHandshakeInfo( handshakeInfo );
	sNetDisconnect( &sessionInfoPtr->stream );
	return( status );
	}

static int commonStartup( SESSION_INFO *sessionInfoPtr,
						  const BOOLEAN isServer )
	{
	SSL_HANDSHAKE_INFO handshakeInfo;
	BOOLEAN resumedSession = FALSE;
	int status;

	/* Initialise the handshake info and begin the handshake */
	status = initHandshakeInfo( &handshakeInfo, isServer );
	if( cryptStatusOK( status ) )
		status = handshakeInfo.beginHandshake( sessionInfoPtr, 
											   &handshakeInfo );
	if( status == OK_SPECIAL )
		resumedSession = TRUE;
	else
		if( cryptStatusError( status ) )
			return( abortStartup( sessionInfoPtr, &handshakeInfo, FALSE, 
								  status ) );

	/* Exchange a key with the server */
	if( !resumedSession )
		{
		status = handshakeInfo.exchangeKeys( sessionInfoPtr, 
											 &handshakeInfo );
		if( cryptStatusError( status ) )
			return( abortStartup( sessionInfoPtr, &handshakeInfo, TRUE, 
								  status ) );
		}

	/* Complete the handshake */
	status = completeHandshake( sessionInfoPtr, &handshakeInfo, !isServer, 
								resumedSession );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		return( abortStartup( sessionInfoPtr, NULL, TRUE, status ) );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HANDSHAKETIMEOUT, NULL, 0 );

	return( CRYPT_OK );
	}

static int clientStartup( SESSION_INFO *sessionInfoPtr )
	{
	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, FALSE ) );
	}

static int serverStartup( SESSION_INFO *sessionInfoPtr )
	{
	/* Clear any user name/password information that may be present from
	   a previous session or from the manual addition of keys to the session
	   cache */
	zeroise( sessionInfoPtr->userName, CRYPT_MAX_TEXTSIZE );
	zeroise( sessionInfoPtr->password, CRYPT_MAX_TEXTSIZE );
	sessionInfoPtr->userNameLength = 0;
	sessionInfoPtr->passwordLength = 0;

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, TRUE ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

static int getAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 void *data, const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *certPtr = ( CRYPT_CERTIFICATE * ) data;
	CRYPT_CERTIFICATE iCryptCert = \
		( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
		sessionInfoPtr->iKeyexAuthContext : sessionInfoPtr->iKeyexCryptContext;

	assert( type == CRYPT_SESSINFO_RESPONSE );

	/* If we didn't get a client/server cert there's nothing to return */
	if( iCryptCert == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( iCryptCert, IMESSAGE_INCREFCOUNT );
	*certPtr = iCryptCert;
	return( CRYPT_OK );
	}

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	BYTE masterSecret[ SSL_SECRET_SIZE ], sessionID[ SESSIONID_SIZE ];
	int uniqueID, status;

	assert( type == CRYPT_SESSINFO_USERNAME || \
			type == CRYPT_SESSINFO_PASSWORD );

	/* At the moment only the server maintains a true session cache, so if 
	   it's a client session we return without any further checking, there
	   can never be a duplicate entry in this case */
	if( !( sessionInfoPtr->flags & SESSION_ISSERVER ) )
		return( CRYPT_OK );

	/* If we're setting the password, we have to have a session ID present to
	   set it for */
	if( type == CRYPT_SESSINFO_PASSWORD && \
		sessionInfoPtr->userNameLength <= 0 )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Wait for any async network driver binding to complete.  This is 
	   required because the session cache is initialised as part of the 
	   asynchronous startup (since it's tied to the session object class
	   rather than a particular session object), so we have to wait until 
	   this has completed before we can access it */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Format the session ID in the appropriate manner and check whether it's
	   present in the cache */
	memset( sessionID, 0, SESSIONID_SIZE );
	memcpy( sessionID, sessionInfoPtr->userName, 
			min( sessionInfoPtr->userNameLength, SESSIONID_SIZE ) );
	uniqueID = findSessionCacheEntryID( sessionID, SESSIONID_SIZE );

	/* If we're adding or deleting a user name, check whether something
	   identified by the name is present in the cache */
	if( type == CRYPT_SESSINFO_USERNAME )
		{
		if( data != NULL )
			{
			/* User name add, presence is an error */
			if( uniqueID )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			}
		else
			{
			/* User name delete, absence is an error */
			if( !uniqueID )
				{
				setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			deleteSessionCacheEntry( uniqueID );
			if( sessionInfoPtr->requiredPasswordStatus > 0 )
				sessionInfoPtr->requiredPasswordStatus--;
			}
		return( CRYPT_OK );
		}

	/* Create the master secret from the user-supplied password */
	status = createSharedMasterSecret( masterSecret, sessionInfoPtr );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Couldn't create SSL master secret from shared "
				"secret/password value" );

	/* Add the entry to the session cache and record the fact that we've got 
	   another shared key present */
	addSessionCacheEntry( sessionID, SESSIONID_SIZE, masterSecret, TRUE );
	zeroise( masterSecret, SSL_SECRET_SIZE );
	sessionInfoPtr->requiredPasswordStatus++;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read/write data over the SSL link */

static int readHeaderFunction( SESSION_INFO *sessionInfoPtr, 
							   READSTATE_INFO *readInfo )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufEnd;
	BOOLEAN isFatal = FALSE;
	int length, status;

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Try and read the header data from the remote system */
	status = readPacketHeader( sessionInfoPtr, &isFatal );
	if( status <= 0 )
		{
		if( isFatal )
			*readInfo = READINFO_FATAL;
		return( status );
		}

	/* Process the header data.  Since data errors are always fatal, we make
	   all errors fatal until we've finished handling the header */
	*readInfo = READINFO_FATAL;
	if( *bufPtr++ != SSL_MSG_APPLICATION_DATA )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet type 0x%02X, expected 0x%02X", 
				bufPtr[ -1 ], SSL_MSG_APPLICATION_DATA );
	if( *bufPtr++ != SSL_MAJOR_VERSION )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid SSL major version number %d", bufPtr[ -1 ] );
	if( *bufPtr++ != sessionInfoPtr->version )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid SSL minor version number %d, expected %d", 
				bufPtr[ -1 ], sessionInfoPtr->version );
	length = mgetWord( bufPtr );
	if( length < ( MIN_SECURED_PACKET_SIZE + \
				   ( ( sessionInfoPtr->protocolFlags & \
					   SSL_PFLAG_EXPLICITIV ) ? \
					 sessionInfoPtr->cryptBlocksize : 0 ) ) || \
		length > sessionInfoPtr->receiveBufSize )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid packet length %d", length );

	/* Determine how much data we'll be expecting */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_EXPLICITIV )
		{
#if 0
		/* If we're using explicit IVs, the first block constitutes the IV.
		   Decrypt it and discard it (alternate code used when we can't 
		   reload an IV during decryption) */
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_CTX_DECRYPT, bufPtr, 
								  sessionInfoPtr->cryptBlocksize );
#else
		RESOURCE_DATA msgData;

		/* If we're using explicit IVs, the first block constitutes the IV.
		   Load it into the context */
		setMessageData( &msgData, bufPtr, sessionInfoPtr->cryptBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_IV );
#endif /* 0 */
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status, "Data packet IV load failed" );
		length -= sessionInfoPtr->cryptBlocksize;
		assert( length >= 0 );
		}
	sessionInfoPtr->pendingPacketLength = \
		sessionInfoPtr->pendingPacketRemaining = length;

	/* Indicate that we got the header */
	*readInfo = READINFO_NOOP;
	return( OK_SPECIAL );
	}

static int processBodyFunction( SESSION_INFO *sessionInfoPtr,
								READSTATE_INFO *readInfo )
	{
	BOOLEAN badDecrypt = FALSE;
	int length;

	assert( sessionInfoPtr->pendingPacketLength > 0 );
	assert( sessionInfoPtr->receiveBufPos + \
				sessionInfoPtr->pendingPacketLength <= \
			sessionInfoPtr->receiveBufEnd );
	assert( sessionInfoPtr->receiveBufEnd <= sessionInfoPtr->receiveBufSize );

	/* All errors processing the payload are fatal */
	*readInfo = READINFO_FATAL;

	/* Unwrap the payload */
	length = unwrapData( sessionInfoPtr, 
						 sessionInfoPtr->receiveBuffer + \
							sessionInfoPtr->receiveBufPos, 
						 sessionInfoPtr->pendingPacketLength, 
						 SSL_MSG_APPLICATION_DATA );
	if( cryptStatusError( length ) )
		return( length );

	/* Adjust the data size indicators to account for the stripped padding
	   and MAC info */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos + length;
	sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd;
	sessionInfoPtr->pendingPacketLength = 0;
	assert( sessionInfoPtr->receiveBufEnd <= sessionInfoPtr->receiveBufSize );

	/* If we only got a partial packet, let the caller know that they should 
	   try again */
	if( length < 1 )
		{
		*readInfo = READINFO_PARTIAL;
		return( OK_SPECIAL );
		}
	*readInfo = READINFO_NONE;
	return( length );
	}

static int writeDataFunction( SESSION_INFO *sessionInfoPtr )
	{
	BYTE *bufPtr = sessionInfoPtr->sendBuffer;
	const int dataLength = sessionInfoPtr->sendBufPos - \
						   sessionInfoPtr->sendBufStartOfs;
	int length;

	assert( dataLength > 0 && dataLength <= MAX_PACKET_SIZE );
	assert( !( sessionInfoPtr->flags & SESSION_SENDCLOSED ) );
	assert( !( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT ) );

	/* Wrap up the payload and send it */
	length = wrapData( sessionInfoPtr, sessionInfoPtr->sendBuffer, dataLength,
					   SSL_MSG_APPLICATION_DATA );
	if( cryptStatusError( length ) )
		return( length );
	return( swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer, 
					length ) );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodSSL( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_NONE,				/* Flags */
		SSL_PORT,					/* SSL port */
		SESSION_NEEDS_PRIVKEYSIGN,	/* Client attributes */
			/* The client private key is optional but if present, it has to 
			   be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYORPASSWORD,
		SSL_MINOR_VERSION_TLS,		/* TLS 1.0 */
			SSL_MINOR_VERSION_SSL, SSL_MINOR_VERSION_TLS11,
			/* We default to TLS 1.0 rather than TLS 1.1 because it's likely
			   that support for the latter will be hit-and-miss during the
			   early stages */
		NULL, NULL,					/* Content-type */
	
		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			MAX_PACKET_SIZE,		/* Send/receive buffer size */
		SSL_HEADER_SIZE,			/* Payload data start */
			/* This may be adjusted during the handshake if we're talking 
			   TLS 1.1, which prepends extra data in the form of an IV to
			   the payload */
		SSL_HEADER_SIZE + \
			MAX_PACKET_SIZE,		/* Payload data end */
		NULL,						/* Alt.transport protocol */
		64							/* Required priv.key size */
		};

	/* Set the access method pointers */
	sessionInfoPtr->flags |= SESSION_CHANGENOTIFY_USERID | \
							 SESSION_CHANGENOTIFY_PASSWD;
	sessionInfoPtr->protocolInfo = &protocolInfo;
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	sessionInfoPtr->transactFunction = \
			( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
			serverStartup : clientStartup;
	sessionInfoPtr->getAttributeFunction = getAttributeFunction;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;
	sessionInfoPtr->readHeaderFunction = readHeaderFunction;
	sessionInfoPtr->processBodyFunction = processBodyFunction;
	sessionInfoPtr->writeDataFunction = writeDataFunction;

	return( CRYPT_OK );
	}
#endif /* USE_SSL */
