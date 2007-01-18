/****************************************************************************
*																			*
*						cryptlib PKCS #15 Read Routines						*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/* OID information used to read a PKCS #15 file */

static const OID_INFO FAR_BSS dataOIDinfo[] = {
	{ OID_CMS_DATA, CRYPT_OK },
	{ NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Translate the PKCS #15 usage flags into cryptlib permitted actions.  The
   PKCS #11 use of the 'derive' flag to mean 'allow key agreement' is a bit
   of a kludge, we map it to allowing keyagreement export and import if it's
   a key-agreement algorithm, if there are further constraints they'll be
   handled by the attached cert.  The PKCS #15 nonRepudiation flag doesn't
   have any definition so we can't do anything with it, although we may need
   to translate it to allowing signing and/or verification if implementations
   appear that expect it to be used this way */

static int getPermittedActions( const int usageFlags,
								const CRYPT_ALGO_TYPE cryptAlgo )
	{
	int actionFlags = 0;

	assert( usageFlags >= 0 );
	assert( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			cryptAlgo <= CRYPT_ALGO_LAST_PKC );

	if( usageFlags & ( PKCS15_USAGE_ENCRYPT | PKCS15_USAGE_WRAP ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
	if( usageFlags & ( PKCS15_USAGE_DECRYPT | PKCS15_USAGE_UNWRAP ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
	if( usageFlags & PKCS15_USAGE_SIGN )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
	if( usageFlags & PKCS15_USAGE_VERIFY )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );
	if( isKeyxAlgo( cryptAlgo ) && ( usageFlags & PKCS15_USAGE_DERIVE ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		/* If there are any restrictions on the key usage, we have to make it
		   internal-only because of RSA's signature/encryption duality */
		if( !( ( usageFlags & ( PKCS15_USAGE_ENCRYPT | PKCS15_USAGE_WRAP | \
								PKCS15_USAGE_DECRYPT | PKCS15_USAGE_UNWRAP ) ) && \
			   ( usageFlags & ( PKCS15_USAGE_SIGN | PKCS15_USAGE_VERIFY ) ) ) )
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
		}
	else
		/* Because of the special-case data formatting requirements for DLP
		   algorithms, we make the usage internal-only */
		actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );

	return( ( actionFlags <= 0 ) ? CRYPT_ERROR_PERMISSION : actionFlags );
	}

/* Copy any new object ID information that we've just read across to the 
   object info */

static void copyObjectIdInfo( PKCS15_INFO *pkcs15infoPtr, 
							  const PKCS15_INFO *pkcs15objectInfo )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( pkcs15objectInfo, sizeof( PKCS15_INFO ) ) );

	/* If any new ID information has become available, copy it over.  The 
	   keyID defaults to the iD, so we only copy the newly-read keyID over 
	   if it's something other than the existing iD */
	if( pkcs15objectInfo->keyIDlength > 0 && \
		pkcs15infoPtr->iDlength != pkcs15objectInfo->keyIDlength || \
		memcmp( pkcs15infoPtr->iD, pkcs15objectInfo->keyID,
				pkcs15objectInfo->keyIDlength ) )
		{
		memcpy( pkcs15infoPtr->keyID, pkcs15objectInfo->keyID,
				pkcs15objectInfo->keyIDlength );
		pkcs15infoPtr->keyIDlength = pkcs15objectInfo->keyIDlength;
		}
	if( pkcs15objectInfo->iAndSIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->iAndSID, pkcs15objectInfo->iAndSID,
				pkcs15objectInfo->iAndSIDlength );
		pkcs15infoPtr->iAndSIDlength = pkcs15objectInfo->iAndSIDlength;
		}
	if( pkcs15objectInfo->subjectNameIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->subjectNameID, pkcs15objectInfo->subjectNameID,
				pkcs15objectInfo->subjectNameIDlength );
		pkcs15infoPtr->subjectNameIDlength = pkcs15objectInfo->subjectNameIDlength;
		}
	if( pkcs15objectInfo->issuerNameIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->issuerNameID, pkcs15objectInfo->issuerNameID,
				pkcs15objectInfo->issuerNameIDlength );
		pkcs15infoPtr->issuerNameIDlength = pkcs15objectInfo->issuerNameIDlength;
		}
	if( pkcs15objectInfo->pgp2KeyIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->pgp2KeyID, pkcs15objectInfo->pgp2KeyID,
				pkcs15objectInfo->pgp2KeyIDlength );
		pkcs15infoPtr->pgp2KeyIDlength = pkcs15objectInfo->pgp2KeyIDlength;
		}
	if( pkcs15objectInfo->openPGPKeyIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->openPGPKeyID, pkcs15objectInfo->openPGPKeyID,
				pkcs15objectInfo->openPGPKeyIDlength );
		pkcs15infoPtr->openPGPKeyIDlength = pkcs15objectInfo->openPGPKeyIDlength;
		}
	}

/* Copy any new object payload information that we've just read across to 
   the object info */

static void copyObjectPayloadInfo( PKCS15_INFO *pkcs15infoPtr, 
								   const PKCS15_INFO *pkcs15objectInfo,
								   const void *object, const int objectLength,
								   const PKCS15_OBJECT_TYPE type )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( pkcs15objectInfo, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( object, objectLength ) );
	assert( type > PKCS15_OBJECT_NONE && type < PKCS15_OBJECT_LAST );

	switch( type )
		{
		case PKCS15_OBJECT_PUBKEY:
			pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
			pkcs15infoPtr->pubKeyData = ( void * ) object;
			pkcs15infoPtr->pubKeyDataSize = objectLength;
			pkcs15infoPtr->pubKeyOffset = pkcs15objectInfo->pubKeyOffset;
			pkcs15infoPtr->pubKeyUsage = pkcs15objectInfo->pubKeyUsage;
			break;

		case PKCS15_OBJECT_PRIVKEY:
			pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
			pkcs15infoPtr->privKeyData = ( void * ) object;
			pkcs15infoPtr->privKeyDataSize = objectLength;
			pkcs15infoPtr->privKeyOffset = pkcs15objectInfo->privKeyOffset;
			pkcs15infoPtr->privKeyUsage = pkcs15objectInfo->privKeyUsage;
			break;

		case PKCS15_OBJECT_CERT:
			if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
				pkcs15infoPtr->type = PKCS15_SUBTYPE_CERT;
			pkcs15infoPtr->certData = ( void * ) object;
			pkcs15infoPtr->certDataSize = objectLength;
			pkcs15infoPtr->certOffset = pkcs15objectInfo->certOffset;
			pkcs15infoPtr->trustedUsage = pkcs15objectInfo->trustedUsage;
			pkcs15infoPtr->implicitTrust = pkcs15objectInfo->implicitTrust;
			break;

		case PKCS15_OBJECT_SECRETKEY:
			assert( NOTREACHED );
			break;

		case PKCS15_OBJECT_DATA:
			pkcs15infoPtr->type = PKCS15_SUBTYPE_DATA;
			pkcs15infoPtr->dataType = pkcs15objectInfo->dataType;
			pkcs15infoPtr->dataData = ( void * ) object;
			pkcs15infoPtr->dataDataSize = objectLength;
			pkcs15infoPtr->dataOffset = pkcs15objectInfo->dataOffset;
			break;

		default:
			/* We don't try and return an error for this, it's a fault 
			   condition but if it's ever reached it just ends up as an 
			   empty (non-useful) object entry */
			assert( NOTREACHED );
		}
	}

/****************************************************************************
*																			*
*							Read Public Key Components						*
*																			*
****************************************************************************/

/* Read public-key components from a PKCS #15 object entry */

int readPublicKeyComponents( const PKCS15_INFO *pkcs15infoPtr,
							 const CRYPT_KEYSET iCryptKeysetCallback,
							 const CRYPT_KEYID_TYPE keyIDtype,
							 const void *keyID, const int keyIDlength,
							 const BOOLEAN publicComponentsOnly,
							 CRYPT_CONTEXT *iCryptContextPtr,
							 CRYPT_CERTIFICATE *iDataCertPtr,
							 int *pubkeyActionFlags, 
							 int *privkeyActionFlags )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_CONTEXT iCryptContext;
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
	STREAM stream;
	int status;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptKeysetCallback ) );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( isWritePtr( iCryptContextPtr, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( iDataCertPtr, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( pubkeyActionFlags, sizeof( int ) ) );
	assert( isWritePtr( privkeyActionFlags, sizeof( int ) ) );

	/* Clear return values */
	*iCryptContextPtr = CRYPT_ERROR;
	*iDataCertPtr = CRYPT_ERROR;
	*pubkeyActionFlags = *privkeyActionFlags = 0;

	/* If we're creating a public-key context we create the cert or PKC 
	   context normally, if we're creating a private-key context we create 
	   a data-only cert (if there's cert information present) and a partial 
	   PKC context ready to accept the private key components.  If there's a 
	   cert present we take all of the info we need from the cert, otherwise 
	   we use the public-key data */
	if( pkcs15infoPtr->certData != NULL )
		{
		/* There's a certificate present, import it and reconstruct the
		   public-key info from it if we're creating a partial PKC context */
		status = iCryptImportCertIndirect( &iCryptContext,
								iCryptKeysetCallback, keyIDtype, keyID,
								keyIDlength, publicComponentsOnly ? \
									KEYMGMT_FLAG_NONE : \
									KEYMGMT_FLAG_DATAONLY_CERT );
		if( cryptStatusError( status ) )
			return( status );
		if( !publicComponentsOnly )
			{
			DYNBUF pubKeyDB;

			/* We got the cert, now create the public part of the context 
			   from the cert's encoded public-key components */
			iDataCert = iCryptContext;
			status = dynCreate( &pubKeyDB, iDataCert, 
								CRYPT_IATTRIBUTE_SPKI );
			if( cryptStatusError( status ) )
				return( status );
			sMemConnect( &stream, dynData( pubKeyDB ),
						 dynLength( pubKeyDB ) );
			status = iCryptReadSubjectPublicKey( &stream, &iCryptContext,
												 TRUE );
			sMemDisconnect( &stream );
			dynDestroy( &pubKeyDB );
			if( cryptStatusError( status ) )
				{
				krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
				return( status );
				}
			}
		}
	else
		{
		/* There's no certificate present, create the public-key context
		   directly */
		sMemConnect( &stream, ( BYTE * ) pkcs15infoPtr->pubKeyData + \
						pkcs15infoPtr->pubKeyOffset,
					 pkcs15infoPtr->pubKeyDataSize - \
						pkcs15infoPtr->pubKeyOffset );
		status = iCryptReadSubjectPublicKey( &stream, &iCryptContext,
											 !publicComponentsOnly );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Get the permitted usage flags for each object type that we'll be
	   instantiating.  If there's a public key present we apply its usage
	   flags to whichever PKC context we create, even if it's done indirectly
	   via the cert import.  Since the private key can also perform the
	   actions of the public key, we set its action flags to the union of the
	   two */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && pkcs15infoPtr->pubKeyData != NULL )
		{
		status = getPermittedActions( pkcs15infoPtr->pubKeyUsage, cryptAlgo );
		if( !cryptStatusError( status ) )
			*pubkeyActionFlags = status;
		}
	if( !cryptStatusError( status ) && !publicComponentsOnly )
		{
		status = getPermittedActions( pkcs15infoPtr->privKeyUsage, cryptAlgo );
		if( !cryptStatusError( status ) )
			*privkeyActionFlags = status | *pubkeyActionFlags;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Return the newly-created objects to the caller */
	*iCryptContextPtr = iCryptContext;
	*iDataCertPtr = iDataCert;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read Public/Private Key Components					*
*																			*
****************************************************************************/

/* Read private-key components from a PKCS #15 object entry */

int readPrivateKeyComponents( const PKCS15_INFO *pkcs15infoPtr,
							  const CRYPT_CONTEXT iCryptContext,
							  const void *password, 
							  const int passwordLength )
	{
	CRYPT_CONTEXT iSessionKey;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	QUERY_INFO queryInfo, contentQueryInfo;
	STREAM stream;
	const void *encryptedKey, *encryptedContent;
	int encryptedContentLength;
	int status;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptContext ) );
	assert( isReadPtr( password, passwordLength ) );

	/* Skip the outer wrapper, version number, and header for the SET OF 
	   EncryptionInfo, and query the exported key information to determine 
	   the parameters required to reconstruct the decryption key */
	sMemConnect( &stream,
				 ( BYTE * ) pkcs15infoPtr->privKeyData + \
							pkcs15infoPtr->privKeyOffset,
				 pkcs15infoPtr->privKeyDataSize - \
				 pkcs15infoPtr->privKeyOffset );
	readConstructed( &stream, NULL, CTAG_OV_DIRECTPROTECTED );
	readShortInteger( &stream, NULL );
	readSet( &stream, NULL );
	status = queryAsn1Object( &stream, &queryInfo );
	if( cryptStatusOK( status ) && \
		queryInfo.type != CRYPT_OBJECT_ENCRYPTED_KEY )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	encryptedKey = sMemBufPtr( &stream );
	status = readUniversal( &stream );	/* Skip the exported key */
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Read the header for the encrypted key and make sure that all of the
	   data is present in the stream */
	status = readCMSencrHeader( &stream, dataOIDinfo, &iSessionKey,
								&contentQueryInfo );
	if( cryptStatusOK( status ) )
		{
		encryptedContent = sMemBufPtr( &stream );
		encryptedContentLength = contentQueryInfo.size;
		if( encryptedContentLength == CRYPT_UNUSED || \
			encryptedContentLength < MIN_OBJECT_SIZE )
			/* Indefinite length or too-small object */
			status = CRYPT_ERROR_BADDATA;
		else
			if( encryptedContentLength > sMemDataLeft( &stream ) )
				status = CRYPT_ERROR_UNDERFLOW;
		}
	zeroise( &contentQueryInfo, sizeof( QUERY_INFO ) );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Create an encryption context and derive the user password into it
	   using the given parameters, and import the session key.  If there's
	   an error in the parameters stored with the exported key we'll get an
	   arg or attribute error when we try to set the attribute so we
	   translate it into an error code which is appropriate for the
	   situation */
	setMessageCreateObjectInfo( &createInfo, queryInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
							  &queryInfo.cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
								  &queryInfo.keySetupAlgo,
								  CRYPT_CTXINFO_KEYING_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
								  &queryInfo.keySetupIterations,
								  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, queryInfo.salt, queryInfo.saltLength );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_SALT );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( void * ) password, passwordLength );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
		}
	if( cryptStatusOK( status ) )
		status = iCryptImportKeyEx( encryptedKey, queryInfo.size,
									CRYPT_FORMAT_CRYPTLIB, 
									createInfo.cryptHandle, iSessionKey,
									NULL );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );
		}

	/* Import the encrypted key into the PKC context */
	setMechanismWrapInfo( &mechanismInfo, ( void * ) encryptedContent,
						  encryptedContentLength, NULL, 0, iCryptContext,
						  iSessionKey, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/****************************************************************************
*																			*
*								Read a Keyset								*
*																			*
****************************************************************************/

/* Read a single object in a keyset */

static int readObject( STREAM *stream, PKCS15_INFO *pkcs15objectInfo, 
					   void **objectPtrPtr, int *objectLengthPtr,
					   const PKCS15_OBJECT_TYPE type, const int endPos )
	{
	STREAM objectStream;
	BYTE buffer[ MIN_OBJECT_SIZE + 8 ];
	void *objectData;
	int headerSize, objectLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15objectInfo, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( objectPtrPtr, sizeof( void * ) ) );
	assert( isWritePtr( objectLengthPtr, sizeof( int ) ) );
	assert( type > PKCS15_OBJECT_NONE && type < PKCS15_OBJECT_LAST );
	assert( endPos > stell( stream ) );

	/* Clear return values */
	memset( pkcs15objectInfo, 0, sizeof( PKCS15_INFO ) );
	*objectPtrPtr = NULL;
	*objectLengthPtr = 0;

	/* Read the current object.  We can't use getObjectLength() here because 
	   we're reading from a file rather than a memory stream, so we have to
	   grab the first MIN_OBJECT_SIZE bytes from the file stream and decode
	   them to see what's next */
	status = sread( stream, buffer, MIN_OBJECT_SIZE );
	if( cryptStatusOK( status ) )
		{
		STREAM headerStream;

		sMemConnect( &headerStream, buffer, MIN_OBJECT_SIZE );
		status = readGenericHole( &headerStream, &objectLength, 
								  MIN_OBJECT_SIZE, DEFAULT_TAG );
		headerSize = stell( &headerStream );
		sMemDisconnect( &headerStream );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( objectLength < MIN_OBJECT_SIZE || \
		objectLength > MAX_PRIVATE_KEYSIZE + 1024 )
		return( CRYPT_ERROR_BADDATA );

	/* Allocate storage for the object and copy the already-read portion to 
	   the start of the storage */
	objectLength += headerSize;
	if( ( objectData = clAlloc( "readObject", objectLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( objectData, buffer, MIN_OBJECT_SIZE );

	/* Read the remainder of the object into the memory buffer and check 
	   that the overall object is valid */
	status = sread( stream, ( BYTE * ) objectData + MIN_OBJECT_SIZE,
					objectLength - MIN_OBJECT_SIZE );
	if( cryptStatusOK( status ) )
		status = checkObjectEncoding( objectData, objectLength );
	if( cryptStatusError( status ) )
		{
		clFree( "readObject", objectData );
		return( status );
		}

	/* Read the object attributes from the in-memory object data */
	sMemConnect( &objectStream, objectData, objectLength );
	status = readObjectAttributes( &objectStream, pkcs15objectInfo, type );
	sMemDisconnect( &objectStream );
	if( cryptStatusError( status ) )
		{
		clFree( "readObject", objectData );
		return( status );
		}

	/* Remember the encoded object data */
	*objectPtrPtr = objectData;
	*objectLengthPtr = objectLength;

	return( CRYPT_OK );
	}

/* Read an entire keyset */

int readKeyset( STREAM *stream, PKCS15_INFO *pkcs15info, 
				const int maxNoPkcs15objects, const long endPos )
	{
	int iterationCount = 0, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );
	assert( maxNoPkcs15objects >= 1 );
	assert( endPos > stell( stream ) );

	/* Scan all of the objects in the file */
	while( cryptStatusOK( status ) && stell( stream ) < endPos && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		typedef struct {
			int tag;
			PKCS15_OBJECT_TYPE type;
			} TAGTOTYPE_INFO;
		static const TAGTOTYPE_INFO tagToTypeTbl[] = {
			{ CTAG_PO_PRIVKEY, PKCS15_OBJECT_PRIVKEY },
			{ CTAG_PO_PUBKEY, PKCS15_OBJECT_PUBKEY },
			{ CTAG_PO_TRUSTEDPUBKEY, PKCS15_OBJECT_PUBKEY },
			{ CTAG_PO_SECRETKEY, PKCS15_OBJECT_SECRETKEY },
			{ CTAG_PO_CERT, PKCS15_OBJECT_CERT },
			{ CTAG_PO_TRUSTEDCERT, PKCS15_OBJECT_CERT },
			{ CTAG_PO_USEFULCERT, PKCS15_OBJECT_CERT },
			{ CTAG_PO_DATA, PKCS15_OBJECT_DATA },
			{ CTAG_PO_AUTH, PKCS15_OBJECT_NONE },
			{ CRYPT_ERROR, PKCS15_OBJECT_NONE }, 
			{ CRYPT_ERROR, PKCS15_OBJECT_NONE }
			};
		PKCS15_OBJECT_TYPE type = PKCS15_OBJECT_NONE;
		int tag, innerEndPos, i, innerIterationCount = 0;

		/* Map the object tag to a PKCS #15 object type */
		tag = peekTag( stream );
		if( cryptStatusError( tag ) )
			return( tag );
		tag = EXTRACT_CTAG( tag );
		for( i = 0; tagToTypeTbl[ i ].tag != CRYPT_ERROR && \
					i < FAILSAFE_ARRAYSIZE( tagToTypeTbl, TAGTOTYPE_INFO ); 
			 i++ )
			{
			if( tagToTypeTbl[ i ].tag == tag )
				{
				type = tagToTypeTbl[ i ].type;
				break;
				}
			}
		if( i >= FAILSAFE_ARRAYSIZE( tagToTypeTbl, TAGTOTYPE_INFO ) )
			retIntError();
		if( type == PKCS15_OBJECT_NONE )
			return( CRYPT_ERROR_BADDATA );

		/* Read the [n] [0] wrapper to find out what we're dealing with */
		readConstructed( stream, NULL, tag );
		status = readConstructed( stream, &innerEndPos, CTAG_OV_DIRECT );
		if( cryptStatusError( status ) )
			return( status );
		innerEndPos += stell( stream );
		if( innerEndPos < MIN_OBJECT_SIZE || innerEndPos > MAX_INTLENGTH )
			return( CRYPT_ERROR_BADDATA );

		/* Scan all objects of this type */
		while( cryptStatusOK( status ) && stell( stream ) < innerEndPos && \
			   innerIterationCount++ < FAILSAFE_ITERATIONS_LARGE )
			{
			PKCS15_INFO pkcs15objectInfo, *pkcs15infoPtr = NULL;
			void *object;
			int objectLength;

			/* Read the object */
			status = readObject( stream, &pkcs15objectInfo, &object,
								 &objectLength, type, endPos );
			if( cryptStatusError( status ) )
				return( status );

			/* If we read an object with associated ID information, find out 
			   where to add the object data */
			if( pkcs15objectInfo.iDlength > 0 )
				pkcs15infoPtr = findEntry( pkcs15info, maxNoPkcs15objects, 
										   CRYPT_KEYIDEX_ID, 
										   pkcs15objectInfo.iD,
										   pkcs15objectInfo.iDlength,
										   KEYMGMT_FLAG_NONE );
			if( pkcs15infoPtr == NULL )
				{
				int index;

				/* This personality isn't present yet, find out where we can 
				   add the object data and copy the fixed object information 
				   over */
				pkcs15infoPtr = findFreeEntry( pkcs15info, 
											   maxNoPkcs15objects, &index );
				if( pkcs15infoPtr == NULL )
					{
					clFree( "readKeyset", object );
					return( CRYPT_ERROR_OVERFLOW );
					}
				pkcs15infoPtr->index = index;
				memcpy( pkcs15infoPtr, &pkcs15objectInfo, 
						sizeof( PKCS15_INFO ) );
				}

			/* Copy over any ID information */
			copyObjectIdInfo( pkcs15infoPtr, &pkcs15objectInfo );

			/* Copy over any other new information that may have become
			   available.  The semantics when multiple date ranges are
			   present (for example one for a key, one for a cert) are a
			   bit uncertain, we use the most recent date available on the
			   assumption that this reflects the newest information */
			if( pkcs15objectInfo.validFrom > pkcs15infoPtr->validFrom )
				pkcs15infoPtr->validFrom = pkcs15objectInfo.validFrom;
			if( pkcs15objectInfo.validTo > pkcs15infoPtr->validTo )
				pkcs15infoPtr->validTo = pkcs15objectInfo.validTo;

			/* Copy the payload over */
			copyObjectPayloadInfo( pkcs15infoPtr, &pkcs15objectInfo,
								   object, objectLength, type );
			}
		if( innerIterationCount >= FAILSAFE_ITERATIONS_LARGE )
			retIntError();
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( status );
	}
#endif /* USE_PKCS15 */
