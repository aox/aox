/****************************************************************************
*																			*
*						  cryptlib PKCS #15 Routines						*
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

/* Each PKCS #15 file can contain information for multiple personalities 
   (although it's extremely unlikely to contain more than one or two), we 
   allow a maximum of MAX_PKCS15_OBJECTS per file in order to discourage 
   them from being used as general-purpose public-key keysets, which they're 
   not supposed to be.  A setting of 32 objects consumes ~4K of memory 
   (32 x ~128), so we choose that as the limit */

#ifdef CONFIG_CONSERVE_MEMORY
  #define MAX_PKCS15_OBJECTS	8
#else
  #define MAX_PKCS15_OBJECTS	32
#endif /* CONFIG_CONSERVE_MEMORY */

#ifdef USE_PKCS15

/* OID information used to read a PKCS #15 file */

static const CMS_CONTENT_INFO FAR_BSS oidInfoPkcs15Data = { 0, 0 };

static const OID_INFO FAR_BSS keyFileOIDinfo[] = {
	{ OID_PKCS15_CONTENTTYPE, CRYPT_OK, &oidInfoPkcs15Data },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Get the hash of various certificate name fields */

int getCertID( const CRYPT_HANDLE iCryptHandle, 
			   CRYPT_ATTRIBUTE_TYPE nameType, 
			   BYTE *nameID, const int nameIdMaxLen )
	{
	HASHFUNCTION hashFunction;
	DYNBUF idDB;
	int status;

	assert( isHandleRangeValid( iCryptHandle ) );
	assert( nameType == CRYPT_IATTRIBUTE_SPKI || \
			nameType == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER || \
			nameType == CRYPT_IATTRIBUTE_SUBJECT || \
			nameType == CRYPT_IATTRIBUTE_ISSUER );
	assert( isWritePtr( nameID, nameIdMaxLen ) );

	/* Get the attribute data and hash algorithm information and hash the 
	   attribute to get the ID */
	status = dynCreate( &idDB, iCryptHandle, nameType );
	if( cryptStatusError( status ) )
		return( status );
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
	hashFunction( NULL, nameID, nameIdMaxLen, dynData( idDB ), 
				  dynLength( idDB ), HASH_ALL );
	dynDestroy( &idDB );
	return( CRYPT_OK );
	}

/* Locate an object based on an ID */

#define matchID( src, srcLen, dest, destLen ) \
		( ( srcLen ) > 0 && ( srcLen ) == ( destLen ) && \
		  !memcmp( ( src ), ( dest ), ( destLen ) ) )

PKCS15_INFO *findEntry( const PKCS15_INFO *pkcs15info,
						const int noPkcs15objects,
						const CRYPT_KEYID_TYPE keyIDtype,
						const void *keyID, const int keyIDlength,
						const int requestedUsage )
	{
	int i;

	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( noPkcs15objects >= 1 );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID || \
			keyIDtype == CRYPT_KEYIDEX_ID || \
			keyIDtype == CRYPT_KEYIDEX_SUBJECTNAMEID );
	assert( ( keyID == NULL && keyIDlength == 0 ) || \
			isReadPtr( keyID, keyIDlength ) );
	assert( ( requestedUsage & KEYMGMT_MASK_USAGEOPTIONS ) != \
			KEYMGMT_MASK_USAGEOPTIONS );

	/* If there's no ID to search on, don't try and do anything.  This can
	   occur when we're trying to build a chain and the necessary chaining
	   data isn't present */
	if( keyID == NULL )
		return( NULL );

	/* Try and locate the appropriate object in the PKCS #15 collection */
	for( i = 0; i < noPkcs15objects; i++ )
		{
		const PKCS15_INFO *pkcs15infoPtr = &pkcs15info[ i ];
		const int compositeUsage = pkcs15infoPtr->pubKeyUsage | \
								   pkcs15infoPtr->privKeyUsage;

		/* If there's no entry at this position, continue */
		if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
			continue;

		/* If there's an explicit usage requested, make sure that the key 
		   usage matches this.  This can get slightly complex since the 
		   advertised usage isn't necessarily the same as the usage 
		   permitted by the associated cert (PKCS #11 apps are particularly 
		   good at setting bogus usage types) and the overall result can be 
		   further influenced by trusted usage settings, so all that we 
		   check for here is an indicated usage for the key matching the 
		   requested usage */
		if( ( requestedUsage & KEYMGMT_FLAG_USAGE_CRYPT ) && \
			!( compositeUsage & ENCR_USAGE_MASK ) )
			continue;
		if( ( requestedUsage & KEYMGMT_FLAG_USAGE_SIGN ) && \
			!( compositeUsage & SIGN_USAGE_MASK ) )
			continue;

		/* Check for a match based on the ID type */
		switch( keyIDtype )
			{
			case CRYPT_KEYID_NAME:
			case CRYPT_KEYID_URI:
				if( matchID( pkcs15infoPtr->label, pkcs15infoPtr->labelLength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_KEYID:
				if( matchID( pkcs15infoPtr->keyID, pkcs15infoPtr->keyIDlength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_PGPKEYID:
				if( matchID( pkcs15infoPtr->pgp2KeyID,
							 pkcs15infoPtr->pgp2KeyIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_ISSUERID:
				if( matchID( pkcs15infoPtr->iAndSID,
							 pkcs15infoPtr->iAndSIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_KEYIDEX_ID:
				if( matchID( pkcs15infoPtr->iD, pkcs15infoPtr->iDlength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_KEYIDEX_SUBJECTNAMEID:
				if( matchID( pkcs15infoPtr->subjectNameID,
							 pkcs15infoPtr->subjectNameIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			default:
				assert( NOTREACHED );
				return( NULL );
			}
		}

	/* If we're trying to match on the PGP key ID and didn't find anything,
	   retry it using the first PGP_KEYID_SIZE bytes of the object ID.  This
	   is necessary because calculation of the OpenPGP ID requires the
	   presence of data that may not be present in non-PGP keys, so we can't
	   calculate a real OpenPGP ID but have to use the next-best thing */
	if( keyIDtype == CRYPT_IKEYID_PGPKEYID )
		{
		for( i = 0; i < noPkcs15objects; i++ )
			{
			const PKCS15_INFO *pkcs15infoPtr = &pkcs15info[ i ];

			if( pkcs15infoPtr->type != PKCS15_SUBTYPE_NONE && \
				pkcs15infoPtr->iDlength >= PGP_KEYID_SIZE && \
				!memcmp( keyID, pkcs15infoPtr->iD, PGP_KEYID_SIZE ) )
				return( ( PKCS15_INFO * ) pkcs15infoPtr );
			}
		}

	return( NULL );
	}

/* Find a free PKCS #15 entry */

PKCS15_INFO *findFreeEntry( const PKCS15_INFO *pkcs15info,
							const int noPkcs15objects, int *index )
	{
	int i;

	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( ( index == NULL ) || isWritePtr( index, sizeof( int ) ) );

	/* Clear return value */
	if( index != NULL )
		*index = CRYPT_ERROR;

	for( i = 0; i < noPkcs15objects; i++ )
		if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
			break;
	if( i >= noPkcs15objects )
		return( NULL );

	if( index != NULL )
		/* Remember the index value (used for enumerating PKCS #15 entries) 
		   for this entry */
		*index = i;
	return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
	}

/* Free object entries */

void pkcs15freeEntry( PKCS15_INFO *pkcs15info )
	{
	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	if( pkcs15info->pubKeyData != NULL )
		{
		zeroise( pkcs15info->pubKeyData, pkcs15info->pubKeyDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->pubKeyData );
		}
	if( pkcs15info->privKeyData != NULL )
		{
		zeroise( pkcs15info->privKeyData, pkcs15info->privKeyDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->privKeyData );
		}
	if( pkcs15info->certData != NULL )
		{
		zeroise( pkcs15info->certData, pkcs15info->certDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->certData );
		}
	if( pkcs15info->dataData != NULL )
		{
		zeroise( pkcs15info->dataData, pkcs15info->dataDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->dataData );
		}
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) );
	}

static void pkcs15Free( PKCS15_INFO *pkcs15info, const int noPkcs15objects )
	{
	int i;

	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( noPkcs15objects >= 1 );

	for( i = 0; i < noPkcs15objects; i++ )
		pkcs15freeEntry( &pkcs15info[ i ] );
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) * noPkcs15objects );
	}

/* Get the PKCS #15 validity information from a certificate */

int getValidityInfo( PKCS15_INFO *pkcs15info,
					 const CRYPT_HANDLE cryptHandle )
	{
	MESSAGE_DATA msgData;
	time_t validFrom, validTo;
	int status;

	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( cryptHandle ) );

	/* Remember the validity information for later.  Note that we always
	   update the validity (even if it's already set) since we may be
	   replacing an older cert with a newer one */
	setMessageData( &msgData, &validFrom, sizeof( time_t ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDFROM );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, &validTo, sizeof( time_t ) );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( pkcs15info->validTo > validTo )
		/* There's an existing, newer cert already present, make sure that 
		   we don't try and add the new one */
		return( CRYPT_ERROR_DUPLICATE );
	pkcs15info->validFrom = validFrom;
	pkcs15info->validTo = validTo;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* A PKCS #15 keyset can contain multiple keys and whatnot, so when we open
   it we parse the contents into memory for later use */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const CRYPT_KEYOPT_TYPE options )
	{
	PKCS15_INFO *pkcs15info;
	STREAM *stream = &keysetInfo->keysetFile->stream;
	long endPos;
	int status;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );
	assert( name == NULL );
	assert( options >= CRYPT_KEYOPT_NONE && options < CRYPT_KEYOPT_LAST );

	/* If we're opening an existing keyset, skip the outer header, optional
	   keyManagementInfo, and inner header.  We do this before we perform any
	   setup operations to weed out potential problem files */
	if( options != CRYPT_KEYOPT_CREATE )
		{
		long dataEndPos;

		/* Read the outer header and make sure that the length information is
		   valid.  readCMSheader() reads the version number field at the 
		   start of the content, so we have to adjust the stream position for
		   this when we calculate the data end position */
		status = readCMSheader( stream, keyFileOIDinfo, &dataEndPos, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		if( dataEndPos == CRYPT_UNUSED )
			/* Indefinite length, don't try and go any further (the general
			   length check below will also catch this, but we make the 
			   check explicit here) */
			return( CRYPT_ERROR_BADDATA );
		endPos = ( stell( stream ) - sizeofShortInteger( 0 ) ) + dataEndPos;
		if( dataEndPos < MIN_OBJECT_SIZE || dataEndPos > MAX_INTLENGTH || \
			endPos < 16 + MIN_OBJECT_SIZE || endPos > MAX_INTLENGTH )
			/* Make sure that the length info is sensible */
			return( CRYPT_ERROR_BADDATA );

		/* Skip the key management info if there is any, and read the inner 
		   wrapper */
		if( peekTag( stream ) == MAKE_CTAG( 0 ) )
			readUniversal( stream );
		status = readLongSequence( stream, NULL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Allocate the PKCS #15 object info */
	if( ( pkcs15info = clAlloc( "initFunction", \
								sizeof( PKCS15_INFO ) * \
								MAX_PKCS15_OBJECTS ) ) == NULL )
		{
		if( options != CRYPT_KEYOPT_CREATE )
			/* Reset the stream position to account for the header info that
			   we've already read */
			sseek( stream, 0 ) ;
		return( CRYPT_ERROR_MEMORY );
		}
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS );
	keysetInfo->keyData = pkcs15info;
	keysetInfo->keyDataSize = sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS;
	keysetInfo->keyDataNoObjects = MAX_PKCS15_OBJECTS;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* Read all of the keys in the keyset */
	status = readKeyset( &keysetInfo->keysetFile->stream, pkcs15info,
						 MAX_PKCS15_OBJECTS, endPos );
	if( cryptStatusError( status ) )
		{
		pkcs15Free( pkcs15info, MAX_PKCS15_OBJECTS );
		clFree( "initFunction", keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		keysetInfo->keyDataSize = 0;
		if( options != CRYPT_KEYOPT_CREATE )
			sseek( stream, 0 ) ;
		return( status );
		}

	return( CRYPT_OK );
	}

/* Shut down the PKCS #15 state, flushing information to disk if necessary */

static int shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	int status = CRYPT_OK;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );

	/* If the contents have been changed, commit the changes to disk.  The
	   STREAM_IOCTL_IOBUFFER ioctl allocates a working I/O buffer for the
	   duration of the flush and disconnects it again after it's complete */
	if( keysetInfo->flags & KEYSET_DIRTY )
		{
		STREAM *stream = &keysetInfo->keysetFile->stream;
		BYTE buffer[ STREAM_BUFSIZE + 8 ];

		sseek( stream, 0 );
		sioctl( stream, STREAM_IOCTL_IOBUFFER, buffer, STREAM_BUFSIZE );
		status = pkcs15Flush( stream, keysetInfo->keyData, 
							  keysetInfo->keyDataNoObjects );
		sioctl( stream, STREAM_IOCTL_IOBUFFER, NULL, 0 );
		if( status == OK_SPECIAL )
			{
			keysetInfo->flags |= KEYSET_EMPTY;
			status = CRYPT_OK;
			}
		}

	/* Free the PKCS #15 object info */
	if( keysetInfo->keyData != NULL )
		{
		pkcs15Free( keysetInfo->keyData, keysetInfo->keyDataNoObjects );
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		clFree( "shutdownFunction", keysetInfo->keyData );
		}

	return( status );
	}

/****************************************************************************
*																			*
*									Get a Key								*
*																			*
****************************************************************************/

/* Set any optional attributes that may be associated with a key */

static int setKeyAttributes( const CRYPT_HANDLE iCryptHandle,
							 const PKCS15_INFO *pkcs15infoPtr,
							 const int actionFlags )
	{
	MESSAGE_DATA msgData;
	int status = CRYPT_OK;

	assert( isHandleRangeValid( iCryptHandle ) );
	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( ( actionFlags == CRYPT_UNUSED ) || ( actionFlags > 0 ) );

	if( actionFlags != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
								  ( void * ) &actionFlags,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusOK( status ) && \
		pkcs15infoPtr->openPGPKeyIDlength > 0 )
		{
		setMessageData( &msgData, ( void * ) pkcs15infoPtr->openPGPKeyID,
						pkcs15infoPtr->openPGPKeyIDlength );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusOK( status ) && \
		pkcs15infoPtr->validFrom > MIN_TIME_VALUE )
		{
		/* This isn't really used for anything, but is required to generate
		   the OpenPGP keyID, which includes the key creation time in the
		   ID-generation process */
		setMessageData( &msgData, ( void * ) &pkcs15infoPtr->validFrom,
						sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_PGPVALIDITY );
		}
	return( status );
	}

/* Get an encoded trusted cert */

static int getTrustedCert( const PKCS15_INFO *pkcs15info,
						   const int noPkcs15objects,
						   void *data, const int dataMaxLength, 
						   int *dataLength, const BOOLEAN resetCertIndex )
	{
	static int trustedCertIndex;

	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return values */
	memset( data, 0, dataMaxLength );
	*dataLength = 0;

	/* If this is the first cert, reset the index value.  This is pretty
	   ugly since this sort of state-information value should be stored with 
	   the caller, however there's no way to pass this back and forth in a 
	   MESSAGE_DATA without resorting to an even uglier hack and it's safe 
	   since this attribute is only ever read by the init thread when it 
	   reads the config keyset at startup */
	if( resetCertIndex )
		trustedCertIndex = 0;
	else
		{
		/* Move on to the next cert */
		if( trustedCertIndex >= noPkcs15objects - 1 )
			return( CRYPT_ERROR_NOTFOUND );
		trustedCertIndex++;	
		}

	/* Find the next trusted cert */
	while( trustedCertIndex < noPkcs15objects && \
		   !pkcs15info[ trustedCertIndex ].implicitTrust )	
		trustedCertIndex++;
	if( trustedCertIndex >= noPkcs15objects )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the data to the caller */
	return( dataCopy( data, dataMaxLength, dataLength,
					  ( BYTE * ) pkcs15info[ trustedCertIndex ].certData + \
								 pkcs15info[ trustedCertIndex ].certOffset,	
					  pkcs15info[ trustedCertIndex ].certDataSize - \
					  pkcs15info[ trustedCertIndex ].certOffset ) );
	}

/* Get an encoded configuration item */

static int getConfigItem( const PKCS15_INFO *pkcs15info,
						  const int noPkcs15objects,
						  const CRYPT_ATTRIBUTE_TYPE dataType,
						  void *data, const int dataMaxLength, 
						  int *dataLength )
	{
	const PKCS15_INFO *pkcs15infoPtr = NULL;
	int i;

	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( dataType == CRYPT_IATTRIBUTE_CONFIGDATA || \
			dataType == CRYPT_IATTRIBUTE_USERINDEX || \
			dataType == CRYPT_IATTRIBUTE_USERINFO );
	assert( ( data == NULL && dataMaxLength == 0 ) || \
			isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return values */
	*dataLength = 0;
	if( data != NULL )
		memset( data, 0, dataMaxLength );

	/* Find the particular data type that we're looking for */
	for( i = 0; i < noPkcs15objects; i++ )
		{
		if( ( pkcs15info[ i ].type == PKCS15_SUBTYPE_DATA && \
			  pkcs15info[ i ].dataType == dataType ) )
			{
			pkcs15infoPtr = &pkcs15info[ i ];
			break;
			}
		}
	if( pkcs15infoPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* If it's just a length check, we're done */
	if( data == NULL )
		{
		*dataLength = pkcs15infoPtr->dataDataSize - pkcs15infoPtr->dataOffset;
		return( CRYPT_OK );
		}

	/* Return it to the caller */
	return( dataCopy( data, dataMaxLength, dataLength,
					  ( BYTE * ) pkcs15infoPtr->dataData + \
								 pkcs15infoPtr->dataOffset,
					  pkcs15infoPtr->dataDataSize - \
					  pkcs15infoPtr->dataOffset ) );
	}

/* Read key data from a PKCS #15 collection */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
	CRYPT_CONTEXT iCryptContext;
	const PKCS15_INFO *pkcs15infoPtr;
	MESSAGE_DATA msgData;
	const BOOLEAN publicComponentsOnly = \
					( itemType != KEYMGMT_ITEM_PRIVATEKEY ) ? TRUE : FALSE;
	const int auxInfoMaxLength = *auxInfoLength;
	int pubkeyActionFlags = 0, privkeyActionFlags = 0, status;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );

	/* If we're being asked for encoded configuration information, return it
	   and exit.  This is a bit odd, but more valid than defining a pile of
	   special-case KEYMGMT_ITEM types that only exist for PKCS #15 keysets,
	   since these are really attributes of the keyset rather than general
	   key types */
	if( iCryptHandle == NULL )
		{
		assert( itemType == KEYMGMT_ITEM_DATA );
		assert( keyIDtype == CRYPT_KEYID_NONE );
		assert( keyID == NULL && keyIDlength == 0 );
		assert( ( auxInfo == NULL && *auxInfoLength == 0 ) || \
				isWritePtr( auxInfo, *auxInfoLength ) );
		assert( isWritePtr( auxInfoLength, sizeof( int ) ) );
		assert( flags == CRYPT_IATTRIBUTE_CONFIGDATA || \
				flags == CRYPT_IATTRIBUTE_USERINDEX || \
				flags == CRYPT_IATTRIBUTE_USERINFO || \
				flags == CRYPT_IATTRIBUTE_TRUSTEDCERT || \
				flags == CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT );

		/* If we're being asked for pre-encoded trusted cert data, return it 
		   to the caller */
		if( flags == CRYPT_IATTRIBUTE_TRUSTEDCERT || \
			flags == CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT )
			{
			return( getTrustedCert( keysetInfo->keyData, 
									keysetInfo->keyDataNoObjects, 
									auxInfo, *auxInfoLength, auxInfoLength,
									( flags == \
										CRYPT_IATTRIBUTE_TRUSTEDCERT ) ? \
										TRUE : FALSE ) );
			}

		/* Return a config data item */
		return( getConfigItem( keysetInfo->keyData, 
							   keysetInfo->keyDataNoObjects, flags, 
							   auxInfo, *auxInfoLength, auxInfoLength ) );
		}

	assert( isWritePtr( iCryptHandle, sizeof( CRYPT_HANDLE ) ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( ( auxInfo == NULL && auxInfoMaxLength == 0 ) || \
			isReadPtr( auxInfo, auxInfoMaxLength ) );

	/* Clear the return values */
	*iCryptHandle = CRYPT_ERROR;

	/* Locate the appropriate object in the PKCS #15 collection and make 
	   sure that the components that we need are present: Either a public 
	   key or a cert for any read, and a private key as well for a private-
	   key read */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, 
							   keysetInfo->keyDataNoObjects, keyIDtype,
							   keyID, keyIDlength, flags );
	if( pkcs15infoPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	if( pkcs15infoPtr->pubKeyData == NULL && \
		pkcs15infoPtr->certData == NULL )
		/* There's not enough information present to get a public key or the
		   public portions of a private key */
		return( CRYPT_ERROR_NOTFOUND );
	if( !publicComponentsOnly && pkcs15infoPtr->privKeyData == NULL )
		/* There's not enough information present to get a private key */
		return( CRYPT_ERROR_NOTFOUND );

	/* If we're just checking whether an object exists, return now.  If all
	   that we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		return( dataCopy( auxInfo, auxInfoMaxLength, auxInfoLength,
						  pkcs15infoPtr->label, 
						  pkcs15infoPtr->labelLength ) );

	/* If we're reading the private key, make sure that the user has
	   supplied a password.  This is checked by the kernel, but we perform
	   another check here just to be safe*/
	if( !publicComponentsOnly && auxInfo == NULL )
		return( CRYPT_ERROR_WRONGKEY );

	/* Read the public components */
	status = readPublicKeyComponents( pkcs15infoPtr, keysetInfo->objectHandle,
									  keyIDtype, keyID, keyIDlength, 
									  publicComponentsOnly,
									  &iCryptContext, &iDataCert,
									  &pubkeyActionFlags, 
									  &privkeyActionFlags );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're only interested in the public components, set the key
	   permissions and exit */
	if( publicComponentsOnly )
		{
		status = setKeyAttributes( iCryptContext, pkcs15infoPtr,
								   ( pkcs15infoPtr->pubKeyData != NULL ) ? \
									 pubkeyActionFlags : CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		*iCryptHandle = iCryptContext;

		return( CRYPT_OK );
		}

	assert( ( pkcs15infoPtr->pubKeyData != NULL || \
			  pkcs15infoPtr->certData != NULL ) && \
			pkcs15infoPtr->privKeyData != NULL );

	/* Set the key label.  We have to do this before we load the key or the
	   key load will be blocked by the kernel */
	if( pkcs15infoPtr->labelLength > 0 )
		{ setMessageData( &msgData, ( void * ) pkcs15infoPtr->label,
						  min( pkcs15infoPtr->labelLength, \
							   CRYPT_MAX_TEXTSIZE ) ); }
	else
		{ setMessageData( &msgData, ( void * ) "Dummy label", 11 ); }
	krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_CTXINFO_LABEL );

	/* Read the private components */
	status = readPrivateKeyComponents( pkcs15infoPtr, iCryptContext, 
									   auxInfo, *auxInfoLength );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Connect the data-only certificate object to the context if it exists.
	   This is an internal object used only by the context so we tell the
	   kernel to mark it as owned by the context only */
	if( iDataCert != CRYPT_ERROR )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETDEPENDENT, 
								  &iDataCert, SETDEP_OPTION_NOINCREF );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
			if( iDataCert != CRYPT_ERROR )
				krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Set the permitted action flags */
	status = setKeyAttributes( iCryptContext, pkcs15infoPtr,
							   privkeyActionFlags );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, MESSAGE_DECREFCOUNT );
		return( status );
		}

	*iCryptHandle = iCryptContext;
	return( CRYPT_OK );
	}

/* Fetch a sequence of certs.  These functions are called indirectly by the
   certificate code to fetch the first and subsequent certs in a cert 
   chain */

static int getItem( PKCS15_INFO *pkcs15info, const int noPkcs15objects, 
					CRYPT_CERTIFICATE *iCertificate, int *stateInfo, 
					const CRYPT_KEYID_TYPE keyIDtype, const void *keyID, 
					const int keyIDlength, const KEYMGMT_ITEM_TYPE itemType, 
					const int options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	const PKCS15_INFO *pkcs15infoPtr;
	BYTE *certDataPtr;
	int tag, status;

	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( stateInfo, sizeof( int ) ) );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID || \
			keyIDtype == CRYPT_KEYIDEX_SUBJECTNAMEID );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( ( options & KEYMGMT_MASK_USAGEOPTIONS ) != \
			KEYMGMT_MASK_USAGEOPTIONS );

	/* Find the appropriate entry based on the ID */
	pkcs15infoPtr = findEntry( pkcs15info, noPkcs15objects, keyIDtype, 
							   keyID, keyIDlength, options );
	if( pkcs15infoPtr == NULL )
		{
		*stateInfo = CRYPT_ERROR;
		return( CRYPT_ERROR_NOTFOUND );
		}
	*stateInfo = pkcs15infoPtr->index;

	/* Import the cert.  This gets somewhat ugly because early drafts of 
	   PKCS #15 wrote the cert as is while the final version wrapped it up
	   in a [0] IMPLICIT tag, so we can run into both the original untagged
	   SEQUENCE form and the newer [0] IMPLICIT SEQUENCE.  To handle this
	   we dynamically replace the tag with the standard SEQUENCE tag and
	   reinstate the original afterwards, this is easier than trying to pass
	   the special-case decoding requirement down through the kernel call */
	certDataPtr = ( BYTE * ) pkcs15infoPtr->certData + \
				  pkcs15infoPtr->certOffset;
	tag = *certDataPtr;
	*certDataPtr = BER_SEQUENCE;
	setMessageCreateObjectIndirectInfo( &createInfo, certDataPtr,
			pkcs15infoPtr->certDataSize - pkcs15infoPtr->certOffset,
			( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
				CERTFORMAT_DATAONLY : CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT, &createInfo,
							  OBJECT_TYPE_CERTIFICATE );
	*certDataPtr = tag;
	if( cryptStatusError( status ) )
		return( status );
	*iCertificate = createInfo.cryptHandle;
	if( pkcs15infoPtr->validFrom <= MIN_TIME_VALUE )
		/* Perform an opportunistic update of the validity info if this 
		   hasn't already been set */
		getValidityInfo( pkcs15info, createInfo.cryptHandle );
	return( CRYPT_OK );
	}

static int getFirstItemFunction( KEYSET_INFO *keysetInfo,
								 CRYPT_CERTIFICATE *iCertificate,
								 int *stateInfo,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength,
								 const KEYMGMT_ITEM_TYPE itemType,
								 const int options )
	{
	PKCS15_INFO *pkcs15info = keysetInfo->keyData;
	const int noPkcs15objects = keysetInfo->keyDataNoObjects;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );
	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( stateInfo, sizeof( int ) ) );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( ( options & KEYMGMT_MASK_USAGEOPTIONS ) != \
			KEYMGMT_MASK_USAGEOPTIONS );

	/* Clear return value */
	*stateInfo = CRYPT_ERROR;

	return( getItem( pkcs15info, noPkcs15objects, iCertificate, stateInfo,
					 keyIDtype, keyID, keyIDlength, itemType, options ) );
	}

static int getNextItemFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	PKCS15_INFO *pkcs15info = keysetInfo->keyData;
	const int noPkcs15objects = keysetInfo->keyDataNoObjects;
	const int lastEntry = *stateInfo;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );
	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( stateInfo, sizeof( int ) ) );
	assert( ( lastEntry >= 0 && lastEntry < noPkcs15objects ) || \
			lastEntry == CRYPT_ERROR );
	assert( ( options & KEYMGMT_MASK_USAGEOPTIONS ) != \
			KEYMGMT_MASK_USAGEOPTIONS );

	/* If the previous cert was the last one, there's nothing left to fetch */
	if( lastEntry == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Safety check */
	if( lastEntry < 0 || lastEntry >= noPkcs15objects )
		retIntError();

	/* Find the cert for which the subjectNameID matches this cert's
	   issuerNameID */
	return( getItem( pkcs15info, noPkcs15objects, iCertificate, stateInfo,
					 CRYPT_KEYIDEX_SUBJECTNAMEID,
					 pkcs15info[ lastEntry ].issuerNameID,
					 pkcs15info[ lastEntry ].issuerNameIDlength,
					 KEYMGMT_ITEM_PUBLICKEY, options ) );
	}

/****************************************************************************
*																			*
*									Add a Key								*
*																			*
****************************************************************************/

/* Check whether we can add anything to the PKCS #15 personality */

static int checkAddInfo( const PKCS15_INFO *pkcs15infoPtr,
						 const CRYPT_HANDLE iCryptHandle,
						 const BOOLEAN isCertChain, 
						 const BOOLEAN privkeyPresent,
						 const BOOLEAN certPresent,
						 const BOOLEAN pkcs15keyPresent,
						 const BOOLEAN pkcs15certPresent,
						 BOOLEAN *isCertUpdate )
	{
	MESSAGE_DATA msgData;
	BOOLEAN unneededCert, unneededKey;
	int status;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptHandle ) );
	assert( isWritePtr( isCertUpdate, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	*isCertUpdate = FALSE;

	/* Check what we can update (if anything) */
	unneededKey = privkeyPresent & pkcs15keyPresent;
	unneededCert = certPresent & pkcs15certPresent;
	if( ( ( unneededCert && !privkeyPresent ) || \
		  ( unneededKey && unneededCert ) ) && \
		pkcs15infoPtr->validTo > MIN_TIME_VALUE )
		{
		time_t validTo;

		/* The cert would be a duplicate, see if it's more recent than the 
		   existing one.  We only perform this check if there's a validTo 
		   time stored for the cert since without this restriction any cert 
		   without a stored time could be overwritten */
		setMessageData( &msgData, &validTo, sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		if( cryptStatusOK( status ) && validTo > pkcs15infoPtr->validTo )
			{
			time_t validFrom;

			/* It's a newer cert, don't treat it as a duplicate.  This check 
			   is effectively impossible to perform automatically since there 
			   are an infinite number of variations that have to be taken 
			   into account (e.g. cert for the same key issued by a different 
			   CA, same CA but it's changed the bits it sets in the keyUsage 
			   (digitalSignature vs.nonRepudiation), slightly different 
			   issuer DN (Thawte certs with a date encoded in the DN), and so 
			   on an so on).  Because it requires manual processing by a 
			   human, we don't even try and sort it all but just allow a cert 
			   for a given key (checked by the ID match) to be replaced by a
			   newer cert for the same key.  This is restrictive enough to 
			   prevent most obviously-wrong replacements, while being 
			   permissive enough to allow most probably-OK replacements */
			unneededCert = FALSE;
			*isCertUpdate = TRUE;

			/* There's one special-case situation in which odd things can 
			   happen when updating certs and that's when adding a future-
			   dated cert, which would result in the cert being replaced with 
			   one that can't be used yet.  There's no clean way to handle 
			   this because in order to know what to do we'd have to be able 
			   to guess the intent of the user, however for anything but 
			   signature certs it's likely that the hit-and-miss cert 
			   checking performed by most software won't even notice a 
			   future-dated cert, and for signature certs the semantics of 
			   signing data now using a cert that isn't valid yet are 
			   somewhat uncertain.  Since in most cases no-one will even 
			   notice the problem, we throw an exception in the debug build 
			   but don't do anything in release builds.  This is probably 
			   less annoying to users than having the code reject an 
			   otherwise-valid future-dated cert */
			setMessageData( &msgData, &validFrom, sizeof( time_t ) );
			status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CERTINFO_VALIDFROM );
			if( cryptStatusOK( status ) && \
				validFrom > getApproxTime() + 86400L )
				{
				assert( !"Attempt to replace cert with future-dated cert" );
				}
			}
		}

	/* Make sure that we can update at least one of the objects in the PKCS 
	   #15 personality */
	if( ( unneededKey && !certPresent ) ||		/* Key only, duplicate */
		( unneededCert && !privkeyPresent ) ||	/* Cert only, duplicate */
		( unneededKey && unneededCert ) )		/* Key+cert, duplicate */
		{
		/* If it's anything other than a cert chain, we can't add anything */
		if( !isCertChain )
			return( CRYPT_ERROR_DUPLICATE );

		/* Tell the caller that it's an opportunistic cert-chain update */
		return( OK_SPECIAL );
		}

	return( CRYPT_OK );
	}

/* Add an item to the PKCS #15 keyset */

static int setItemFunction( KEYSET_INFO *keysetInfo,
							const CRYPT_HANDLE cryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const char *password, const int passwordLength,
							const int flags )
	{
	CRYPT_CERTIFICATE iCryptCert;
	PKCS15_INFO *pkcs15info = keysetInfo->keyData, *pkcs15infoPtr;
	MESSAGE_DATA msgData;
	BYTE iD[ CRYPT_MAX_HASHSIZE + 8 ];
	BOOLEAN certPresent = FALSE, privkeyPresent;
	BOOLEAN pkcs15certPresent = FALSE, pkcs15keyPresent = FALSE;
	BOOLEAN isCertChain = FALSE, isCertUpdate = FALSE;
	const int noPkcs15objects = keysetInfo->keyDataNoObjects;
	int pkcs15index = CRYPT_ERROR, iDsize, value, status;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );
	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( ( cryptHandle == CRYPT_UNUSED ) || \
			isHandleRangeValid( cryptHandle ) );
	assert( itemType == KEYMGMT_ITEM_DATA || \
			itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );

	/* If we're being sent pre-encoded data or a secret key, add it to the
	   PKCS #15 data and exit */
	if( cryptHandle == CRYPT_UNUSED )
		{
		assert( itemType == KEYMGMT_ITEM_DATA );

		return( addConfigData( pkcs15info, noPkcs15objects, password, 
							   passwordLength, flags ) );
		}
	if( itemType == KEYMGMT_ITEM_SECRETKEY )
		return( addSecretKey( pkcs15info, noPkcs15objects, cryptHandle ) );

	assert( isHandleRangeValid( cryptHandle ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );
	assert( ( itemType == KEYMGMT_ITEM_PUBLICKEY && \
			  password == NULL && passwordLength == 0 ) || \
			( itemType == KEYMGMT_ITEM_PRIVATEKEY && \
			  isReadPtr( password, passwordLength ) ) );

	/* Check the object, extract ID information from it, and determine
	   whether it's a standalone cert (which produces a PKCS #15 cert
	   object) or a private-key context (which produces a PKCS #15 private
	   key object and either a PKCS #15 public-key object (if there's no
	   cert present) or a cert object (if there's a cert present)).

	   Note that we don't allow the addition of standalone public keys
	   (without corresponding private keys) since file keysets are private-
	   key keysets and not general-purpose public key exchange mechanisms.
	   Without this safeguard, some users would use them as a type of
	   unsigned certificate for exchanging public keys.  In addition,
	   allowing the storage of standalone public keys is rather problematic
	   since they need to have a label attached in order to be identified,
	   so performing a public-key add with a private-key context would
	   work but performing one with a public-key context would fail.  A 
	   certificate update on this public-key-only item would result in the 
	   presence a private-key-labelled certificate, which is even more 
	   strange for users to comprehend.  To keep things sensible, we 
	   therefore disallow the addition of standalone public keys */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, iD, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		iDsize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	privkeyPresent = cryptStatusOK( \
			krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							 MESSAGE_CHECK_PKC_PRIVATE ) ) ? TRUE : FALSE;

	/* If we're adding a private key, make sure that there's a context and a
	   password present.  Conversely, if we're adding a public key, make
	   sure that there's no password present.  The password-check has
	   already been performed by the kernel but we perform a second check
	   here just to be safe.  The private-key check can't be performed by
	   the kernel since it doesn't know the difference between public- and
	   private-key contexts */
	switch( itemType )
		{
		case KEYMGMT_ITEM_PUBLICKEY:
			if( privkeyPresent )
				return( CRYPT_ARGERROR_NUM1 );
			if( password != NULL )
				return( CRYPT_ARGERROR_STR1 );
			break;

		case KEYMGMT_ITEM_PRIVATEKEY:
			if( !privkeyPresent )
				return( CRYPT_ARGERROR_NUM1 );
			if( password == NULL )
				return( CRYPT_ARGERROR_STR1 );
			break;
		
		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_INTERNAL );
		}

	/* If there's a cert present, make sure that it's something that can be
	   stored.  We don't treat the wrong type as an error since we can still
	   store the public/private key components even if we don't store the
	   cert */
	if( cryptStatusOK( \
		krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_CERTINFO_CERTTYPE ) ) && \
		( value == CRYPT_CERTTYPE_CERTIFICATE || \
		  value == CRYPT_CERTTYPE_CERTCHAIN ) )
		{
		/* If it's a cert chain, remember this for later since we may
		   need to store multiple certs */
		if( value == CRYPT_CERTTYPE_CERTCHAIN )
			isCertChain = TRUE;

		/* If the cert isn't signed, we can't store it in this state */
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ERROR_NOTINITED );
		krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT, &iCryptCert,
						 OBJECT_TYPE_CERTIFICATE );
		certPresent = TRUE;
		}

	/* Find out where we can add data and what needs to be added.  The 
	   strategy for adding items is:

										Existing
			New		|	None	| Priv+Pub	| Priv+Cert	|	Cert	|
		------------+-----------+-----------+-----------+-----------+
		Priv + Pub	|	Add		|	----	|	----	|	Add		|
					|			|			|			|			|
		Priv + Cert	|	Add		| Repl.pubk	| Add cert	| Add cert	|
					|			| with cert	| if newer	| if newer	|
		Cert		| If trusted|	Add		| Add cert	| Add cert	|
					|			|			| if newer	| if newer	|
		------------+-----------+-----------+-----------+-----------+

	   We don't check for the addition of a trusted cert at this point since 
	   it could be buried in the middle of a cert chain, so we leave the 
	   checking to addCertChain() */
	pkcs15infoPtr = findEntry( pkcs15info, noPkcs15objects, CRYPT_KEYIDEX_ID,
							   iD, iDsize, KEYMGMT_FLAG_NONE );
	if( pkcs15infoPtr != NULL )
		{
		/* Determine what actually needs to be added */
		if( pkcs15infoPtr->privKeyData != NULL )
			pkcs15keyPresent = TRUE;
		if( pkcs15infoPtr->certData != NULL )
			pkcs15certPresent = TRUE;

		/* See what we can add */
		status = checkAddInfo( pkcs15infoPtr, cryptHandle, isCertChain, 
							   privkeyPresent, certPresent, 
							   pkcs15keyPresent, pkcs15certPresent,
							   &isCertUpdate );
		if( cryptStatusError( status ) )
			{
			/* If it's not an OK_SPECIAL status telling us that we can still 
			   try for an opportunistic cert chain add, exit */
			if( status != OK_SPECIAL )
				return( status );
			
			/* In theory we can't add anything, however since we've been 
			   given a cert chain there may be new certs present, so we can 
			   try and add them opportunistically */
			status = krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_TRUE,
									  CRYPT_IATTRIBUTE_LOCKED );
			if( cryptStatusError( status ) )
				return( status );
			status = addCertChain( pkcs15infoPtr, noPkcs15objects, 
								   cryptHandle );
			krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
			return( status );
			}
		}
	else
		{
		/* This key/cert isn't already present, make sure that the label of
		   what we're adding doesn't duplicate the label of an existing
		   object */
		if( privkeyPresent )
			{
			char label[ CRYPT_MAX_TEXTSIZE + 8 ];

			setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CTXINFO_LABEL );
			if( cryptStatusError( status ) )
				return( status );
			if( findEntry( pkcs15info, noPkcs15objects, CRYPT_KEYID_NAME,
						   msgData.data, msgData.length,
						   KEYMGMT_FLAG_NONE ) != NULL )
				return( CRYPT_ERROR_DUPLICATE );
			}

		/* Find out where we can add the new key data */
		pkcs15infoPtr = findFreeEntry( pkcs15info, noPkcs15objects, 
									   &pkcs15index );
		if( pkcs15infoPtr == NULL )
			return( CRYPT_ERROR_OVERFLOW );
		}

	/* We're ready to go, lock the object for our exclusive use */
	if( certPresent )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE,
								  CRYPT_IATTRIBUTE_LOCKED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the key data.  This will add the public/private key and any cert 
	   data associated with the key as required */
	status = addKey( pkcs15infoPtr, cryptHandle, password, passwordLength,
					 keysetInfo->ownerHandle, privkeyPresent, certPresent, 
					 ( isCertUpdate || !pkcs15certPresent ) ? TRUE : FALSE,
					 pkcs15keyPresent );
	if( cryptStatusError( status ) )
		{
		if( certPresent )
			krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
		return( status );
		}

	/* The update was successful, update the type and index info if this was
	   a newly-created entry */
	if( pkcs15index != CRYPT_ERROR )
		{
		pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
		pkcs15infoPtr->index = pkcs15index;
		}

	/* If we've been given a cert chain, try and add opportunistically add 
	   any further certs that may be present in it.  Error handling once we
	   get this far gets a bit tricky, we can still get an error at this 
	   point if the cert chain update fails even if the main cert add 
	   succeeded, however it's uncertain whether we should still report an 
	   error when the main intended update (of the private key and public 
	   key or cert) succeeded.  Since the primary items to be added are the 
	   keys and a corresponding certificate (as handled in addKey()), we 
	   don't report an error if adding one of the coincidental certs fails, 
	   since the primary items were added successfully */
	if( isCertChain )
		addCertChain( pkcs15infoPtr, noPkcs15objects, cryptHandle );

	/* Clean up */
	if( certPresent )
		krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	return( status );
	}

/****************************************************************************
*																			*
*									Delete a Key							*
*																			*
****************************************************************************/

static int deleteItemFunction( KEYSET_INFO *keysetInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	PKCS15_INFO *pkcs15infoPtr;

	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) && \
			keysetInfo->type == KEYSET_FILE && \
			keysetInfo->subType == KEYSET_SUBTYPE_PKCS15 );
	assert( itemType > KEYMGMT_ITEM_NONE && \
			itemType < KEYMGMT_ITEM_LAST );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( isReadPtr( keyID, keyIDlength ) );

	/* Locate the appropriate object in the PKCS #15 collection */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, 
							   keysetInfo->keyDataNoObjects, keyIDtype, 
							   keyID, keyIDlength, KEYMGMT_FLAG_NONE );
	if( pkcs15infoPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* Clear this entry */
	pkcs15freeEntry( pkcs15infoPtr );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodPKCS15( KEYSET_INFO *keysetInfo )
	{
	assert( isWritePtr( keysetInfo, sizeof( KEYSET_INFO ) ) );

	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->getFirstItemFunction = getFirstItemFunction;
	keysetInfo->getNextItemFunction = getNextItemFunction;
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_PKCS15 */
