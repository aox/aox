/****************************************************************************
*																			*
*						  cryptlib PKCS #15 Routines						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

/* The format used to protect the private key components is a standard
   cryptlib envelope, however for various reasons the required enveloping
   functionality (which in practice is just minimal code to process a 
   PasswordRecipientInfo at the start of the data) is duplicated here:

	1. It's somewhat inelegant to use the heavyweight enveloping routines to
	   wrap up 100 bytes of data.
	2. The enveloping code is enormous and complex, especially when extra
	   sections like zlib and PGP and S/MIME support are factored in.  This
	   makes it difficult to compile a stripped-down version of cryptlib,
	   since private key storage will require all the enveloping code to be
	   included.
	3. Since the enveloping code is general-purpose, it doesn't allow very
	   precise control over the data being processed.  Specifically, it's
	   necessary to write the private key components to a buffer in plaintext
	   form, which isn't permitted by the cryptlib kernel.

   For these reasons this module includes the code to process minimal
   (password-encrypted data) envelopes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/* OID information used to read a PKCS #15 file */

static const FAR_BSS CMS_CONTENT_INFO oidInfoPkcs15Data = { 0, 0 };
static const FAR_BSS OID_INFO keyFileOIDinfo[] = {
	{ OID_PKCS15_CONTENTTYPE, CRYPT_OK, &oidInfoPkcs15Data },
	{ NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Locate an object based on an ID */

#define matchID( src, srcLen, dest, destLen ) \
		( ( srcLen ) == ( destLen ) && \
		  !memcmp( ( src ), ( dest ), ( destLen ) ) )

PKCS15_INFO *findEntry( const PKCS15_INFO *pkcs15info,
						const CRYPT_KEYID_TYPE keyIDtype,
						const void *keyID, const int keyIDlength,
						const int requestedUsage )
	{
	int i;

	assert( isReadPtr( pkcs15info, sizeof( PKCS15_INFO ) * \
								   MAX_PKCS15_OBJECTS ) );
	assert( keyIDlength == 0 || isReadPtr( keyID, keyIDlength ) );
	assert( ( requestedUsage & KEYMGMT_MASK_USAGEOPTIONS ) != \
			KEYMGMT_MASK_USAGEOPTIONS );

	/* If there's no ID to search on, don't try and do anything (this can
	   occur when we're trying to build a chain and the necessary chaining
	   data isn't present) */
	if( keyIDlength == 0 )
		return( NULL );

	/* Try and locate the appropriate object in the PKCS #15 collection */
	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		{
		const PKCS15_INFO *pkcs15infoPtr = &pkcs15info[ i ];
		const int compositeUsage = pkcs15infoPtr->pubKeyUsage | \
								   pkcs15infoPtr->privKeyUsage;

		/* If there's no entry at this position, continue */
		if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
			continue;

		/* If there's an explicit usage requested, make sure the key usage
		   matches this.  This can get slightly complex since the advertised
		   usage isn't necessarily the same as the usage permitted by the
		   associated cert (PKCS #11 apps are particularly good at setting
		   bogus usage types) and the overall result can be further
		   influenced by trusted usage settings, all we check for here is
		   an indicated usage for the key matching the requested usage */
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
			}
		}

	/* If we're trying to match on the PGP key ID and didn't find anything,
	   retry it using the first PGP_KEYID_SIZE bytes of the object ID.  This
	   is necessary because calculation of the OpenPGP ID requires the
	   presence of data that may not be present in non-PGP keys, so we can't
	   calculate a real OpenPGP ID but have to use the next-best thing */
	if( keyIDtype == CRYPT_IKEYID_PGPKEYID )
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].iDlength >= PGP_KEYID_SIZE && \
				!memcmp( keyID, pkcs15info[ i ].iD, PGP_KEYID_SIZE ) )
				return( ( PKCS15_INFO * ) &pkcs15info[ i ] );

	return( NULL );
	}

/* Free object entries */

void pkcs15freeEntry( PKCS15_INFO *pkcs15info )
	{
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

void pkcs15Free( PKCS15_INFO *pkcs15info )
	{
	int i;

	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) * \
									MAX_PKCS15_OBJECTS ) );

	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		pkcs15freeEntry( &pkcs15info[ i ] );
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS );
	}

/* Get the PKCS #15 validity information from a certificate */

int getValidityInfo( PKCS15_INFO *pkcs15info,
					 const CRYPT_HANDLE cryptHandle )
	{
	RESOURCE_DATA msgData;
	time_t validFrom, validTo;
	int status;

	/* Remember the validity information for later.  Note that we always
	   update the validity (even if it's already set) since we may be
	   replacing an older cert with a newer one */
	setMessageData( &msgData, &validFrom, sizeof( time_t ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDFROM );
	setMessageData( &msgData, &validTo, sizeof( time_t ) );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
	if( cryptStatusError( status ) )
		{
		/* There wasn't any standard validity info present, try for PGP
		   validity info */
		setMessageData( &msgData, &validFrom, sizeof( time_t ) );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_PGPVALIDITY );
		validTo = 0;
		}
	if( cryptStatusError( status ) )
		return( status );
	if( pkcs15info->validTo > validTo )
		/* There's an existing, newer cert already present, make sure we
		   don't try and add the new one */
		return( CRYPT_ERROR_DUPLICATE );
	pkcs15info->validFrom = validFrom;
	pkcs15info->validTo = validTo;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							PKCS #15 Init Functions							*
*																			*
****************************************************************************/

/* A PKCS #15 keyset can contain multiple keys and whatnot, so when we open
   it we parse the contents into memory for later use */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const CRYPT_KEYOPT_TYPE options )
	{
	PKCS15_INFO *pkcs15info;
	long endPos;
	int status;

	assert( name == NULL );

	/* If we're opening an existing keyset, skip the outer header, optional 
	   keyManagementInfo, and inner header.  We do this before we perform any
	   setup operations to weed out potential problem files */
	if( options != CRYPT_KEYOPT_CREATE )
		{
		STREAM *stream = &keysetInfo->keysetFile->stream;
		long dataEndPos;

		status = readCMSheader( stream, keyFileOIDinfo, &dataEndPos, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		endPos = dataEndPos + ( stell( stream ) - sizeofShortInteger( 0 ) );
		if( dataEndPos < 16 || dataEndPos > MAX_INTLENGTH || \
			endPos < 16 || endPos > MAX_INTLENGTH )
			/* Make sure that the length info is sensible */
			return( CRYPT_ERROR_BADDATA );
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
		return( CRYPT_ERROR_MEMORY );
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS );
	keysetInfo->keyData = pkcs15info;
	keysetInfo->keyDataSize = sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* Read all of the keys in the keyset */
	status = readKeyset( &keysetInfo->keysetFile->stream, pkcs15info, 
						 endPos );
	if( cryptStatusError( status ) )
		{
		pkcs15Free( pkcs15info );
		clFree( "initFunction", keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		keysetInfo->keyDataSize = 0;
		}

	return( status );
	}

/****************************************************************************
*																			*
*						PKCS #15 Shutdown Functions							*
*																			*
****************************************************************************/

/* Write the wrapping needed for individual objects */

static void writeObjectWrapper( STREAM *stream, const int length,
								const int tag )
	{
	writeConstructed( stream, ( int ) sizeofObject( length ), tag );
	writeConstructed( stream, length, CTAG_OV_DIRECT );
	assert( sStatusOK( stream ) );
	}

/* Write a data item */

static int sizeofDataItem( const PKCS15_INFO *pkcs15infoPtr )
	{
	const int dataSize = \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO ) ? \
				pkcs15infoPtr->dataDataSize : \
				( int ) sizeofObject( pkcs15infoPtr->dataDataSize );
	const int labelSize = \
			( pkcs15infoPtr->labelLength ) ? \
				( int ) sizeofObject( pkcs15infoPtr->labelLength ) : 0;

	return( ( int ) \
		sizeofObject( \
			sizeofObject( labelSize ) + \
			sizeofObject( sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) ) + \
			sizeofObject( \
				sizeofObject( \
					sizeofOID( OID_CRYPTLIB_CONFIGDATA ) + dataSize ) ) ) );
	}

static void writeDataItem( STREAM *stream, const PKCS15_INFO *pkcs15infoPtr )
	{
	const BYTE *oid = \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_CONFIGDATA ) ? \
				OID_CRYPTLIB_CONFIGDATA : \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINDEX ) ? \
				OID_CRYPTLIB_USERINDEX : OID_CRYPTLIB_USERINFO;
	const int labelSize = \
			( pkcs15infoPtr->labelLength ) ? \
				( int ) sizeofObject( pkcs15infoPtr->labelLength ) : 0;
	const int contentSize = sizeofOID( oid ) + \
			( ( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO ) ? \
				pkcs15infoPtr->dataDataSize : \
				( int ) sizeofObject( pkcs15infoPtr->dataDataSize ) );

	assert( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_CONFIGDATA || \
			pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINDEX || \
			pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO );

	writeConstructed( stream, \
			( int ) sizeofObject( labelSize ) + \
			( int ) sizeofObject( sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) ) + \
			( int ) sizeofObject( sizeofObject( contentSize ) ),
			CTAG_DO_OIDDO );
	writeSequence( stream, labelSize );
	if( labelSize )
		writeCharacterString( stream, ( BYTE * ) pkcs15infoPtr->label,
							  pkcs15infoPtr->labelLength, BER_STRING_UTF8 );
	writeSequence( stream, sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) );
	writeOID( stream, OID_CRYPTLIB_CONTENTTYPE );
	writeConstructed( stream, ( int ) sizeofObject( contentSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( stream, contentSize );
	writeOID( stream, oid );
	if( pkcs15infoPtr->dataType != CRYPT_IATTRIBUTE_USERINFO )
		/* UserInfo is a straight object, the others are SEQUENCEs of
		   objects */
		writeSequence( stream, pkcs15infoPtr->dataDataSize );
	swrite( stream, pkcs15infoPtr->dataData, pkcs15infoPtr->dataDataSize );
	assert( sStatusOK( stream ) );
	}

/* Flush a PKCS #15 collection to a stream */

static int pkcs15Flush( STREAM *stream, const PKCS15_INFO *pkcs15info )
	{
	int pubKeySize = 0, privKeySize = 0, certSize = 0, dataSize = 0;
	int objectsSize = 0, i;

	/* Determine the overall size of the objects */
	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		switch( pkcs15info[ i ].type )
			{
			case PKCS15_SUBTYPE_NONE:
				break;

			case PKCS15_SUBTYPE_NORMAL:
				pubKeySize += pkcs15info[ i ].pubKeyDataSize;
				privKeySize += pkcs15info[ i ].privKeyDataSize;
				/* Drop through */

			case PKCS15_SUBTYPE_CERT:
				certSize += pkcs15info[ i ].certDataSize;
				break;

			case PKCS15_SUBTYPE_SECRETKEY:
				assert( NOTREACHED );
				break;

			case PKCS15_SUBTYPE_DATA:
				dataSize += sizeofDataItem( &pkcs15info[ i ] );
				break;

			default:
				assert( NOTREACHED );
			}

	/* Determine how much data there is to write.  If there's no data
	   present, let the caller know that the keyset is empty */
	objectsSize = \
		( pubKeySize > 0 ? \
			( int ) sizeofObject( sizeofObject( pubKeySize ) ) : 0 ) +
		( privKeySize > 0 ? \
			( int ) sizeofObject( sizeofObject( privKeySize ) ) : 0 ) +
		( certSize > 0 ? \
			( int ) sizeofObject( sizeofObject( certSize ) ) : 0 ) +
		( dataSize > 0 ? \
			( int ) sizeofObject( sizeofObject( dataSize ) ) : 0 );
	if( objectsSize <= 0 )
		return( OK_SPECIAL );

	/* Write the header information and each public key, private key, and
	   cert */
	writeCMSheader( stream, OID_PKCS15_CONTENTTYPE,
					sizeofShortInteger( 0 ) + sizeofObject( objectsSize ),
					FALSE );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeSequence( stream, objectsSize );
	if( privKeySize > 0 )
		{
		writeObjectWrapper( stream, privKeySize, PKCS15_OBJECT_PRIVKEY );
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].privKeyDataSize > 0 )
				swrite( stream, pkcs15info[ i ].privKeyData,
						pkcs15info[ i ].privKeyDataSize );
		}
	if( pubKeySize > 0 )
		{
		writeObjectWrapper( stream, pubKeySize, PKCS15_OBJECT_PUBKEY );
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].pubKeyDataSize > 0 )
				swrite( stream, pkcs15info[ i ].pubKeyData,
						pkcs15info[ i ].pubKeyDataSize );
		}
	if( certSize > 0 )
		{
		writeObjectWrapper( stream, certSize, PKCS15_OBJECT_CERT );
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( ( pkcs15info[ i ].type == PKCS15_SUBTYPE_NORMAL && \
				  pkcs15info[ i ].certDataSize > 0 ) || \
				( pkcs15info[ i ].type == PKCS15_SUBTYPE_CERT ) )
				swrite( stream, pkcs15info[ i ].certData,
						pkcs15info[ i ].certDataSize );
		}
	if( dataSize > 0 )
		{
		writeObjectWrapper( stream, dataSize, PKCS15_OBJECT_DATA );

		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].dataDataSize > 0 )
				writeDataItem( stream, &pkcs15info[ i ] );
		}
	assert( sStatusOK( stream ) );

	return( sflush( stream ) );
	}

/* Shut down the PKCS #15 state, flushing information to disk if necessary */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	/* If the contents have been changed, commit the changes to disk */
	if( keysetInfo->flags & KEYSET_DIRTY )
		{
		BYTE buffer[ STREAM_BUFSIZE ];
		int status;

		sseek( &keysetInfo->keysetFile->stream, 0 );
		sioctl( &keysetInfo->keysetFile->stream, 
				STREAM_IOCTL_IOBUFFER, buffer, STREAM_BUFSIZE );
		status = pkcs15Flush( &keysetInfo->keysetFile->stream,
							  keysetInfo->keyData );
		sioctl( &keysetInfo->keysetFile->stream, 
				STREAM_IOCTL_IOBUFFER, NULL, 0 );
		if( status == OK_SPECIAL )
			keysetInfo->flags |= KEYSET_EMPTY;
		}

	/* Free the PKCS #15 object info */
	if( keysetInfo->keyData != NULL )
		{
		pkcs15Free( keysetInfo->keyData );
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		clFree( "shutdownFunction", keysetInfo->keyData );
		}
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

	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( keyID != NULL ); assert( keyIDlength >= 1 );

	/* Locate the appropriate object in the PKCS #15 collection */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, keyIDtype, keyID,
							   keyIDlength, KEYMGMT_FLAG_NONE );
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
	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;
	initPKCS15read( keysetInfo );
	initPKCS15write( keysetInfo );

	return( CRYPT_OK );
	}
#endif /* USE_PKCS15 */
