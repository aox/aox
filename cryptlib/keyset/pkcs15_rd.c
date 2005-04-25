/****************************************************************************
*																			*
*						cryptlib PKCS #15 Read Routines						*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

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

/* The minimum size of an object in a keyset, used for sanity-checking when
   reading a keyset */

#define MIN_OBJECT_SIZE		16

/* OID information used to read a PKCS #15 file */

static const FAR_BSS OID_INFO dataOIDinfo[] = {
	{ OID_CMS_DATA, CRYPT_OK },
	{ NULL, 0 }
	};

static const FAR_BSS OID_INFO cryptlibDataOIDinfo[] = {
	{ OID_CRYPTLIB_CONFIGDATA, CRYPT_IATTRIBUTE_CONFIGDATA },
	{ OID_CRYPTLIB_USERINDEX, CRYPT_IATTRIBUTE_USERINDEX },
	{ OID_CRYPTLIB_USERINFO, CRYPT_IATTRIBUTE_USERINFO },
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

	return( !actionFlags ? CRYPT_ERROR_PERMISSION : actionFlags );
	}

/****************************************************************************
*																			*
*							Read PKCS #15 Attributes						*
*																			*
****************************************************************************/

/* Read a sequence of PKCS #15 key identifiers */

static int readKeyIdentifiers( STREAM *stream, PKCS15_INFO *pkcs15info,
							   const int length )
	{
	const int endPos = stell( stream ) + length;
	int status = CRYPT_OK;

	while( cryptStatusOK( status ) && stell( stream ) < endPos )
		{
		HASHFUNCTION hashFunction;
		void *iAndSPtr;
		long value;
		int hashSize, payloadLength, iAndSLength;

		/* Read each identifier type and copy the useful ones into the PKCS
		   #15 info */
		readSequence( stream, &payloadLength );
		status = readShortInteger( stream, &value );
		if( cryptStatusError( status ) )
			break;
		switch( value )
			{
			case PKCS15_KEYID_ISSUERANDSERIALNUMBER:
				/* Hash the full issuerAndSerialNumber to get an iAndSID */
				getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
				iAndSPtr = sMemBufPtr( stream );
				status = readSequence( stream, &iAndSLength );
				if( cryptStatusOK( status ) )
					status = sSkip( stream, iAndSLength );
				if( cryptStatusError( status ) )
					break;
				hashFunction( NULL, ( BYTE * ) pkcs15info->iAndSID, iAndSPtr,
							  ( int ) sizeofObject( iAndSLength ), HASH_ALL );
				pkcs15info->iAndSIDlength = hashSize;
				break;

			case PKCS15_KEYID_SUBJECTKEYIDENTIFIER:
				status = readOctetString( stream, pkcs15info->keyID,
								&pkcs15info->keyIDlength, CRYPT_MAX_HASHSIZE );
				break;

			case PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH:
				/* If we've already got the iAndSID by hashing the
				   issuerAndSerialNumber, use that version instead */
				if( pkcs15info->iAndSIDlength )
					{
					readUniversal( stream );
					continue;
					}
				status = readOctetString( stream, pkcs15info->iAndSID,
								&pkcs15info->iAndSIDlength, KEYID_SIZE );
				break;

			case PKCS15_KEYID_ISSUERNAMEHASH:
				status = readOctetString( stream, pkcs15info->issuerNameID,
								&pkcs15info->issuerNameIDlength, KEYID_SIZE );
				break;

			case PKCS15_KEYID_SUBJECTNAMEHASH:
				status = readOctetString( stream, pkcs15info->subjectNameID,
								&pkcs15info->subjectNameIDlength, KEYID_SIZE );
				break;

			case PKCS15_KEYID_PGP2:
				status = readOctetString( stream, pkcs15info->pgp2KeyID,
								&pkcs15info->pgp2KeyIDlength, PGP_KEYID_SIZE );
				break;

			case PKCS15_KEYID_OPENPGP:
				status = readOctetString( stream, pkcs15info->openPGPKeyID,
								&pkcs15info->openPGPKeyIDlength, PGP_KEYID_SIZE );
				break;

			default:
				status = readUniversal( stream );
			}
		}

	return( status );
	}

/* Read an object's attributes */

static int readObjectAttributes( STREAM *stream, PKCS15_INFO *pkcs15info,
								 const PKCS15_OBJECT_TYPE type )
	{
	int length, endPos, status;

	/* Clear the return value */
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) );

	/* Skip the outer header, which has already been checked when we read in
	   the object data */
	readGenericHole( stream, NULL, DEFAULT_TAG );

	/* Process the PKCS15CommonObjectAttributes */
	status = readSequence( stream, &length );
	if( cryptStatusOK( status ) && length > 0 )
		{
		endPos = stell( stream ) + length;

		/* Read the label if it's present and skip anything else */
		if( peekTag( stream ) == BER_STRING_UTF8 )
			status = readCharacterString( stream,
						( BYTE * ) pkcs15info->label, &pkcs15info->labelLength,
						CRYPT_MAX_TEXTSIZE, BER_STRING_UTF8 );
		if( cryptStatusOK( status ) && stell( stream ) < endPos )
			status = sseek( stream, endPos );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Process the PKCS15CommonXXXAttributes */
	readSequence( stream, &length );
	endPos = stell( stream ) + length;
	if( type == PKCS15_OBJECT_DATA )
		{
		/* It's a data object, make sure it's one of ours */
		status = readFixedOID( stream, OID_CRYPTLIB_CONTENTTYPE );
		if( cryptStatusOK( status ) && stell( stream ) < endPos )
			status = sseek( stream, endPos );
		}
	else
		{
		/* It's a key or cert object, read the ID and assorted flags */
		status = readOctetString( stream, pkcs15info->iD,
								  &pkcs15info->iDlength, CRYPT_MAX_HASHSIZE );
		if( cryptStatusError( status ) )
			return( status );
		if( type == PKCS15_OBJECT_PUBKEY || type == PKCS15_OBJECT_PRIVKEY )
			{
			int usageFlags;

			readBitString( stream, &usageFlags );		/* Usage flags */
			if( peekTag( stream ) == BER_BOOLEAN )		/* Native flag */
				status = readUniversal( stream );
			if( stell( stream ) < endPos &&				/* Access flags */
				peekTag( stream ) == BER_BITSTRING )
				status = readUniversal( stream );
			if( stell( stream ) < endPos &&				/* Key reference */
				peekTag( stream ) == BER_INTEGER )
				status = readUniversal( stream );
			if( stell( stream ) < endPos &&				/* Start date */
				peekTag( stream ) == BER_TIME_GENERALIZED )
				status = readGeneralizedTime( stream, 
									&pkcs15info->validFrom );
			if( stell( stream ) < endPos &&				/* End date */
				peekTag( stream ) == MAKE_CTAG( CTAG_KA_VALIDTO ) )
				status = readGeneralizedTimeTag( stream, 
									&pkcs15info->validTo, CTAG_KA_VALIDTO );
			if( type == PKCS15_OBJECT_PUBKEY )
				pkcs15info->pubKeyUsage = usageFlags;
			else
				pkcs15info->privKeyUsage = usageFlags;
			}
		else
			if( type == PKCS15_OBJECT_CERT )
				{
				if( peekTag( stream ) == BER_BOOLEAN )	/* Authority flag */
					status = readUniversal( stream );
				if( stell( stream ) < endPos &&			/* Identifier */
					peekTag( stream ) == BER_SEQUENCE )
					status = readUniversal( stream );
				if( stell( stream ) < endPos &&			/* Thumbprint */
					peekTag( stream ) == MAKE_CTAG( CTAG_CA_DUMMY ) )
					status = readUniversal( stream );
				if( stell( stream ) < endPos &&			/* Trusted usage */
					peekTag( stream ) == MAKE_CTAG( CTAG_CA_TRUSTED_USAGE ) )
					{
					readConstructed( stream, NULL, CTAG_CA_TRUSTED_USAGE );
					status = readBitString( stream, &pkcs15info->trustedUsage );
					}
				if( stell( stream ) < endPos &&			/* Identifiers */
					peekTag( stream ) == MAKE_CTAG( CTAG_CA_IDENTIFIERS ) )
					{
					status = readConstructed( stream, &length, 
											  CTAG_CA_IDENTIFIERS );
					if( cryptStatusOK( status ) )
						status = readKeyIdentifiers( stream, pkcs15info, 
													 length );
					}
				if( stell( stream ) < endPos &&			/* Implicitly trusted */
					peekTag( stream ) == \
							MAKE_CTAG_PRIMITIVE( CTAG_CA_TRUSTED_IMPLICIT ) )
					status = readBooleanTag( stream,
											 &pkcs15info->implicitTrust,
											 CTAG_CA_TRUSTED_IMPLICIT );
				if( peekTag( stream ) == MAKE_CTAG( CTAG_CA_VALIDTO ) )
					{
					/* Due to miscommunication between PKCS #15 and 7816-15,
					   there are two ways to encode the validity information
					   for certs, one based on the format used elsewhere in
					   PKCS #15 (for PKCS #15) and the other based on the 
					   format used in certs (for 7816-15).  Luckily they can
					   be distinguished by the tagging type */
					readConstructed( stream, NULL, CTAG_CA_VALIDTO );
					readUTCTime( stream, &pkcs15info->validFrom );
					status = readUTCTime( stream, &pkcs15info->validTo );
					}
				else
					{
					if( stell( stream ) < endPos &&		/* Start date */
						peekTag( stream ) == BER_TIME_GENERALIZED )
						status = readGeneralizedTime( stream, 
									&pkcs15info->validFrom );
					if( stell( stream ) < endPos &&		/* End date */
						peekTag( stream ) == MAKE_CTAG_PRIMITIVE( CTAG_CA_VALIDTO ) )
						status = readGeneralizedTimeTag( stream, 
														 &pkcs15info->validTo, 
													 CTAG_CA_VALIDTO );
					}
				}
		if( cryptStatusOK( status ) && stell( stream ) < endPos )
			status = sseek( stream, endPos );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* For now we use the iD as the keyID, this may be overridden later if
	   there's a real keyID present */
	memcpy( pkcs15info->keyID, pkcs15info->iD, pkcs15info->iDlength );
	pkcs15info->keyIDlength = pkcs15info->iDlength;

	/* Skip the public/private key attributes if present */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_OB_SUBCLASSATTR ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the type attributes, which just consists of remembering where
	   the payload starts */
	readConstructed( stream, NULL, CTAG_OB_TYPEATTR );
	status = readSequence( stream, &length );
	endPos = stell( stream ) + length;
	if( cryptStatusOK( status ) )
		{
		int value;

		switch( type )
			{
			case PKCS15_OBJECT_PUBKEY:
				readConstructed( stream, NULL, CTAG_OV_DIRECT );
				pkcs15info->pubKeyOffset = stell( stream );
				break;

			case PKCS15_OBJECT_PRIVKEY:
				pkcs15info->privKeyOffset = stell( stream );
				break;

			case PKCS15_OBJECT_CERT:
			case PKCS15_OBJECT_TRUSTEDCERT:
			case PKCS15_OBJECT_USEFULCERT:
				pkcs15info->certOffset = stell( stream );
				break;

			case PKCS15_OBJECT_DATA:
				readOID( stream, cryptlibDataOIDinfo, &value );
				if( value != CRYPT_IATTRIBUTE_USERINFO )
					/* UserInfo is a straight object, the others are
					   SEQUENCEs of objects */
					readSequence( stream, NULL );
				pkcs15info->dataType = value;
				pkcs15info->dataOffset = stell( stream );
				break;
			}
		if( cryptStatusOK( status ) && stell( stream ) < endPos )
			status = sseek( stream, endPos );
		}

	return( status );
	}

/* Read an entire keyset */

int readKeyset( STREAM *stream, PKCS15_INFO *pkcs15info, const long endPos )
	{
	int status = CRYPT_OK;

	/* Scan all the objects in the file.  We allow a bit of slop to handle
	   incorrect length encodings */
	while( cryptStatusOK( status ) && \
		   stell( stream ) < endPos - MIN_OBJECT_SIZE )
		{
		const int tag = peekTag( stream );
		const PKCS15_OBJECT_TYPE type = EXTRACT_CTAG( tag );
		long innerEndPos;

		/* Read the [n] [0] wrapper to find out what we're dealing with.  We
		   use the long form since keysets with large numbers of objects can
		   grow larger than the maximum size allowed by the standard form */
		if( type < 0 || type >= PKCS15_OBJECT_LAST )
			{
			status = CRYPT_ERROR_BADDATA;
			break;
			}
		readLongConstructed( stream, NULL, tag );
		status = readLongConstructed( stream, &innerEndPos, CTAG_OV_DIRECT );
		if( cryptStatusError( status ) )
			break;
		innerEndPos += stell( stream );
		if( innerEndPos < 16 || innerEndPos > MAX_INTLENGTH )
			return( CRYPT_ERROR_BADDATA );	/* Safety check */

		/* Scan all objects of this type, again allowing for slop */
		while( cryptStatusOK( status ) && \
			   stell( stream ) < innerEndPos - MIN_OBJECT_SIZE )
			{
			PKCS15_INFO pkcs15objectInfo, *pkcs15infoPtr;
			BYTE buffer[ 16 ];
			void *objectData;
			int headerSize, objectLength;

			/* Read the current object.  We can't use getObjectLength() here
			   because we're reading from a file rather than a memory stream */
			status = sread( stream, buffer, 16 );
			if( !cryptStatusError( status ) )	/* sread() returns length */
				status = ( status == 16 || status == CRYPT_OK ) ? \
						 CRYPT_OK : CRYPT_ERROR_UNDERFLOW;
			if( cryptStatusOK( status ) )
				{
				STREAM headerStream;

				sMemConnect( &headerStream, buffer, 16 );
				status = readGenericHole( &headerStream, &objectLength, 
										  DEFAULT_TAG );
				headerSize = stell( &headerStream );
				sMemDisconnect( &headerStream );
				}
			if( cryptStatusOK( status ) && \
				( objectLength < MIN_OBJECT_SIZE || \
				  objectLength > MAX_PRIVATE_KEYSIZE + 1024 ) )
				status = CRYPT_ERROR_BADDATA;
			if( cryptStatusOK( status ) )
				{
				objectLength += headerSize;
				if( ( objectData = clAlloc( "readKeyset", \
											objectLength ) ) == NULL )
					status = CRYPT_ERROR_MEMORY;
				}
			if( cryptStatusError( status ) )
				break;
			memcpy( objectData, buffer, 16 );
			status = sread( stream, ( BYTE * ) objectData + 16, 
							objectLength - 16 );
			if( !cryptStatusError( status ) )	/* sread() returns length */
				status = checkObjectEncoding( objectData, objectLength );
			if( !cryptStatusError( status ) )	/* cOE() returns length */
				{
				STREAM objectStream;

				sMemConnect( &objectStream, objectData, objectLength );
				status = readObjectAttributes( &objectStream,
											   &pkcs15objectInfo, type );
				sMemDisconnect( &objectStream );
				}
			if( cryptStatusError( status ) )
				{
				clFree( "readKeyset", objectData );
				break;
				}

			/* Find out where to add the object data */
			pkcs15infoPtr = findEntry( pkcs15info, CRYPT_KEYIDEX_ID,
									   pkcs15objectInfo.iD,
									   pkcs15objectInfo.iDlength,
									   KEYMGMT_FLAG_NONE );
			if( pkcs15infoPtr == NULL )
				{
				int i;

				/* This personality isn't present yet, find out where we can
				   add the object data and copy the fixed information
				   over */
				for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
					if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
						break;
				if( i == MAX_PKCS15_OBJECTS )
					{
					clFree( "readKeyset", objectData );
					status = CRYPT_ERROR_OVERFLOW;
					break;
					}
				pkcs15info[ i ] = pkcs15objectInfo;
				pkcs15infoPtr = &pkcs15info[ i ];
				pkcs15infoPtr->index = i;
				}

			/* If any new ID information has become available, copy it over.
			   The keyID defaults to the iD, so we only copy the newly-read
			   keyID over if it's something other than the existing iD */
			if( pkcs15infoPtr->iDlength != pkcs15objectInfo.keyIDlength || \
				memcmp( pkcs15infoPtr->iD, pkcs15objectInfo.keyID,
						pkcs15objectInfo.keyIDlength ) )
				{
				memcpy( pkcs15infoPtr->keyID, pkcs15objectInfo.keyID,
						pkcs15objectInfo.keyIDlength );
				pkcs15infoPtr->keyIDlength = pkcs15objectInfo.keyIDlength;
				}
			if( pkcs15objectInfo.iAndSIDlength )
				{
				memcpy( pkcs15infoPtr->iAndSID, pkcs15objectInfo.iAndSID,
						pkcs15objectInfo.iAndSIDlength );
				pkcs15infoPtr->iAndSIDlength = pkcs15objectInfo.iAndSIDlength;
				}
			if( pkcs15objectInfo.subjectNameIDlength )
				{
				memcpy( pkcs15infoPtr->subjectNameID,
						pkcs15objectInfo.subjectNameID,
						pkcs15objectInfo.subjectNameIDlength );
				pkcs15infoPtr->subjectNameIDlength = \
						pkcs15objectInfo.subjectNameIDlength;
				}
			if( pkcs15objectInfo.issuerNameIDlength )
				{
				memcpy( pkcs15infoPtr->issuerNameID,
						pkcs15objectInfo.issuerNameID,
						pkcs15objectInfo.issuerNameIDlength );
				pkcs15infoPtr->issuerNameIDlength = \
						pkcs15objectInfo.issuerNameIDlength;
				}
			if( pkcs15objectInfo.pgp2KeyIDlength )
				{
				memcpy( pkcs15infoPtr->pgp2KeyID,
						pkcs15objectInfo.pgp2KeyID,
						pkcs15objectInfo.pgp2KeyIDlength );
				pkcs15infoPtr->pgp2KeyIDlength = \
						pkcs15objectInfo.pgp2KeyIDlength;
				}
			if( pkcs15objectInfo.openPGPKeyIDlength )
				{
				memcpy( pkcs15infoPtr->openPGPKeyID,
						pkcs15objectInfo.openPGPKeyID,
						pkcs15objectInfo.openPGPKeyIDlength );
				pkcs15infoPtr->openPGPKeyIDlength = \
						pkcs15objectInfo.openPGPKeyIDlength;
				}

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
			switch( type )
				{
				case PKCS15_OBJECT_PUBKEY:
					pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
					pkcs15infoPtr->pubKeyData = objectData;
					pkcs15infoPtr->pubKeyDataSize = objectLength;
					pkcs15infoPtr->pubKeyOffset = pkcs15objectInfo.pubKeyOffset;
					pkcs15infoPtr->pubKeyUsage = pkcs15objectInfo.pubKeyUsage;
					break;

				case PKCS15_OBJECT_PRIVKEY:
					pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
					pkcs15infoPtr->privKeyData = objectData;
					pkcs15infoPtr->privKeyDataSize = objectLength;
					pkcs15infoPtr->privKeyOffset = pkcs15objectInfo.privKeyOffset;
					pkcs15infoPtr->privKeyUsage = pkcs15objectInfo.privKeyUsage;
					break;

				case PKCS15_OBJECT_CERT:
				case PKCS15_OBJECT_TRUSTEDCERT:
				case PKCS15_OBJECT_USEFULCERT:
					if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
						pkcs15infoPtr->type = PKCS15_SUBTYPE_CERT;
					pkcs15infoPtr->certData = objectData;
					pkcs15infoPtr->certDataSize = objectLength;
					pkcs15infoPtr->certOffset = pkcs15objectInfo.certOffset;
					pkcs15infoPtr->trustedUsage = pkcs15objectInfo.trustedUsage;
					pkcs15infoPtr->implicitTrust = pkcs15objectInfo.implicitTrust;
					break;

				case PKCS15_OBJECT_SECRETKEY:
					assert( NOTREACHED );

				case PKCS15_OBJECT_DATA:
					pkcs15infoPtr->type = PKCS15_SUBTYPE_DATA;
					pkcs15infoPtr->dataType = pkcs15objectInfo.dataType;
					pkcs15infoPtr->dataData = objectData;
					pkcs15infoPtr->dataDataSize = objectLength;
					pkcs15infoPtr->dataOffset = pkcs15objectInfo.dataOffset;
					break;
				}
			}
		}

	return( status );
	}

/****************************************************************************
*																			*
*									Read a Key								*
*																			*
****************************************************************************/

/* Set any optional attributes that may be associated with a key */

static int setKeyAttributes( const CRYPT_HANDLE iCryptHandle, 
							 const PKCS15_INFO *pkcs15infoPtr,
							 const int actionFlags )
	{
	RESOURCE_DATA msgData;
	int status = CRYPT_OK;

	if( actionFlags != CRYPT_UNUSED )
		status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE, 
								  ( void * ) &actionFlags,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusOK( status ) && pkcs15infoPtr->openPGPKeyIDlength )
		{
		setMessageData( &msgData, ( void * ) pkcs15infoPtr->openPGPKeyID,
						pkcs15infoPtr->openPGPKeyIDlength );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusOK( status ) && pkcs15infoPtr->validFrom )
		{
		setMessageData( &msgData, ( void * ) &pkcs15infoPtr->validFrom,
						sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_PGPVALIDITY );
		}
	return( status );
	}

/* Read the decryption information for the encrypted private key and use it
   to import the encrypted private components into an existing PKC context */

static int readEncryptedKey( STREAM *stream,
							 const CRYPT_CONTEXT iPrivateKey,
							 const char *password, const int passwordLength )
	{
	CRYPT_CONTEXT iSessionKey;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_WRAP_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	QUERY_INFO queryInfo, contentQueryInfo;
	void *encryptedKey;
	int status;

	/* Skip the version number and header for the SET OF EncryptionInfo and
	   query the exported key information to determine the parameters
	   required to reconstruct the decryption key */
	readShortInteger( stream, NULL );
	readSet( stream, NULL );
	status = queryAsn1Object( stream, &queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfo.type != CRYPT_OBJECT_ENCRYPTED_KEY )
		return( CRYPT_ERROR_BADDATA );
	encryptedKey = sMemBufPtr( stream );
	readUniversal( stream );	/* Skip the exported key */

	/* Read the session key information into a context */
	status = readCMSencrHeader( stream, dataOIDinfo, &iSessionKey, 
								&contentQueryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( contentQueryInfo.size > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Create an encryption context and derive the user password into it
	   using the given parameters, and import the session key.  If there's
	   an error in the parameters stored with the exported key we'll get an
	   arg or attribute error when we try to set the attribute so we
	   translate it into an error code which is appropriate for the
	   situation */
	setMessageCreateObjectInfo( &createInfo, queryInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, &queryInfo.cryptMode, 
								  CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE,
									  &queryInfo.keySetupAlgo,
									  CRYPT_CTXINFO_KEYING_ALGO );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE,
									  &queryInfo.keySetupIterations,
									  CRYPT_CTXINFO_KEYING_ITERATIONS );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, queryInfo.salt, queryInfo.saltLength );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_KEYING_SALT );
			}
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, ( void * ) password, passwordLength );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_KEYING_VALUE );
			}
		if( cryptStatusOK( status ) )
			status = iCryptImportKeyEx( encryptedKey, queryInfo.size,
										CRYPT_FORMAT_CRYPTLIB, 
										createInfo.cryptHandle, iSessionKey,
										NULL );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		}
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );
		}

	/* Import the encrypted key into the PKC context */
	setMechanismWrapInfo( &mechanismInfo, sMemBufPtr( stream ),
						  contentQueryInfo.size, NULL, 0, iPrivateKey,
						  iSessionKey, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Return an encoded configuration item */

static int getConfigItem( KEYSET_INFO *keysetInfo,
						  const CRYPT_ATTRIBUTE_TYPE dataType,
						  void *data, int *dataLength )
	{
	const PKCS15_INFO *pkcs15infoPtr = keysetInfo->keyData;
	static int trustedCertIndex;

	assert( dataType == CRYPT_IATTRIBUTE_CONFIGDATA || \
			dataType == CRYPT_IATTRIBUTE_USERINDEX || \
			dataType == CRYPT_IATTRIBUTE_USERINFO || \
			dataType == CRYPT_IATTRIBUTE_TRUSTEDCERT || \
			dataType == CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT );

	/* If we're being asked for pre-encoded data, return it to the caller */
	if( dataType == CRYPT_IATTRIBUTE_CONFIGDATA || \
		dataType == CRYPT_IATTRIBUTE_USERINDEX || \
		dataType == CRYPT_IATTRIBUTE_USERINFO )
		{
		int length, i;

		/* Find the particular data type we're looking for */
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( ( pkcs15infoPtr[ i ].type == PKCS15_SUBTYPE_DATA && \
				  pkcs15infoPtr[ i ].dataType == dataType ) )
				break;
		if( i == MAX_PKCS15_OBJECTS )
			return( CRYPT_ERROR_NOTFOUND );
		pkcs15infoPtr = &pkcs15infoPtr[ i ];

		/* Return it to the caller */
		length = pkcs15infoPtr->dataDataSize - pkcs15infoPtr->dataOffset;
		if( data != NULL )
			{
			if( *dataLength < length )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_OVERFLOW );
				}
			memcpy( data, ( BYTE * ) pkcs15infoPtr->dataData + \
									 pkcs15infoPtr->dataOffset, length );
			}
		*dataLength = length;
		return( CRYPT_OK );
		}

	/* If this is the first cert, reset the index value.  This is pretty
	   ugly since this sort of value should be stored with the caller,
	   however there's no way to pass this back and forth in a RESOURCE_DATA
	   without resorting to an even uglier hack and it's safe since this
	   attribute is only ever read for the config keyset */
	if( dataType == CRYPT_IATTRIBUTE_TRUSTEDCERT )
		trustedCertIndex = 0;

	/* If we're being asked for a trusted cert, find the first or next one */
	while( trustedCertIndex < MAX_PKCS15_OBJECTS )
		{
		if( pkcs15infoPtr[ trustedCertIndex ].implicitTrust )
			{
			const int length =
						pkcs15infoPtr[ trustedCertIndex ].certDataSize - \
						pkcs15infoPtr[ trustedCertIndex ].certOffset;
			int status = CRYPT_OK;

			assert( isWritePtr( data, *dataLength ) );
			if( *dataLength < length )
				{
				assert( NOTREACHED );
				status = CRYPT_ERROR_OVERFLOW;
				}
			else
				memcpy( data,
						( BYTE * ) pkcs15infoPtr[ trustedCertIndex ].certData + \
								   pkcs15infoPtr[ trustedCertIndex ].certOffset,
						length );
			*dataLength = length;
			trustedCertIndex++;	/* Move on to the next cert */
			return( status );
			}
		trustedCertIndex++;
		}

	return( CRYPT_ERROR_NOTFOUND );
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
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
	CRYPT_CONTEXT iCryptContext;
	const PKCS15_INFO *pkcs15infoPtr;
	RESOURCE_DATA msgData;
	STREAM stream;
	const BOOLEAN publicComponentsOnly = \
					( itemType == KEYMGMT_ITEM_PUBLICKEY ) ? TRUE : FALSE;
	int pubkeyActionFlags = 0, privkeyActionFlags = 0, status;

	/* If we're being asked for encoded configuration information, return it
	   and exit.  This is a bit odd, but more valid than defining a pile of
	   special-case KEYMGMT_ITEM types that only exist for PKCS #15 keysets,
	   since these are really attributes of the keyset rather than general 
	   key types */
	if( iCryptHandle == NULL )
		{
		assert( keyIDtype == CRYPT_KEYID_NONE );
		assert( keyID == NULL ); assert( keyIDlength == 0 );

		return( getConfigItem( keysetInfo, flags, auxInfo, auxInfoLength ) );
		}

	assert( iCryptHandle != NULL );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( keyID != NULL ); assert( keyIDlength >= 1 );

	/* Clear the return values */
	*iCryptHandle = CRYPT_ERROR;

	/* Locate the appropriate object in the PKCS #15 collection and make sure
	   the components we need are present: Either a public key or a cert for
	   any read, and a private key as well for a private-key read */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, keyIDtype,
							   keyID, keyIDlength, flags );
	if( pkcs15infoPtr == NULL || \
		( pkcs15infoPtr->pubKeyData == NULL && \
		  pkcs15infoPtr->certData == NULL ) )
		/* There's not enough information present to get a public key or the
		   public portions of a private key */
		return( CRYPT_ERROR_NOTFOUND );
	if( !publicComponentsOnly && pkcs15infoPtr->privKeyData == NULL )
		/* There's not enough information present to get a private key */
		return( CRYPT_ERROR_NOTFOUND );

	/* If we're just checking whether an object exists, return now.  If all
	   we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		{
		*auxInfoLength = pkcs15infoPtr->labelLength;
		if( auxInfo != NULL )
			memcpy( auxInfo, pkcs15infoPtr->label,
					pkcs15infoPtr->labelLength );
		return( CRYPT_OK );
		}

	/* If we're reading the private key, make sure that the user has 
	   supplied a password.  This is checked by the kernel, but we perform 
	   another check here just to be safe*/
	if( !publicComponentsOnly && auxInfo == NULL )
		return( CRYPT_ERROR_WRONGKEY );

	/* Read the public components.  If we're creating a public-key context we
	   create the cert or PKC context normally, if we're creating a private-
	   key context we create a data-only cert (if there's cert information 
	   present) and a partial PKC context ready to accept the private key 
	   components.  If there's a cert present we take all the info we need 
	   from the cert, otherwise we use the public-key data */
	if( pkcs15infoPtr->certData != NULL )
		{
		/* There's a certificate present, import it and reconstruct the 
		   public-key info from it if we're creating a partial PKC context */
		status = iCryptImportCertIndirect( &iCryptContext,
								keysetInfo->objectHandle, keyIDtype, keyID,
								keyIDlength, publicComponentsOnly ? \
									KEYMGMT_FLAG_NONE : \
									KEYMGMT_FLAG_DATAONLY_CERT );
		if( cryptStatusOK( status ) && !publicComponentsOnly )
			{
			DYNBUF pubKeyDB;

			iDataCert = iCryptContext;	/* We got the cert, now get the context */
			status = dynCreate( &pubKeyDB, iDataCert, CRYPT_IATTRIBUTE_SPKI );
			if( cryptStatusError( status ) )
				return( status );
			sMemConnect( &stream, dynData( pubKeyDB ), 
						 dynLength( pubKeyDB ) );
			status = iCryptReadSubjectPublicKey( &stream, &iCryptContext, 
												 TRUE );
			sMemDisconnect( &stream );
			dynDestroy( &pubKeyDB );
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
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the permitted usage flags for each object type that we'll be
	   instantiating.  If there's a public key present we apply its usage
	   flags to whichever PKC context we create, even if it's done indirectly
	   via the cert import.  Since the private key can also perform the
	   actions of the public key, we set its action flags to the union of the
	   two */
	if( pkcs15infoPtr->pubKeyData != NULL )
		{
		pubkeyActionFlags = getPermittedActions( pkcs15infoPtr->pubKeyUsage,
												 cryptAlgo );
		if( cryptStatusError( pubkeyActionFlags ) )
			status = pubkeyActionFlags;
		}
	if( !publicComponentsOnly )
		{
		privkeyActionFlags = getPermittedActions( pkcs15infoPtr->privKeyUsage,
												  cryptAlgo );
		if( cryptStatusError( privkeyActionFlags ) )
			status = privkeyActionFlags;
		privkeyActionFlags |= pubkeyActionFlags;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
		}

	/* If we're only interested in the public components, set the key 
	   permissions and exit */
	if( publicComponentsOnly )
		{
		status = setKeyAttributes( iCryptContext, pkcs15infoPtr, 
								   ( pkcs15infoPtr->pubKeyData != NULL ) ? \
								   pubkeyActionFlags : CRYPT_UNUSED );
		if( cryptStatusOK( status ) )
			*iCryptHandle = iCryptContext;
		else
			krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	assert( ( pkcs15infoPtr->pubKeyData != NULL || \
			  pkcs15infoPtr->certData != NULL ) && \
			pkcs15infoPtr->privKeyData != NULL );

	/* Set the key label.  We have to do this before we load the key or the
	   key load will be blocked by the kernel */
	setMessageData( &msgData, ( void * ) pkcs15infoPtr->label,
					pkcs15infoPtr->labelLength );
	krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_LABEL );

	/* Read the private key header fields and import the private key */
	sMemConnect( &stream, 
				 ( BYTE * ) pkcs15infoPtr->privKeyData + \
							pkcs15infoPtr->privKeyOffset,
				 pkcs15infoPtr->privKeyDataSize - \
							pkcs15infoPtr->privKeyOffset );
	status = readConstructed( &stream, NULL, CTAG_OV_DIRECTPROTECTED );
	if( cryptStatusOK( status ) )
		status = readEncryptedKey( &stream, iCryptContext, auxInfo,
								   *auxInfoLength );
	sMemDisconnect( &stream );
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
		krnlSendMessage( iCryptContext, IMESSAGE_SETDEPENDENT, &iDataCert, 
						 SETDEP_OPTION_NOINCREF );

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
   certificate code to fetch the first and subsequent certs in a chain */

static int getItem( PKCS15_INFO *pkcs15info, CRYPT_CERTIFICATE *iCertificate, 
					int *stateInfo, const CRYPT_KEYID_TYPE keyIDtype, 
					const void *keyID, const int keyIDlength, 
					const KEYMGMT_ITEM_TYPE itemType, const int options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	const PKCS15_INFO *pkcs15infoPtr;
	int status;
	
	/* Find the appropriate entry based on the ID */
	pkcs15infoPtr = findEntry( pkcs15info, keyIDtype, keyID, keyIDlength, 
							   options );
	if( pkcs15infoPtr == NULL )
		{
		*stateInfo = CRYPT_ERROR;
		return( CRYPT_ERROR_NOTFOUND );
		}
	*stateInfo = pkcs15infoPtr->index;

	/* Import the cert */
	setMessageCreateObjectIndirectInfo( &createInfo,
			( BYTE * ) pkcs15infoPtr->certData + pkcs15infoPtr->certOffset,
			pkcs15infoPtr->certDataSize - pkcs15infoPtr->certOffset,
			( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
				CERTFORMAT_DATAONLY : CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT, &createInfo, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		*iCertificate = createInfo.cryptHandle;
		if( pkcs15infoPtr->validFrom == 0 )
			/* Perform an opportunistic update of the validity info if
			   this hasn't already been set */
			getValidityInfo( pkcs15info, createInfo.cryptHandle );
		}
	return( status );
	}

static int getFirstItemFunction( KEYSET_INFO *keysetInfo,
								 CRYPT_CERTIFICATE *iCertificate,
								 int *stateInfo,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength,
								 const KEYMGMT_ITEM_TYPE itemType,
								 const int options )
	{
	assert( stateInfo != NULL );
	assert( keyIDtype != CRYPT_KEYID_NONE && keyID != NULL && \
			keyIDlength > 0 );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );

	return( getItem( keysetInfo->keyData, iCertificate, stateInfo,
					 keyIDtype, keyID, keyIDlength, itemType, options ) );
	}

static int getNextItemFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	PKCS15_INFO *pkcs15infoPtr = keysetInfo->keyData;

	assert( stateInfo != NULL );
	assert( ( *stateInfo >= 0 && *stateInfo < MAX_PKCS15_OBJECTS ) || \
			*stateInfo == CRYPT_ERROR );

	/* If the previous cert was the last one, there's nothing left to fetch */
	if( *stateInfo == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Find the cert for which the subjectNameID matches this cert's
	   issuerNameID */
	return( getItem( pkcs15infoPtr, iCertificate, stateInfo,
					 CRYPT_KEYIDEX_SUBJECTNAMEID, 
					 pkcs15infoPtr[ *stateInfo ].issuerNameID, 
					 pkcs15infoPtr[ *stateInfo ].issuerNameIDlength, 
					 KEYMGMT_ITEM_PUBLICKEY, options ) );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

void initPKCS15read( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->getFirstItemFunction = getFirstItemFunction;
	keysetInfo->getNextItemFunction = getNextItemFunction;
	}
#endif /* USE_PKCS15 */
