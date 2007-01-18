/****************************************************************************
*																			*
*					cryptlib PKCS #15 Attribute Management					*
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

/* A macro to check that we're OK to read more data beyond this point */

#define canContinue( stream, status, endPos ) \
		( cryptStatusOK( status ) && stell( stream ) < endPos )

/* OID information used to read a PKCS #15 file */

static const OID_INFO FAR_BSS cryptlibDataOIDinfo[] = {
	{ OID_CRYPTLIB_CONFIGDATA, CRYPT_IATTRIBUTE_CONFIGDATA },
	{ OID_CRYPTLIB_USERINDEX, CRYPT_IATTRIBUTE_USERINDEX },
	{ OID_CRYPTLIB_USERINFO, CRYPT_IATTRIBUTE_USERINFO },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read a sequence of PKCS #15 key identifiers */

static int readKeyIdentifiers( STREAM *stream, PKCS15_INFO *pkcs15infoPtr,
							   const int endPos )
	{
	int iterationCount = 0, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( endPos > stell( stream ) );

	while( cryptStatusOK( status ) && stell( stream ) < endPos && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		long value;
		int payloadLength;

		/* Read each identifier type and copy the useful ones into the PKCS
		   #15 info */
		readSequence( stream, &payloadLength );
		status = readShortInteger( stream, &value );
		if( cryptStatusError( status ) )
			return( status );
		switch( value )
			{
			case PKCS15_KEYID_ISSUERANDSERIALNUMBER:
				{
				HASHFUNCTION hashFunction;
				void *iAndSPtr;
				int iAndSLength, hashSize;

				/* If we've already got the iAndSID, use that version 
				   instead */
				if( pkcs15infoPtr->iAndSIDlength > 0 )
					{
					readUniversal( stream );
					continue;
					}

				/* Hash the full issuerAndSerialNumber to get an iAndSID */
				getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
				iAndSPtr = sMemBufPtr( stream );
				status = iAndSLength = getStreamObjectLength( stream );
				if( !cryptStatusError( status ) )
					status = sSkip( stream, iAndSLength );
				if( cryptStatusError( status ) )
					return( status );
				hashFunction( NULL, pkcs15infoPtr->iAndSID, KEYID_SIZE, 
							  iAndSPtr, iAndSLength, HASH_ALL );
				pkcs15infoPtr->iAndSIDlength = hashSize;
				break;
				}

			case PKCS15_KEYID_SUBJECTKEYIDENTIFIER:
				status = readOctetString( stream, pkcs15infoPtr->keyID,
										  &pkcs15infoPtr->keyIDlength, 
										  8, CRYPT_MAX_HASHSIZE );
				break;

			case PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH:
				/* If we've already got the iAndSID by hashing the
				   issuerAndSerialNumber, use that version instead */
				if( pkcs15infoPtr->iAndSIDlength > 0 )
					{
					readUniversal( stream );
					continue;
					}
				status = readOctetString( stream, pkcs15infoPtr->iAndSID,
										  &pkcs15infoPtr->iAndSIDlength, 
										  KEYID_SIZE, KEYID_SIZE );
				break;

			case PKCS15_KEYID_ISSUERNAMEHASH:
				status = readOctetString( stream, pkcs15infoPtr->issuerNameID,
										  &pkcs15infoPtr->issuerNameIDlength, 
										  KEYID_SIZE, KEYID_SIZE );
				break;

			case PKCS15_KEYID_SUBJECTNAMEHASH:
				status = readOctetString( stream, pkcs15infoPtr->subjectNameID,
										  &pkcs15infoPtr->subjectNameIDlength, 
										  KEYID_SIZE, KEYID_SIZE );
				break;

			case PKCS15_KEYID_PGP2:
				status = readOctetString( stream, pkcs15infoPtr->pgp2KeyID,
										  &pkcs15infoPtr->pgp2KeyIDlength, 
										  PGP_KEYID_SIZE, PGP_KEYID_SIZE );
				break;

			case PKCS15_KEYID_OPENPGP:
				status = readOctetString( stream, pkcs15infoPtr->openPGPKeyID,
										  &pkcs15infoPtr->openPGPKeyIDlength, 
										  PGP_KEYID_SIZE, PGP_KEYID_SIZE );
				break;

			default:
				status = readUniversal( stream );
			}
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();

	return( status );
	}

/* Get assorted ID information from a context or certificate */

static int getKeyIDs( PKCS15_INFO *pkcs15infoPtr,
					  const CRYPT_HANDLE iCryptContext )
	{
	MESSAGE_DATA msgData;
	BYTE sKIDbuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptContext ) );

	/* Get various pieces of information from the object.  The information
	   may already have been set up earlier on so we only set it if this is
	   a newly-added key.  We use a guard for the existence of both a label
	   and an ID, since there may be a pre-set user ID (which isn't the same
	   as the key ID) present for implicitly created keys in user keysets */
	if( pkcs15infoPtr->labelLength <= 0 )
		{
		setMessageData( &msgData, pkcs15infoPtr->label, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15infoPtr->labelLength = msgData.length;
		setMessageData( &msgData, pkcs15infoPtr->keyID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15infoPtr->keyIDlength = msgData.length;
		}
	if( pkcs15infoPtr->iDlength <= 0 && pkcs15infoPtr->keyIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->iD, pkcs15infoPtr->keyID, 
				pkcs15infoPtr->keyIDlength );
		pkcs15infoPtr->iDlength = pkcs15infoPtr->keyIDlength;
		}
	if( pkcs15infoPtr->pgp2KeyIDlength <= 0 )
		{
		setMessageData( &msgData, pkcs15infoPtr->pgp2KeyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_PGP );
		if( cryptStatusOK( status ) )
			/* Not present for all key types, so an error isn't fatal */
			pkcs15infoPtr->pgp2KeyIDlength = msgData.length;
		}
	if( pkcs15infoPtr->openPGPKeyIDlength <= 0 )
		{
		setMessageData( &msgData, pkcs15infoPtr->openPGPKeyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15infoPtr->openPGPKeyIDlength = msgData.length;
		}

	/* The subjectKeyIdentifier, if present, may not be the same as the keyID
	   if the cert it's in has come from a CA that does strange things with
	   the sKID, so we try and read this value and if it's present override
	   the implicit sKID (== keyID) value with the actual sKID */
	setMessageData( &msgData, sKIDbuffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( cryptStatusOK( status ) )
		{
		memcpy( pkcs15infoPtr->keyID, sKIDbuffer, msgData.length );
		pkcs15infoPtr->keyIDlength = msgData.length;
		}

	return( CRYPT_OK );
	}

static int getCertIDs( PKCS15_INFO *pkcs15infoPtr, 
					   const CRYPT_HANDLE iCryptCert, BOOLEAN *isCA, 
					   BOOLEAN *trustedImplicit, int *trustedUsage )
	{
	int status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptCert ) );
	assert( isWritePtr( isCA, sizeof( BOOLEAN ) ) );
	assert( isWritePtr( trustedImplicit, sizeof( BOOLEAN ) ) );
	assert( isWritePtr( trustedUsage, sizeof( int ) ) );

	/* Clear return values */
	*isCA = *trustedImplicit = FALSE;
	*trustedUsage = CRYPT_UNUSED;

	/* Get various pieces of status information from the certificate */
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE, isCA,
							  CRYPT_CERTINFO_CA );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		*isCA = FALSE;
		status = CRYPT_OK;
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE,
								  trustedUsage, CRYPT_CERTINFO_TRUSTED_USAGE );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* If there's no trusted usage defined, don't store a trust
			   setting */
			*trustedUsage = CRYPT_UNUSED;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE,
							&trustedImplicit, CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* If it's not implicitly trusted, don't store a trust setting */
			*trustedImplicit = FALSE;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusOK( status ) )
		status = getValidityInfo( pkcs15infoPtr, iCryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're adding a standalone cert then the iD and keyID won't have 
	   been set up yet, so we need to set these up as well.  Since the cert 
	   could be a data-only cert, we create the iD ourselves from the 
	   encoded public key components rather than trying to read an 
	   associated context's keyID attribute.  For similar reasons we 
	   specifically don't try and read the PGP ID information since for a 
	   cert chain it'll come from the context of the leaf cert rather than 
	   the current cert (in any case they're not necessary since none of the 
	   certs in the chain will be PGP keys) */
	if( pkcs15infoPtr->iDlength <= 0 )
		{
		status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_SPKI,
							pkcs15infoPtr->iD, KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15infoPtr->iDlength = KEYID_SIZE;
		}
	if( pkcs15infoPtr->keyIDlength <= 0 )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, pkcs15infoPtr->keyID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
		if( cryptStatusOK( status ) )
			pkcs15infoPtr->keyIDlength = msgData.length;
		else
			{
			memcpy( pkcs15infoPtr->keyID, pkcs15infoPtr->iD, 
					pkcs15infoPtr->iDlength );
			pkcs15infoPtr->keyIDlength = pkcs15infoPtr->iDlength;
			}
		}

	/* Get the various other IDs for the cert */
	status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,
						pkcs15infoPtr->iAndSID, KEYID_SIZE );
	if( cryptStatusOK( status ) )
		status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_SUBJECT,
							pkcs15infoPtr->subjectNameID, KEYID_SIZE );
	if( cryptStatusOK( status ) )
		status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_ISSUER,
							pkcs15infoPtr->issuerNameID, KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	pkcs15infoPtr->iAndSIDlength = pkcs15infoPtr->subjectNameIDlength = \
		pkcs15infoPtr->issuerNameIDlength = KEYID_SIZE;

	return( CRYPT_OK );
	}

/* Get the PKCS #15 key usage flags for a context */

static int getKeyUsageFlags( const CRYPT_HANDLE iCryptContext,
							 const int privKeyUsage )
	{
	int keyUsage = 0, value, status;

	assert( isHandleRangeValid( iCryptContext ) );
	assert( privKeyUsage >= 0 );

	/* Obtaining the usage flags gets a bit complicated because they're a 
	   mixture of parts of X.509 and PKCS #11 flags (and the X.509 -> PKCS 
	   #15 mapping isn't perfect, see for example key agreement), so we have 
	   to build them up from bits and pieces pulled in from all over the 
	   place */
	if( cryptStatusOK( krnlSendMessage( iCryptContext, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_ENCRYPT ) ) )
		keyUsage = PKCS15_USAGE_ENCRYPT;
	if( cryptStatusOK( krnlSendMessage( iCryptContext, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_DECRYPT ) ) )
		keyUsage |= PKCS15_USAGE_DECRYPT;
	if( cryptStatusOK( krnlSendMessage( iCryptContext, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_SIGN ) ) )
		keyUsage |= PKCS15_USAGE_SIGN;
	if( cryptStatusOK( krnlSendMessage( iCryptContext, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_SIGCHECK ) ) )
		keyUsage |= PKCS15_USAGE_VERIFY;
	if( cryptStatusOK( krnlSendMessage( iCryptContext, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_KA_EXPORT ) ) || \
		cryptStatusOK( krnlSendMessage( iCryptContext, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_KA_IMPORT ) ) )
		keyUsage |= PKCS15_USAGE_DERIVE;	/* I don't think so Tim */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_CERTINFO_KEYUSAGE );
	if( cryptStatusOK( status ) && \
		( value & CRYPT_KEYUSAGE_NONREPUDIATION ) )
		/* This may be a raw key or a cert with no keyUsage present so a
		   failure to read the usage attribute isn't a problem */
		keyUsage |= PKCS15_USAGE_NONREPUDIATION;

	/* If the key ends up being unusable, tell the caller */
	if( keyUsage <= 0 )
		return( 0 );

	/* If this is a public-key object which is updating a private-key one,
	   the only key usages that we'll have found are public-key ones.  To 
	   ensure that we don't disable use of the private-key object, we copy 
	   across private-key usages where corresponding public-key ones are 
	   enabled.  This is used, for example, when updating an unrestricted-
	   usage raw private key with a restricted-usage public key, e.g. from a
	   certificate */
	if( cryptStatusError( krnlSendMessage( iCryptContext, IMESSAGE_CHECK, NULL,
										   MESSAGE_CHECK_PKC_PRIVATE ) ) )
		{
		if( keyUsage & PKCS15_USAGE_ENCRYPT )
			keyUsage |= privKeyUsage & PKCS15_USAGE_DECRYPT;
		if( keyUsage & PKCS15_USAGE_VERIFY )
			keyUsage |= privKeyUsage & PKCS15_USAGE_SIGN;
		}

	return( keyUsage );
	}

/****************************************************************************
*																			*
*							Read PKCS #15 Attributes						*
*																			*
****************************************************************************/

/* Read public/private key attributes */

static int readPubkeyAttributes( STREAM *stream, PKCS15_INFO *pkcs15infoPtr,
								 const int endPos, 
								 const BOOLEAN isPubKeyObject )
	{
	int usageFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( endPos > 0 );

	status = readBitString( stream, &usageFlags );		/* Usage flags */
	if( canContinue( stream, status, endPos ) &&		/* Native flag */
		peekTag( stream ) == BER_BOOLEAN )
		status = readUniversal( stream );
	if( canContinue( stream, status, endPos ) &&		/* Access flags */
		peekTag( stream ) == BER_BITSTRING )
		status = readUniversal( stream );
	if( canContinue( stream, status, endPos ) &&		/* Key reference */
		peekTag( stream ) == BER_INTEGER )
		status = readUniversal( stream );
	if( canContinue( stream, status, endPos ) &&		/* Start date */
		peekTag( stream ) == BER_TIME_GENERALIZED )
		status = readGeneralizedTime( stream, &pkcs15infoPtr->validFrom );
	if( canContinue( stream, status, endPos ) &&		/* End date */
		peekTag( stream ) == MAKE_CTAG( CTAG_KA_VALIDTO ) )
		status = readGeneralizedTimeTag( stream, &pkcs15infoPtr->validTo, 
										 CTAG_KA_VALIDTO );
	if( cryptStatusError( status ) )
		return( status );
	if( isPubKeyObject )
		pkcs15infoPtr->pubKeyUsage = usageFlags;
	else
		pkcs15infoPtr->privKeyUsage = usageFlags;

	return( CRYPT_OK );
	}

/* Read certificate attributes */

static int readCertAttributes( STREAM *stream, PKCS15_INFO *pkcs15infoPtr, 
							   const int endPos )
	{
	int length, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( endPos > 0 );

	if( canContinue( stream, status, endPos ) &&	/* Authority flag */
		peekTag( stream ) == BER_BOOLEAN )
		status = readUniversal( stream );
	if( canContinue( stream, status, endPos ) &&	/* Identifier */
		peekTag( stream ) == BER_SEQUENCE )
		status = readUniversal( stream );
	if( canContinue( stream, status, endPos ) &&	/* Thumbprint */
		peekTag( stream ) == MAKE_CTAG( CTAG_CA_DUMMY ) )
		status = readUniversal( stream );
	if( canContinue( stream, status, endPos ) &&	/* Trusted usage */
		peekTag( stream ) == MAKE_CTAG( CTAG_CA_TRUSTED_USAGE ) )
		{
		readConstructed( stream, NULL, CTAG_CA_TRUSTED_USAGE );
		status = readBitString( stream, &pkcs15infoPtr->trustedUsage );
		}
	if( canContinue( stream, status, endPos ) &&	/* Identifiers */
		peekTag( stream ) == MAKE_CTAG( CTAG_CA_IDENTIFIERS ) )
		{
		status = readConstructed( stream, &length, CTAG_CA_IDENTIFIERS );
		if( cryptStatusOK( status ) )
			status = readKeyIdentifiers( stream, pkcs15infoPtr, 
										 stell( stream ) + length );
		}
	if( canContinue( stream, status, endPos ) &&	/* Implicitly trusted */
		peekTag( stream ) == MAKE_CTAG_PRIMITIVE( CTAG_CA_TRUSTED_IMPLICIT ) )
		status = readBooleanTag( stream, &pkcs15infoPtr->implicitTrust,
								 CTAG_CA_TRUSTED_IMPLICIT );
	if( canContinue( stream, status, endPos ) &&	/* Validity */
		peekTag( stream ) == MAKE_CTAG( CTAG_CA_VALIDTO ) )
		{
		/* Due to miscommunication between PKCS #15 and 7816-15, there are 
		   two ways to encode the validity information for certs, one based 
		   on the format used elsewhere in PKCS #15 (for PKCS #15) and the 
		   other based on the format used in certs (for 7816-15).  Luckily 
		   they can be distinguished by the tagging type */
		readConstructed( stream, NULL, CTAG_CA_VALIDTO );
		readUTCTime( stream, &pkcs15infoPtr->validFrom );
		status = readUTCTime( stream, &pkcs15infoPtr->validTo );
		}
	else
		{
		if( canContinue( stream, status, endPos ) &&	/* Start date */
			peekTag( stream ) == BER_TIME_GENERALIZED )
			status = readGeneralizedTime( stream, &pkcs15infoPtr->validFrom );
		if( canContinue( stream, status, endPos ) &&	/* End date */
			peekTag( stream ) == MAKE_CTAG_PRIMITIVE( CTAG_CA_VALIDTO ) )
			status = readGeneralizedTimeTag( stream, &pkcs15infoPtr->validTo,
											 CTAG_CA_VALIDTO );
		}

	return( status );
	}

/* Read an object's attributes */

int readObjectAttributes( STREAM *stream, PKCS15_INFO *pkcs15infoPtr,
						  const PKCS15_OBJECT_TYPE type )
	{
	int length, endPos, value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( type > PKCS15_OBJECT_NONE && type < PKCS15_OBJECT_LAST );

	/* Clear the return value */
	memset( pkcs15infoPtr, 0, sizeof( PKCS15_INFO ) );

	/* Skip the outer header, which has already been checked when we read in
	   the object data */
	readGenericHole( stream, NULL, MIN_OBJECT_SIZE, DEFAULT_TAG );

	/* Process the PKCS15CommonObjectAttributes */
	status = readSequence( stream, &length );
	if( cryptStatusOK( status ) && length > 0 )
		{
		endPos = stell( stream ) + length;

		/* Read the label if it's present and skip anything else */
		if( peekTag( stream ) == BER_STRING_UTF8 )
			status = readCharacterString( stream,
						pkcs15infoPtr->label, &pkcs15infoPtr->labelLength,
						CRYPT_MAX_TEXTSIZE, BER_STRING_UTF8 );
		if( cryptStatusOK( status ) && stell( stream ) < endPos )
			status = sseek( stream, endPos );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Process the PKCS15CommonXXXAttributes */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	switch( type )
		{
		case PKCS15_OBJECT_DATA:
			/* It's a data object, make sure that it's one of ours */
			status = readFixedOID( stream, OID_CRYPTLIB_CONTENTTYPE );
			break;
		
		case PKCS15_OBJECT_PUBKEY:
		case PKCS15_OBJECT_PRIVKEY:
			/* It's a key object, read the ID and assorted flags */
			status = readOctetString( stream, pkcs15infoPtr->iD,
									  &pkcs15infoPtr->iDlength, 
									  1, CRYPT_MAX_HASHSIZE );
			if( cryptStatusOK( status ) )
				status = readPubkeyAttributes( stream, pkcs15infoPtr, endPos,
											   type == PKCS15_OBJECT_PUBKEY );
			break;

		case PKCS15_OBJECT_CERT:
			/* It's a certificate object, read the ID and assorted flags */
			status = readOctetString( stream, pkcs15infoPtr->iD,
									  &pkcs15infoPtr->iDlength, 
									  1, CRYPT_MAX_HASHSIZE );
			if( cryptStatusOK( status ) )
				status = readCertAttributes( stream, pkcs15infoPtr, endPos );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_INTERNAL );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Skip any additional attribute information that may be present */
	if( stell( stream ) < endPos )
		{
		status = sseek( stream, endPos );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* For now we use the iD as the keyID, this may be overridden later if
	   there's a real keyID present */
	if( pkcs15infoPtr->iDlength > 0 )
		{
		memcpy( pkcs15infoPtr->keyID, pkcs15infoPtr->iD, 
				pkcs15infoPtr->iDlength );
		pkcs15infoPtr->keyIDlength = pkcs15infoPtr->iDlength;
		}

	/* Skip the public/private key attributes if present */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_OB_SUBCLASSATTR ) )
		{
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the type attributes, which just consists of remembering where
	   the payload starts */
	readConstructed( stream, NULL, CTAG_OB_TYPEATTR );
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	switch( type )
		{
		case PKCS15_OBJECT_PUBKEY:
			status = readConstructed( stream, NULL, CTAG_OV_DIRECT );
			pkcs15infoPtr->pubKeyOffset = stell( stream );
			break;

		case PKCS15_OBJECT_PRIVKEY:
			pkcs15infoPtr->privKeyOffset = stell( stream );
			break;

		case PKCS15_OBJECT_CERT:
			pkcs15infoPtr->certOffset = stell( stream );
			break;

		case PKCS15_OBJECT_DATA:
			status = readOID( stream, cryptlibDataOIDinfo, &value );
			if( cryptStatusOK( status ) && \
				value != CRYPT_IATTRIBUTE_USERINFO )
				/* UserInfo is a straight object, the others are SEQUENCEs 
				   of objects */
				status = readSequence( stream, NULL );
			pkcs15infoPtr->dataOffset = stell( stream );
			pkcs15infoPtr->dataType = value;
			break;

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the object data and any additional attribute information that 
	   may be present */
	if( stell( stream ) < endPos )
		{
		status = sseek( stream, endPos );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write PKCS #15 Attributes						*
*																			*
****************************************************************************/

/* Write PKCS #15 identifier values */

static int sizeofObjectIDs( const PKCS15_INFO *pkcs15infoPtr )
	{
	int identifierSize;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );

	identifierSize = ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_SUBJECTKEYIDENTIFIER ) + \
				sizeofObject( pkcs15infoPtr->keyIDlength ) );
	if( pkcs15infoPtr->iAndSIDlength > 0 )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH ) + \
				sizeofObject( pkcs15infoPtr->iAndSIDlength ) );
	if( pkcs15infoPtr->issuerNameIDlength > 0 )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_ISSUERNAMEHASH ) + \
				sizeofObject( pkcs15infoPtr->issuerNameIDlength ) );
	if( pkcs15infoPtr->subjectNameIDlength > 0 )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_SUBJECTNAMEHASH ) + \
				sizeofObject( pkcs15infoPtr->subjectNameIDlength ) );
	if( pkcs15infoPtr->pgp2KeyIDlength > 0 )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_PGP2 ) + \
				sizeofObject( pkcs15infoPtr->pgp2KeyIDlength ) );
	if( pkcs15infoPtr->openPGPKeyIDlength > 0 )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_OPENPGP ) + \
				sizeofObject( pkcs15infoPtr->openPGPKeyIDlength ) );

	return( identifierSize );
	}

static void writeObjectIDs( STREAM *stream, const PKCS15_INFO *pkcs15infoPtr,
							const int length, const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( length > MIN_OBJECT_SIZE );
	assert( tag >= 0 );

	writeConstructed( stream, length, tag );
	writeSequence( stream,
				   sizeofShortInteger( PKCS15_KEYID_SUBJECTKEYIDENTIFIER ) + \
				   sizeofObject( pkcs15infoPtr->keyIDlength ) );
	writeShortInteger( stream, PKCS15_KEYID_SUBJECTKEYIDENTIFIER,
					   DEFAULT_TAG );
	writeOctetString( stream, pkcs15infoPtr->keyID,
					  pkcs15infoPtr->keyIDlength, DEFAULT_TAG );
	if( pkcs15infoPtr->iAndSIDlength > 0 )
		{
		writeSequence( stream,
					   sizeofShortInteger( PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH ) + \
					   sizeofObject( pkcs15infoPtr->iAndSIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH,
						   DEFAULT_TAG );
		writeOctetString( stream, pkcs15infoPtr->iAndSID,
						  pkcs15infoPtr->iAndSIDlength, DEFAULT_TAG );
		}
	if( pkcs15infoPtr->issuerNameIDlength > 0 )
		{
		writeSequence( stream,
					   sizeofShortInteger( PKCS15_KEYID_ISSUERNAMEHASH ) + \
					   sizeofObject( pkcs15infoPtr->issuerNameIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_ISSUERNAMEHASH, DEFAULT_TAG );
		writeOctetString( stream, pkcs15infoPtr->issuerNameID,
						  pkcs15infoPtr->issuerNameIDlength, DEFAULT_TAG );
		}
	if( pkcs15infoPtr->subjectNameIDlength > 0 )
		{
		writeSequence( stream,
					   sizeofShortInteger( PKCS15_KEYID_SUBJECTNAMEHASH ) + \
					   sizeofObject( pkcs15infoPtr->subjectNameIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_SUBJECTNAMEHASH, DEFAULT_TAG );
		writeOctetString( stream, pkcs15infoPtr->subjectNameID,
						  pkcs15infoPtr->subjectNameIDlength, DEFAULT_TAG );
		}
	if( pkcs15infoPtr->pgp2KeyIDlength > 0 )
		{
		writeSequence( stream, sizeofShortInteger( PKCS15_KEYID_PGP2 ) + \
							   sizeofObject( pkcs15infoPtr->pgp2KeyIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_PGP2, DEFAULT_TAG );
		writeOctetString( stream, pkcs15infoPtr->pgp2KeyID,
						  pkcs15infoPtr->pgp2KeyIDlength, DEFAULT_TAG );
		}
	if( pkcs15infoPtr->openPGPKeyIDlength > 0 )
		{
		writeSequence( stream, sizeofShortInteger( PKCS15_KEYID_OPENPGP ) + \
							   sizeofObject( pkcs15infoPtr->openPGPKeyIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_OPENPGP, DEFAULT_TAG );
		writeOctetString( stream, pkcs15infoPtr->openPGPKeyID,
						  pkcs15infoPtr->openPGPKeyIDlength, DEFAULT_TAG );
		}
	}

/* Write atributes to a buffer */

int writeKeyAttributes( void *privKeyAttributes, 
						const int privKeyAttributeMaxLen,
						int *privKeyAttributeSize, void *pubKeyAttributes,
						const int pubKeyAttributeMaxLen,
						int *pubKeyAttributeSize, PKCS15_INFO *pkcs15infoPtr,
						const CRYPT_HANDLE iCryptContext )
	{
	STREAM stream;
	int commonAttributeSize, commonKeyAttributeSize, keyUsage, status;

	assert( isWritePtr( privKeyAttributes, privKeyAttributeMaxLen ) );
	assert( isWritePtr( privKeyAttributeSize, sizeof( int ) ) );
	assert( isWritePtr( pubKeyAttributes, pubKeyAttributeMaxLen ) );
	assert( isWritePtr( pubKeyAttributeSize, sizeof( int ) ) );
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptContext ) );

	/* Clear return values */
	*privKeyAttributeSize = *pubKeyAttributeSize = 0;

	/* Get ID information from the context */
	status = getKeyIDs( pkcs15infoPtr, iCryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Try and get the validity information.  This isn't used at this point,
	   but may be needed before it's set in the certificate write code, for
	   example when adding two certs that differ only in validity period to
	   a keyset.  Since we could be adding a raw key, we ignore any return
	   code */
	getValidityInfo( pkcs15infoPtr, iCryptContext );

	/* Figure out the PKCS #15 key usage flags.  The action flags for an 
	   object can change over time under the influence of another object.  
	   For example when a raw private key is initially written and unless 
	   something else has told it otherwise, it'll have all permissible 
	   actions enabled.  When a certificate for the key is later added, the 
	   permissible actions for the key may be constrained by the 
	   certificate, so the private key flags will change when the object is 
	   re-written to the keyset */
	keyUsage = getKeyUsageFlags( iCryptContext, 
								 pkcs15infoPtr->privKeyUsage );
	if( keyUsage <= 0 )
		return( CRYPT_ERROR_PERMISSION );	/* No easy way to report this one */

	/* Determine how big the private key attribute collections will be */
	commonAttributeSize = ( int) sizeofObject( pkcs15infoPtr->labelLength );
	commonKeyAttributeSize = ( int ) sizeofObject( pkcs15infoPtr->iDlength ) + \
							 sizeofBitString( keyUsage ) + \
							 sizeofBitString( KEYATTR_ACCESS_PRIVATE );
	if( pkcs15infoPtr->validFrom > MIN_TIME_VALUE )
		commonKeyAttributeSize += sizeofGeneralizedTime();
	if( pkcs15infoPtr->validTo > MIN_TIME_VALUE )
		commonKeyAttributeSize += sizeofGeneralizedTime();

	/* Write the private key attributes */
	sMemOpen( &stream, privKeyAttributes, privKeyAttributeMaxLen );
	writeSequence( &stream, commonAttributeSize );
	writeCharacterString( &stream, ( BYTE * ) pkcs15infoPtr->label,
						  pkcs15infoPtr->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonKeyAttributeSize );
	writeOctetString( &stream, pkcs15infoPtr->iD, pkcs15infoPtr->iDlength,
					  DEFAULT_TAG );
	writeBitString( &stream, keyUsage, DEFAULT_TAG );
	status = writeBitString( &stream, KEYATTR_ACCESS_PRIVATE, DEFAULT_TAG );
	if( pkcs15infoPtr->validFrom > MIN_TIME_VALUE )
		status = writeGeneralizedTime( &stream, pkcs15infoPtr->validFrom, 
									   DEFAULT_TAG );
	if( pkcs15infoPtr->validTo > MIN_TIME_VALUE )
		status = writeGeneralizedTime( &stream, pkcs15infoPtr->validTo, 
									   CTAG_KA_VALIDTO );
	*privKeyAttributeSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( status );
		}
	pkcs15infoPtr->privKeyUsage = keyUsage;	/* Update stored usage info */

	/* Determine how big the public key attribute collections will be */
	keyUsage &= PUBKEY_USAGE_MASK;
	commonKeyAttributeSize = ( int ) sizeofObject( pkcs15infoPtr->iDlength ) + \
							 sizeofBitString( keyUsage ) + \
							 sizeofBitString( KEYATTR_ACCESS_PUBLIC );
	if( pkcs15infoPtr->validFrom > MIN_TIME_VALUE )
		commonKeyAttributeSize += sizeofGeneralizedTime();
	if( pkcs15infoPtr->validTo > MIN_TIME_VALUE )
		commonKeyAttributeSize += sizeofGeneralizedTime();

	/* Write the public key attributes */
	sMemOpen( &stream, pubKeyAttributes, pubKeyAttributeMaxLen );
	writeSequence( &stream, commonAttributeSize );
	writeCharacterString( &stream, ( BYTE * ) pkcs15infoPtr->label,
						  pkcs15infoPtr->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonKeyAttributeSize );
	writeOctetString( &stream, pkcs15infoPtr->iD, pkcs15infoPtr->iDlength,
					  DEFAULT_TAG );
	writeBitString( &stream, keyUsage, DEFAULT_TAG );
	status = writeBitString( &stream, KEYATTR_ACCESS_PUBLIC, DEFAULT_TAG );
	if( pkcs15infoPtr->validFrom > MIN_TIME_VALUE )
		status = writeGeneralizedTime( &stream, pkcs15infoPtr->validFrom, 
									   DEFAULT_TAG );
	if( pkcs15infoPtr->validTo > MIN_TIME_VALUE )
		status = writeGeneralizedTime( &stream, pkcs15infoPtr->validTo, 
									   CTAG_KA_VALIDTO );
	*pubKeyAttributeSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( status );
		}
	pkcs15infoPtr->pubKeyUsage = keyUsage;	/* Update stored usage info */

	return( CRYPT_OK );
	}

int writeCertAttributes( void *certAttributes, const int certAttributeMaxLen,
						 int *certAttributeSize, PKCS15_INFO *pkcs15infoPtr,
						 const CRYPT_HANDLE iCryptCert )
	{
	STREAM stream;
	BOOLEAN trustedImplicit;
	int commonAttributeSize, commonCertAttributeSize;
	int keyIdentifierDataSize, trustedUsageSize;
	int isCA, trustedUsage, status;

	assert( isWritePtr( certAttributes, certAttributeMaxLen ) );
	assert( isWritePtr( certAttributeSize, sizeof( int ) ) );
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isHandleRangeValid( iCryptCert ) );

	/* Clear return values */
	*certAttributeSize = 0;

	/* Get ID information from the cert */
	status = getCertIDs( pkcs15infoPtr, iCryptCert, &isCA, 
						 &trustedImplicit, &trustedUsage );
	if( cryptStatusError( status ) )
		return( status );

	/* At this point we could create a pseudo-label by walking up the cert DN
	   from the CN until we find a component that we can use, however label-
	   less items will only occur when adding a standalone (i.e. trusted,
	   implicitly-handled) cert.  If we were to set labels for these, the
	   keyset would end up acting as a general-purpose certificate store
	   which it isn't meant to be, so we always leave implicitly handled
	   certs label-less */

	/* Determine how big the attribute collection will be */
	trustedUsageSize = ( trustedUsage != CRYPT_UNUSED ) ? \
					   sizeofBitString( trustedUsage ) : 0;
	keyIdentifierDataSize = sizeofObjectIDs( pkcs15infoPtr );
	commonAttributeSize = ( pkcs15infoPtr->labelLength > 0 ) ? \
						  ( int) sizeofObject( pkcs15infoPtr->labelLength ) : 0;
	commonCertAttributeSize = ( int ) \
						sizeofObject( pkcs15infoPtr->iDlength ) + \
						( isCA ? sizeofBoolean() : 0 ) + \
						( ( trustedUsage != CRYPT_UNUSED ) ? \
						  sizeofObject( trustedUsageSize ) : 0 ) + \
						sizeofObject( keyIdentifierDataSize ) + \
						( trustedImplicit ? sizeofBoolean() : 0 ) + \
						sizeofGeneralizedTime() + sizeofGeneralizedTime();

	/* Write the cert attributes */
	sMemOpen( &stream, certAttributes, certAttributeMaxLen );
	writeSequence( &stream, commonAttributeSize );
	if( commonAttributeSize > 0 )
		writeCharacterString( &stream, pkcs15infoPtr->label,
							  pkcs15infoPtr->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonCertAttributeSize );
	writeOctetString( &stream, pkcs15infoPtr->iD, pkcs15infoPtr->iDlength,
					  DEFAULT_TAG );
	if( isCA )
		writeBoolean( &stream, TRUE, DEFAULT_TAG );
	if( trustedUsage != CRYPT_UNUSED )
		{
		writeConstructed( &stream, trustedUsageSize, CTAG_CA_TRUSTED_USAGE );
		writeBitString( &stream, trustedUsage, DEFAULT_TAG );
		}
	writeObjectIDs( &stream, pkcs15infoPtr, keyIdentifierDataSize,
					CTAG_CA_IDENTIFIERS );
	if( trustedImplicit )
		writeBoolean( &stream, TRUE, CTAG_CA_TRUSTED_IMPLICIT );
	writeGeneralizedTime( &stream, pkcs15infoPtr->validFrom, DEFAULT_TAG );
	status = writeGeneralizedTime( &stream, pkcs15infoPtr->validTo, \
								   CTAG_CA_VALIDTO );
	*certAttributeSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( status );
		}

	return( CRYPT_OK );
	}
#endif /* USE_PKCS15 */
