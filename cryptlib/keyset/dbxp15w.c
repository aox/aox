/****************************************************************************
*																			*
*						cryptlib PKCS #15 Write Routines					*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/* When writing attributes it's useful to have a fixed-size buffer rather
   than having to mess around with all sorts of variable-length structures,
   the following value defines the maximum size of the attribute data that 
   we can write (that is, the I/O stream is opened with this size and 
   generates a CRYPT_ERROR_OVERFLOW if we go beyond this).  The maximum-
   length buffer contents are two CRYPT_MAX_TEXTSIZE strings and a few odd 
   bits and pieces so this is plenty */

#define KEYATTR_BUFFER_SIZE		256

/* The minimum number of keying iterations to use when deriving a key wrap
   key from a password.  Any recent system will handle a significant 
   iteration count in no time but older systems may take awhile to handle
   this, however there's no easy way to determine CPU speed so we make the 
   mimimal assumption that a 16-bit system isn't going to be too fast */

#if INT_MAX > 32767
  #define MIN_KEYING_ITERATIONS	2000
#else
  #define MIN_KEYING_ITERATIONS	800
#endif /* 16-bit systems */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Get the hash of various certificate name fields */

static int getCertID( const CRYPT_HANDLE iCryptHandle,
					  CRYPT_ATTRIBUTE_TYPE nameType, BYTE *nameID )
	{
	DYNBUF idDB;
	int status;

	assert( nameType == CRYPT_IATTRIBUTE_SPKI || \
			nameType == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER || \
			nameType == CRYPT_IATTRIBUTE_SUBJECT || \
			nameType == CRYPT_IATTRIBUTE_ISSUER );

	status = dynCreate( &idDB, iCryptHandle, nameType );
	if( cryptStatusOK( status ) )
		{
		HASHFUNCTION hashFunction;

		/* Get the hash algorithm information and hash the name to get a name
		   ID */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
		hashFunction( NULL, nameID, dynData( idDB ), dynLength( idDB ), 
					  HASH_ALL );
		}
	dynDestroy( &idDB );
	return( status );
	}

/****************************************************************************
*																			*
*							Write PKCS #15 Attributes						*
*																			*
****************************************************************************/

/* Write PKCS #15 identifier values */

static int sizeofObjectIDs( const PKCS15_INFO *pkcs15info )
	{
	int identifierSize;
	
	identifierSize = ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_SUBJECTKEYIDENTIFIER ) + \
				sizeofObject( pkcs15info->keyIDlength ) );
	if( pkcs15info->iAndSIDlength )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH ) + \
				sizeofObject( pkcs15info->iAndSIDlength ) );
	if( pkcs15info->issuerNameIDlength )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_ISSUERNAMEHASH ) + \
				sizeofObject( pkcs15info->issuerNameIDlength ) );
	if( pkcs15info->subjectNameIDlength )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_SUBJECTNAMEHASH ) + \
				sizeofObject( pkcs15info->subjectNameIDlength ) );
	if( pkcs15info->pgp2KeyIDlength )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_PGP2 ) + \
				sizeofObject( pkcs15info->pgp2KeyIDlength ) );
	if( pkcs15info->openPGPKeyIDlength )
		identifierSize += ( int ) \
			sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_OPENPGP ) + \
				sizeofObject( pkcs15info->openPGPKeyIDlength ) );

	return( identifierSize );
	}

static void writeObjectIDs( STREAM *stream, const PKCS15_INFO *pkcs15info,
							const int length, const int tag )
	{
	writeConstructed( stream, length, tag );
	writeSequence( stream,
				   sizeofShortInteger( PKCS15_KEYID_SUBJECTKEYIDENTIFIER ) + \
				   sizeofObject( pkcs15info->keyIDlength ) );
	writeShortInteger( stream, PKCS15_KEYID_SUBJECTKEYIDENTIFIER,
					   DEFAULT_TAG );
	writeOctetString( stream, pkcs15info->keyID,
					  pkcs15info->keyIDlength, DEFAULT_TAG );
	if( pkcs15info->iAndSIDlength )
		{
		writeSequence( stream,
					   sizeofShortInteger( PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH ) + \
					   sizeofObject( pkcs15info->iAndSIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH,
						   DEFAULT_TAG );
		writeOctetString( stream, pkcs15info->iAndSID,
						  pkcs15info->iAndSIDlength, DEFAULT_TAG );
		}
	if( pkcs15info->issuerNameIDlength )
		{
		writeSequence( stream,
					   sizeofShortInteger( PKCS15_KEYID_ISSUERNAMEHASH ) + \
					   sizeofObject( pkcs15info->issuerNameIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_ISSUERNAMEHASH, DEFAULT_TAG );
		writeOctetString( stream, pkcs15info->issuerNameID,
						  pkcs15info->issuerNameIDlength, DEFAULT_TAG );
		}
	if( pkcs15info->subjectNameIDlength )
		{
		writeSequence( stream,
					   sizeofShortInteger( PKCS15_KEYID_SUBJECTNAMEHASH ) + \
					   sizeofObject( pkcs15info->subjectNameIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_SUBJECTNAMEHASH, DEFAULT_TAG );
		writeOctetString( stream, pkcs15info->subjectNameID,
						  pkcs15info->subjectNameIDlength, DEFAULT_TAG );
		}
	if( pkcs15info->pgp2KeyIDlength )
		{
		writeSequence( stream, sizeofShortInteger( PKCS15_KEYID_PGP2 ) + \
							   sizeofObject( pkcs15info->pgp2KeyIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_PGP2, DEFAULT_TAG );
		writeOctetString( stream, pkcs15info->pgp2KeyID,
						  pkcs15info->pgp2KeyIDlength, DEFAULT_TAG );
		}
	if( pkcs15info->openPGPKeyIDlength )
		{
		writeSequence( stream, sizeofShortInteger( PKCS15_KEYID_OPENPGP ) + \
							   sizeofObject( pkcs15info->openPGPKeyIDlength ) );
		writeShortInteger( stream, PKCS15_KEYID_OPENPGP, DEFAULT_TAG );
		writeOctetString( stream, pkcs15info->openPGPKeyID,
						  pkcs15info->openPGPKeyIDlength, DEFAULT_TAG );
		}
	}

/* Write atributes to a buffer */

static int writeKeyAttributes( void *privKeyAttributes,
							   int *privKeyAttributeSize,
							   void *pubKeyAttributes,
							   int *pubKeyAttributeSize,
							   PKCS15_INFO *pkcs15info,
							   const CRYPT_HANDLE cryptHandle )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE sKIDbuffer[ CRYPT_MAX_HASHSIZE ];
	int keyUsage = 0, value, status;
	int commonAttributeSize, commonKeyAttributeSize;

	/* Get various pieces of information from the object.  The information
	   may already have been set up earlier on so we only set it if this is
	   a newly-added key.  We use a guard for the existence of both a label
	   and an ID, since there may be a pre-set user ID (which isn't the same
	   as the key ID) present for implicitly created keys in user keysets */
	if( !pkcs15info->labelLength )
		{
		setMessageData( &msgData, pkcs15info->label, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15info->labelLength = msgData.length;
		setMessageData( &msgData, pkcs15info->keyID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15info->keyIDlength = msgData.length;
		}
	if( !pkcs15info->iDlength )
		{
		memcpy( pkcs15info->iD, pkcs15info->keyID, pkcs15info->keyIDlength );
		pkcs15info->iDlength = pkcs15info->keyIDlength;
		}

	/* The subjectKeyIdentifier, if present, may not be the same as the keyID
	   if the cert it's in has come from a CA that does strange things with
	   the sKID, so we try and read this value and if it's present override
	   the implicit sKID (== keyID) value with the actual sKID */
	setMessageData( &msgData, sKIDbuffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( cryptStatusOK( status ) )
		{
		memcpy( pkcs15info->keyID, sKIDbuffer, msgData.length );
		pkcs15info->keyIDlength = msgData.length;
		}

	/* Try and get the validity information.  This isn't used at this point,
	   but may be needed before it's set in the certificate write code, for
	   example when adding two certs that differ only in validity period to
	   a keyset.  Since we could be adding a raw key, we ignore any return
	   code */
	getValidityInfo( pkcs15info, cryptHandle );

	/* Figure out the PKCS #15 key usage flags.  This gets complicated
	   because they're a mixture of parts of X.509 and PKCS #11 flags (and
	   the X.509 -> PKCS #15 mapping isn't perfect, see for example key
	   agreement), so we have to build them up from bits and pieces pulled in
	   from all over the place.

	   One point to note is that the action flags for an object can change
	   over time under the influence of another object.  For example when a
	   raw private key is initially written and unless something else has
	   told it otherwise, it'll have all permissible actions enabled.  When a
	   certificate for the key is later added, the permissible actions for
	   the key may be constrained by the certificate, so the private key
	   flags will change when the object is re-written to the keyset */
	if( cryptStatusOK( krnlSendMessage( cryptHandle, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_ENCRYPT ) ) )
		keyUsage = PKCS15_USAGE_ENCRYPT;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_DECRYPT ) ) )
		keyUsage |= PKCS15_USAGE_DECRYPT;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_SIGN ) ) )
		keyUsage |= PKCS15_USAGE_SIGN;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_SIGCHECK ) ) )
		keyUsage |= PKCS15_USAGE_VERIFY;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_KA_EXPORT ) ) || \
		cryptStatusOK( krnlSendMessage( cryptHandle, IMESSAGE_CHECK,
										NULL, MESSAGE_CHECK_PKC_KA_IMPORT ) ) )
		keyUsage |= PKCS15_USAGE_DERIVE;	/* I don't think so Tim */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_CERTINFO_KEYUSAGE );
	if( cryptStatusOK( status ) && \
		( value & CRYPT_KEYUSAGE_NONREPUDIATION ) )
		/* This may be a raw key or a cert with no keyUsage present so a
		   failure to read the usage attribute isn't a problem */
		keyUsage |= PKCS15_USAGE_NONREPUDIATION;
	if( !keyUsage )
		return( CRYPT_ERROR_PERMISSION );	/* No easy way to report this one */

	/* If this is a public-key object which is updating a private-key one, 
	   the only key usages we'll have found are public-key ones.  To ensure 
	   that we don't disable use of the private-key object, we copy across
	   private-key usages where corresponding public-key ones are enabled.
	   This is used, for example, when updating an unrestricted-usage raw
	   private key with a restricted-usage public key, e.g. from a
	   certificate */
	if( cryptStatusError( krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
										   MESSAGE_CHECK_PKC_PRIVATE ) ) )
		{
		if( keyUsage & PKCS15_USAGE_ENCRYPT )
			keyUsage |= pkcs15info->privKeyUsage & PKCS15_USAGE_DECRYPT;
		if( keyUsage & PKCS15_USAGE_VERIFY )
			keyUsage |= pkcs15info->privKeyUsage & PKCS15_USAGE_SIGN;
		}

	/* Determine how big the private key attribute collections will be */
	commonAttributeSize = ( int) sizeofObject( pkcs15info->labelLength );
	commonKeyAttributeSize = ( int ) sizeofObject( pkcs15info->iDlength ) + \
							 sizeofBitString( keyUsage ) + \
							 sizeofBitString( KEYATTR_ACCESS_PRIVATE );
	if( pkcs15info->validFrom )
		commonKeyAttributeSize += sizeofGeneralizedTime();
	if( pkcs15info->validTo )
		commonKeyAttributeSize += sizeofGeneralizedTime();

	/* Write the private key attributes */
	sMemOpen( &stream, privKeyAttributes, KEYATTR_BUFFER_SIZE );
	writeSequence( &stream, commonAttributeSize );
	writeCharacterString( &stream, ( BYTE * ) pkcs15info->label,
						  pkcs15info->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonKeyAttributeSize );
	writeOctetString( &stream, pkcs15info->iD, pkcs15info->iDlength,
					  DEFAULT_TAG );
	writeBitString( &stream, keyUsage, DEFAULT_TAG );
	writeBitString( &stream, KEYATTR_ACCESS_PRIVATE, DEFAULT_TAG );
	if( pkcs15info->validFrom )
		writeGeneralizedTime( &stream, pkcs15info->validFrom, DEFAULT_TAG );
	if( pkcs15info->validTo )
		writeGeneralizedTime( &stream, pkcs15info->validTo, CTAG_KA_VALIDTO );
	*privKeyAttributeSize = stell( &stream );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );
	pkcs15info->privKeyUsage = keyUsage;	/* Update stored usage info */

	/* Determine how big the public key attribute collections will be */
	keyUsage &= PUBKEY_USAGE_MASK;
	commonKeyAttributeSize = ( int ) sizeofObject( pkcs15info->iDlength ) + \
							 sizeofBitString( keyUsage ) + \
							 sizeofBitString( KEYATTR_ACCESS_PUBLIC );
	if( pkcs15info->validFrom )
		commonKeyAttributeSize += sizeofGeneralizedTime();
	if( pkcs15info->validTo )
		commonKeyAttributeSize += sizeofGeneralizedTime();

	/* Write the public key attributes */
	sMemOpen( &stream, pubKeyAttributes, KEYATTR_BUFFER_SIZE );
	writeSequence( &stream, commonAttributeSize );
	writeCharacterString( &stream, ( BYTE * ) pkcs15info->label,
						  pkcs15info->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonKeyAttributeSize );
	writeOctetString( &stream, pkcs15info->iD, pkcs15info->iDlength,
					  DEFAULT_TAG );
	writeBitString( &stream, keyUsage, DEFAULT_TAG );
	status = writeBitString( &stream, KEYATTR_ACCESS_PUBLIC, DEFAULT_TAG );
	if( pkcs15info->validFrom )
		status = writeGeneralizedTime( &stream, pkcs15info->validFrom, \
									   DEFAULT_TAG );
	if( pkcs15info->validTo )
		status = writeGeneralizedTime( &stream, pkcs15info->validTo, \
									   CTAG_KA_VALIDTO );
	*pubKeyAttributeSize = stell( &stream );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );
	pkcs15info->pubKeyUsage = keyUsage;		/* Update stored usage info */

	return( status );
	}

static int writeCertAttributes( void *certAttributes,
								int *certAttributeSize,
							    PKCS15_INFO *pkcs15info,
								const CRYPT_HANDLE cryptHandle )
	{
	STREAM stream;
	BOOLEAN trustedImplicit = FALSE;
	int isCA, trustedUsage, status;
	int commonAttributeSize, commonCertAttributeSize;
	int keyIdentifierDataSize, trustedUsageSize;

	/* Get various pieces of information from the object.  If we're adding a
	   standalone cert then the iD and keyID won't have been set up yet, so
	   we need to set these up as well.  Since the cert could be a data-only
	   cert, we create the iD ourselves from the encoded public key
	   components rather than trying to read an associated context's keyID
	   attribute.  For similar reasons we specifically don't try and read the
	   PGP ID information since for a cert chain it'll come from the context
	   of the leaf cert rather than the current cert (in any case they're not
	   necessary since none of the certs in the chain will be PGP keys */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &isCA, 
							  CRYPT_CERTINFO_CA );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		isCA = FALSE;
		status = CRYPT_OK;
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, 
							&trustedUsage, CRYPT_CERTINFO_TRUSTED_USAGE );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* If there's no trusted usage defined, don't store a trust
			   setting */
			trustedUsage = CRYPT_UNUSED;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, 
							&trustedImplicit, CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* If it's not implicitly trusted, don't store a trust setting */
			trustedImplicit = FALSE;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusOK( status ) )
		status = getValidityInfo( pkcs15info, cryptHandle );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, pkcs15info->pgp2KeyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_PGP );
		if( cryptStatusOK( status ) )
			/* Not present for all key types, so an error isn't fatal */
			pkcs15info->pgp2KeyIDlength = msgData.length;
		setMessageData( &msgData, pkcs15info->openPGPKeyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		pkcs15info->openPGPKeyIDlength = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( status );
	if( !pkcs15info->iDlength )
		{
		status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_SPKI,
							pkcs15info->iD );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15info->iDlength = KEYID_SIZE;
		}
	if( !pkcs15info->keyIDlength )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, pkcs15info->keyID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
		if( cryptStatusOK( status ) )
			pkcs15info->keyIDlength = msgData.length;
		else
			{
			memcpy( pkcs15info->keyID, pkcs15info->iD, pkcs15info->iDlength );
			pkcs15info->keyIDlength = pkcs15info->iDlength;
			}
		}

	/* At this point we could create a pseudo-label by walking up the cert DN
	   from the CN until we find a component we can use, however label-less
	   items will only occur when adding a standalone (i.e. trusted, 
	   implicitly-handled) cert.  If we were to set labels for these, the 
	   keyset would end up acting as a general-purpose certificate store 
	   which it isn't meant to be, so we always leave implicitly handled 
	   certs label-less */

	/* Calculate the various IDs for the cert */
	status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,
						pkcs15info->iAndSID );
	if( cryptStatusOK( status ) )
		status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_SUBJECT,
							pkcs15info->subjectNameID );
	if( cryptStatusOK( status ) )
		status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_ISSUER,
							pkcs15info->issuerNameID );
	if( cryptStatusError( status ) )
		return( status );
	pkcs15info->iAndSIDlength = pkcs15info->subjectNameIDlength = \
		pkcs15info->issuerNameIDlength = KEYID_SIZE;
	trustedUsageSize = ( trustedUsage != CRYPT_UNUSED ) ? \
					   sizeofBitString( trustedUsage ) : 0;
	keyIdentifierDataSize = sizeofObjectIDs( pkcs15info );

	/* Determine how big the attribute collection will be */
	commonAttributeSize = pkcs15info->labelLength ? \
						  ( int) sizeofObject( pkcs15info->labelLength ) : 0;
	commonCertAttributeSize = ( int ) \
						sizeofObject( pkcs15info->iDlength ) + \
						( isCA ? sizeofBoolean() : 0 ) + \
						( ( trustedUsage != CRYPT_UNUSED ) ? \
						  sizeofObject( trustedUsageSize ) : 0 ) + \
						sizeofObject( keyIdentifierDataSize ) + \
						( trustedImplicit ? sizeofBoolean() : 0 ) + \
						sizeofGeneralizedTime() + sizeofGeneralizedTime();

	/* Write the cert attributes */
	sMemOpen( &stream, certAttributes, KEYATTR_BUFFER_SIZE );
	writeSequence( &stream, commonAttributeSize );
	if( commonAttributeSize )
		writeCharacterString( &stream, pkcs15info->label,
							  pkcs15info->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonCertAttributeSize );
	writeOctetString( &stream, pkcs15info->iD, pkcs15info->iDlength,
					  DEFAULT_TAG );
	if( isCA )
		writeBoolean( &stream, TRUE, DEFAULT_TAG );
	if( trustedUsage != CRYPT_UNUSED )
		{
		writeConstructed( &stream, trustedUsageSize, CTAG_CA_TRUSTED_USAGE );
		writeBitString( &stream, trustedUsage, DEFAULT_TAG );
		}
	writeObjectIDs( &stream, pkcs15info, keyIdentifierDataSize, 
					CTAG_CA_IDENTIFIERS );
	if( trustedImplicit )
		writeBoolean( &stream, TRUE, CTAG_CA_TRUSTED_IMPLICIT );
	writeGeneralizedTime( &stream, pkcs15info->validFrom, DEFAULT_TAG );
	status = writeGeneralizedTime( &stream, pkcs15info->validTo, \
								   CTAG_CA_VALIDTO );
	*certAttributeSize = stell( &stream );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*									Write a Key								*
*																			*
****************************************************************************/

/* When adding key/cert data to a PKCS #15 collection, we have to be able to 
   cleanly handle the addition of arbitrary collections of objects, which 
   leads to some rather convoluted logic for deciding what needs updating 
   and under which conditions.  The actions taken are:

	key only:	if present
					return( CRYPT_ERROR_DUPLICATE )
				else
					add key;
	cert only:	if present
					return( CRYPT_ERROR_DUPLICATE );
				elif( matching key present )
#ifdef RETAIN_PUBKEY
					add, update key data;
#else
					add, delete key data;
#endif // RETAIN_PUBKEY
				elif( trusted cert )
					add as trusted cert;
				else
					error;
	key+cert:	if key present and cert present
					return( CRYPT_ERROR_DUPLICATE );
#ifdef RETAIN_PUBKEY
				if key present -> don't add key;
#else
				delete key;
#endif // RETAIN_PUBKEY
				if cert present -> don't add cert;

   The following values specify the action to be taken when adding a cert */

typedef enum {
	CERTADD_UPDATE_EXISTING,/* Update existing key info with a cert */
	CERTADD_NORMAL,			/* Add a cert for which no key info present */
	CERTADD_STANDALONE_CERT	/* Add a standalone cert not assoc'd with a key */
	} CERTADD_TYPE;

/* Determine the tag to use when encoding a given key type.  There isn't any
   tag for Elgamal but the keys are the same as X9.42 DH keys and cryptlib
   uses the OID rather than the tag to determine the key type, so the 
   following sleight-of-hand works */

static int getKeyTypeTag( const CRYPT_CONTEXT cryptContext )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	int status;

	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( DEFAULT_TAG );

		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_ELGAMAL:
			return( 1 );

		case CRYPT_ALGO_DSA:
			return( 2 );

		case CRYPT_ALGO_KEA:
			return( 3 );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/* Generate a session key and write the wrapped key in the form
   SET OF {	[ 0 ] (EncryptedKey) } */

static int writeWrappedSessionKey( STREAM *stream,
								   CRYPT_CONTEXT iSessionKeyContext,
								   const CRYPT_USER cryptOwner,
								   const char *password,
								   const int passwordLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	CRYPT_ALGO_TYPE cryptAlgo;
	int iterations, exportedKeySize, status;

	/* In the interests of luser-proofing, we're really paranoid and force
	   the use of non-weak algorithms and modes of operation.  In addition
	   since OIDs are only defined for a limited subset of algorithms, we
	   also default to a guaranteed available algorithm if no OID is defined
	   for the one requested */
	krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE, &cryptAlgo,
					 CRYPT_OPTION_ENCR_ALGO );
	if( isWeakCryptAlgo( cryptAlgo ) || \
		cryptStatusError( sizeofAlgoIDex( cryptAlgo,
									( CRYPT_ALGO_TYPE ) CRYPT_MODE_CBC, 0 ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;
	krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE, &iterations,
					 CRYPT_OPTION_KEYING_ITERATIONS );
	if( iterations < MIN_KEYING_ITERATIONS )
		iterations = MIN_KEYING_ITERATIONS;

	/* Create an encryption context and derive the user password into it */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
							  &iterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, ( void * ) password, passwordLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_KEYING_VALUE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Determine the size of the exported key and write the encrypted data
	   content field */
	if( cryptStatusOK( status ) )
		status = iCryptExportKeyEx( NULL, &exportedKeySize, 0, 
									CRYPT_FORMAT_CMS, iSessionKeyContext, 
									createInfo.cryptHandle, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		writeSet( stream, exportedKeySize );
		status = iCryptExportKeyEx( sMemBufPtr( stream ), &exportedKeySize, 
									sMemDataLeft( stream ), CRYPT_FORMAT_CMS, 
									iSessionKeyContext, createInfo.cryptHandle, 
									CRYPT_UNUSED );
		sSkip( stream, exportedKeySize );
		}

	/* Clean up */
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Add a certificate to a PKCS #15 collection, updating affected public and 
   private key attributes as required */

static int addCert( PKCS15_INFO *pkcs15infoPtr, 
					const CRYPT_CERTIFICATE cryptCert,
					const void *pubKeyAttributes, 
					const int pubKeyAttributeSize,
					const void *privKeyAttributes,
					const int privKeyAttributeSize,
					const CERTADD_TYPE certAddType )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE keyBuffer[ MAX_PRIVATE_KEYSIZE ];
	BYTE certAttributes[ KEYATTR_BUFFER_SIZE ];
	void *newPrivKeyData = pkcs15infoPtr->privKeyData;
#ifdef RETAIN_PUBKEY
	void *newPubKeyData = pkcs15infoPtr->pubKeyData;
#endif /* RETAIN_PUBKEY */
	void *newCertData = pkcs15infoPtr->certData;
	const int keyTypeTag = getKeyTypeTag( cryptCert );
	int newPrivKeyDataSize, newPrivKeyOffset, privKeyInfoSize;
#ifdef RETAIN_PUBKEY
	int newPubKeyDataSize, newPubKeyOffset, pubKeyInfoSize;
#endif /* RETAIN_PUBKEY */
	int newCertDataSize, newCertOffset, certAttributeSize;
	int status;

	/* If we've been passed a standalone cert, it has to be implicitly
	   trusted in order to be added */
	if( certAddType == CERTADD_STANDALONE_CERT )
		{
		int value;

		status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ARGERROR_NUM1 );

		/* Set the personality type to cert-only */
		pkcs15infoPtr->type = PKCS15_SUBTYPE_CERT;
		}

	/* Write the cert attributes */
	status = writeCertAttributes( certAttributes, &certAttributeSize,
								  pkcs15infoPtr, cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Find out how big the PKCS #15 data will be and allocate room for it.
	   Since the cert will affect the key attributes, we need to rewrite the
	   key information once we've done the cert.  If the rewritten key data
	   will fit into the existing space (for example if only a permission bit
	   or two has changed) we reuse the current storage, otherwise we
	   allocate new storage */
	if( certAddType == CERTADD_UPDATE_EXISTING )
		{
#ifdef RETAIN_PUBKEY
		pubKeyInfoSize = pkcs15infoPtr->pubKeyDataSize - \
						 pkcs15infoPtr->pubKeyOffset;
		newPubKeyDataSize = pubKeyAttributeSize + \
							( int ) sizeofObject( \
									  sizeofObject( \
										sizeofObject( pubKeyInfoSize ) ) );
		if( sizeofObject( newPubKeyDataSize ) > \
										pkcs15infoPtr->pubKeyDataSize )
			{
			newPubKeyData = \
					clAlloc( "addCert", \
							 ( int ) sizeofObject( newPubKeyDataSize ) );
			if( newPubKeyData == NULL )
				return( CRYPT_ERROR_MEMORY );
			}
#else
		if( pkcs15infoPtr->pubKeyData != NULL )
			{
			zeroise( pkcs15infoPtr->pubKeyData, pkcs15infoPtr->pubKeyDataSize );
			clFree( "addCert", pkcs15infoPtr->pubKeyData );
			pkcs15infoPtr->pubKeyData = NULL;
			pkcs15infoPtr->pubKeyDataSize = 0;
			}
#endif /* RETAIN_PUBKEY */
		privKeyInfoSize = pkcs15infoPtr->privKeyDataSize - \
						  pkcs15infoPtr->privKeyOffset;
		newPrivKeyDataSize = privKeyAttributeSize + \
							 ( int ) sizeofObject( \
									  sizeofObject( privKeyInfoSize ) );
		if( sizeofObject( newPrivKeyDataSize ) > \
										pkcs15infoPtr->privKeyDataSize )
			{
			newPrivKeyData = \
					clAlloc( "addCert", \
							 ( int ) sizeofObject( newPrivKeyDataSize ) );
			if( ( newPrivKeyData == NULL ) )
				{
#ifdef RETAIN_PUBKEY
				clFree( "addCert", newPubKeyData );
#endif /* RETAIN_PUBKEY */
				return( CRYPT_ERROR_MEMORY );
				}
			}
		}
	setMessageData( &msgData, keyBuffer, MAX_PRIVATE_KEYSIZE );
	status = krnlSendMessage( cryptCert, IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		newCertDataSize = ( int ) sizeofObject( \
										certAttributeSize + \
										sizeofObject( \
											sizeofObject( msgData.length ) ) );
		if( newCertDataSize > pkcs15infoPtr->certDataSize )
			{
			newCertData = clAlloc( "addCert", newCertDataSize );
			if( newCertData == NULL )
				status = CRYPT_ERROR_MEMORY;
			}
		}
	if( cryptStatusOK( status ) )
		{
		sMemOpen( &stream, newCertData, newCertDataSize );
		writeSequence( &stream, certAttributeSize + \
					   ( int ) sizeofObject( sizeofObject( msgData.length ) ) );
		swrite( &stream, certAttributes, certAttributeSize );
		writeConstructed( &stream, ( int ) sizeofObject( msgData.length ),
						  CTAG_OB_TYPEATTR );
		writeSequence( &stream, msgData.length );
		newCertOffset = stell( &stream );
		swrite( &stream, keyBuffer, msgData.length );
		assert( sStatusOK( &stream ) );
		sMemDisconnect( &stream );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo what we've done so far without changing the existing PKCS #15
		   data */
#ifdef RETAIN_PUBKEY
		if( newPubKeyData != pkcs15infoPtr->pubKeyData )
			clFree( "addCert", newPubKeyData );
#endif /* RETAIN_PUBKEY */
		if( newPrivKeyData != pkcs15infoPtr->privKeyData )
			clFree( "addCert", newPrivKeyData );
		if( newCertData != pkcs15infoPtr->certData && newCertData != NULL )
			clFree( "addCert", newCertData );
		return( status );
		}

	/* Replace the old cert (if there is one) with the new cert.  If it's an
	   add of a standalone cert, we're done */
	if( newCertData != pkcs15infoPtr->certData )
		{
		if( pkcs15infoPtr->certData != NULL )
			{
			zeroise( pkcs15infoPtr->certData, pkcs15infoPtr->certDataSize );
			clFree( "addCert", pkcs15infoPtr->certData );
			}
		pkcs15infoPtr->certData = newCertData;
		}
	pkcs15infoPtr->certDataSize = newCertDataSize;
	pkcs15infoPtr->certOffset = newCertOffset;
	if( certAddType != CERTADD_UPDATE_EXISTING )
		return( CRYPT_OK );

#ifdef RETAIN_PUBKEY
	assert( pubKeyInfoSize < MAX_PRIVATE_KEYSIZE );
#endif /* RETAIN_PUBKEY */
	assert( privKeyInfoSize < MAX_PRIVATE_KEYSIZE );

	/* The corresponding key is already present, we need to update the key
	   info since adding the certificate may have changed the attributes.
	   First we write the new attributes and append the existing key info.
	   Since we may be doing an in-place update, we copy the data out to a
	   temporary buffer while we make the changes */
#ifdef RETAIN_PUBKEY
	memcpy( keyBuffer, ( BYTE * ) pkcs15infoPtr->pubKeyData +
								  pkcs15infoPtr->pubKeyOffset, 
			pubKeyInfoSize );
	sMemOpen( &stream, newPubKeyData,
			  ( int ) sizeofObject( newPubKeyDataSize ) );
	writeConstructed( &stream, newPubKeyDataSize, keyTypeTag );
	swrite( &stream, pubKeyAttributes, pubKeyAttributeSize );
	writeConstructed( &stream,
					  ( int ) sizeofObject( sizeofObject( pubKeyInfoSize ) ),
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, ( int ) sizeofObject( pubKeyInfoSize ) );
	writeConstructed( &stream, pubKeyInfoSize, CTAG_OV_DIRECT );
	newPubKeyOffset = stell( &stream );
	swrite( &stream, keyBuffer, pubKeyInfoSize );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );
#endif /* RETAIN_PUBKEY */
	memcpy( keyBuffer, ( BYTE * ) pkcs15infoPtr->privKeyData +
								  pkcs15infoPtr->privKeyOffset, 
			privKeyInfoSize );
	sMemOpen( &stream, newPrivKeyData,
			  ( int ) sizeofObject( newPrivKeyDataSize ) );
	writeConstructed( &stream, newPrivKeyDataSize, keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, ( int ) sizeofObject( privKeyInfoSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, privKeyInfoSize );
	newPrivKeyOffset = stell( &stream );
	swrite( &stream, keyBuffer, privKeyInfoSize );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );
	zeroise( keyBuffer, MAX_PRIVATE_KEYSIZE );

	/* Replace the old data with the newly-written data */
#ifdef RETAIN_PUBKEY
	if( newPubKeyData != pkcs15infoPtr->pubKeyData )
		{
		zeroise( pkcs15infoPtr->pubKeyData, pkcs15infoPtr->pubKeyDataSize );
		clFree( "addCert", pkcs15infoPtr->pubKeyData );
		pkcs15infoPtr->pubKeyData = newPubKeyData;
		}
#endif /* RETAIN_PUBKEY */
	if( newPrivKeyData != pkcs15infoPtr->privKeyData )
		{
		zeroise( pkcs15infoPtr->privKeyData, pkcs15infoPtr->privKeyDataSize );
		clFree( "addCert", pkcs15infoPtr->privKeyData );
		pkcs15infoPtr->privKeyData = newPrivKeyData;
		}
#ifdef RETAIN_PUBKEY
	pkcs15infoPtr->pubKeyDataSize = ( int ) sizeofObject( newPubKeyDataSize );
	pkcs15infoPtr->pubKeyOffset = newPubKeyOffset;
#endif /* RETAIN_PUBKEY */
	pkcs15infoPtr->privKeyDataSize = ( int ) sizeofObject( newPrivKeyDataSize );
	pkcs15infoPtr->privKeyOffset = newPrivKeyOffset;

	return( CRYPT_OK );
	}

/* Add a complete cert chain to a PKCS #15 collection */

static int addCertChain( PKCS15_INFO *pkcs15info, 
						 const CRYPT_CERTIFICATE iCryptCert )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int status;

	/* See if there are certs in the chain beyond the first one, which we've
	   already added.  Getting a data not found error is OK since it just
	   means that there are no more certs present */
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_CURSORFIRST,
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORNEXT,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR_NOTFOUND ) ? CRYPT_OK : status );

	/* Walk up the chain checking each cert to see whether we need to add
	   it */
	do
		{
		PKCS15_INFO *pkcs15infoPtr;
		BYTE iAndSID [ CRYPT_MAX_HASHSIZE ];
		int i;

		/* Check whether this cert is present */
		status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,
							iAndSID );
		if( cryptStatusError( status ) )
			continue;
		if( findEntry( pkcs15info, CRYPT_IKEYID_ISSUERID, iAndSID,
					   KEYID_SIZE, KEYMGMT_FLAG_NONE ) != NULL )
			continue;

		/* We've found a cert that isn't present yet, try and add it */
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
				break;
		if( i == MAX_PKCS15_OBJECTS )
			return( CRYPT_ERROR_OVERFLOW );
		pkcs15infoPtr = &pkcs15info[ i ];
		pkcs15infoPtr->index = i;
		pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
		status = addCert( pkcs15infoPtr, iCryptCert, NULL, 0, NULL, 0, 
						  CERTADD_NORMAL );

		/* A cert being added may already be present, however we can't fail
		   immediately because there may be further certs in the chain, so we
		   keep track of whether we've successfully added at least one cert
		   and clear data duplicate errors */
		if( status == CRYPT_OK )
			seenNonDuplicate = TRUE;
		else
			if( status == CRYPT_ERROR_DUPLICATE )
				status = CRYPT_OK;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* We reached the end of the chain without finding anything we could
		   add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;
	return( status );
	}

/* Add a public key to a PKCS #15 collection */

static int addPublicKey( PKCS15_INFO *pkcs15info, 
						 const CRYPT_HANDLE cryptHandle,
						 const void *pubKeyAttributes, 
						 const int pubKeyAttributeSize,
						 const CRYPT_ALGO_TYPE pkcCryptAlgo,
						 const int modulusSize )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	const int keyTypeTag = getKeyTypeTag( cryptHandle );
	int pubKeyDataSize, extraDataSize = 0, status;

	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_KEY_SPKI );
	pubKeyDataSize = msgData.length;
	if( pkcCryptAlgo == CRYPT_ALGO_RSA )
		/* RSA keys have an extra element for PKCS #11 compatibility */
		extraDataSize = sizeofShortInteger( modulusSize );
	if( cryptStatusOK( status ) )
		{
		pkcs15info->pubKeyDataSize = ( int ) sizeofObject( \
									pubKeyAttributeSize + \
									sizeofObject( \
									  sizeofObject( \
										sizeofObject( pubKeyDataSize ) + \
										extraDataSize ) ) );
		if( ( pkcs15info->pubKeyData = \
				clAlloc( "addCert", pkcs15info->pubKeyDataSize ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the public key data */
	sMemOpen( &stream, pkcs15info->pubKeyData,
			  pkcs15info->pubKeyDataSize );
	writeConstructed( &stream, pubKeyAttributeSize + \
					  ( int ) sizeofObject( \
								sizeofObject( \
								  sizeofObject( pubKeyDataSize ) + \
								  extraDataSize ) ),
					  keyTypeTag );
	swrite( &stream, pubKeyAttributes, pubKeyAttributeSize );
	writeConstructed( &stream,
					  ( int ) sizeofObject( \
								sizeofObject( pubKeyDataSize ) + \
								extraDataSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, ( int ) sizeofObject( pubKeyDataSize ) + \
									extraDataSize );
	writeConstructed( &stream, pubKeyDataSize, CTAG_OV_DIRECT );
	pkcs15info->pubKeyOffset = stell( &stream );
	status = exportAttributeToStream( &stream, cryptHandle, 
									  CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusOK( status ) && pkcCryptAlgo == CRYPT_ALGO_RSA )
		{
		/* When using the SPKI option for storing key components, the RSA
		   components require a [1] tag since the basic (non-SPKI) option is
		   also a SEQUENCE, so if it's an RSA key we modify the tag.  This is
		   easier than passing the tag requirement down through the kernel
		   call to the context.  In addition RSA keys have an extra element
		   for PKCS #11 compatibility */
#if 0	/* Disabled until 3.1 is widespread, since 3.0 used readSequence() */
		sMemBufPtr( &stream )[ 0 ] = MAKE_CTAG( 1 );
#endif /* 0 */
		status = writeShortInteger( &stream, modulusSize, DEFAULT_TAG );
		}
	sMemDisconnect( &stream );
	return( status );
	}

/* Add a private key to a PKCS #15 collection */

static int addPrivateKey( PKCS15_INFO *pkcs15info, 
						  const CRYPT_HANDLE cryptHandle,
						  const CRYPT_HANDLE ownerHandle,
						  const char *password, const int passwordLength,
						  const void *privKeyAttributes, 
						  const int privKeyAttributeSize,
						  const CRYPT_ALGO_TYPE pkcCryptAlgo,
						  const int modulusSize )
	{
	CRYPT_ALGO_TYPE wrapCryptAlgo;
	CRYPT_CONTEXT iSessionKeyContext;
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	void *headerPtr, *dataPtr;
	const int keyTypeTag = getKeyTypeTag( cryptHandle );
	int privKeyInfoSize, privKeyDataSize;
	int value, status;

	/* Create a session key context and generate a key and IV into it.  The IV
	   would be generated automatically later on when we encrypt data for the
	   first time, but we do it explicitly here to catch any possible errors
	   at a point where recovery is easier.  In the interests of luser-
	   proofing we're really paranoid and force the use of non-weak algorithms
	   and modes of operation.  In addition since OIDs are only defined for a
	   limited subset of algorithms, we also default to a guaranteed available
	   algorithm if no OID is defined for the one requested */
	krnlSendMessage( ownerHandle, IMESSAGE_GETATTRIBUTE, &wrapCryptAlgo, 
					 CRYPT_OPTION_ENCR_ALGO );
	if( isWeakCryptAlgo( wrapCryptAlgo ) ||
		cryptStatusError( sizeofAlgoIDex( wrapCryptAlgo,
									( CRYPT_ALGO_TYPE ) CRYPT_MODE_CBC, 0 ) ) )
		wrapCryptAlgo = CRYPT_ALGO_3DES;
	setMessageCreateObjectInfo( &createInfo, wrapCryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_GENKEY,
								  NULL, FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		if( createInfo.cryptHandle != CRYPT_ERROR )
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	iSessionKeyContext = createInfo.cryptHandle;

	/* Calculate the eventual encrypted key size and allocate storage for it */
	setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, cryptHandle,
						  iSessionKeyContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	privKeyInfoSize = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusOK( status ) )
		{
		pkcs15info->privKeyDataSize = privKeyAttributeSize +
										 privKeyInfoSize + 512;
		if( ( pkcs15info->privKeyData = \
					clAlloc( "addPrivateKey", \
							 pkcs15info->privKeyDataSize ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Since we can't write the header and attributes until we write the
	   encrypted private key, we leave enough space at the start to contain
	   this information and write the private key after that */
	sMemOpen( &stream, pkcs15info->privKeyData, pkcs15info->privKeyDataSize );
	sseek( &stream, 200 + privKeyAttributeSize );
	dataPtr = sMemBufPtr( &stream );

	/* Write the encryption information with a gap at the start for the CMS
	   header.  Since we're using KEKRecipientInfo, we use a version of 2
	   rather than 0  */
	writeShortInteger( &stream, 2, DEFAULT_TAG );
	status = writeWrappedSessionKey( &stream, iSessionKeyContext,
									 ownerHandle, password, passwordLength );
	if( cryptStatusOK( status ) )
		status = writeCMSencrHeader( &stream, OID_CMS_DATA, privKeyInfoSize,
									 iSessionKeyContext );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Export the encrypted private key */
	setMechanismWrapInfo( &mechanismInfo, sMemBufPtr( &stream ),
						  privKeyInfoSize, NULL, 0, cryptHandle,
						  iSessionKeyContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	if( cryptStatusOK( status ) && pkcCryptAlgo == CRYPT_ALGO_RSA )
		{
		STREAM encDataStream;
		int length;

		/* Check that the wrapped key data no longer contains identifiable
		   structured data.  We can only do this for RSA keys since the
		   amount of information present for DLP keys is too small to 
		   reliably check.  For RSA keys the data would be:
			SEQUENCE {
				[0] INTEGER | [3] INTEGER,
				...
				}
		   This check is performed in addition to checks already performed by
		   the encryption code and the key wrap code */
		sMemConnect( &encDataStream, mechanismInfo.wrappedData, 
					 mechanismInfo.wrappedDataLength );
		status = readSequence( &encDataStream, &length );
		if( cryptStatusOK( status ) )
			{
			/* The data must contain at least p and q, or at most all key
			   components */
			if( length < ( bitsToBytes( MIN_PKCSIZE_BITS ) * 2 ) || \
				length > MAX_PRIVATE_KEYSIZE )
				status = CRYPT_ERROR;
			else
				{
				/* The first value is either n or p */
				value = peekTag( &encDataStream );
				if( value == MAKE_CTAG( 0 ) || value == MAKE_CTAG( 3 ) )
					{
					status = readIntegerTag( &encDataStream, NULL, 
											 &length, CRYPT_MAX_PKCSIZE, 
											 value );
					if( cryptStatusOK( status ) && \
						( length < bitsToBytes( MIN_PKCSIZE_BITS ) || \
						  length > CRYPT_MAX_PKCSIZE ) )
						status = CRYPT_ERROR;
					}
				}
			}
		sMemDisconnect( &encDataStream );
		status = ( cryptStatusError( status ) ) ? \
				 CRYPT_OK : CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		status = sSkip( &stream, mechanismInfo.wrappedDataLength );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	privKeyDataSize = stell( &stream ) - ( 200 + privKeyAttributeSize );

	/* Kludge the CMS header onto the start of the data */
	sseek( &stream, 100 + privKeyAttributeSize );
	headerPtr = sMemBufPtr( &stream );
	writeConstructed( &stream, privKeyDataSize, CTAG_OV_DIRECTPROTECTED );
	memmove( sMemBufPtr( &stream ), dataPtr, privKeyDataSize );
	privKeyDataSize += stell( &stream ) - ( 100 + privKeyAttributeSize );

	/* Now that we've written the private key data and know how long it is,
	   move back to the start and write the attributes and outer header, then
	   move the private key information down to the end.  Finally, adjust the
	   private key size value to reflect its true size (rather than the
	   allocated buffer size) */
	sseek( &stream, 0 );
	if( pkcCryptAlgo == CRYPT_ALGO_RSA )
		/* RSA keys have an extra element for PKCS #11 compatibility */
		privKeyDataSize += sizeofShortInteger( modulusSize );
	writeConstructed( &stream, privKeyAttributeSize + \
					  ( int ) sizeofObject( sizeofObject( privKeyDataSize ) ),
					  keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, ( int ) sizeofObject( privKeyDataSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, privKeyDataSize );
	pkcs15info->privKeyOffset = stell( &stream );
	if( pkcCryptAlgo == CRYPT_ALGO_RSA )
		{
		/* RSA keys have an extra element for PKCS #11 compability that we
		   need to kludge onto the end of the private-key data */
		privKeyDataSize -= sizeofShortInteger( modulusSize );
		memmove( sMemBufPtr( &stream ), headerPtr, privKeyDataSize );
		sSkip( &stream, privKeyDataSize );
		status = writeShortInteger( &stream, modulusSize, DEFAULT_TAG );
		}
	else
		{
		memmove( sMemBufPtr( &stream ), headerPtr, privKeyDataSize );
		status = sSkip( &stream, privKeyDataSize );
		}
	pkcs15info->privKeyDataSize = stell( &stream );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );

	return( status );
	}

/* Add configuration data to a PKCS #15 collection */

static int addConfigData( PKCS15_INFO *pkcs15info, const char *data, 
						  const int dataLength, const int flags )
	{
	int i;

	assert( flags == CRYPT_IATTRIBUTE_CONFIGDATA || \
			flags == CRYPT_IATTRIBUTE_USERINDEX || \
			flags == CRYPT_IATTRIBUTE_USERID || \
			flags == CRYPT_IATTRIBUTE_USERINFO );

	/* If it's a user ID, set all object IDs to this value.  This is needed 
	   for user keysets where there usually isn't any key ID present (there 
	   is one for SO keysets since they have public/private keys attached to 
	   them, but they're not identified by key ID so it's not much use).  In 
	   this case the caller has to explicitly set an ID, which is the user 
	   ID */
	if( flags == CRYPT_IATTRIBUTE_USERID )
		{
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			{
			memcpy( pkcs15info[ i ].iD, data, dataLength );
			pkcs15info[ i ].iDlength = dataLength;
			}
		return( CRYPT_OK );
		}

	/* Find either the first free entry or an entry that contains data 
	   identical to what we're adding now, which we'll replace with the new 
	   data */
	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		if( ( pkcs15info[ i ].type == PKCS15_SUBTYPE_DATA && \
			  pkcs15info[ i ].dataType == flags ) || \
			pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
			break;
	if( i == MAX_PKCS15_OBJECTS )
		return( CRYPT_ERROR_OVERFLOW );
	pkcs15info = &pkcs15info[ i ];

	/* If there's existing data present which was read from a keyset that
	   was opened for update, clear and free it */
	if( pkcs15info->dataData != NULL )
		{
		assert( pkcs15info->dataType == flags );

		zeroise( pkcs15info->dataData, pkcs15info->dataDataSize );
		clFree( "addConfigData", pkcs15info->dataData );
		pkcs15info->type = PKCS15_SUBTYPE_NONE;

		/* If we're being sent empty data (corresponding to an empty 
		   SEQUENCE), it means the caller wants to clear this entry */
		if( dataLength < 8 )
			{
			zeroise( pkcs15info, sizeof( PKCS15_INFO ) );
			return( CRYPT_OK );
			}
		}

	/* Remember the pre-encoded config data */
	assert( pkcs15info->type == PKCS15_SUBTYPE_NONE );
	if( ( pkcs15info->dataData = \
						clAlloc( "addConfigData", dataLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( pkcs15info->dataData, data, dataLength );
	pkcs15info->dataDataSize = dataLength;

	/* Set the type information for the data */
	pkcs15info->type = PKCS15_SUBTYPE_DATA;
	pkcs15info->dataType = flags;

	return( CRYPT_OK );
	}

/* Add a secret key to a PKCS #15 collection */

static int addSecretKey( PKCS15_INFO *pkcs15info, 
						 const CRYPT_HANDLE cryptHandle )
	{
	RESOURCE_DATA msgData;
	char label[ CRYPT_MAX_TEXTSIZE + 1 ];
	int i, status;

	/* Check the object and make sure the label of what we're adding 
	   doesn't duplicate the label of an existing object */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_CRYPT );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		return( status );
	if( findEntry( pkcs15info, CRYPT_KEYID_NAME, msgData.data, 
				   msgData.length, KEYMGMT_FLAG_NONE ) != NULL )
		return( CRYPT_ERROR_DUPLICATE );

	/* Find out where we can add the new key data */
	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
			break;
	if( i == MAX_PKCS15_OBJECTS )
		return( CRYPT_ERROR_OVERFLOW );
	pkcs15info = &pkcs15info[ i ];

	pkcs15info->type = PKCS15_SUBTYPE_SECRETKEY;

	/* This functionality is currently unused */
	assert( NOTREACHED );
	return( CRYPT_ERROR );
	}

/* Add an item to the PKCS #15 keyset */

static int setItemFunction( KEYSET_INFO *keysetInfo,
							const CRYPT_HANDLE cryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const char *password, const int passwordLength,
							const int flags )
	{
	CRYPT_ALGO_TYPE pkcCryptAlgo;
	CRYPT_CERTIFICATE iCryptCert;
	PKCS15_INFO *pkcs15infoPtr;
	RESOURCE_DATA msgData;
	BYTE iD[ CRYPT_MAX_HASHSIZE ];
	BYTE pubKeyAttributes[ KEYATTR_BUFFER_SIZE ];
	BYTE privKeyAttributes[ KEYATTR_BUFFER_SIZE ];
	BOOLEAN certPresent = FALSE, privkeyContextPresent;
	BOOLEAN pkcs15certPresent = FALSE, pkcs15keyPresent = FALSE;
	BOOLEAN isCertChain = FALSE, isCertUpdate = FALSE;
	int pubKeyAttributeSize;
	int privKeyAttributeSize;
	int iDsize, modulusSize, value, status;

	/* If we're being sent pre-encoded data or a secret key, add it to the 
	   PKCS #15 data and exit */
	if( cryptHandle == CRYPT_UNUSED )
		return( addConfigData( keysetInfo->keyData, password, passwordLength, 
							   flags ) );
	if( itemType == KEYMGMT_ITEM_SECRETKEY )
		return( addSecretKey( keysetInfo->keyData, cryptHandle ) );

	/* Check the object, extract ID information from it, and determine
	   whether it's a standalone cert (which produces a PKCS #15 cert object)
	   or a private-key context (which produces PKCS #15 a private key object 
	   and either a PKCS #15 public-key object or a cert object) */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC );
	if( cryptStatusOK( status ) )
		{
		krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &pkcCryptAlgo, 
						 CRYPT_CTXINFO_ALGO );
		krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &modulusSize, 
						 CRYPT_CTXINFO_KEYSIZE );
		setMessageData( &msgData, iD, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		iDsize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	privkeyContextPresent = cryptStatusOK( \
			krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							 MESSAGE_CHECK_PKC_PRIVATE ) ) ? TRUE : FALSE;

	/* If there's a cert present, make sure it's something that can be
	   stored.  We don't treat the wrong type as an error since we can still
	   store the public/private key components even if we don't store the
	   cert */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && \
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

	/* Find out where we can add data and what needs to be added */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, CRYPT_KEYIDEX_ID,
							   iD, iDsize, KEYMGMT_FLAG_NONE );
	if( pkcs15infoPtr != NULL )
		{
		BOOLEAN unneededCert, unneededKey;

		/* Determine what actually needs to be added */
		if( pkcs15infoPtr->privKeyData != NULL )
			pkcs15keyPresent = TRUE;
		if( pkcs15infoPtr->certData != NULL )
			pkcs15certPresent = TRUE;

		/* Make sure we can update at least one of the PKCS #15 objects in
		   the personality */
		unneededKey = privkeyContextPresent & pkcs15keyPresent;
		unneededCert = certPresent & pkcs15certPresent;
		if( ( ( unneededCert && !privkeyContextPresent ) || \
			  ( unneededKey && unneededCert ) ) && \
			pkcs15infoPtr->validTo != 0 )
			{
			time_t validTo;

			/* If the cert would be a duplicate, see if the new cert is more
			   recent than the existing one.  We only perform this check if 
			   there's a validTo time stored for the cert since without this 
			   restriction any cert without a stored time could be 
			   overwritten */
			setMessageData( &msgData, &validTo, sizeof( time_t ) );
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CERTINFO_VALIDTO );
			if( cryptStatusOK( status ) && validTo > pkcs15infoPtr->validTo )
				{
				time_t validFrom;

				/* It's a newer cert, don't treat it as a duplicate.  This
				   check is effectively impossible to perform automatically
				   since there are an infinite number of variations that
				   have to be taken into account (e.g. cert for the same key
				   issued by a different CA, same CA but it's changed the
				   bits it sets in the keyUsage (digitalSignature vs
				   nonRepudiation), slightly different issuer DN (Thawte
				   certs with a date encoded in the DN), and so on an so on).
				   Because it requires manual processing by a human, we
				   don't even try and sort it all but just allow a cert for
				   a given key (checked by the ID match) to be replaced by a
				   newer cert for the same key.  This is restrictive enough
				   to prevent most obviously-wrong replacements, while being
				   permissive enough to allow most probably-OK replacements */
				unneededCert = FALSE;
				isCertUpdate = TRUE;

				/* There is one special-case situation in which odd things 
				   can happen when updating certs and that's when adding a 
				   future-dated cert, which would result in the cert being 
				   replaced with one that can't be used yet.  There's no 
				   clean way to handle this because in order to know what to 
				   do we'd have to be able to guess the intent of the user, 
				   however for anything but signature certs it's likely that 
				   the hit-and-miss cert checking performed by most software 
				   won't even notice a future-dated cert, and for signature
				   certs the semantics of signing data now using a cert that 
				   isn't valid yet are somewhat uncertain.  Since in most 
				   cases no-one will even notice the problem, we throw an 
				   exception in the debug build but don't do anything in 
				   release builds.  This is probably less annoying to users
				   than having the code reject a future-dated cert */
				setMessageData( &msgData, &validFrom, sizeof( time_t ) );
				status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
										  &msgData, CRYPT_CERTINFO_VALIDFROM );
				if( cryptStatusOK( status ) && \
					validFrom > getApproxTime() + 86400 )
					{
					assert( !"Attempt to replace cert with future-dated cert" );
					}
				}
			}
		if( ( unneededKey && !certPresent ) ||				/* Key only, duplicate */
			( unneededCert && !privkeyContextPresent ) ||	/* Cert only, duplicate */
			( unneededKey && unneededCert ) )				/* Key+cert, duplicate */
			{
			/* If it's anything other than a cert chain, we can't add
			   anything */
			if( !isCertChain )
				return( CRYPT_ERROR_DUPLICATE );

			/* It's a cert chain, there may be new certs present, try and add
			   them */
			status = krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_TRUE, 
									  CRYPT_IATTRIBUTE_LOCKED );
			if( cryptStatusError( status ) )
				return( status );
			status = addCertChain( pkcs15infoPtr, cryptHandle );
			krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, 
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
			return( status );
			}
		}
	else
		{
		char label[ CRYPT_MAX_TEXTSIZE + 1 ];
		int i;

		/* This key/cert isn't already present, make sure the label of what
		   we're adding doesn't duplicate the label of an existing object */
		if( privkeyContextPresent )
			{
			setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CTXINFO_LABEL );
			if( cryptStatusError( status ) )
				return( status );
			}
		if( findEntry( keysetInfo->keyData, CRYPT_KEYID_NAME,
					   msgData.data, msgData.length,
					   KEYMGMT_FLAG_NONE ) != NULL )
			return( CRYPT_ERROR_DUPLICATE );

		/* Find out where we can add the new key data */
		pkcs15infoPtr = keysetInfo->keyData;
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15infoPtr[ i ].type == PKCS15_SUBTYPE_NONE )
				break;
		if( i == MAX_PKCS15_OBJECTS )
			return( CRYPT_ERROR_OVERFLOW );
		pkcs15infoPtr = &pkcs15infoPtr[ i ];
		pkcs15infoPtr->index = i;
		}
	pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;

	/* If we're adding a private key, make sure there's a context and a 
	   password present.  Conversely, if there's a password present make 
	   sure that we're adding a private key.  This has already been checked 
	   by the kernel, but we perform a second check here just to be safe */
	if( itemType == KEYMGMT_ITEM_PRIVATEKEY )
		{
		if( !privkeyContextPresent )
			return( CRYPT_ARGERROR_NUM1 );
		if( password == NULL )
			return( CRYPT_ARGERROR_STR1 );
		}
	else
		if( password != NULL )
			return( CRYPT_ARGERROR_NUM1 );

	/* We're ready to go, lock the object for our exclusive use */
	if( certPresent )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the attribute information.  We have to rewrite the key
	   information when we add a non-standalone cert even if we don't change
	   the key because adding a cert can affect key attributes */
	if( ( certPresent && pkcs15keyPresent ) ||				/* Updating existing */
		( privkeyContextPresent && !pkcs15keyPresent ) )	/* Adding new */
		status = writeKeyAttributes( privKeyAttributes, &privKeyAttributeSize,
									 pubKeyAttributes, &pubKeyAttributeSize,
									 pkcs15infoPtr, cryptHandle );
	if( cryptStatusError( status ) )
		{
		if( certPresent )
			krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
		return( status );
		}

	/* Write the cert if necessary.  We do this one first because it's the
	   easiest to back out of */
	if( certPresent && ( isCertUpdate || !pkcs15certPresent ) )
		{
		/* Select the leaf cert in case it's a cert chain */
		krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );

		/* Write the cert information.  There may be further certs in the
		   chain but we don't try and do anything with these until after the
		   rest of the key information has been added */
		status = addCert( pkcs15infoPtr, cryptHandle, pubKeyAttributes,
						  pubKeyAttributeSize, privKeyAttributes,
						  privKeyAttributeSize, pkcs15keyPresent ? \
							CERTADD_UPDATE_EXISTING : \
						  privkeyContextPresent ? \
							CERTADD_NORMAL : CERTADD_STANDALONE_CERT );
		if( cryptStatusError( status ) )
			{
			if( certPresent )
				krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								 MESSAGE_VALUE_FALSE, 
								 CRYPT_IATTRIBUTE_LOCKED );
			return( status );
			}

		/* If there's no context to add we return now, however if we've been
		   given a cert chain with further certs in it we try and add these as
		   well before we exit.  Note that we may return an error at this 
		   point if the cert chain update fails even if the main cert add
		   succeeded.  This is better than returning CRYPT_OK but only adding
		   some certs since it lets the caller know the operation wasn't
		   completely successful and can be retried if necessary, at which
		   point it'll be handled via the cert-chain-only update code earlier
		   on */
		if( !privkeyContextPresent || pkcs15keyPresent )
			{
			if( isCertChain )
				status = addCertChain( pkcs15infoPtr, cryptHandle );
			if( certPresent )
				krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								 MESSAGE_VALUE_FALSE, 
								 CRYPT_IATTRIBUTE_LOCKED );
			return( status );
			}
		}
	assert( itemType == KEYMGMT_ITEM_PRIVATEKEY );
	assert( !isCertUpdate );

	/* Add the public key info if necessary */
#ifdef RETAIN_PUBKEY
	status = addPublicKey( pkcs15infoPtr, cryptHandle, pubKeyAttributes, 
						   pubKeyAttributeSize, pkcCryptAlgo, modulusSize );
#else
	if( !certPresent )
		status = addPublicKey( pkcs15infoPtr, cryptHandle, pubKeyAttributes, 
							   pubKeyAttributeSize, pkcCryptAlgo, 
							   modulusSize );
#endif /* RETAIN_PUBKEY */
	if( cryptStatusError( status ) )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		if( certPresent )
			krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
		return( status );
		}

	/* Add the private key info */
	status = addPrivateKey( pkcs15infoPtr, cryptHandle, 
							keysetInfo->ownerHandle, password, 
							passwordLength, privKeyAttributes, 
							privKeyAttributeSize, pkcCryptAlgo, 
							modulusSize );
	if( cryptStatusError( status ) )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		if( certPresent )
			krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
		return( status );
		}

	/* If we've been given a cert chain, try and add any further certs that
	   may be present in it.  Once we've done that, we can unlock the
	   object to allow others access */
	if( isCertChain )
		{
		status = addCertChain( pkcs15infoPtr, cryptHandle );
		if( status == CRYPT_ERROR_DUPLICATE )
			/* The certs in the chain are already present, this isn't an
			   error */
			status = CRYPT_OK;
		}
	if( certPresent )
		krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	return( status );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

void initPKCS15write( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->setItemFunction = setItemFunction;
	}
#endif /* USE_PKCS15 */
