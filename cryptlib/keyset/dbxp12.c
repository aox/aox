/****************************************************************************
*																			*
*						  cryptlib PKCS #12 Routines						*
*						Copyright Peter Gutmann 1997-2002					*
*																			*
****************************************************************************/

/* This code is based on breakms.c, which breaks the encryption of several of
   MS's extremely broken PKCS #12 implementations.  Because of the security
   problems associated with key files produced by MS software and the fact
   that this format is commonly used to spray private keys around without any
   regard to their sensitivity, cryptlib doesn't support it.  As one vendor 
   who shall remain anonymous put it, "We don't want to put our keys anywhere 
   where MS software can get to them" */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS12

/* A PKCS #12 file can in theory contain multiple key and cert objects,
   however nothing seems to use this capability, both because there are half
   a dozen different interpretations as to how it's supposed to work, both in
   terms of how to interpret the format and what to do with things like 
   MACing, which can only use a single key even if there are multiple
   different encryption keys used for the data, and because the complete
   abscence of key indexing information means that there's no easy way to 
   sort out which key is used for what.  The code is written to handle 
   multiple personalities like PKCS #15 and PGP, but is restricted to using 
   only a single personality */

#define MAX_PKCS12_OBJECTS		1

/* The minimum number of keying iterations to use when deriving a key wrap
   key from a password */

#define MIN_KEYING_ITERATIONS	1000

/* Parameters for PKCS #12's homebrew password-derivation mechanism.  The ID
   values function as diversifiers when generating the same keying material
   from a given password and in effect function as an extension of the salt */

#define KEYWRAP_ID_IV			1
#define KEYWRAP_ID_MACKEY		2
#define KEYWRAP_ID_WRAPKEY		3
#define KEYWRAP_SALTSIZE		8

/* The following structure contains the information for one personality, 
   which covers one or more of a private key, public key, and cert.  We also
   need to store a MAC context for use when we write the data to disk, this 
   is supposedly optional but most apps will reject the keyset (or even 
   crash) if it's not present */

typedef struct {
	/* General information */
	int index;						/* Unique value for this personality */
	char label[ CRYPT_MAX_TEXTSIZE ];/* PKCS #12 object label */
	int labelLength;

	/* Key wrap and MAC information */
	BYTE wrapSalt[ CRYPT_MAX_HASHSIZE ];
	int wrapSaltSize;				/* Salt for key wrap key */
	int wrapIterations;				/* Number of iters.to derive key wrap key */
	CRYPT_CONTEXT iMacContext;		/* MAC context */
	BYTE macSalt[ CRYPT_MAX_HASHSIZE ];
	int macSaltSize;				/* Salt for MAC key */
	int macIterations;				/* Number of iters.to derive MAC key */

	/* Key/cert object data */
	void *privKeyData, *certData;	/* Encoded object data */
	int privKeyDataSize, certDataSize;
	} PKCS12_INFO;

/* OID information for a PKCS #12 file */

static const FAR_BSS OID_SELECTION dataOIDselection[] = {
    { OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_OK },
    { NULL, 0, 0, 0 }
    };

static const FAR_BSS OID_SELECTION keyDataOIDselection[] = {
	{ OID_CMS_ENCRYPTEDDATA, 0, 2, TRUE },				/* Encr.priv.key */
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, FALSE },/* Non-encr priv.key */
	{ NULL, 0, 0, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Free object entries */

static void pkcs12freeEntry( PKCS12_INFO *pkcs12info )
	{
	if( pkcs12info->iMacContext != CRYPT_ERROR )
		krnlSendNotifier( pkcs12info->iMacContext, IMESSAGE_DECREFCOUNT );
	if( pkcs12info->privKeyData != NULL )
		{
		zeroise( pkcs12info->privKeyData, pkcs12info->privKeyDataSize );
		clFree( "pkcs12freeEntry", pkcs12info->privKeyData );
		}
	if( pkcs12info->certData != NULL )
		{
		zeroise( pkcs12info->certData, pkcs12info->certDataSize );
		clFree( "pkcs12freeEntry", pkcs12info->certData );
		}
	zeroise( pkcs12info, sizeof( PKCS12_INFO ) );
	}

static void pkcs12Free( PKCS12_INFO *pkcs12info )
	{
	int i;

	for( i = 0; i < MAX_PKCS12_OBJECTS; i++ )
		pkcs12freeEntry( &pkcs12info[ i ] );
	}

/* Create key wrap and MAC contexts from a password */

static int createKeyWrapContext( CRYPT_CONTEXT *iCryptContext,
								 const CRYPT_USER cryptOwner,
								 const char *password,
								 const int passwordLength,
								 PKCS12_INFO *pkcs12info )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_DERIVE_INFO deriveInfo;
	BYTE key[ CRYPT_MAX_KEYSIZE ], iv[ CRYPT_MAX_IVSIZE ];
	BYTE saltData[ 1 + KEYWRAP_SALTSIZE ];
	int status;

	/* Derive the encryption key and IV from the password */
	getNonce( pkcs12info->wrapSalt, KEYWRAP_SALTSIZE );
	pkcs12info->wrapSaltSize = KEYWRAP_SALTSIZE;
	saltData[ 0 ] = KEYWRAP_ID_WRAPKEY;
	memcpy( saltData + 1, pkcs12info->wrapSalt, KEYWRAP_SALTSIZE );
	krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE,
					 &pkcs12info->wrapIterations,
					 CRYPT_OPTION_KEYING_ITERATIONS );
	if( pkcs12info->wrapIterations < MIN_KEYING_ITERATIONS )
		pkcs12info->wrapIterations = MIN_KEYING_ITERATIONS;
	setMechanismDeriveInfo( &deriveInfo, key, 20, password, passwordLength,
							CRYPT_ALGO_SHA, saltData, KEYWRAP_SALTSIZE + 1,
							pkcs12info->wrapIterations );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &deriveInfo, MECHANISM_PKCS12 );
	if( cryptStatusOK( status ) )
		{
		setMechanismDeriveInfo( &deriveInfo, iv, 20, password, passwordLength,
								CRYPT_ALGO_SHA, saltData, KEYWRAP_SALTSIZE + 1,
								pkcs12info->wrapIterations );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								  &deriveInfo, MECHANISM_PKCS12 );
		}
	clearMechanismInfo( &deriveInfo );
	if( cryptStatusError( status ) )
		{
		zeroise( key, CRYPT_MAX_KEYSIZE );
		zeroise( iv, CRYPT_MAX_KEYSIZE );
		return( status );
		}

	/* Create an encryption context and load the key and IV into it.
	   Because PKCS #12 is restricted to an oddball subset of algorithms and
	   modes, we hardcode in the use of 3DES to make sure that we get 
	   something which is safe to use */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_3DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, key, 16 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusOK( status ) )
			{
			int ivSize;

			krnlSendMessage( createInfo.cryptHandle, IMESSAGE_GETATTRIBUTE, 
							 &ivSize, CRYPT_CTXINFO_IVSIZE );
			setResourceData( &msgData, iv, ivSize );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_IV );
			}
		if( cryptStatusError( status ) )
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		else
			*iCryptContext = createInfo.cryptHandle;
		}

	/* Clean up */
	zeroise( key, CRYPT_MAX_KEYSIZE );
	zeroise( iv, CRYPT_MAX_IVSIZE );
	return( status );
	}

static int createMacContext( PKCS12_INFO *pkcs12info, 
							 const CRYPT_USER cryptOwner, 
							 const char *password, const int passwordLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_DERIVE_INFO deriveInfo;
	BYTE key[ CRYPT_MAX_KEYSIZE ], saltData[ 1 + KEYWRAP_SALTSIZE ];
	int status;

	/* Derive the MAC key from the password */
	getNonce( pkcs12info->macSalt, KEYWRAP_SALTSIZE );
	pkcs12info->macSaltSize = KEYWRAP_SALTSIZE;
	saltData[ 0 ] = KEYWRAP_ID_MACKEY;
	memcpy( saltData + 1, pkcs12info->macSalt, KEYWRAP_SALTSIZE );
	krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE,
					 &pkcs12info->macIterations,
					 CRYPT_OPTION_KEYING_ITERATIONS );
	if( pkcs12info->macIterations < MIN_KEYING_ITERATIONS )
		pkcs12info->macIterations = MIN_KEYING_ITERATIONS;
	setMechanismDeriveInfo( &deriveInfo, key, 20, password, passwordLength,
							CRYPT_ALGO_SHA, saltData, KEYWRAP_SALTSIZE + 1,
							pkcs12info->macIterations );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &deriveInfo, MECHANISM_PKCS12 );
	clearMechanismInfo( &deriveInfo );
	if( cryptStatusError( status ) )
		{
		zeroise( key, CRYPT_MAX_KEYSIZE );
		return( status );
		}

	/* Create a MAC context and load the key into it */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_HMAC_SHA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, key, 20 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		else
			pkcs12info->iMacContext = createInfo.cryptHandle;
		}

	/* Clean up */
	zeroise( key, CRYPT_MAX_KEYSIZE );
	return( status );
	}

/****************************************************************************
*																			*
*									Read a Key								*
*																			*
****************************************************************************/

/* Get a key from a PKCS #12 file.  If this code were complete it would use
   the same method as the one used by the PKCS #15 code where we scan the
   file when we open it (stripping out unnecessary junk on the way) and
   simply fetch the appropriate key from the preprocessed data when 
   getItemFunction() is called */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID,  const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	return( CRYPT_ERROR_NOTAVAIL );	/* Make sure that we always fail */
	}

/****************************************************************************
*																			*
*									Write a Key								*
*																			*
****************************************************************************/

/* Write the PKCS #12 mangling of a CMS wrapper */

static void writeNonCMSheader( STREAM *stream, const BYTE *oid,
							   const int length, const int attrDataLength )
	{
	writeSequence( stream, ( int ) \
				   ( sizeofOID( oid ) + \
				     sizeofObject( sizeofObject( length ) ) + \
					 sizeofObject( attrDataLength ) ) );
	writeOID( stream, oid );
	writeConstructed( stream, ( int ) sizeofObject( length ), 0 );
	writeSequence( stream, length );
	}

/* Write a PKCS #12 item ("safeBag").  We can't write this directly to the
   output stream but have to buffer it via an intermediate stream so we can
   MAC it */

static void writeItem( STREAM *stream, const PKCS12_INFO *pkcs12info,
					   const BOOLEAN isPrivateKey, const BOOLEAN macData )
	{
	STREAM memStream;
	BYTE buffer[ 256 ];
	void *dataPtr;
	const int idDataSize = ( int ) \
						( sizeofOID( OID_PKCS9_LOCALKEYID ) + \
						  sizeofObject( \
							sizeofObject( 1 ) ) );
	const int labelDataSize = ( int ) \
						( sizeofOID( OID_PKCS9_FRIENDLYNAME ) + \
						  sizeofObject( \
							sizeofObject( pkcs12info->labelLength * 2 ) ) );
	const int attrDataSize = ( int ) \
						( sizeofObject( idDataSize ) + \
						  sizeofObject( labelDataSize ) );
	int dataSize, i, j;

	sMemOpen( &memStream, buffer, 256 );

	/* Write the item wrapper and item data */
	if( isPrivateKey )
		{
		writeNonCMSheader( &memStream, OID_PKCS12_SHROUDEDKEYBAG,
						   pkcs12info->privKeyDataSize,
						   attrDataSize );
		dataPtr = pkcs12info->privKeyData;
		dataSize = pkcs12info->privKeyDataSize;
		}
	else
		{
		writeNonCMSheader( &memStream, OID_PKCS12_CERTBAG, ( int ) \
						   ( sizeofOID( OID_PKCS9_X509CERTIFICATE ) + \
							 sizeofObject( \
								sizeofObject( pkcs12info->certDataSize ) ) ),
							 attrDataSize );
		writeOID( &memStream, OID_PKCS9_X509CERTIFICATE );
		writeConstructed( &memStream, ( int ) \
						  sizeofObject( pkcs12info->certDataSize ), 0 );
		writeOctetStringHole( &memStream, pkcs12info->certDataSize, 
							  DEFAULT_TAG );
		dataPtr = pkcs12info->certData;
		dataSize = pkcs12info->certDataSize;
		}
	assert( stell( &memStream ) < 256 );
	swrite( stream, buffer, stell( &memStream ) );
	swrite( stream, dataPtr, dataSize );

	/* Mac the payload data if necessary */
	if( macData )
		{
		krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH,
						 buffer, stell( &memStream ) );
		krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH,
						 dataPtr, dataSize );
		}

	/* Write the item's ID and label.  These are supposedly optional, but
	   some apps will break if they're not present.  We have to keep the ID
	   short (rather than using, say, a keyID) because some apps assume it's
	   a 32-bit int or a similar type of value */
	sseek( &memStream, 0 );
	writeSet( &memStream, attrDataSize );
	writeSequence( &memStream, idDataSize );
	writeOID( &memStream, OID_PKCS9_LOCALKEYID );
	writeSet( &memStream, sizeofObject( 1 ) );
	writeOctetStringHole( &memStream, 1, DEFAULT_TAG );
	sputc( &memStream, pkcs12info->index );
	writeSequence( &memStream, labelDataSize );
	writeOID( &memStream, OID_PKCS9_FRIENDLYNAME );
	writeSet( &memStream, ( int ) sizeofObject( pkcs12info->labelLength * 2 ) );
	writeGenericHole( &memStream, pkcs12info->labelLength * 2,
					  BER_STRING_BMP );
	for( i = 0, j = 0; i < pkcs12info->labelLength; i++ )
		{
		/* Convert the ASCII string to a BMP string */
		sputc( &memStream, 0 );
		sputc( &memStream, pkcs12info->label[ i ] );
		}
	assert( stell( &memStream ) < 256 );
	swrite( stream, buffer, stell( &memStream ) );

	/* Mac the attribute data if necessary */
	if( macData )
		krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH, 
						 buffer, stell( &memStream ) );
	sMemClose( &memStream );
	}

/* Flush a PKCS #12 collection to a stream */

static int pkcs12Flush( STREAM *stream, const PKCS12_INFO *pkcs12info )
	{
	STREAM memStream;
	RESOURCE_DATA msgData;
	BYTE buffer[ 32 ];
	BOOLEAN privateKeyPresent = FALSE;
	int safeDataSize, authSafeDataSize, macDataSize, i, status;

	/* Determine the overall size of the objects */
	sMemOpen( &memStream, NULL, 0 );
	for( i = 0; i < MAX_PKCS12_OBJECTS; i++ )
		{
		if( pkcs12info[ i ].privKeyDataSize )
			{
			privateKeyPresent = TRUE;
			writeItem( &memStream, pkcs12info, TRUE, FALSE );
			}
		if( pkcs12info[ i ].certDataSize )
			writeItem( &memStream, pkcs12info, FALSE, FALSE );
		}
	safeDataSize = stell( &memStream );
	sMemClose( &memStream );
	if( !privateKeyPresent )
		/* If there's no data present, let the caller know that the keyset
		   is empty */
		return( OK_SPECIAL );
	authSafeDataSize = ( int ) \
					sizeofObject( \
						sizeofObject( \
							sizeofOID( OID_CMS_DATA ) + \
							sizeofObject( \
								sizeofObject( sizeofObject( safeDataSize ) ) ) ) );
	macDataSize = ( int ) \
				sizeofObject( \
					sizeofAlgoID( CRYPT_ALGO_SHA ) + \
					sizeofObject( 20 ) ) + \
				sizeofObject( pkcs12info->macSaltSize ) + \
				sizeofShortInteger( pkcs12info->macIterations );

	/* Write the outermost (authSafe) layer of cruft */
	writeSequence( stream, ( int ) \
				   sizeofShortInteger( 3 ) + \
				   sizeofObject( \
						sizeofOID( OID_CMS_DATA ) + \
						sizeofObject( \
							sizeofObject( authSafeDataSize ) ) ) + \
				   sizeofObject( macDataSize ) );
	writeShortInteger( stream, 3, DEFAULT_TAG );
	writeCMSheader( stream, OID_CMS_DATA, authSafeDataSize,
					TRUE );

	/* Create an intermediate memory stream so we can MAC the data before we
	   write it to disk */
	sMemOpen( &memStream, buffer, 32 );

	/* Write and MAC the next layer (safe) of cruft */
	writeSequence( &memStream, ( int ) \
				   sizeofObject( \
						sizeofOID( OID_CMS_DATA ) + \
						sizeofObject( \
							sizeofObject( sizeofObject( safeDataSize ) ) ) ) );
	writeCMSheader( &memStream, OID_CMS_DATA, sizeofObject( safeDataSize ),
					TRUE );
	writeSequence( &memStream, safeDataSize );
	assert( stell( &memStream ) < 32 );
	swrite( stream, buffer, stell( &memStream ) );
	krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH, 
					 buffer, stell( &memStream ) );
	sMemClose( &memStream );

	/* Write the individual objects */
	for( i = 0; i < MAX_PKCS12_OBJECTS; i++ )
		{
		if( pkcs12info[ i ].privKeyDataSize )
			writeItem( stream, pkcs12info, TRUE, TRUE );
		if( pkcs12info[ i ].certDataSize )
			writeItem( stream, pkcs12info, FALSE, TRUE );
		}

	/* Wrap up the MACing and write the MAC data.  Despite the fact that the
	   algorithm being used is HMAC, the OID we have to write is the one for 
	   plain SHA-1 */
	status = krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH, 
							  "", 0 );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
		krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, macDataSize );
	writeSequence( stream, sizeofAlgoID( CRYPT_ALGO_SHA ) + \
						   sizeofObject( 20 ) );
	writeAlgoID( stream, CRYPT_ALGO_SHA );
	writeOctetString( stream, buffer, msgData.length, DEFAULT_TAG );
	writeOctetString( stream, pkcs12info->macSalt, pkcs12info->macSaltSize,
					  DEFAULT_TAG );
	writeShortInteger( stream, pkcs12info->macIterations, DEFAULT_TAG );

	return( sflush( stream ) );
	}

/* Add an item to the PKCS #12 keyset */

static int setItemFunction( KEYSET_INFO *keysetInfo,
							const CRYPT_HANDLE cryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const char *password, const int passwordLength,
							const int flags )
	{
	CRYPT_CONTEXT iKeyWrapContext;
	CRYPT_ALGO_TYPE cryptAlgo;
	MECHANISM_WRAP_INFO mechanismInfo;
	PKCS12_INFO *pkcs12infoPtr = keysetInfo->keyData;
	STREAM stream;
	BOOLEAN certPresent = FALSE, contextPresent;
	BOOLEAN pkcs12keyPresent = pkcs12infoPtr->privKeyDataSize ? TRUE : FALSE;
	int privKeyInfoSize, pbeInfoDataSize;
	int value, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY );

	/* If there's already a key and cert present, we can't add anything
	   else.  This check also catches the (invalid) case of a cert being
	   present without a corresponding private key */
	if( pkcs12infoPtr->certDataSize )
		return( CRYPT_ERROR_INITED );

	/* Check the object and extract ID information from it */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) && cryptAlgo != CRYPT_ALGO_RSA )
			/* PKCS #12 can only store RSA keys */
			status = CRYPT_ARGERROR_NUM1;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	contextPresent = cryptStatusOK( krnlSendMessage( cryptHandle,
								IMESSAGE_CHECK, NULL,
								MESSAGE_CHECK_PKC_PRIVATE ) ) ? TRUE : FALSE;

	/* If there's a cert present, make sure that it's something that can be
	   stored.  We don't treat the wrong type as an error since we can still
	   store the public/private key components even if we don't store the
	   cert */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && \
		( value == CRYPT_CERTTYPE_CERTIFICATE || \
		  value == CRYPT_CERTTYPE_CERTCHAIN ) )
		{
		/* If the cert isn't signed, we can't store it in this state */
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ERROR_NOTINITED );
		certPresent = TRUE;
		if( !pkcs12keyPresent )
			/* We can't add a cert unless there's already a key present.
			   Since PKCS #12 doesn't store any index information, we have
			   no idea whether the two actually belong together, so we just
			   have to hope for the best */
			return( CRYPT_ERROR_NOTINITED );
		}
	else
		/* If we're trying to add a standalone key and there's already one
		   present, we can't add another one */
		if( pkcs12keyPresent )
			return( CRYPT_ERROR_INITED );

	/* If we're adding a private key, make sure that there's a password 
	   present.  Conversely, if there's a password present make sure that 
	   we're adding a private key */
	if( pkcs12keyPresent )
		{
		/* We're adding a cert, there can't be a password present */
		if( password != NULL )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* We're adding a private key, there must be a password present */
		if( password == NULL )
			return( CRYPT_ARGERROR_STR1 );

	/* Get what little index information PKCS #12 stores with a key */
	if( !pkcs12keyPresent )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, pkcs12infoPtr->label, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusError( status ) )
			return( status );
		pkcs12infoPtr->labelLength = msgData.length;
		pkcs12infoPtr->index = 1;
		}

	/* We're ready to go, lock the object for our exclusive use */
	status = krnlSendNotifier( cryptHandle, IMESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the cert if necessary.  We do this one first because it's the
	   easiest to back out of */
	if( certPresent )
		{
		RESOURCE_DATA msgData;

		/* Select the leaf cert in case it's a cert chain */
		krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );

		/* Get the encoded cert */
		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
		if( cryptStatusOK( status ) && \
			( pkcs12infoPtr->certData = clAlloc( "setItemFunction", \
												 msgData.length ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		if( cryptStatusOK( status ) )
			{
			msgData.data = pkcs12infoPtr->certData;
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
			if( cryptStatusOK( status ) )
				pkcs12infoPtr->certDataSize = msgData.length;
			else
				{
				clFree( "setItemFunction", pkcs12infoPtr->certData );
				pkcs12infoPtr->certData = NULL;
				}
			}

		/* If there's no context to add, return now */
		if( cryptStatusError( status ) || pkcs12keyPresent )
			{
			krnlSendNotifier( cryptHandle, IMESSAGE_UNLOCK );
			return( status );
			}
		}

	/* Create the key wrap context and the MAC context (if necessary) from 
	   the password.  See the comment at the start of the file for the 
	   ambiguity involved with the MAC context */
	status = createKeyWrapContext( &iKeyWrapContext, keysetInfo->ownerHandle, 
								   password, passwordLength, pkcs12infoPtr );
	if( cryptStatusOK( status ) && pkcs12infoPtr->iMacContext == CRYPT_ERROR )
		status = createMacContext( pkcs12infoPtr, keysetInfo->ownerHandle, 
								   password, passwordLength );
	if( cryptStatusError( status ) )
		{
		pkcs12freeEntry( pkcs12infoPtr );
		krnlSendNotifier( cryptHandle, IMESSAGE_UNLOCK );
		return( status );
		}

	/* Calculate the eventual encrypted key size and allocate storage for it */
	setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, cryptHandle,
						  iKeyWrapContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP_PKCS8 );
	privKeyInfoSize = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusOK( status ) && \
		( pkcs12infoPtr->privKeyData = \
				clAlloc( "setItemFunction", privKeyInfoSize + 64 ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
	if( cryptStatusError( status ) )
		{
		pkcs12freeEntry( pkcs12infoPtr );
		krnlSendNotifier( iKeyWrapContext, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( cryptHandle, IMESSAGE_UNLOCK );
		return( status );
		}
	pkcs12infoPtr->privKeyDataSize = privKeyInfoSize + 64;

	/* Write the key-derivation information and wrapped key */
	pbeInfoDataSize = ( int ) sizeofObject( pkcs12infoPtr->wrapSaltSize ) + \
					  sizeofShortInteger( pkcs12infoPtr->wrapIterations );
	sMemOpen( &stream, pkcs12infoPtr->privKeyData,
			  pkcs12infoPtr->privKeyDataSize );
	writeSequence( &stream,
				   sizeofOID( OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC ) + \
				   ( int ) sizeofObject( pbeInfoDataSize ) );
	writeOID( &stream, OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC );
	writeSequence( &stream, pbeInfoDataSize );
	writeOctetString( &stream, pkcs12infoPtr->wrapSalt, 
					  pkcs12infoPtr->wrapSaltSize, DEFAULT_TAG );
	writeShortInteger( &stream, pkcs12infoPtr->wrapIterations, DEFAULT_TAG );
	writeOctetStringHole( &stream, privKeyInfoSize, DEFAULT_TAG );
	assert( stell( &stream ) < 64 );
	assert( sStatusOK( &stream ) );
	setMechanismWrapInfo( &mechanismInfo,
						  ( BYTE * ) pkcs12infoPtr->privKeyData + \
									 ( int ) stell( &stream ),
						  privKeyInfoSize, NULL, 0, cryptHandle,
						  iKeyWrapContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP_PKCS8 );
	if( cryptStatusOK( status ) )
		pkcs12infoPtr->privKeyDataSize = ( int ) stell( &stream ) + \
										 privKeyInfoSize;
	else
		pkcs12freeEntry( pkcs12infoPtr );
	sMemDisconnect( &stream );
	krnlSendNotifier( cryptHandle, IMESSAGE_UNLOCK );

	return( status );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* At one point Netscape produced PKCS #12 files with each primitive portion
   of encapsulated content (T, L, and V) wrapped up in its own constructed
   OCTET STRING segment.  The following function unpacks this mess */

static int unwrapOctetString( STREAM *stream, BYTE *buffer,
							  const int totalLength )
	{
	int bufPos = 0, status;

	while( checkEOC( stream ) != TRUE )
		{
		int length;

		/* Read the current OCTET STRING segment into the buffer */
		status = readOctetStringHole( stream, &length, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure that we don't overshoot the buffer if the length 
		   encodings are wrong */
		if( bufPos + length > totalLength )
			return( CRYPT_ERROR_BADDATA );

		/* Copy in the current segment */
		status = sread( stream, buffer + bufPos, length );
		if( cryptStatusError( status ) )
			return( status );
		bufPos += length;
		}

	return( bufPos );
	}

/* A PKCS #12 file can contain steaming mounds of keys and whatnot, so when we
   open it we scan it and record various pieces of information about it which
   we can use later when we need to access it */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const CRYPT_KEYOPT_TYPE options )
	{
	PKCS12_INFO *pkcs12info;
	STREAM *stream = &keysetInfo->keysetFile->stream, memStream;
	BYTE *buffer;
	BOOLEAN isIndefinite = FALSE;
	long length;
	int totalLength, status;

	assert( name == NULL );

	/* Read the outer wrapper, version number field, and CMS data wrapper.  
	   We do this before we perform any setup operations to weed out
	   potential problem files */
	if( options != CRYPT_KEYOPT_CREATE )
		{
		long version;

		readSequence( stream, NULL );
		readShortInteger( stream, &version );
		status = readCMSheader( stream, dataOIDselection, &length, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		if( version != 3 )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Allocate the PKCS #12 object info */
	if( ( pkcs12info = clAlloc( "initFunction", \
								sizeof( PKCS12_INFO ) * \
								MAX_PKCS12_OBJECTS ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( pkcs12info, 0, sizeof( PKCS12_INFO ) * MAX_PKCS12_OBJECTS );
	keysetInfo->keyData = pkcs12info;
	keysetInfo->keyDataSize = sizeof( PKCS12_INFO ) * MAX_PKCS12_OBJECTS;
	pkcs12info->iMacContext = CRYPT_ERROR;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* Extract the OCTET STRING data into an in-memory buffer.  If the file
	   is of a known length we allocate a buffer of that size, otherwise we
	   just try for a reasonable value (indefinite-length encodings are only
	   used by broken older Netscape code which breaks each component up into
	   its own OCTET STRING) */
	if( length == CRYPT_UNUSED )
		{
		totalLength = 8192;
		isIndefinite = TRUE;
		}
	else
		totalLength = ( int ) length;
	if( ( buffer = clAlloc( "initFunction", totalLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	if( isIndefinite )
		status = totalLength = unwrapOctetString( stream, buffer,
												  totalLength );
	else
		status = sread( stream, buffer, totalLength );
	if( cryptStatusError( status ) )
		{
		clFree( "initFunction", buffer );
		return( status );
		}

	/* Extract the next level of unnecessarily nested data from the mess */
	sMemConnect( &memStream, buffer, totalLength );
	readSequence( &memStream, NULL );
	status = readCMSheader( &memStream, keyDataOIDselection, &length, TRUE );
	if( cryptStatusOK( status ) )
		{
		BYTE *innerBuffer;

		/* If it's straight Data, it'll be a PKCS #8 encrypted nested mess
		   rather than a straight encrypted mess */
		isIndefinite = ( length == CRYPT_UNUSED ) ? TRUE : FALSE;
		if( !isIndefinite )
			totalLength = ( int ) length;
		if( ( innerBuffer = clAlloc( "initFunction", totalLength ) ) != NULL )
			{
			if( isIndefinite )
				{
				status = totalLength = unwrapOctetString( &memStream,
												innerBuffer, totalLength );
				if( !cryptStatusError( status ) )
					status = CRYPT_OK;
				}
			else
				status = sread( stream, innerBuffer, totalLength );

			/* At this point you're on your own - this is too ghastly to
			   continue */

			clFree( "initFunction", innerBuffer );
			}
		}
	sMemDisconnect( &memStream );
	clFree( "initFunction", buffer );

	return( CRYPT_OK );
	}

/* Shut down the PKCS #12 state, flushing information to disk if necessary */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	/* If the contents have been changed, commit the changes to disk */
	if( keysetInfo->flags & KEYSET_DIRTY )
		{
		int status;

		sseek( &keysetInfo->keysetFile->stream, 0 );
		status = pkcs12Flush( &keysetInfo->keysetFile->stream,
							  keysetInfo->keyData );
		if( status == OK_SPECIAL )
			keysetInfo->flags |= KEYSET_EMPTY;
		}

	/* Free the PKCS #12 object info */
	if( keysetInfo->keyData != NULL )
		{
		pkcs12Free( keysetInfo->keyData );
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		clFree( "shutdownFunction", keysetInfo->keyData );
		}
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodPKCS12( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_PKCS12 */
