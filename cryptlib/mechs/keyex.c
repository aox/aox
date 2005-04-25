/****************************************************************************
*																			*
*							Key Exchange Routines							*
*						Copyright Peter Gutmann 1993-2004					*
*																			*
****************************************************************************/

#include <string.h>
#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "pgp.h"
  #include "mechanism.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "mechanism.h"
  #include "../misc/asn1.h"
  #include "../misc/asn1_ext.h"
  #include "../misc/misc_rw.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "mechs/mechanism.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Low-level Key Export Functions					*
*																			*
****************************************************************************/

/* Export a conventionally encrypted session key */

static int exportConventionalKey( void *encryptedKey, int *encryptedKeyLength,
								  const int encryptedKeyMaxLength,
								  const CRYPT_CONTEXT iSessionKeyContext,
								  const CRYPT_CONTEXT iExportContext,
								  const KEYEX_TYPE keyexType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	const WRITEKEK_FUNCTION writeKeyexFunction = \
										kekWriteTable[ keyexType ];
	BYTE buffer[ CRYPT_MAX_KEYSIZE + 16 ];
	int keySize, ivSize, status;

	/* Make sure the requested key exchange format is available */
	if( writeKeyexFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* PGP doesn't actually wrap up a key but derives the session key 
	   directly from the password.  Because of this there isn't any key
	   wrapping to be done, so we just write the key derivation parameters
	   and exit */
	if( keyexType == KEYEX_PGP )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, encryptedKeyMaxLength );
		status = writeKeyexFunction( &stream, iExportContext, NULL, 0 );
		*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );

		return( status );
		}

	status = krnlSendMessage( iSessionKeyContext, IMESSAGE_GETATTRIBUTE, 
							  &keySize, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	if( cryptStatusError( krnlSendMessage( iExportContext, 
										   IMESSAGE_GETATTRIBUTE, &ivSize, 
										   CRYPT_CTXINFO_IVSIZE ) ) )
		ivSize = 0;

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		int dummyDataSize;

		/* Calculate the eventual encrypted key size */
		setMechanismWrapInfo( &mechanismInfo, NULL, 0,
							  NULL, 0, iSessionKeyContext, iExportContext,
							  CRYPT_UNUSED );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
								  &mechanismInfo, MECHANISM_ENC_CMS );
		dummyDataSize = mechanismInfo.wrappedDataLength;
		clearMechanismInfo( &mechanismInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Generate an IV to allow the KEK write to succeed - see the comment
		   below about this */
		if( ivSize )
			krnlSendNotifier( iExportContext, IMESSAGE_CTX_GENIV );

		/* Write the data to a null stream to determine its size.  The 
		   buffer doesn't contain anything useful since it's only used for a 
		   size check */
		sMemOpen( &nullStream, NULL, 0 );
		status = writeKeyexFunction( &nullStream, iExportContext, buffer,
									 dummyDataSize );
		*encryptedKeyLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Load an IV into the exporting context.  This is somewhat nasty in that
	   a side-effect of exporting a key is to load an IV into the exporting
	   context which isn't really part of the function's job description.  
	   The alternative is to require the user to explicitly load an IV before
	   exporting the key, which is equally nasty (they'll never remember).  
	   The lesser of the two evils is to load the IV here and assume that 
	   anyone loading the IV themselves will read the docs which warn about 
	   the side-effects of exporting a key.

	   Note that we always load a new IV when we export a key because the
	   caller may be using the context to exchange multiple keys.  Since each
	   exported key requires its own IV, we perform an unconditional reload.
	   In addition because we don't want another thread coming along and
	   changing the IV while we're in the process of encrypting with it, we
	   lock the exporting key object until the encryption has completed and 
	   the IV is written to the output */
	status = krnlSendMessage( iExportContext, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( ivSize )
		krnlSendNotifier( iExportContext, IMESSAGE_CTX_GENIV );

	/* Encrypt the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, buffer, CRYPT_MAX_KEYSIZE + 16,
						  NULL, 0, iSessionKeyContext, iExportContext,
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_ENC_CMS );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, encryptedKeyMaxLength );
		status = writeKeyexFunction( &stream, iExportContext, 
									 mechanismInfo.wrappedData, 
									 mechanismInfo.wrappedDataLength );
		*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	krnlSendMessage( iExportContext, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	clearMechanismInfo( &mechanismInfo );
	zeroise( buffer, CRYPT_MAX_KEYSIZE + 16 );
	return( status );
	}

/* Export a public-key encrypted session key */

static int exportPublicKey( void *encryptedKey, int *encryptedKeyLength,
							const int encryptedKeyMaxLength,
							const CRYPT_CONTEXT iSessionKeyContext,
							const CRYPT_CONTEXT iExportContext,
							const void *auxInfo, const int auxInfoLength,
							const KEYEX_TYPE keyexType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	const WRITEKEYTRANS_FUNCTION writeKeyexFunction = \
										keytransWriteTable[ keyexType ];
	BYTE buffer[ MAX_PKCENCRYPTED_SIZE + 8 ];
	int keySize, status;

	/* Make sure the requested key exchange format is available */
	if( writeKeyexFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	status = krnlSendMessage( iSessionKeyContext, IMESSAGE_GETATTRIBUTE, 
							  &keySize, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		int dummyDataSize;

		/* Calculate the eventual encrypted key size */
		setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, 
							  iSessionKeyContext, iExportContext,
							  CRYPT_UNUSED );
		status = krnlSendMessage( iExportContext, IMESSAGE_DEV_EXPORT, 
								  &mechanismInfo, 
								  ( keyexType == KEYEX_PGP ) ? \
									MECHANISM_ENC_PKCS1_PGP : \
									MECHANISM_ENC_PKCS1 );
		dummyDataSize = mechanismInfo.wrappedDataLength;
		clearMechanismInfo( &mechanismInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Write the data to a null stream to determine its size.  The 
		   buffer doesn't contain anything useful since it's only used for a 
		   size check */
		sMemOpen( &nullStream, NULL, 0 );
		status = writeKeyexFunction( &nullStream, iExportContext, buffer,
									 dummyDataSize, auxInfo, auxInfoLength );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Encrypt the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, buffer, MAX_PKCENCRYPTED_SIZE, 
						  NULL, 0, iSessionKeyContext, iExportContext, 
						  CRYPT_UNUSED );
	status = krnlSendMessage( iExportContext, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, ( keyexType == KEYEX_PGP ) ? \
								MECHANISM_ENC_PKCS1_PGP : \
								MECHANISM_ENC_PKCS1 );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, encryptedKeyMaxLength );
		status = writeKeyexFunction( &stream, iExportContext, 
									 mechanismInfo.wrappedData, 
									 mechanismInfo.wrappedDataLength, 
									 auxInfo, auxInfoLength );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	clearMechanismInfo( &mechanismInfo );

	/* Clean up */
	zeroise( buffer, MAX_PKCENCRYPTED_SIZE );
	return( status );
	}

#if 0	/* 24/11/02 Removed since it was only used for Fortezza */

/* Export a key agreement key */

static int exportKeyAgreeKey( void *encryptedKey, int *encryptedKeyLength,
							  const int encryptedKeyMaxLength,
							  const CRYPT_CONTEXT iSessionKeyContext,
							  const CRYPT_CONTEXT iExportContext,
							  const CRYPT_CONTEXT iAuxContext,
							  const void *auxInfo, const int auxInfoLength )
	{
	CRYPT_ALGO_TYPE keyAgreeAlgo;
	MECHANISM_WRAP_INFO mechanismInfo;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int wrappedKeyLen, ukmLen, status;

	/* Extract general information */
	status = krnlSendMessage( iExportContext, IMESSAGE_GETATTRIBUTE,
							  &keyAgreeAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;

		/* Calculate the eventual encrypted key size */
		setMechanismWrapInfo( &mechanismInfo, NULL, 0,
							  NULL, 0, iSessionKeyContext, iExportContext,
							  iAuxContext );
		status = krnlSendMessage( iExportContext, IMESSAGE_DEV_EXPORT, 
								  &mechanismInfo, MECHANISM_KEA );
		wrappedKeyLen = mechanismInfo.wrappedDataLength >> 8;
		ukmLen = mechanismInfo.wrappedDataLength & 0xFF;
		clearMechanismInfo( &mechanismInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Write the data to a null stream to determine its size.  The 
		   buffer doesn't contain anything useful since it's only used for a 
		   size check */
		sMemOpen( &nullStream, NULL, 0 );
		status = writeKeyAgreeInfo( &nullStream, iExportContext, 
									buffer, wrappedKeyLen, buffer, 
									ukmLen, auxInfo, auxInfoLength );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Export the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, buffer, CRYPT_MAX_PKCSIZE,
						  NULL, 0, iSessionKeyContext, iExportContext,
						  iAuxContext );
	status = krnlSendMessage( iExportContext, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_KEA );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		/* Extract the length information */
		wrappedKeyLen = mechanismInfo.wrappedDataLength >> 8;
		ukmLen = mechanismInfo.wrappedDataLength & 0xFF;

		sMemOpen( &stream, encryptedKey, encryptedKeyMaxLength );
		status = writeKeyAgreeInfo( &stream, iExportContext, buffer, 
									wrappedKeyLen, buffer, ukmLen, auxInfo, 
									auxInfoLength );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	clearMechanismInfo( &mechanismInfo );

	/* Clean up */
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Low-level Key Import Functions					*
*																			*
****************************************************************************/

/* Import a conventionally encrypted session key */

static int importConventionalKey( const void *encryptedKey,
								  const int encryptedKeyLength,
								  const CRYPT_CONTEXT iSessionKeyContext,
								  const CRYPT_CONTEXT iImportContext,
								  const KEYEX_TYPE keyexType )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_MODE_TYPE cryptMode;
	MECHANISM_WRAP_INFO mechanismInfo;
	const READKEK_FUNCTION readKeyexFunction = \
										kekReadTable[ keyexType ];
	QUERY_INFO queryInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	int status;

	/* Make sure the requested key exchange format is available */
	if( readKeyexFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Get information on the importing key */
	krnlSendMessage( iImportContext, IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
					 CRYPT_CTXINFO_ALGO );
	status = krnlSendMessage( iImportContext, IMESSAGE_GETATTRIBUTE, 
							  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* Read the encrypted key record up to the start of the encrypted key and
	   make sure we'll be using the correct type of encryption context to
	   decrypt it */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, encryptedKey, encryptedKeyLength );
	status = readKeyexFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) && \
		( cryptAlgo != queryInfo.cryptAlgo || \
		  cryptMode != queryInfo.cryptMode ) )
		status = CRYPT_ARGERROR_NUM1;
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Extract the encrypted key from the buffer and decrypt it.  Since we 
	   don't want another thread changing the IV while we're using the import
	   context, we lock it for the duration */
	status = krnlSendMessage( iImportContext, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( needsIV( cryptMode ) && cryptAlgo != CRYPT_ALGO_RC4 )
		{
		setMessageData( &msgData, queryInfo.iv, queryInfo.ivLength );
		krnlSendMessage( iImportContext, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_IV );
		}
	setMechanismWrapInfo( &mechanismInfo, 
						  queryInfo.dataStart, queryInfo.dataLength, 
						  NULL, 0, iSessionKeyContext, iImportContext, 
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT, 
							  &mechanismInfo, MECHANISM_ENC_CMS );
	krnlSendMessage( iImportContext, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	clearMechanismInfo( &mechanismInfo );
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );

	return( status );
	}

/* Import a public-key encrypted session key */

static int importPublicKey( const void *encryptedKey, 
							const int encryptedKeyLength,
							const CRYPT_CONTEXT iSessionKeyContext,
							const CRYPT_CONTEXT iImportContext,
							CRYPT_CONTEXT *iReturnedContext,
							const KEYEX_TYPE keyexType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	const READKEYTRANS_FUNCTION readKeyexFunction = \
										keytransReadTable[ keyexType ];
	QUERY_INFO queryInfo;
	STREAM stream;
	int status;

	/* Make sure the requested key exchange format is available */
	if( readKeyexFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Read the encrypted key record up to the start of the encrypted key and
	   make sure we've been given the correct key */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, encryptedKey, encryptedKeyLength );
	status = readKeyexFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;
		int compareType;

		setMessageData( &msgData, queryInfo.keyID, 
						queryInfo.keyIDlength );
		switch( keyexType )
			{
			case KEYEX_CMS:
				setMessageData( &msgData, queryInfo.iAndSStart, 
								queryInfo.iAndSLength );
				compareType = MESSAGE_COMPARE_ISSUERANDSERIALNUMBER;
				break;

			case KEYEX_CRYPTLIB:
				compareType = MESSAGE_COMPARE_KEYID;
				break;

			case KEYEX_PGP:
				compareType = ( queryInfo.version == PGP_VERSION_2 ) ? \
							  MESSAGE_COMPARE_KEYID_PGP : \
							  MESSAGE_COMPARE_KEYID_OPENPGP;
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ERROR_NOTAVAIL );
			}
		status = krnlSendMessage( iImportContext, IMESSAGE_COMPARE, 
								  &msgData, compareType );
		if( cryptStatusError( status ) && \
			compareType == MESSAGE_COMPARE_KEYID_OPENPGP )
			/* Some broken PGP implementations put PGP 2.x IDs in packets
			   marked as OpenPGP packets, so if we were doing a check for
			   an OpenPGP ID and it failed, fall back to a PGP 2.x one */
			status = krnlSendMessage( iImportContext, IMESSAGE_COMPARE, 
									  &msgData, MESSAGE_COMPARE_KEYID_PGP );
		if( cryptStatusError( status ) )
			/* A failed comparison is reported as a generic CRYPT_ERROR,
			   convert it into a wrong-key error */
			status = CRYPT_ERROR_WRONGKEY;
		}
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Decrypt the encrypted key and load it into the context */
	if( keyexType != KEYEX_PGP )
		{
		setMechanismWrapInfo( &mechanismInfo, 
							  queryInfo.dataStart, queryInfo.dataLength, 
							  NULL, 0, iSessionKeyContext, iImportContext, 
							  CRYPT_UNUSED );
		status = krnlSendMessage( iImportContext, IMESSAGE_DEV_IMPORT, 
								  &mechanismInfo, MECHANISM_ENC_PKCS1 );
		}
	else
		{
		/* PGP doesn't provide separate session key information with the 
		   encrypted data but wraps it up alongside the encrypted key, so we
		   can't import the wrapped key into a context via the standard key
		   import functions but instead have to create the context as part 
		   of the unwrap process */
		setMechanismWrapInfo( &mechanismInfo, queryInfo.dataStart, 
							  queryInfo.dataLength, NULL, 0, CRYPT_UNUSED, 
							  iImportContext, CRYPT_UNUSED );
		status = krnlSendMessage( iImportContext, IMESSAGE_DEV_IMPORT, 
								  &mechanismInfo, MECHANISM_ENC_PKCS1_PGP );
		if( cryptStatusOK( status ) )
			*iReturnedContext = mechanismInfo.keyContext;
		}
	clearMechanismInfo( &mechanismInfo );
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );

	return( status );
	}

#if 0	/* 24/11/02 Removed since it was only used for Fortezza */

/* Import a key agreement session key */

static int importKeyAgreeKey( const void *encryptedKey, 
							  const int encryptedKeyLength,
							  const CRYPT_CONTEXT iSessionKeyContext,
							  const CRYPT_CONTEXT iImportContext )
	{
	CRYPT_CONTEXT iLocalContext;
	QUERY_INFO queryInfo;
	STREAM stream;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int status;

	/* Read the key agreement record.  Due to the somewhat peculiar concept
	   of what constitutes a public key for DH, this doesn't really work as
	   well as the standard key wrap algorithms since what we're reading are
	   the components of a complete context.  As a result the initiator and
	   responder for the DH exchange end up with the following:

							Initiator				Responder

	   cryptInfoPtr			p, g, x(I), y(I)		-

	   iLocalContext		p, g, y(R)				p, g, y(I)

	   If we're doing the import for the responder, we copy the values from
	   the import context into the responder context and perform a key load,
	   which generates the responders x value and key ID.  This is a horrible
	   kludge, what we should be doing is passing the import context back to
	   the user but this isn't possible because cryptImportKey() passes the
	   import context by value.

	   If we're doing the import for the initiator, we just check that the
	   key used by the responder was the same as the one used by the
	   initiator */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, encryptedKey, encryptedKeyLength );
	status = readKeyAgreeInfo( &stream, &queryInfo, &iLocalContext );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendNotifier( iLocalContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the shared secret value and load it into the session key
	   context.  We use a fixed 64-bit salt and explicitly set the iteration 
	   count to make sure it isn't upset if the user changes config options */
	status = krnlSendMessage( iImportContext, IMESSAGE_CTX_DECRYPT, 
							  buffer, CRYPT_UNUSED );
	if( !cryptStatusError( status ) )
		{
		static const BYTE *salt = ( BYTE * ) "\x00\x00\x00\x00\x00\x00\x00\x00";
		static const int iterations = 100;
		RESOURCE_DATA msgData;

		krnlSendMessage( iSessionKeyContext, IMESSAGE_SETATTRIBUTE, 
						 ( int * ) &iterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
		setMessageData( &msgData, ( void * ) salt, 8 );
		krnlSendMessage( iSessionKeyContext, IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_KEYING_SALT );
		setMessageData( &msgData, buffer, status );
		status = krnlSendMessage( iSessionKeyContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
		}

	return( status );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Import/Export a Session Key						*
*																			*
****************************************************************************/

/* Import an extended encrypted key, either a cryptlib key or a CMS key */

static CRYPT_FORMAT_TYPE getFormatType( const void *data )
	{
	STREAM stream;
	const BYTE *dataPtr = data;
#ifdef USE_PGP
	long length;
#endif /* USE_PGP */
	int status;

	/* Figure out what we've got.  PKCS #7/CMS/SMIME keyTrans begins:
		keyTransRecipientInfo ::= SEQUENCE {
			version		INTEGER (0|2),
	   while a kek begins:
		kekRecipientInfo ::= [3] IMPLICIT SEQUENCE {
			version		INTEGER (4),
	   which allows us to determine which type of object we have */
	if( *dataPtr == BER_SEQUENCE )
		{
		CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;

		sMemConnect( &stream, data, 16 );
		status = readSequence( &stream, NULL );
		if( cryptStatusOK( status ) )
			{
			long version;

			if( cryptStatusOK( readShortInteger( &stream, &version ) ) )
				formatType = ( version == 0 ) ? CRYPT_FORMAT_CMS : \
							 ( version == 2 ) ? CRYPT_FORMAT_CRYPTLIB : \
							 CRYPT_FORMAT_NONE;
			}
		sMemDisconnect( &stream );

		return( formatType );
		}
	if( *dataPtr == MAKE_CTAG( 3 ) )
		{
		CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;

		sMemConnect( &stream, data, 16 );
		status = readConstructed( &stream, NULL, 3 );
		if( cryptStatusOK( status ) )
			{
			long version;

			if( cryptStatusOK( readShortInteger( &stream, &version ) ) )
				formatType = ( version == 0 ) ? CRYPT_FORMAT_CRYPTLIB : \
												CRYPT_FORMAT_NONE;
			}
		sMemDisconnect( &stream );

		return( formatType );
		}

#ifdef USE_PGP
	/* It's not ASN.1 data, check for PGP data */
	sMemConnect( &stream, data, 16 );
	status = pgpReadPacketHeader( &stream, NULL, &length );
	if( cryptStatusOK( status ) && length > 30 && length < 8192 )
		{
		sMemDisconnect( &stream );
		return( CRYPT_FORMAT_PGP );
		}
	sMemDisconnect( &stream );
#endif /* USE_PGP */

	return( CRYPT_FORMAT_NONE );
	}

C_RET cryptImportKeyEx( C_IN void C_PTR encryptedKey,
						C_IN int encryptedKeyLength,
						C_IN CRYPT_CONTEXT importKey,
						C_IN CRYPT_CONTEXT sessionKeyContext,
						C_OUT CRYPT_CONTEXT C_PTR returnedContext )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_CONTEXT iReturnedContext;
	MESSAGE_CHECK_TYPE checkType;
	int owner, originalOwner, status;

	/* Perform basic error checking */
	if( encryptedKeyLength < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_PARAM2 );
	if( !isReadPtr( encryptedKey, encryptedKeyLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( ( formatType = getFormatType( encryptedKey ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );

	/* Check the importing key */
	status = krnlSendMessage( importKey, MESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		checkType = ( cryptAlgo == CRYPT_ALGO_DH ) ? \
					MESSAGE_CHECK_PKC_KA_IMPORT : MESSAGE_CHECK_PKC_DECRYPT;
	else
		checkType = MESSAGE_CHECK_CRYPT;
	if( isDlpAlgo( cryptAlgo ) )
		/* The DLP algorithms have specialised data-formatting requirements 
		   and can't normally be directly accessed via external messages, 
		   however if we're performing a key export this is OK since they're
		   being used from cryptlib-internal routines.  Doing the check via
		   an internal message is safe since we've already checked its 
		   external accessibility when we got the algorithm info */
		status = krnlSendMessage( importKey, IMESSAGE_CHECK, NULL, 
								  checkType );
	else
		status = krnlSendMessage( importKey, MESSAGE_CHECK, NULL, 
								  checkType );
	if( cryptAlgo == CRYPT_ALGO_DH && status == CRYPT_ERROR_NOTINITED )
		/* For key agreement keys the fact that there's no key attribute set
		   is OK since the key parameters are read from the exchanged object */
		status = CRYPT_OK;
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );

	/* Check the session key */
	if( formatType == CRYPT_FORMAT_PGP )
		{
		/* PGP stores the session key information with the encrypted key 
		   data, so the user can't provide a context */
		if( sessionKeyContext != CRYPT_UNUSED )
			return( CRYPT_ERROR_PARAM4 );
		if( !isWritePtr( returnedContext, sizeof( CRYPT_CONTEXT ) ) )
			return( CRYPT_ERROR_PARAM5 );
		}
	else
		{
		CRYPT_ALGO_TYPE sessionKeyAlgo;

		status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE, 
								  &sessionKeyAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( sessionKeyContext, MESSAGE_CHECK, NULL, 
							( sessionKeyAlgo >= CRYPT_ALGO_FIRST_MAC ) ? \
								MESSAGE_CHECK_MAC_READY : \
								MESSAGE_CHECK_CRYPT_READY );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
					CRYPT_ERROR_PARAM4 : status );
		if( returnedContext != NULL )
			return( CRYPT_ERROR_PARAM5 );
		}

	/* If the importing key is owned, bind the session key context to the same 
	   owner before we load a key into it.  We also need to save the original 
	   owner so we can undo the binding later if things fail */
	status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE, 
							  &originalOwner, CRYPT_PROPERTY_OWNER );
	if( cryptStatusError( status ) )
		originalOwner = CRYPT_ERROR;	/* Unowned object */
	status = krnlSendMessage( importKey, MESSAGE_GETATTRIBUTE, &owner, 
							  CRYPT_PROPERTY_OWNER );
	if( cryptStatusOK( status ) )
		krnlSendMessage( sessionKeyContext, MESSAGE_SETATTRIBUTE, &owner, 
						 CRYPT_PROPERTY_OWNER );

	/* Import it as appropriate */
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		if( formatType == CRYPT_FORMAT_PGP )
			{
			status = importPublicKey( encryptedKey, encryptedKeyLength,
									  CRYPT_UNUSED, importKey, 
									  &iReturnedContext, KEYEX_PGP );
			if( cryptStatusOK( status ) )
				/* Make the newly-created context externally visible */
				krnlSendMessage( iReturnedContext, IMESSAGE_SETATTRIBUTE,
								 MESSAGE_VALUE_FALSE, 
								 CRYPT_IATTRIBUTE_INTERNAL );
			}
		else
			status = importPublicKey( encryptedKey, encryptedKeyLength,
									  sessionKeyContext, importKey, NULL,
									  ( formatType == CRYPT_FORMAT_CMS ) ? \
										KEYEX_CMS : KEYEX_CRYPTLIB );
		}
	else
		status = importConventionalKey( encryptedKey, encryptedKeyLength,
							sessionKeyContext, importKey,
							( formatType == CRYPT_FORMAT_CRYPTLIB ) ? \
								KEYEX_CRYPTLIB : KEYEX_PGP );

	/* If the import failed, return the session key context to its
	   original owner */
	if( cryptStatusError( status ) )
		{
		if( originalOwner != CRYPT_ERROR )
			krnlSendMessage( sessionKeyContext, MESSAGE_SETATTRIBUTE,
							 &originalOwner, CRYPT_PROPERTY_OWNER );
		}
	else
		/* If we created the session key as part of the import operation,
		   return it to the caller */
		if( formatType == CRYPT_FORMAT_PGP )
			*returnedContext = iReturnedContext;

	if( cryptArgError( status ) )
		/* If we get an argument error from the lower-level code, map the
		   parameter number to the function argument number */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM4 : CRYPT_ERROR_PARAM3;
	return( status );
	}

C_RET cryptImportKey( C_IN void C_PTR encryptedKey,
					  C_IN int encryptedKeyLength,
					  C_IN CRYPT_CONTEXT importKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	return( cryptImportKeyEx( encryptedKey, encryptedKeyLength, importKey, 
							  sessionKeyContext, NULL ) );
	}

/* Export an extended encrypted key, either a cryptlib key or a CMS key */

C_RET cryptExportKeyEx( C_OUT void C_PTR encryptedKey, 
						C_IN int encryptedKeyMaxLength,
						C_OUT int C_PTR encryptedKeyLength,
						C_IN CRYPT_FORMAT_TYPE formatType,
						C_IN CRYPT_HANDLE exportKey,
						C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_MODE_TYPE sessionKeyMode;
	MESSAGE_CHECK_TYPE checkType;
	int status;

	/* Perform basic error checking */
	if( encryptedKey != NULL )
		{
		if( encryptedKeyMaxLength < MIN_CRYPT_OBJECTSIZE )
			return( CRYPT_ERROR_PARAM2 );
		if( !isWritePtr( encryptedKey, encryptedKeyMaxLength ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( encryptedKey, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( !isWritePtr( encryptedKeyLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*encryptedKeyLength = 0;
	if( formatType <= CRYPT_FORMAT_NONE || \
		formatType >= CRYPT_FORMAT_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM4 );

	/* Check the exporting key */
	status = krnlSendMessage( exportKey, MESSAGE_GETATTRIBUTE, &cryptAlgo, 
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		checkType = ( cryptAlgo == CRYPT_ALGO_DH ) ? \
					MESSAGE_CHECK_PKC_KA_EXPORT : MESSAGE_CHECK_PKC_ENCRYPT;
	else
		checkType = MESSAGE_CHECK_CRYPT;
	if( isDlpAlgo( cryptAlgo ) )
		/* The DLP algorithms have specialised data-formatting requirements 
		   and can't normally be directly accessed via external messages, 
		   however if we're performing a key export this is OK since they're
		   being used from cryptlib-internal routines.  Doing the check via
		   an internal message is safe since we've already checked its 
		   external accessibility when we got the algorithm info */
		status = krnlSendMessage( exportKey, IMESSAGE_CHECK, NULL, 
								  checkType );
	else
		status = krnlSendMessage( exportKey, MESSAGE_CHECK, NULL, 
								  checkType );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL && \
		cryptStatusError( sizeofAlgoIDex( cryptAlgo,
								( CRYPT_ALGO_TYPE ) CRYPT_MODE_CBC, 0 ) ) )
		/* Conventional key wrap requires the use of an CBC mode for the 
		   wrapping (which also implies the use of a block cipher).  CBC mode
		   isn't essential but it's a good safety check, the use of a block 
		   cipher is essential */
		return( CRYPT_ERROR_PARAM5 );

	/* Check the exported key */
	status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE,
							  &sessionKeyMode, CRYPT_CTXINFO_MODE );
	if( status == CRYPT_ARGERROR_VALUE )
		{
		/* No encryption mode attribute present, it has to be a MAC 
		   context */
		checkType = MESSAGE_CHECK_MAC;
		status = CRYPT_OK;
		}
	else
		checkType = MESSAGE_CHECK_CRYPT;
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sessionKeyContext, MESSAGE_CHECK, NULL, 
								  checkType );
#ifdef USE_PGP
	if( formatType == CRYPT_FORMAT_PGP )
		{
		CRYPT_ALGO_TYPE sessionKeyAlgo;

		/* PGP can only handle a limited subset of algorithms, make sure this
		   is an algorithm type which can be represented in the PGP format */
		status = krnlSendMessage( sessionKeyContext, MESSAGE_GETATTRIBUTE, 
								  &sessionKeyAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
					CRYPT_ERROR_PARAM6 : status );
		if( cryptlibToPgpAlgo( sessionKeyAlgo ) == PGP_ALGO_NONE )
			return( CRYPT_ERROR_PARAM6 );
		}
#endif /* USE_PGP */
	if( cryptAlgo == CRYPT_ALGO_DH )
		{
		/* If we're using a key agreement algorithm it doesn't matter if the
		   session key context has a key attribute present or not, but the 
		   format has to be cryptlib */
		if( status == CRYPT_ERROR_NOTINITED )
			status = CRYPT_OK;
		if( formatType == CRYPT_FORMAT_CMS || \
			formatType == CRYPT_FORMAT_SMIME )
			status = CRYPT_ERROR_PARAM4;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM6 : status );

	/* Export the key via the shared export function */
	status = iCryptExportKeyEx( encryptedKey, encryptedKeyLength,
								encryptedKeyMaxLength, formatType,
								sessionKeyContext, exportKey,
								CRYPT_UNUSED );
	if( cryptArgError( status ) )
		/* If we get an argument error from the lower-level code, map the
		   parameter number to the function argument number */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM6 : CRYPT_ERROR_PARAM5;
	return( status );
	}

C_RET cryptExportKey( C_OUT void C_PTR encryptedKey, 
					  C_IN int encryptedKeyMaxLength,
					  C_OUT int C_PTR encryptedKeyLength,
					  C_IN CRYPT_HANDLE exportKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	int status;

	status = cryptExportKeyEx( encryptedKey, encryptedKeyMaxLength, 
							   encryptedKeyLength, CRYPT_FORMAT_CRYPTLIB, 
							   exportKey, sessionKeyContext );
	return( ( status == CRYPT_ERROR_PARAM5 ) ? CRYPT_ERROR_PARAM4 : \
			( status == CRYPT_ERROR_PARAM6 ) ? CRYPT_ERROR_PARAM5 : status );
	}

/****************************************************************************
*																			*
*						Internal Import/Export Functions					*
*																			*
****************************************************************************/

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions which have already checked the parameters for validity */

int iCryptImportKeyEx( const void *encryptedKey, const int encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iImportKey,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   CRYPT_CONTEXT *iReturnedContext )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	const KEYEX_TYPE keyexType = \
			( formatType == CRYPT_FORMAT_AUTO || \
			  formatType == CRYPT_FORMAT_CRYPTLIB ) ? KEYEX_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_PGP ) ? KEYEX_PGP : KEYEX_CMS;
	int status;

	assert( isReadPtr( encryptedKey, encryptedKeyLength ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( checkHandleRange( iImportKey ) );
	assert( ( formatType == CRYPT_FORMAT_PGP && \
			  iSessionKeyContext == CRYPT_UNUSED ) || \
			( formatType != CRYPT_FORMAT_PGP && \
			  checkHandleRange( iSessionKeyContext ) ) );
	assert( ( formatType == CRYPT_FORMAT_PGP && \
			  iReturnedContext != NULL ) || \
			( formatType != CRYPT_FORMAT_PGP && \
			  iReturnedContext == NULL ) );

	/* Import it as appropriate.  We don't handle key agreement at this
	   level */
	status = krnlSendMessage( iImportKey, IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		return( importConventionalKey( encryptedKey, encryptedKeyLength,
									   iSessionKeyContext, iImportKey, 
									   keyexType ) );
	return( importPublicKey( encryptedKey, encryptedKeyLength,
							 iSessionKeyContext, iImportKey, 
							 iReturnedContext, keyexType ) );
	}

int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const int encryptedKeyMaxLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportKey,
					   const CRYPT_CONTEXT iAuxContext )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	const KEYEX_TYPE keyexType = \
			( formatType == CRYPT_FORMAT_CRYPTLIB ) ? KEYEX_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_PGP ) ? KEYEX_PGP : KEYEX_CMS;
	DYNBUF auxDB;
	BOOLEAN lockObject = FALSE;
	int status;

	assert( encryptedKey == NULL || \
			isWritePtr( encryptedKey, MIN_CRYPT_OBJECTSIZE ) );
	assert( isWritePtr( encryptedKeyLength, sizeof( int ) ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( checkHandleRange( iExportKey ) );

	/* Clear return value */
	*encryptedKeyLength = 0;

	/* Perform simplified error checking */
	status = krnlSendMessage( iExportKey, IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* If we're exporting a key in CMS format using a public key we need to
	   obtain recipient information */
	if( ( formatType == CRYPT_FORMAT_CMS || \
		  formatType == CRYPT_FORMAT_SMIME ) && \
		( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
		  cryptAlgo <= CRYPT_ALGO_LAST_PKC ) )
		{
		/* Lock the cert for our exclusive use, and in case it's a cert 
		   chain, select the first cert in the chain */
		status = krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_PARAM5 );
		krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_CURSORFIRST, 
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );

		/* Get the recipient information from the cert */
		status = dynCreate( &auxDB, iExportKey, 
							( cryptAlgo == CRYPT_ALGO_DH || \
							  cryptAlgo == CRYPT_ALGO_KEA ) ? \
								CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER : \
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusError( status ) )
			{
			krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
			return( CRYPT_ERROR_PARAM5 );
			}
		lockObject = TRUE;
		}
	else
		dynCreate( &auxDB, CRYPT_UNUSED, CRYPT_UNUSED );

	/* Export it as appropriate */
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		status = exportPublicKey( encryptedKey, encryptedKeyLength,
								  ( encryptedKey == NULL ) ? \
										0 : encryptedKeyMaxLength,
								  iSessionKeyContext, iExportKey, 
								  dynData( auxDB ), dynLength( auxDB ), 
								  keyexType );
	else
		status = exportConventionalKey( encryptedKey, encryptedKeyLength,
										( encryptedKey == NULL ) ? \
											0 : encryptedKeyMaxLength,
										iSessionKeyContext, iExportKey,
										keyexType );

	/* Clean up */
	if( lockObject )
		krnlSendMessage( iExportKey, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	dynDestroy( &auxDB );
	return( status );
	}
