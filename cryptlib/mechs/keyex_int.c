/****************************************************************************
*																			*
*						Internal Key Exchange Routines						*
*						Copyright Peter Gutmann 1993-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "mech.h"
  #include "asn1.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Low-level Key Export Functions					*
*																			*
****************************************************************************/

/* Export a conventionally encrypted session key */

int exportConventionalKey( void *encryptedKey, int *encryptedKeyLength,
						   const int encryptedKeyMaxLength,
						   const CRYPT_CONTEXT iSessionKeyContext,
						   const CRYPT_CONTEXT iExportContext,
						   const KEYEX_TYPE keyexType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	const WRITEKEK_FUNCTION writeKeyexFunction = getWriteKekFunction( keyexType );
	BYTE buffer[ CRYPT_MAX_KEYSIZE + 16 + 8 ];
	BYTE *bufPtr = ( encryptedKey == NULL ) ? NULL : buffer;
	const int bufSize = ( encryptedKey == NULL ) ? 0 : CRYPT_MAX_KEYSIZE + 16;
	int keySize, ivSize, status;

	assert( ( encryptedKey == NULL && encryptedKeyMaxLength == 0 ) || \
			isWritePtr( encryptedKey, encryptedKeyMaxLength ) );
	assert( isWritePtr( encryptedKeyLength, sizeof( int ) ) );
	assert( ( keyexType == KEYEX_PGP && \
			  iSessionKeyContext == CRYPT_UNUSED ) || \
			( keyexType != KEYEX_PGP && \
			  isHandleRangeValid( iSessionKeyContext ) ) );
	assert( isHandleRangeValid( iExportContext ) );
	assert( keyexType > KEYEX_NONE && keyexType < KEYEX_LAST );

	/* Make sure that the requested key exchange format is available */
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
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );

		return( status );
		}

	/* Get the export parameters */
	status = krnlSendMessage( iSessionKeyContext, IMESSAGE_GETATTRIBUTE,
							  &keySize, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	if( cryptStatusError( krnlSendMessage( iExportContext,
										   IMESSAGE_GETATTRIBUTE, &ivSize,
										   CRYPT_CTXINFO_IVSIZE ) ) )
		ivSize = 0;

	/* Load an IV into the exporting context.  This is somewhat nasty in that
	   a side-effect of exporting a key is to load an IV into the exporting
	   context, which isn't really part of the function's job description.
	   The alternative is to require the user to explicitly load an IV before
	   exporting the key, which is equally nasty (they'll never remember).
	   The lesser of the two evils is to load the IV here and assume that
	   anyone loading the IV themselves will read the docs, which warn about
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
	if( ivSize > 0 )
		krnlSendNotifier( iExportContext, IMESSAGE_CTX_GENIV );

	/* Encrypt the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, bufPtr, bufSize, NULL, 0, 
						  iSessionKeyContext, iExportContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_ENC_CMS );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, encryptedKeyMaxLength );
		status = writeKeyexFunction( &stream, iExportContext,
									 ( encryptedKey != NULL ) ? \
										mechanismInfo.wrappedData: buffer,
									 mechanismInfo.wrappedDataLength );
		if( cryptStatusOK( status ) )
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

int exportPublicKey( void *encryptedKey, int *encryptedKeyLength,
					 const int encryptedKeyMaxLength,
					 const CRYPT_CONTEXT iSessionKeyContext,
					 const CRYPT_CONTEXT iExportContext,
					 const void *auxInfo, const int auxInfoLength,
					 const KEYEX_TYPE keyexType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	const WRITEKEYTRANS_FUNCTION writeKetransFunction = getWriteKeytransFunction( keyexType );
	BYTE buffer[ MAX_PKCENCRYPTED_SIZE + 8 ];
	BYTE *bufPtr = ( encryptedKey == NULL ) ? NULL : buffer;
	const int bufSize = ( encryptedKey == NULL ) ? 0 : MAX_PKCENCRYPTED_SIZE;
	int keySize, status;

	assert( ( encryptedKey == NULL && encryptedKeyMaxLength == 0 ) || \
			isWritePtr( encryptedKey, encryptedKeyMaxLength ) );
	assert( isWritePtr( encryptedKeyLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iSessionKeyContext ) );
	assert( isHandleRangeValid( iExportContext ) );
	assert( ( auxInfo == NULL && auxInfoLength == 0 ) || \
			isReadPtr( auxInfo,  auxInfoLength ) );
	assert( keyexType > KEYEX_NONE && keyexType < KEYEX_LAST );

	/* Make sure that the requested key exchange format is available */
	if( writeKetransFunction  == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Get the export parameters */
	status = krnlSendMessage( iSessionKeyContext, IMESSAGE_GETATTRIBUTE,
							  &keySize, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );

	/* Encrypt the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, bufPtr, bufSize, NULL, 0, 
						  iSessionKeyContext, iExportContext, CRYPT_UNUSED );
	status = krnlSendMessage( iExportContext, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, ( keyexType == KEYEX_PGP ) ? \
								MECHANISM_ENC_PKCS1_PGP : \
								MECHANISM_ENC_PKCS1 );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, encryptedKeyMaxLength );
		status = writeKetransFunction ( &stream, iExportContext,
										( encryptedKey != NULL ) ? \
											mechanismInfo.wrappedData: buffer,
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

int exportKeyAgreeKey( void *encryptedKey, int *encryptedKeyLength,
					   const int encryptedKeyMaxLength,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportContext,
					   const CRYPT_CONTEXT iAuxContext,
					   const void *auxInfo, const int auxInfoLength )
	{
	CRYPT_ALGO_TYPE keyAgreeAlgo;
	MECHANISM_WRAP_INFO mechanismInfo;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE *bufPtr = ( encryptedKey == NULL ) ? NULL : buffer;
	const int bufSize = ( encryptedKey == NULL ) ? 0 : CRYPT_MAX_PKCSIZE;
	int wrappedKeyLen, ukmLen, status;

	assert( ( encryptedKey == NULL && encryptedKeyMaxLength == 0 ) || \
			isWritePtr( encryptedKey, encryptedKeyMaxLength ) );
	assert( isWritePtr( encryptedKeyLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iSessionKeyContext ) );
	assert( isHandleRangeValid( iExportContext ) );
	assert( isHandleRangeValid( iAuxContext ) );
	assert( ( auxInfo == NULL && auxInfoLength == 0 ) || \
			isReadPtr( auxInfo,  auxInfoLength ) );

	/* Get the export parameters */
	status = krnlSendMessage( iExportContext, IMESSAGE_GETATTRIBUTE,
							  &keyAgreeAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* Export the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, bufPtr, bufSize, NULL, 0, 
						  iSessionKeyContext, iExportContext, iAuxContext );
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

int importConventionalKey( const void *encryptedKey, 
						   const int encryptedKeyLength,
						   const CRYPT_CONTEXT iSessionKeyContext,
						   const CRYPT_CONTEXT iImportContext,
						   const KEYEX_TYPE keyexType )
	{
	CRYPT_ALGO_TYPE importAlgo;
	CRYPT_MODE_TYPE importMode;
	MECHANISM_WRAP_INFO mechanismInfo;
	const READKEK_FUNCTION readKeyexFunction = getReadKekFunction( keyexType );
	QUERY_INFO queryInfo;
	MESSAGE_DATA msgData;
	STREAM stream;
	int status;

	assert( isReadPtr( encryptedKey, encryptedKeyLength ) );
	assert( isHandleRangeValid( iSessionKeyContext ) );
	assert( isHandleRangeValid( iImportContext ) );
	assert( keyexType > KEYEX_NONE && keyexType < KEYEX_LAST );

	/* Make sure that the requested key exchange format is available */
	if( readKeyexFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Get the import parameters */
	krnlSendMessage( iImportContext, IMESSAGE_GETATTRIBUTE, &importAlgo,
					 CRYPT_CTXINFO_ALGO );
	status = krnlSendMessage( iImportContext, IMESSAGE_GETATTRIBUTE,
							  &importMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM2 : status );

	/* Read and check the encrypted key record and make sure that we'll be 
	   using the correct type of encryption context to decrypt it */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, encryptedKey, encryptedKeyLength );
	status = readKeyexFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) && \
		( importAlgo != queryInfo.cryptAlgo || \
		  importMode != queryInfo.cryptMode ) )
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
	if( needsIV( importMode ) && importAlgo != CRYPT_ALGO_RC4 )
		{
		setMessageData( &msgData, queryInfo.iv, queryInfo.ivLength );
		krnlSendMessage( iImportContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_IV );
		}
	setMechanismWrapInfo( &mechanismInfo,
						  ( BYTE * ) encryptedKey + queryInfo.dataStart, 
						  queryInfo.dataLength, NULL, 0, 
						  iSessionKeyContext, iImportContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_ENC_CMS );
	krnlSendMessage( iImportContext, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	clearMechanismInfo( &mechanismInfo );
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );

	return( status );
	}

/* Import a public-key encrypted session key */

int importPublicKey( const void *encryptedKey, const int encryptedKeyLength,
					 const CRYPT_CONTEXT iSessionKeyContext,
					 const CRYPT_CONTEXT iImportContext,
					 CRYPT_CONTEXT *iReturnedContext, 
					 const KEYEX_TYPE keyexType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	const READKEYTRANS_FUNCTION readKetransFunction = getReadKeytransFunction( keyexType );
	QUERY_INFO queryInfo;
	MESSAGE_DATA msgData;
	STREAM stream;
	int compareType, status;

	assert( isReadPtr( encryptedKey, encryptedKeyLength ) );
	assert( ( keyexType == KEYEX_PGP && \
			  iSessionKeyContext == CRYPT_UNUSED ) || \
			( keyexType != KEYEX_PGP && \
			  isHandleRangeValid( iSessionKeyContext ) ) );
	assert( isHandleRangeValid( iImportContext ) );
	assert( ( keyexType == KEYEX_PGP && \
			  isWritePtr( iReturnedContext, sizeof( CRYPT_CONTEXT ) ) ) || \
			( keyexType != KEYEX_PGP && iReturnedContext == NULL ) );
	assert( keyexType > KEYEX_NONE && keyexType < KEYEX_LAST );

	/* Make sure that the requested key exchange format is available */
	if( readKetransFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Read and check the encrypted key record */
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, encryptedKey, encryptedKeyLength );
	status = readKetransFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Make sure that we've been given the correct key */
	setMessageData( &msgData, queryInfo.keyID, queryInfo.keyIDlength );
	switch( keyexType )
		{
		case KEYEX_CMS:
			setMessageData( &msgData, \
					( BYTE * ) encryptedKey + queryInfo.iAndSStart, \
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
			return( CRYPT_ERROR_FAILED );
		}
	status = krnlSendMessage( iImportContext, IMESSAGE_COMPARE, &msgData, 
							  compareType );
	if( cryptStatusError( status ) && \
		compareType == MESSAGE_COMPARE_KEYID_OPENPGP )
		{
		/* Some broken PGP implementations put PGP 2.x IDs in packets marked 
		   as OpenPGP packets, so if we were doing a check for an OpenPGP ID 
		   and it failed, fall back to a PGP 2.x one */
		status = krnlSendMessage( iImportContext, IMESSAGE_COMPARE, 
								  &msgData, MESSAGE_COMPARE_KEYID_PGP );
		}
	if( cryptStatusError( status ) )
		{
		/* A failed comparison is reported as a generic CRYPT_ERROR, convert 
		   it into a wrong-key error */
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( CRYPT_ERROR_WRONGKEY );
		}

	/* Decrypt the encrypted key and load it into the context */
	if( keyexType != KEYEX_PGP )
		{
		setMechanismWrapInfo( &mechanismInfo,
							  ( BYTE * ) encryptedKey + queryInfo.dataStart, 
							  queryInfo.dataLength, NULL, 0, 
							  iSessionKeyContext, iImportContext, CRYPT_UNUSED );
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
		setMechanismWrapInfo( &mechanismInfo, 
							  ( BYTE * ) encryptedKey + queryInfo.dataStart,
							  queryInfo.dataLength, NULL, 0, 
							  CRYPT_UNUSED, iImportContext, CRYPT_UNUSED );
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

int importKeyAgreeKey( const void *encryptedKey, const int encryptedKeyLength,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iImportContext )
	{
	CRYPT_CONTEXT iLocalContext;
	QUERY_INFO queryInfo;
	STREAM stream;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int status;

	assert( isReadPtr( encryptedKey, encryptedKeyMaxLength ) );
	assert( isWritePtr( encryptedKeyLength, sizeof( int ) ) );
	assert( isHandleRangeValid( iSessionKeyContext ) );
	assert( isHandleRangeValid( iImportContext ) );

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
	   which generates the responder's x value and key ID.  This is a horrible
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
	krnlSendNotifier( iLocalContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the shared secret value and load it into the session key
	   context.  We use a fixed 64-bit salt and explicitly set the iteration
	   count to make sure that it isn't upset if the user changes config
	   options */
	status = krnlSendMessage( iImportContext, IMESSAGE_CTX_DECRYPT,
							  buffer, CRYPT_UNUSED );
	if( !cryptStatusError( status ) )
		{
		static const BYTE *salt = ( BYTE * ) "\x00\x00\x00\x00\x00\x00\x00\x00";
		static const int iterations = 100;
		MESSAGE_DATA msgData;

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
