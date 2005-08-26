/****************************************************************************
*																			*
*					cryptlib Encryption Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2004						*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INC_ALL
  #include "crypt.h"
  #include "pgp.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "../misc/asn1.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* Prototypes for kernel-internal access functions */

int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The length of the input data for PKCS #1 transformations is usually
   determined by the key size, however sometimes we can be passed data that
   has been zero-padded (for example data coming from an ASN.1 INTEGER in
   which the high bit is a sign bit) making it longer than the key size, or
   that has leading zero byte(s), making it shorter than the key size.  The
   best place to handle this is somewhat uncertain, it's an encoding issue
   so it probably shouldn't be visible to the raw crypto routines, but
   putting it at the mechanism layer removes the algorithm-independence of
   that layer, and putting it at the mid-level sign/key-exchange routine
   layer both removes the algorithm-independence and requires duplication of
   the code for signatures and encryption.  The best place to put it seems to
   be at the mechanism layer, since an encoding issue really shouldn't be
   visible at the crypto layer, and because it would require duplicating the
   handling every time a new PKC implementation is plugged in.

   The intent of the size adjustment is to make the data size match the key
   length.  If it's longer, we try to strip leading zero bytes.  If it's
   shorter, we pad it with zero bytes to match the key size.  The result is
   either the data adjusted to match the key size, or CRYPT_ERROR_BADDATA if
   this isn't possible */

int adjustPKCS1Data( BYTE *outData, const BYTE *inData, const int inLength, 
					 const int keySize )
	{
	int length = inLength;

	assert( outData != inData );

	/* If it's of the correct size, exit */
	if( length == keySize )
		{
		memcpy( outData, inData, keySize );
		return( CRYPT_OK );
		}

	/* If it's suspiciously short, don't try and process it */
	if( length < 56 )
		return( CRYPT_ERROR_BADDATA );

	/* If it's too long, try and strip leading zero bytes.  If it's still too
	   long, complain */
	while( length > keySize && !*inData )
		{
		length--;
		inData++;
		}
	if( length > keySize )
		return( CRYPT_ERROR_BADDATA );

	/* We've adjusted the size to account for zero-padding during encoding,
	   now we have to move the data into a fixed-length format to match the
	   key size.  To do this we copy the payload into the output buffer with
	   enough leading-zero bytes to bring the total size up to the key size */
	memset( outData, 0, keySize );
	memcpy( outData + ( keySize - length ), inData, length );

	return( CRYPT_OK );
	}

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* PGP checksums the PKCS #1 wrapped data (even though this doesn't really
   serve any purpose), the following routine calculates this checksum and
   either appends it to the data or checks it against the stored value */

BOOLEAN pgpCalculateChecksum( BYTE *dataPtr, const int length,
							  const BOOLEAN writeChecksum )
	{
	BYTE *checksumPtr = dataPtr + length;
	int checksum = 0, i;

	for( i = 0; i < length; i++ )
		checksum += dataPtr[ i ];
	if( !writeChecksum )
		{
		int storedChecksum = mgetWord( checksumPtr );

		return( storedChecksum == checksum );
		}
	mputWord( checksumPtr, checksum );
	return( TRUE );
	}

/* PGP includes the session key information alongside the encrypted key so
   it's not really possible to import the key into a context in the
   conventional sense.  Instead, the import code has to create the context
   as part of the import process and return it to the caller.  This is ugly,
   but less ugly than doing a raw import and handling the key directly in
   the calling code */

int pgpExtractKey( CRYPT_CONTEXT *iCryptContext, STREAM *stream,
				   const int length )
	{
	CRYPT_ALGO_TYPE cryptAlgo = CRYPT_ALGO_NONE;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;
	int status;

	/* Get the session key algorithm.  We delay checking the algorithm ID
	   until after the checksum calculation to reduce the chance of being
	   used as an oracle */
	cryptAlgo = pgpToCryptlibAlgo( sgetc( stream ), PGP_ALGOCLASS_CRYPT );

	/* Checksum the session key.  This is actually superfluous since any
	   decryption error will be caught by corrupted PKCS #1 padding with
	   vastly higher probability than this simple checksum, but we do it
	   anyway because PGP does it too */
	if( !pgpCalculateChecksum( sMemBufPtr( stream ), length, FALSE ) )
		return( CRYPT_ERROR_BADDATA );

	/* Make sure that the algorithm ID is valid.  We only perform the check 
	   at this point because this returns a different error code than the 
	   usual bad-data, we want to be absolutely sure that the problem really 
	   is an unknown algorithm and not the result of scrambled decrypted 
	   data */
	if( cryptAlgo == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Create the context ready to have the key loaded into it */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &mode, CRYPT_CTXINFO_MODE );
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/****************************************************************************
*																			*
*							Key Wrap/Unwrap Mechanisms						*
*																			*
****************************************************************************/

/* Perform PKCS #1 wrapping/unwrapping.  There are several variations of
   this that are handled through common PKCS #1 mechanism functions */

typedef enum { PKCS1_WRAP_NORMAL, PKCS1_WRAP_RAW, PKCS1_WRAP_PGP } PKCS1_WRAP_TYPE;

static int pkcs1Wrap( MECHANISM_WRAP_INFO *mechanismInfo,
					  const PKCS1_WRAP_TYPE type )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	RESOURCE_DATA msgData;
	BYTE *wrappedData = mechanismInfo->wrappedData, *dataPtr;
	int payloadSize, length, padSize, status;
#ifdef USE_PGP
	int pgpAlgoID;
#endif /* USE_PGP */

	assert( type == PKCS1_WRAP_NORMAL || type == PKCS1_WRAP_RAW || \
			type == PKCS1_WRAP_PGP );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Get various algorithm parameters */
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_GETATTRIBUTE, &length,
								  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		/* Determine how long the encrypted value will be.  In the case of
		   Elgamal it's just an estimate since it can change by up to two
		   bytes depending on whether the values have the high bit set or
		   not, which requires zero-padding of the ASN.1-encoded integers.
		   This is rather nasty because it means we can't tell how large an
		   encrypted value will be without actually creating it.  The 10-byte
		   length at the start is for the ASN.1 SEQUENCE (4) and 2 *
		   INTEGER (2*3) encoding */
		mechanismInfo->wrappedDataLength = ( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? \
										   10 + ( 2 * ( length + 1 ) ) : length;
		return( CRYPT_OK );
		}

	/* Get the payload details, either as data passed in by the caller or
	   from the key context */
	if( type == PKCS1_WRAP_RAW )
		payloadSize = mechanismInfo->keyDataLength;
	else
		{
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_GETATTRIBUTE, &payloadSize,
								  CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
#ifdef USE_PGP
	if( type == PKCS1_WRAP_PGP )
		{
		CRYPT_ALGO_TYPE sessionKeyAlgo;

		/* PGP includes an additional algorithm specifier and checksum with
		   the wrapped key so we adjust the length to take this into
		   account */
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_GETATTRIBUTE, &sessionKeyAlgo,
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		pgpAlgoID = cryptlibToPgpAlgo( sessionKeyAlgo );
		if( pgpAlgoID == PGP_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		payloadSize += 3;
		}
#endif /* USE_PGP */

	/* Determine PKCS #1 padding parameters and make sure that the key is 
	   long enough to encrypt the payload.  PKCS #1 requires that the 
	   maximum payload size be 11 bytes less than the length (to give a 
	   minimum of 8 bytes of random padding) */
	padSize = length - ( payloadSize + 3 );
	if( payloadSize > length - 11 )
		return( CRYPT_ERROR_OVERFLOW );

	/* Encode the payload using the PKCS #1 format:
	   
		[ 0 ][ 2 ][ nonzero random padding ][ 0 ][ payload ]

	   Note that the random padding is a nice place for a subliminal channel,
	   especially with large public key sizes where you can communicate more
	   information in the padding than in the payload */
	wrappedData[ 0 ] = 0;
	wrappedData[ 1 ] = 2;
	setMessageData( &msgData, wrappedData + 2, padSize );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NZ );
	wrappedData[ 2 + padSize ] = 0;
	if( cryptStatusError( status ) )
		{
		zeroise( wrappedData, length );
		return( status );
		}

	/* Copy the payload in at the last possible moment, then encrypt it */
	dataPtr = wrappedData + 2 + padSize + 1;
	switch( type )
		{
		case PKCS1_WRAP_NORMAL:
			status = extractKeyData( mechanismInfo->keyContext, dataPtr );
			break;

		case PKCS1_WRAP_RAW:
			memcpy( dataPtr, mechanismInfo->keyData, payloadSize );
			break;

#ifdef USE_PGP
		case PKCS1_WRAP_PGP:
			*dataPtr++ = pgpAlgoID;
			status = extractKeyData( mechanismInfo->keyContext, dataPtr );
			pgpCalculateChecksum( dataPtr, payloadSize - 3, TRUE );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo == CRYPT_ALGO_RSA )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT, wrappedData, length );
	else
		{
		DLP_PARAMS dlpParams;

		assert( cryptAlgo == CRYPT_ALGO_ELGAMAL );

		/* For DLP-based PKC's the output length isn't the same as the key
		   size so we adjust the return length as required */
		setDLPParams( &dlpParams, wrappedData, length, wrappedData,
					  mechanismInfo->wrappedDataLength );
		if( type == PKCS1_WRAP_PGP )
			dlpParams.formatType = CRYPT_FORMAT_PGP;
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT, &dlpParams,
								  sizeof( DLP_PARAMS ) );
		if( cryptStatusOK( status ) )
			length = dlpParams.outLen;
		}
	if( cryptStatusError( status ) )
		{
		zeroise( wrappedData, length );
		return( status );
		}
	mechanismInfo->wrappedDataLength = length;

	return( CRYPT_OK );
	}

static int pkcs1Unwrap( MECHANISM_WRAP_INFO *mechanismInfo,
						const PKCS1_WRAP_TYPE type )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	STREAM stream;
	RESOURCE_DATA msgData;
	BYTE decryptedData[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( type == PKCS1_WRAP_NORMAL || type == PKCS1_WRAP_RAW || \
			type == PKCS1_WRAP_PGP );

	/* Clear the return value if we're returning raw data */
	if( type == PKCS1_WRAP_RAW )
		memset( mechanismInfo->keyData, 0, mechanismInfo->keyDataLength );

	/* Get various algorithm parameters */
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_GETATTRIBUTE, &length,
								  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Decrypt the data */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		status = adjustPKCS1Data( decryptedData, mechanismInfo->wrappedData,
								  mechanismInfo->wrappedDataLength, length );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( mechanismInfo->wrapContext,
									  IMESSAGE_CTX_DECRYPT, decryptedData,
									  length );
		}
	else
		{
		DLP_PARAMS dlpParams;

		assert( cryptAlgo == CRYPT_ALGO_ELGAMAL );

		setDLPParams( &dlpParams, mechanismInfo->wrappedData,
					  mechanismInfo->wrappedDataLength, decryptedData,
					  CRYPT_MAX_PKCSIZE );
		if( type == PKCS1_WRAP_PGP )
			dlpParams.formatType = CRYPT_FORMAT_PGP;
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_DECRYPT, &dlpParams,
								  sizeof( DLP_PARAMS ) );
		length = dlpParams.outLen;
		}
	if( cryptStatusOK( status ) && \
		( length < 11 + bitsToBytes( MIN_KEYSIZE_BITS ) || \
		  length > mechanismInfo->wrappedDataLength ) )
		/* PKCS #1 padding requires at least 11 bytes of padding data, if 
		   there isn't this much present we can't have a valid payload */
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* Undo the PKCS #1 padding:

		[ 0 ][ 2 ][ random nonzero padding ][ 0 ][ payload ]
	
	   with a minimum of 8 bytes padding.  Note that some implementations 
	   may have bignum code that zero-truncates the result, producing a 
	   CRYPT_ERROR_BADDATA error, it's the responsibility of the lower-level 
	   crypto layer to reformat the data to return a correctly-formatted 
	   result if necessary */
	sMemConnect( &stream, decryptedData, length );
	if( sgetc( &stream ) || sgetc( &stream ) != 2 )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		int ch = 1, i;

		for( i = 0; i < length - 3; i++ )
			if( ( ch = sgetc( &stream ) ) == 0 )
				break;
		if( ch != 0 || i < 8 )
			status = CRYPT_ERROR_BADDATA;
		else
			length -= 2 + i + 1;	/* [ 0 ][ 2 ] + padding + [ 0 ] */
		}
	if( cryptStatusOK( status ) && length < bitsToBytes( MIN_KEYSIZE_BITS ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* Return the result to the caller or load it into a context as a key */
	switch( type )
		{
#ifdef USE_PGP
		case PKCS1_WRAP_PGP:
			/* PGP includes extra wrapping around the key, so we have to
			   process that before we can load it */
			length -= 3;	/* Subtract extra wrapping length */
			status = pgpExtractKey( &mechanismInfo->keyContext, &stream,
									length );
			if( cryptStatusError( status ) )
				break;
			/* Fall through */
#endif /* USE_PGP */

		case PKCS1_WRAP_NORMAL:
			/* Load the decrypted keying information into the session key
			   context */
			setMessageData( &msgData, sMemBufPtr( &stream ), length );
			status = krnlSendMessage( mechanismInfo->keyContext,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_KEY );
			if( status == CRYPT_ARGERROR_STR1 || \
				status == CRYPT_ARGERROR_NUM1 )
				/* If there was an error with the key value or size, convert
				   the return value into something more appropriate */
				status = CRYPT_ERROR_BADDATA;
			break;

		case PKCS1_WRAP_RAW:
			/* Return the result to the caller */
			if( length > mechanismInfo->keyDataLength )
				status = CRYPT_ERROR_OVERFLOW;
			else
				{
				memcpy( mechanismInfo->keyData, sMemBufPtr( &stream ),
						length );
				mechanismInfo->keyDataLength = length;
				}
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR );
		}
	sMemDisconnect( &stream );
	zeroise( decryptedData, CRYPT_MAX_PKCSIZE );

	return( status );
	}

int exportPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( pkcs1Wrap( mechanismInfo,
					   ( mechanismInfo->keyContext == CRYPT_UNUSED ) ? \
					   PKCS1_WRAP_RAW : PKCS1_WRAP_NORMAL ) );
	}

int importPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( pkcs1Unwrap( mechanismInfo,
						 ( mechanismInfo->keyData != NULL ) ? \
						 PKCS1_WRAP_RAW : PKCS1_WRAP_NORMAL ) );
	}

#ifdef USE_PGP

int exportPKCS1PGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( pkcs1Wrap( mechanismInfo, PKCS1_WRAP_PGP ) );
	}

int importPKCS1PGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	return( pkcs1Unwrap( mechanismInfo, PKCS1_WRAP_PGP ) );
	}
#endif /* USE_PGP */

/* Perform CMS data wrapping.  Returns an error code or the number of output
   bytes */

#define CMS_KEYBLOCK_HEADERSIZE		4

static int cmsGetPadSize( const CRYPT_CONTEXT iExportContext,
						  const int payloadSize )
	{
	int blockSize, totalSize, status;

	status = krnlSendMessage( iExportContext, IMESSAGE_GETATTRIBUTE,
							  &blockSize, CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine the padding size, which is the amount of padding required to
	   bring the total data size up to a multiple of the block size with a
	   minimum size of two blocks */
	totalSize = roundUp( payloadSize, blockSize );
	if( totalSize < blockSize * 2 )
		totalSize = blockSize * 2;

	return( totalSize - payloadSize );
	}

int exportCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	BYTE *keyBlockPtr = ( BYTE * ) mechanismInfo->wrappedData;
	int payloadSize, padSize, status = CRYPT_OK;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( ( mechanismInfo->wrappedData == NULL && \
			  mechanismInfo->wrappedDataLength == 0 ) || \
			( mechanismInfo->wrappedDataLength >= 16 && \
			  mechanismInfo->wrappedDataLength >= mechanismInfo->keyDataLength ) );
	assert( mechanismInfo->keyData == NULL );
	assert( mechanismInfo->keyDataLength == 0 );
	assert( mechanismInfo->keyContext != CRYPT_UNUSED );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Get the payload details, either as data passed in by the caller or
	   from the key context */
	if( mechanismInfo->keyContext == CRYPT_UNUSED )
		payloadSize = mechanismInfo->keyDataLength;
	else
		{
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_GETATTRIBUTE, &payloadSize,
								  CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	payloadSize += CMS_KEYBLOCK_HEADERSIZE;
	padSize = cmsGetPadSize( mechanismInfo->wrapContext, payloadSize );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		return( CRYPT_OK );
		}

	/* Pad the payload out with a random nonce if required */
	if( padSize > 0 )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, keyBlockPtr + payloadSize, padSize );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Format the key block:

		[ length ][ check value ][ key ][ padding ]
		
	   then copy the payload in at the last possible moment and perform two 
	   passes of encryption, retaining the IV from the first pass for the 
	   second pass */
	keyBlockPtr[ 0 ] = payloadSize - CMS_KEYBLOCK_HEADERSIZE;
	if( mechanismInfo->keyContext != CRYPT_UNUSED )
		status = extractKeyData( mechanismInfo->keyContext,
								 keyBlockPtr + CMS_KEYBLOCK_HEADERSIZE );
	else
		memcpy( keyBlockPtr + CMS_KEYBLOCK_HEADERSIZE,
				mechanismInfo->keyData, payloadSize );
	keyBlockPtr[ 1 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE ] ^ 0xFF;
	keyBlockPtr[ 2 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE + 1 ] ^ 0xFF;
	keyBlockPtr[ 3 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE + 2 ] ^ 0xFF;
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData,
								  payloadSize + padSize );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData,
								  payloadSize + padSize );
	if( cryptStatusError( status ) )
		{
		zeroise( mechanismInfo->wrappedData,
				 mechanismInfo->wrappedDataLength );
		return( status );
		}
	mechanismInfo->wrappedDataLength = payloadSize + padSize;

	return( CRYPT_OK );
	}

/* Perform CMS data unwrapping */

int importCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_KEYSIZE + 16 ], ivBuffer[ CRYPT_MAX_IVSIZE ];
	BYTE *dataEndPtr = buffer + mechanismInfo->wrappedDataLength;
	int blockSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->wrappedData != NULL );
	assert( mechanismInfo->wrappedDataLength >= 16 );
	assert( mechanismInfo->keyData == NULL );
	assert( mechanismInfo->keyDataLength == 0 );
	assert( mechanismInfo->keyContext != CRYPT_UNUSED );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Make sure that the data is a multiple of the cipher block size */
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_GETATTRIBUTE, &blockSize,
							  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( mechanismInfo->wrappedDataLength & ( blockSize - 1 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Save the current IV for the inner decryption */
	setMessageData( &msgData, ivBuffer, CRYPT_MAX_IVSIZE );
	krnlSendMessage( mechanismInfo->wrapContext, IMESSAGE_GETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_IV );

	/* Using the n-1'th ciphertext block as the new IV, decrypt the n'th block.
	   Then, using the decrypted n'th ciphertext block as the IV, decrypt the
	   remainder of the ciphertext blocks */
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	setMessageData( &msgData, dataEndPtr - 2 * blockSize, blockSize );
	krnlSendMessage( mechanismInfo->wrapContext,
					 IMESSAGE_SETATTRIBUTE_S, &msgData, CRYPT_CTXINFO_IV );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_CTX_DECRYPT, dataEndPtr - blockSize,
							  blockSize );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, dataEndPtr - blockSize, blockSize );
		krnlSendMessage( mechanismInfo->wrapContext,
						 IMESSAGE_SETATTRIBUTE_S, &msgData, CRYPT_CTXINFO_IV );
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_DECRYPT, buffer,
								  mechanismInfo->wrappedDataLength - blockSize );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, CRYPT_MAX_KEYSIZE + 16 );
		return( status );
		}

	/* Using the original IV, decrypt the inner data */
	setMessageData( &msgData, ivBuffer, blockSize );
	krnlSendMessage( mechanismInfo->wrapContext, IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_IV );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_CTX_DECRYPT, buffer,
							  mechanismInfo->wrappedDataLength );

	/* Make sure that everything is in order and load the decrypted keying
	   information into the session key context */
	if( cryptStatusOK( status ) )
		{
		if( buffer[ 0 ] < bitsToBytes( MIN_KEYSIZE_BITS ) || \
			buffer[ 0 ] > bitsToBytes( MAX_KEYSIZE_BITS ) )
			status = CRYPT_ERROR_BADDATA;
		if( buffer[ 1 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE ] ^ 0xFF ) || \
			buffer[ 2 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE + 1 ] ^ 0xFF ) || \
			buffer[ 3 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE + 2 ] ^ 0xFF ) )
			status = CRYPT_ERROR_WRONGKEY;
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, buffer + CMS_KEYBLOCK_HEADERSIZE,
						buffer[ 0 ] );
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( status == CRYPT_ARGERROR_STR1 || status == CRYPT_ARGERROR_NUM1 )
			/* If there was an error with the key value or size, convert the
			   return value into something more appropriate */
			status = CRYPT_ERROR_BADDATA;
		}
	zeroise( buffer, CRYPT_MAX_KEYSIZE + 16 );

	return( status );
	}
