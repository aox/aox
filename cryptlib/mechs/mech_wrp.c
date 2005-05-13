/****************************************************************************
*																			*
*						  cryptlib Mechanism Routines						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INC_ALL
  #include "crypt.h"
  #include "pgp.h"
  #include "asn1.h"
  #include "misc_rw.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "../misc/asn1.h"
  #include "../misc/misc_rw.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "misc/asn1.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* Decrypt a PGP MPI */

static int pgpReadDecryptMPI( STREAM *stream,
							  const CRYPT_CONTEXT iCryptContext )
	{
	int bitLength, length, status;

	/* Read the MPI length and make sure that it's in order */
	bitLength = readUint16( stream );
	length = bitsToBytes( bitLength );
	if( length < 1 || length > PGP_MAX_MPISIZE || \
		length > sMemDataLeft( stream ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Decrypt the payload */
	status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_DECRYPT,
							  sMemBufPtr( stream ), length );
	if( cryptStatusError( status ) )
		return( sSetError( stream, status ) );
	return( sSkip( stream, length ) );
	}

/* Checksum a PGP MPI */

static unsigned int pgpChecksumMPI( STREAM *stream )
	{
	unsigned int checkSum;
	int bitLength, length;

	/* Read the MPI length and make sure that it's in order */
	bitLength = readUint16( stream );
	length = bitsToBytes( bitLength );
	if( length < 1 || length > PGP_MAX_MPISIZE || \
		length > sMemDataLeft( stream ) )
		{
		/* There's a problem with the stream, return a dummy value.  This
		   means that the checksum will (almost certainly) fail, but in
		   any case the stream error state will cause it to fail too */
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( 0 );
		}

	/* Calculate the MPI checksum */
	checkSum = ( ( BYTE ) ( bitLength >> 8 ) ) + ( ( BYTE ) bitLength );
	while( length-- )
		checkSum += sgetc( stream );
	return( checkSum );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/****************************************************************************
*																			*
*							Key Wrap/Unwrap Mechanisms						*
*																			*
****************************************************************************/

/* Perform private key wrapping/unwrapping.  There are several variations of
   this that are handled through common private key wrap mechanism
   functions */

typedef enum { PRIVATEKEY_WRAP_NORMAL,
			   PRIVATEKEY_WRAP_OLD } PRIVATEKEY_WRAP_TYPE;

static int privateKeyWrap( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo,
						   const PRIVATEKEY_WRAP_TYPE type )
	{
	int exportPrivateKeyData( STREAM *stream,
							  const CRYPT_CONTEXT iCryptContext,
							  const KEYFORMAT_TYPE type );
	const KEYFORMAT_TYPE formatType = ( type == PRIVATEKEY_WRAP_NORMAL ) ? \
								KEYFORMAT_PRIVATE : KEYFORMAT_PRIVATE_OLD;
	STREAM stream;
	int payloadSize, blockSize, padSize, status;

	UNUSED( dummy );

	assert( type == PRIVATEKEY_WRAP_NORMAL || \
			type == PRIVATEKEY_WRAP_OLD );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Get the payload details */
	sMemOpen( &stream, NULL, 0 );
	status = exportPrivateKeyData( &stream, mechanismInfo->keyContext,
								   formatType );
	payloadSize = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_GETATTRIBUTE, &blockSize,
								  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	padSize = roundUp( payloadSize + 1, blockSize ) - payloadSize;

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		return( CRYPT_OK );
		}

	/* Write the private key data, PKCS #5-pad it, and encrypt it */
	sMemOpen( &stream, mechanismInfo->wrappedData,
			  mechanismInfo->wrappedDataLength );
	status = exportPrivateKeyData( &stream, mechanismInfo->keyContext,
								   formatType );
	if( cryptStatusOK( status ) )
		{
		BYTE startSample[ 8 ], endSample[ 8 ];
		const void *endSamplePtr = ( BYTE * ) mechanismInfo->wrappedData + \
								   stell( &stream ) - 8;
		int i;

		/* Sample the first and last 8 bytes of data so that we can check 
		   that they really have been encrypted */
		memcpy( startSample, mechanismInfo->wrappedData, 8 );
		memcpy( endSample, endSamplePtr, 8 );

		/* Add the PKCS #5 padding and encrypt the data */
		for( i = 0; i < padSize; i++ )
			sputc( &stream, padSize );
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData,
								  payloadSize + padSize );

		/* Make sure that the original data samples differ from the final 
		   data */
		if( cryptStatusOK( status ) && \
			( !memcmp( startSample, mechanismInfo->wrappedData, 8 ) || \
			  !memcmp( endSample, endSamplePtr, 8 ) ) )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_FAILED;
			}
		zeroise( startSample, 8 );
		zeroise( endSample, 8 );
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		zeroise( mechanismInfo->wrappedData, 
				 mechanismInfo->wrappedDataLength );
		}
	else
		{
		sMemDisconnect( &stream );
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		}

	return( status );
	}

static int privateKeyUnwrap( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo,
							 const PRIVATEKEY_WRAP_TYPE type )
	{
	int importPrivateKeyData( STREAM *stream,
							  const CRYPT_CONTEXT iCryptContext,
							  const KEYFORMAT_TYPE type );
	const KEYFORMAT_TYPE formatType = ( type == PRIVATEKEY_WRAP_NORMAL ) ? \
								KEYFORMAT_PRIVATE : KEYFORMAT_PRIVATE;
	void *buffer;
	int blockSize, status;

	UNUSED( dummy );

	assert( type == PRIVATEKEY_WRAP_NORMAL || \
			type == PRIVATEKEY_WRAP_OLD );

	/* Make sure that the data has a sane length and is a multiple of the 
	   cipher block size (since we force the use of CBC mode we know it has 
	   to have this property) */
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_GETATTRIBUTE, &blockSize,
							  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( ( mechanismInfo->wrappedDataLength >= MAX_PRIVATE_KEYSIZE ) || \
		( mechanismInfo->wrappedDataLength & ( blockSize - 1 ) ) )
		return( CRYPT_ERROR_BADDATA );

	/* Copy the encrypted private key data to a temporary buffer, decrypt it,
	   and read it into the context.  If we get a corrupted-data error then
	   it's far more likely to be because we decrypted with the wrong key
	   than because any data was corrupted, so we convert it to a wrong-key
	   error */
	if( ( status = krnlMemalloc( &buffer, \
							mechanismInfo->wrappedDataLength ) ) != CRYPT_OK )
		return( status );
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_CTX_DECRYPT, buffer,
							  mechanismInfo->wrappedDataLength );
	if( cryptStatusOK( status ) )
		{
		int length;

		length = getObjectLength( buffer, mechanismInfo->wrappedDataLength );
		if( cryptStatusError( length ) )
			status = ( length == CRYPT_ERROR_BADDATA ) ? \
					 CRYPT_ERROR_WRONGKEY : length;
		else
			{
			const BYTE *bufPtr = ( BYTE * ) buffer + length;
			const int padSize = blockSize - ( length & ( blockSize - 1 ) );
			int i;

			/* Check that the PKCS #5 padding is as expected.  Performing the
			   check this way is the reverse of the way it's usually done
			   because we already know the payload size from the ASN.1 and
			   can use this to determine the expected padding value and thus
			   check that the end of the encrypted data hasn't been subject
			   to a bit-flipping attack.  For example for RSA private keys
			   the end of the data is:

				[ INTEGER u ][ INTEGER keySize ][ padding ]

			   where the keySize is encoded as a 4-byte value and the padding
			   is 1-8 bytes.  In order to flip the low bits of u, there's a
			   5/8 chance that either the keySize value (checked in the RSA
			   read code) or padding will be messed up, both of which will be
			   detected (in addition the RSA key load checks try and verify u
			   when the key is loaded).  For DLP keys the end of the data is:

				[ INTEGER x ][ padding ]

			   for which bit flipping is rather harder to detect since 7/8 of
			   the time the following block won't be affected, however the
			   DLP key load checks also verify x when the key is loaded.
			   The padding checking is effectively free and helps make Klima-
			   Rosa type attacks harder */
			for( i = 0; i < padSize; i++ )
				if( bufPtr[ i ] != padSize )
					status = CRYPT_ERROR_BADDATA;
			}
		}
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		status = importPrivateKeyData( &stream, mechanismInfo->keyContext,
									   formatType );
		if( status == CRYPT_ERROR_BADDATA )
			status = CRYPT_ERROR_WRONGKEY;
		sMemDisconnect( &stream );
		}
	zeroise( buffer, mechanismInfo->wrappedDataLength );
	krnlMemfree( &buffer );

	return( status );
	}

int exportPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( privateKeyWrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_NORMAL ) );
	}

int importPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( privateKeyUnwrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_NORMAL ) );
	}

int exportPrivateKeyPKCS8( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( privateKeyWrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_OLD ) );
	}

int importPrivateKeyPKCS8( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( privateKeyUnwrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_OLD ) );
	}

#ifdef USE_PGPKEYS 

/* Perform PGP private key wrapping/unwrapping.  There are several variations
   of this that are handled through common private key wrap mechanism
   functions */

typedef enum { PRIVATEKEY_WRAP_PGP,
			   PRIVATEKEY_WRAP_OPENPGP } PRIVATEKEY_WRAP_PGP_TYPE;

static int privateKeyUnwrapPGP( void *dummy,
								MECHANISM_WRAP_INFO *mechanismInfo,
								const PRIVATEKEY_WRAP_PGP_TYPE type )
	{
	int importPrivateKeyData( STREAM *stream, 
							  const CRYPT_CONTEXT iCryptContext,
							  const KEYFORMAT_TYPE type );
	CRYPT_ALGO_TYPE cryptAlgo;
	STREAM stream;
	void *buffer;
	int status;

	UNUSED( dummy );

	assert( type == PRIVATEKEY_WRAP_PGP || type == PRIVATEKEY_WRAP_OPENPGP );

	/* Get various algorithm parameters */
	status = krnlSendMessage( mechanismInfo->keyContext,
							  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the encrypted private key data to a temporary buffer, decrypt it,
	   and read it into the context.  If we get a corrupted-data error then
	   it's far more likely to be because we decrypted with the wrong key
	   than because any data was corrupted, so we convert it to a wrong-key
	   error */
	if( ( status = krnlMemalloc( &buffer, MAX_PRIVATE_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	if( type == PRIVATEKEY_WRAP_OPENPGP )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_DECRYPT, buffer,
								  mechanismInfo->wrappedDataLength );
	else
		{
		/* The PGP 2.x wrap encrypts only the MPI data rather than the
		   entire private key record, so we have to read and then decrypt
		   each component separately */
		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		status = pgpReadDecryptMPI( &stream,			/* d or x */
									mechanismInfo->wrapContext );
		if( cryptStatusOK( status ) && cryptAlgo == CRYPT_ALGO_RSA )
			{
			status = pgpReadDecryptMPI( &stream,		/* p */
										mechanismInfo->wrapContext );
			if( cryptStatusOK( status ) )
				status = pgpReadDecryptMPI( &stream,	/* q */
											mechanismInfo->wrapContext );
			if( cryptStatusOK( status ) )
				status = pgpReadDecryptMPI( &stream,	/* u */
											mechanismInfo->wrapContext );
			}
		sMemDisconnect( &stream );
		}
	if( cryptStatusOK( status ) )
		{
		unsigned int checkSum, packetChecksum;
		int streamPos;

		/* Checksum the MPI payload to make sure that the decrypt went OK */
		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		checkSum = pgpChecksumMPI( &stream );		/* d or x */
		if( cryptAlgo == CRYPT_ALGO_RSA )
			{
			checkSum += pgpChecksumMPI( &stream );	/* p */
			checkSum += pgpChecksumMPI( &stream );	/* q */
			checkSum += pgpChecksumMPI( &stream );	/* u */
			}
		streamPos = stell( &stream );
		if( mechanismInfo->wrappedDataLength - streamPos == 20 )
			{
			HASHFUNCTION hashFunction;
			BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
			int hashSize;

			/* There's too much data present for it to be a simple checksum,
			   it must be an SHA-1 hash */
			getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
			hashFunction( NULL, hashValue, buffer, streamPos, HASH_ALL );
			if( mechanismInfo->wrappedDataLength - streamPos != hashSize || \
				memcmp( hashValue, sMemBufPtr( &stream ), hashSize ) )
				status = CRYPT_ERROR_WRONGKEY;
			}
		else
			{
			packetChecksum = readUint16( &stream );
			if( checkSum != packetChecksum )
				status = CRYPT_ERROR_WRONGKEY;
			}
		if( !sStatusOK( &stream ) )
			status = CRYPT_ERROR_WRONGKEY;
		sMemDisconnect( &stream );
		}
	if( cryptStatusOK( status ) )
		{
		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		status = importPrivateKeyData( &stream, mechanismInfo->keyContext,
									   KEYFORMAT_PGP );
		if( status == CRYPT_ERROR_BADDATA )
			status = CRYPT_ERROR_WRONGKEY;
		sMemDisconnect( &stream );
		}
	zeroise( buffer, mechanismInfo->wrappedDataLength );
	krnlMemfree( &buffer );

	return( status );
	}

int importPrivateKeyPGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( privateKeyUnwrapPGP( dummy, mechanismInfo,
								 PRIVATEKEY_WRAP_PGP ) );
	}

int importPrivateKeyOpenPGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( privateKeyUnwrapPGP( dummy, mechanismInfo,
								 PRIVATEKEY_WRAP_OPENPGP ) );
	}
#endif /* USE_PGPKEYS */
