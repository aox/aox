/****************************************************************************
*																			*
*						  cryptlib Mechanism Routines						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "pgp.h"
  #include "asn1_rw.h"
  #include "asn1s_rw.h"
#else
  #include "envelope/pgp.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

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

static int adjustPKCS1Data( BYTE *outData, const BYTE *inData,
							const int inLength, const int keySize )
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

#ifdef USE_PKCS12

/* Concantenate enough copies of input data together to fill an output
   buffer */

static void expandData( BYTE *outPtr, const int outLen, const BYTE *inPtr,
						const int inLen )
	{
	int remainder = outLen;

	while( remainder > 0 )
		{
		const int bytesToCopy = min( inLen, remainder );

		memcpy( outPtr, inPtr, bytesToCopy );
		outPtr += bytesToCopy;
		remainder -= bytesToCopy;
		}
	}
#endif /* USE_PKCS12 */

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* PGP checksums the PKCS #1 wrapped data (even though this doesn't really
   serve any purpose), the following routine calculates this checksum and
   either appends it to the data or checks it against the stored value */

static BOOLEAN pgpCalculateChecksum( BYTE *dataPtr, const int length,
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

static int pgpExtractKey( CRYPT_CONTEXT *iCryptContext, STREAM *stream,
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

	/* Create the context and load the key into it */
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

/* Decrypt a PGP MPI */

static int pgpReadDecryptMPI( STREAM *stream,
							  const CRYPT_CONTEXT iCryptContext )
	{
	int bitLength, length, status;

	/* Read the MPI length and make sure that it's in order */
	bitLength = ( sgetc( stream ) << 8 ) | sgetc( stream );
	length = bitsToBytes( bitLength );
	if( length < 1 || length > PGP_MAX_MPISIZE || \
		length > sMemDataLeft( stream ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Decrypt the payload */
	status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_DECRYPT,
							  sMemBufPtr( stream ), length );
	if( cryptStatusError( status ) )
		{
		sSetError( stream, status );
		return( status );
		}
	return( sSkip( stream, length ) );
	}

/* Checksum a PGP MPI */

static unsigned int pgpChecksumMPI( STREAM *stream )
	{
	unsigned int checkSum;
	int bitLength, length;

	/* Read the MPI length and make sure that it's in order */
	bitLength = ( sgetc( stream ) << 8 ) | sgetc( stream );
	length = bitsToBytes( bitLength );
	if( length < 1 || length > PGP_MAX_MPISIZE || \
		length > sMemDataLeft( stream ) )
		{
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
*							Key Derivation Mechanisms						*
*																			*
****************************************************************************/

/* HMAC-based PRF used for PKCS #5 v2 and TLS */

#define HMAC_DATASIZE		64

static void prfInit( HASHFUNCTION hashFunction, void *hashState,
					 const int hashSize, void *processedKey,
					 int *processedKeyLength, const void *key,
					 const int keyLength )
	{
	BYTE hashBuffer[ HMAC_DATASIZE ], *keyPtr = processedKey;
	int i;

	/* If the key size is larger than tha SHA data size, reduce it to the
	   SHA hash size before processing it (yuck.  You're required to do this
	   though) */
	if( keyLength > HMAC_DATASIZE )
		{
		/* Hash the user key down to the hash size and use the hashed form of
		   the key */
		hashFunction( NULL, processedKey, ( void * ) key, keyLength, HASH_ALL );
		*processedKeyLength = hashSize;
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( processedKey, key, keyLength );
		*processedKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XORed
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, HMAC_DATASIZE );
	for( i = 0; i < *processedKeyLength; i++ )
		hashBuffer[ i ] ^= *keyPtr++;
	hashFunction( hashState, NULL, hashBuffer, HMAC_DATASIZE, HASH_START );
	zeroise( hashBuffer, HMAC_DATASIZE );
	}

static void prfEnd( HASHFUNCTION hashFunction, void *hashState,
					const int hashSize, void *hash,
					const void *processedKey, const int processedKeyLength )
	{
	BYTE hashBuffer[ HMAC_DATASIZE ], digestBuffer[ CRYPT_MAX_HASHSIZE ];
	int i;

	/* Complete the inner hash and extract the digest */
	hashFunction( hashState, digestBuffer, NULL, 0, HASH_END );

	/* Perform the outer hash using the zero-padded key XORed with the opad
	   value followed by the digest from the inner hash */
	memset( hashBuffer, HMAC_OPAD, HMAC_DATASIZE );
	memcpy( hashBuffer, processedKey, processedKeyLength );
	for( i = 0; i < processedKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_OPAD;
	hashFunction( hashState, NULL, hashBuffer, HMAC_DATASIZE, HASH_START );
	zeroise( hashBuffer, HMAC_DATASIZE );
	hashFunction( hashState, hash, digestBuffer, hashSize, HASH_END );
	zeroise( digestBuffer, CRYPT_MAX_HASHSIZE );
	}

/* Perform PKCS #5 v2 derivation */

int derivePKCS5( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	const CRYPT_ALGO_TYPE hmacAlgo = \
				( mechanismInfo->hashAlgo == CRYPT_ALGO_HMAC_MD5 ) ? \
					CRYPT_ALGO_MD5 : \
				( mechanismInfo->hashAlgo == CRYPT_ALGO_HMAC_RIPEMD160 ) ? \
					CRYPT_ALGO_RIPEMD160 : CRYPT_ALGO_SHA;
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo, initialHashInfo;
	BYTE processedKey[ HMAC_DATASIZE ], block[ CRYPT_MAX_HASHSIZE ];
	BYTE countBuffer[ 4 ];
	BYTE *dataOutPtr = mechanismInfo->dataOut;
	int hashSize, keyIndex, processedKeyLength, blockCount = 1;

	UNUSED( dummy );

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5100 bytes of key) so we only change the
	   last byte */
	memset( countBuffer, 0, 4 );

	/* Initialise the HMAC information with the user key.  Although the user
	   has specified the algorithm in terms of an HMAC, we're synthesising it
	   from the underlying hash algorithm since this allows us to perform the
	   PRF setup once and reuse it for any future hashing since it's
	   constant */
	getHashParameters( hmacAlgo, &hashFunction, &hashSize );
	prfInit( hashFunction, initialHashInfo, hashSize,
			 processedKey, &processedKeyLength,
			 mechanismInfo->dataIn, mechanismInfo->dataInLength );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += hashSize, dataOutPtr += hashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > hashSize ) ? \
			hashSize : mechanismInfo->dataOutLength - keyIndex;
		int i;

		/* Calculate HMAC( salt || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
		hashFunction( hashInfo, NULL, mechanismInfo->salt,
					  mechanismInfo->saltLength, HASH_CONTINUE );
		hashFunction( hashInfo, NULL, countBuffer, 4, HASH_CONTINUE );
		prfEnd( hashFunction, hashInfo, hashSize, block, processedKey,
				processedKeyLength );
		memcpy( dataOutPtr, block, noKeyBytes );

		/* Calculate HMAC( T1 ) ^ HMAC( T1 ) ^ ... HMAC( Tc ) */
		for( i = 0; i < mechanismInfo->iterations - 1; i++ )
			{
			int j;

			/* Generate the PRF output for the current iteration */
			memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
			hashFunction( hashInfo, NULL, block, hashSize, HASH_CONTINUE );
			prfEnd( hashFunction, hashInfo, hashSize, block, processedKey,
					processedKeyLength );

			/* Xor the new PRF output into the existing PRF output */
			for( j = 0; j < noKeyBytes; j++ )
				dataOutPtr[ j ] ^= block[ j ];
			}
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( initialHashInfo, sizeof( HASHINFO ) );
	zeroise( processedKey, HMAC_DATASIZE );
	zeroise( block, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

#ifdef USE_PKCS12

/* Perform PKCS #12 derivation */

#define P12_BLOCKSIZE	64

int derivePKCS12( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	BYTE p12_DSP[ P12_BLOCKSIZE + P12_BLOCKSIZE + ( P12_BLOCKSIZE * 3 ) ];
	BYTE p12_Ai[ P12_BLOCKSIZE ], p12_B[ P12_BLOCKSIZE ];
	BYTE *bmpPtr = p12_DSP + P12_BLOCKSIZE + P12_BLOCKSIZE;
	BYTE *dataOutPtr = mechanismInfo->dataOut;
	const BYTE *dataInPtr = mechanismInfo->dataIn;
	const BYTE *saltPtr = mechanismInfo->salt;
	const int bmpLen = ( mechanismInfo->dataInLength * 2 ) + 2;
	const int p12_PLen = ( mechanismInfo->dataInLength <= 30 ) ? \
							P12_BLOCKSIZE : \
						 ( mechanismInfo->dataInLength <= 62 ) ? \
							( P12_BLOCKSIZE * 2 ) : ( P12_BLOCKSIZE * 3 );
	int hashSize, keyIndex, i;

	UNUSED( dummy );

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Set up the diversifier in the first P12_BLOCKSIZE bytes, the salt in
	   the next P12_BLOCKSIZE bytes, and the password as a Unicode null-
	   terminated string in the final bytes */
	for( i = 0; i < P12_BLOCKSIZE; i++ )
		p12_DSP[ i ] = saltPtr[ 0 ];
	expandData( p12_DSP + P12_BLOCKSIZE, P12_BLOCKSIZE, saltPtr + 1,
				mechanismInfo->saltLength - 1 );
	for( i = 0; i < mechanismInfo->dataInLength; i++ )
		{
		*bmpPtr++ = '\0';
		*bmpPtr++ = dataInPtr[ i ];
		}
	*bmpPtr++ = '\0';
	*bmpPtr++ = '\0';
	expandData( p12_DSP + ( P12_BLOCKSIZE * 2 ) + bmpLen, p12_PLen - bmpLen,
				p12_DSP + ( P12_BLOCKSIZE * 2 ), bmpLen );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += hashSize, dataOutPtr += hashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > hashSize ) ? \
			hashSize : mechanismInfo->dataOutLength - keyIndex;
		BYTE *p12_DSPj;

		/* Hash the keying material the required number of times to obtain the
		   output value */
		hashFunction( NULL, p12_Ai, p12_DSP,
					  P12_BLOCKSIZE + P12_BLOCKSIZE + p12_PLen, HASH_ALL );
		for( i = 1; i < mechanismInfo->iterations; i++ )
			hashFunction( NULL, p12_Ai, p12_Ai, hashSize, HASH_ALL );
		memcpy( dataOutPtr, p12_Ai, noKeyBytes );
		if( noKeyBytes <= hashSize)
			break;

		/* Update the input keying material for the next iteration */
		expandData( p12_B, P12_BLOCKSIZE, p12_Ai, hashSize );
		for( p12_DSPj = p12_DSP + P12_BLOCKSIZE; 
			 p12_DSPj < p12_DSP + ( 2 * P12_BLOCKSIZE ) + p12_PLen; 
			 p12_DSPj += P12_BLOCKSIZE )
			{
			int dspIndex = P12_BLOCKSIZE - 1, bIndex = P12_BLOCKSIZE - 1;
			int carry = 1;

			/* Ij = (Ij + B + 1) mod 2^BLOCKSIZE */
			for( dspIndex = P12_BLOCKSIZE - 1, bIndex = P12_BLOCKSIZE - 1;
				 dspIndex >= 0; dspIndex--, bIndex-- )
				{
				const int value = p12_DSPj[ dspIndex ] + p12_B[ bIndex ] + carry;
				p12_DSPj[ dspIndex ] = value & 0xFF;
				carry = value >> 8;
				}
			}
		}
	zeroise( p12_DSP, P12_BLOCKSIZE + P12_BLOCKSIZE + ( P12_BLOCKSIZE * 3 ) );
	zeroise( p12_Ai, P12_BLOCKSIZE );
	zeroise( p12_B, P12_BLOCKSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_PKCS12 */

#ifdef USE_SSL

/* Perform SSL key derivation */

int deriveSSL( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION md5HashFunction, shaHashFunction;
	HASHINFO hashInfo;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], counterData[ 16 ];
	int md5HashSize, shaHashSize, counter = 0, keyIndex;

	UNUSED( dummy );

	getHashParameters( CRYPT_ALGO_MD5, &md5HashFunction, &md5HashSize );
	getHashParameters( CRYPT_ALGO_SHA, &shaHashFunction, &shaHashSize );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += md5HashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > md5HashSize ) ? \
			md5HashSize : mechanismInfo->dataOutLength - keyIndex;
		int i;

		/* Set up the counter data */
		for( i = 0; i <= counter; i++ )
			counterData[ i ] = 'A' + counter;
		counter++;

		/* Calculate SHA1( 'A'/'BB'/'CCC'/... || keyData || salt ) */
		shaHashFunction( hashInfo, NULL, counterData, counter, HASH_START );
		shaHashFunction( hashInfo, NULL, mechanismInfo->dataIn,
						 mechanismInfo->dataInLength, HASH_CONTINUE );
		shaHashFunction( hashInfo, hash, mechanismInfo->salt,
						 mechanismInfo->saltLength, HASH_END );

		/* Calculate MD5( keyData || SHA1-hash ) */
		md5HashFunction( hashInfo, NULL, mechanismInfo->dataIn,
						 mechanismInfo->dataInLength, HASH_START );
		md5HashFunction( hashInfo, hash, hash, shaHashSize, HASH_END );

		/* Copy the result to the output */
		memcpy( ( BYTE * )( mechanismInfo->dataOut ) + keyIndex, hash, noKeyBytes );
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( hash, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Perform TLS key derivation (this is the function described as PRF() in the
   TLS spec) */

int deriveTLS( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION md5HashFunction, shaHashFunction;
	HASHINFO md5HashInfo, md5InitialHashInfo, md5AnHashInfo;
	HASHINFO shaHashInfo, shaInitialHashInfo, shaAnHashInfo;
	BYTE md5ProcessedKey[ HMAC_DATASIZE ], shaProcessedKey[ HMAC_DATASIZE ];
	BYTE md5A[ CRYPT_MAX_HASHSIZE ], shaA[ CRYPT_MAX_HASHSIZE ];
	BYTE md5Hash[ CRYPT_MAX_HASHSIZE ], shaHash[ CRYPT_MAX_HASHSIZE ];
	BYTE *md5DataOutPtr = mechanismInfo->dataOut;
	BYTE *shaDataOutPtr = mechanismInfo->dataOut;
	const BYTE *dataEndPtr = ( BYTE * ) mechanismInfo->dataOut + \
							 mechanismInfo->dataOutLength;
	const void *s1, *s2;
	const int sLen = ( mechanismInfo->dataInLength + 1 ) / 2;
	int md5ProcessedKeyLength, shaProcessedKeyLength;
	int md5HashSize, shaHashSize, keyIndex;

	UNUSED( dummy );

	getHashParameters( CRYPT_ALGO_MD5, &md5HashFunction, &md5HashSize );
	getHashParameters( CRYPT_ALGO_SHA, &shaHashFunction, &shaHashSize );

	/* Find the start of the two halves of the keying info used for the
	   HMAC'ing.  The size of each half is given by
	   ceil( dataInLength / 2 ), so there's a one-byte overlap if the input
	   is an odd number of bytes long */
	s1 = mechanismInfo->dataIn;
	s2 = ( BYTE * ) mechanismInfo->dataIn + ( mechanismInfo->dataInLength - sLen );

	/* The two hash functions have different block sizes that would require
	   complex buffering to handle leftover bytes from SHA-1, a simpler
	   method is to zero the output data block and XOR in the values from
	   each hash mechanism using separate output location indices for MD5 and
	   SHA-1 */
	memset( mechanismInfo->dataOut, 0, mechanismInfo->dataOutLength );

	/* Initialise the MD5 and SHA-1 information with the keying info.  These
	   are reused for any future hashing since they're constant */
	prfInit( md5HashFunction, md5InitialHashInfo, md5HashSize,
			 md5ProcessedKey, &md5ProcessedKeyLength, s1, sLen );
	prfInit( shaHashFunction, shaInitialHashInfo, shaHashSize,
			 shaProcessedKey, &shaProcessedKeyLength, s2, sLen );

	/* Calculate A1 = HMAC( salt ) */
	memcpy( md5HashInfo, md5InitialHashInfo, sizeof( HASHINFO ) );
	md5HashFunction( md5HashInfo, NULL, mechanismInfo->salt,
					 mechanismInfo->saltLength, HASH_CONTINUE );
	prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5A,
			md5ProcessedKey, md5ProcessedKeyLength );
	memcpy( shaHashInfo, shaInitialHashInfo, sizeof( HASHINFO ) );
	shaHashFunction( shaHashInfo, NULL, mechanismInfo->salt,
					 mechanismInfo->saltLength, HASH_CONTINUE );
	prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaA,
			shaProcessedKey, shaProcessedKeyLength );

	/* Produce enough blocks of output to fill the key.  We use the MD5 hash
	   size as the loop increment since this produces the smaller output
	   block */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength;
		 keyIndex += md5HashSize )
		{
		const int md5NoKeyBytes = \
					min( ( dataEndPtr - md5DataOutPtr ), md5HashSize );
		const int shaNoKeyBytes = \
					min( ( dataEndPtr - shaDataOutPtr ), shaHashSize );
		int i;		/* Spurious ()'s needed for broken compilers */

		/* Calculate HMAC( An || salt ) */
		memcpy( md5HashInfo, md5InitialHashInfo, sizeof( HASHINFO ) );
		md5HashFunction( md5HashInfo, NULL, md5A, md5HashSize, HASH_CONTINUE );
		memcpy( md5AnHashInfo, md5HashInfo, sizeof( HASHINFO ) );
		md5HashFunction( md5HashInfo, NULL, mechanismInfo->salt,
						 mechanismInfo->saltLength, HASH_CONTINUE );
		prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5Hash,
				md5ProcessedKey, md5ProcessedKeyLength );
		memcpy( shaHashInfo, shaInitialHashInfo, sizeof( HASHINFO ) );
		shaHashFunction( shaHashInfo, NULL, shaA, shaHashSize, HASH_CONTINUE );
		memcpy( shaAnHashInfo, shaHashInfo, sizeof( HASHINFO ) );
		shaHashFunction( shaHashInfo, NULL, mechanismInfo->salt,
						 mechanismInfo->saltLength, HASH_CONTINUE );
		prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaHash,
				shaProcessedKey, shaProcessedKeyLength );

		/* Calculate An+1 = HMAC( An ) */
		memcpy( md5HashInfo, md5AnHashInfo, sizeof( HASHINFO ) );
		prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5A,
				md5ProcessedKey, md5ProcessedKeyLength );
		memcpy( shaHashInfo, shaAnHashInfo, sizeof( HASHINFO ) );
		prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaA,
				shaProcessedKey, shaProcessedKeyLength );

		/* Copy the result to the output */
		for( i = 0; i < md5NoKeyBytes; i++ )
			md5DataOutPtr[ i ] ^= md5Hash[ i ];
		for( i = 0; i < shaNoKeyBytes; i++ )
			shaDataOutPtr[ i ] ^= shaHash[ i ];
		md5DataOutPtr += md5NoKeyBytes;
		shaDataOutPtr += shaNoKeyBytes;
		}
	zeroise( md5HashInfo, sizeof( HASHINFO ) );
	zeroise( md5InitialHashInfo, sizeof( HASHINFO ) );
	zeroise( md5AnHashInfo, sizeof( HASHINFO ) );
	zeroise( shaHashInfo, sizeof( HASHINFO ) );
	zeroise( shaInitialHashInfo, sizeof( HASHINFO ) );
	zeroise( shaAnHashInfo, sizeof( HASHINFO ) );
	zeroise( md5ProcessedKey, HMAC_DATASIZE );
	zeroise( shaProcessedKey, HMAC_DATASIZE );
	zeroise( md5A, CRYPT_MAX_HASHSIZE );
	zeroise( shaA, CRYPT_MAX_HASHSIZE );
	zeroise( md5Hash, CRYPT_MAX_HASHSIZE );
	zeroise( shaHash, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_SSL */

#ifdef USE_CMP

/* Perform CMP/Entrust key derivation */

int deriveCMP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	int hashSize, iterations = mechanismInfo->iterations - 1;

	UNUSED( dummy );

	/* Calculate SHA1( password || salt ) */
	getHashParameters( mechanismInfo->hashAlgo, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, mechanismInfo->dataIn,
				  mechanismInfo->dataInLength, HASH_START );
	hashFunction( hashInfo, mechanismInfo->dataOut, mechanismInfo->salt,
				  mechanismInfo->saltLength, HASH_END );

	/* Iterate the hashing the remaining number of times */
	while( iterations-- )
		hashFunction( NULL, mechanismInfo->dataOut, mechanismInfo->dataOut,
					  hashSize, HASH_ALL );
	zeroise( hashInfo, sizeof( HASHINFO ) );

	return( CRYPT_OK );
	}
#endif /* USE_CMP */

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* Perform OpenPGP S2K key derivation */

int derivePGP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE hashedKey[ CRYPT_MAX_KEYSIZE ];
	long byteCount = ( long ) mechanismInfo->iterations << 6;
	long secondByteCount = 0;
	int hashSize;

	getHashParameters( mechanismInfo->hashAlgo, &hashFunction, &hashSize );

	/* If it's a non-iterated hash or the count won't allow even a single
	   pass over the 8-byte salt and password, adjust it to make sure that 
	   we run at least one full iteration */
	if( byteCount < PGP_SALTSIZE + mechanismInfo->dataInLength )
		byteCount = PGP_SALTSIZE + mechanismInfo->dataInLength;

	/* If the hash output size is less than the required key size, run a
	   second round of hashing after the first one to provide the required
	   amount of keying material */
	if( hashSize < mechanismInfo->dataOutLength )
		secondByteCount = byteCount;

	/* Repeatedly hash the salt and password until we've met the byte count */
	hashFunction( hashInfo, NULL, mechanismInfo->salt,
				  mechanismInfo->saltLength, HASH_START );
	byteCount -= mechanismInfo->saltLength;
	do
		{
		if( byteCount <= mechanismInfo->dataInLength )
			hashFunction( hashInfo, hashedKey, mechanismInfo->dataIn,
						  byteCount, HASH_END );
		else
			hashFunction( hashInfo, NULL, mechanismInfo->dataIn,
						  mechanismInfo->dataInLength, HASH_CONTINUE );
		byteCount -= mechanismInfo->dataInLength;
		if( byteCount <= 0 )
			continue;
		if( byteCount <= mechanismInfo->saltLength )
			hashFunction( hashInfo, hashedKey, mechanismInfo->salt,
						  byteCount, HASH_END );
		else
			hashFunction( hashInfo, NULL, mechanismInfo->salt,
						  mechanismInfo->saltLength, HASH_CONTINUE );
		byteCount -= mechanismInfo->saltLength;
		}
	while( byteCount > 0 );
	if( secondByteCount )
		{
		/* Perform a second round of hashing, preloading the hash with a
		   single zero byte */
		hashFunction( hashInfo, NULL, ( const BYTE * ) "\x00", 1,
					  HASH_START );
		while( secondByteCount )
			{
			if( secondByteCount <= mechanismInfo->saltLength )
				hashFunction( hashInfo, hashedKey + hashSize,
							  mechanismInfo->salt, secondByteCount,
							  HASH_END );
			else
				hashFunction( hashInfo, NULL, mechanismInfo->salt,
							  mechanismInfo->saltLength, HASH_CONTINUE );
			secondByteCount -= mechanismInfo->saltLength;
			if( secondByteCount <= 0 )
				continue;
			if( secondByteCount <= mechanismInfo->dataInLength )
				hashFunction( hashInfo, hashedKey + hashSize,
							  mechanismInfo->dataIn, secondByteCount,
							  HASH_END );
			else
				hashFunction( hashInfo, NULL, mechanismInfo->dataIn,
							  mechanismInfo->dataInLength, HASH_CONTINUE );
			secondByteCount -= mechanismInfo->dataInLength;
			}
		}
	memcpy( mechanismInfo->dataOut, hashedKey, mechanismInfo->dataOutLength );
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( hashedKey, CRYPT_MAX_KEYSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/****************************************************************************
*																			*
*								Signature Mechanisms 						*
*																			*
****************************************************************************/

/* Perform PKCS #1 signing/sig.checking */

int signPKCS1( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], preSigData[ CRYPT_MAX_PKCSIZE ];
	BOOLEAN useSideChannelProtection;
	int payloadSize, hashSize, length, i, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( ( mechanismInfo->signature == NULL && \
			  mechanismInfo->signatureLength == 0 ) || \
			( mechanismInfo->signatureLength >= 64 ) );

	/* Clear the return value */
	if( mechanismInfo->signature != NULL )
		memset( mechanismInfo->signature, 0,
				mechanismInfo->signatureLength );

	/* Get various algorithm and config parameters */
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE, &hashAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->signContext,
								  IMESSAGE_GETATTRIBUTE, &length,
								  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->signContext, 
								  IMESSAGE_GETATTRIBUTE, 
								  &useSideChannelProtection,
								  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		mechanismInfo->signatureLength = length;
		return( CRYPT_OK );
		}

	/* Get the hash data and determine the encoded payload size */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	payloadSize = sizeofMessageDigest( hashAlgo, hashSize );

	/* Encode the payload using the format given in PKCS #1, which for
	   signed data is [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] */
	sMemOpen( &stream, mechanismInfo->signature, length );
	sputc( &stream, 0 );
	sputc( &stream, 1 );
	for( i = 0; i < length - ( payloadSize + 3 ); i++ )
		sputc( &stream, 0xFF );
	sputc( &stream, 0 );
	writeMessageDigest( &stream, hashAlgo, hash, hashSize );
	sMemDisconnect( &stream );
	if( useSideChannelProtection )
		/* Remember a copy of the signature data for later so we can check it
		   against the recovered signature data */
		memcpy( preSigData, mechanismInfo->signature, length );

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGN, mechanismInfo->signature,
							  length );
	if( cryptStatusError( status ) )
		return( status );
	mechanismInfo->signatureLength = length;

	/* If we're using side-channel protection, check that the signature 
	   verifies */
	if( useSideChannelProtection )
		{
		BYTE recoveredSignature[ CRYPT_MAX_PKCSIZE ];

		/* Make sure that the recovered signature data matches what we 
		   signed, unless we're in the unlikely situation that the key
		   isn't valid for sig.checking.  The rationale behind this 
		   operation is covered (in great detail) in lib_rsa.c */
		memcpy( recoveredSignature, mechanismInfo->signature, length );
		status = krnlSendMessage( mechanismInfo->signContext,
								  IMESSAGE_CTX_SIGCHECK, recoveredSignature,
								  length );
		if( status != CRYPT_ERROR_PERMISSION && \
			status != CRYPT_ERROR_NOTAVAIL && \
			memcmp( preSigData, recoveredSignature, length ) )
			{
			assert( NOTREACHED );
			zeroise( mechanismInfo->signature, length );
			mechanismInfo->signatureLength = 0;
			return( CRYPT_ERROR_FAILED );
			}
		zeroise( recoveredSignature, length );
		zeroise( preSigData, length );
		}

	return( CRYPT_OK );
	}

int sigcheckPKCS1( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo, recoveredHashAlgo;
	STREAM stream;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE ];
	BYTE hash[ CRYPT_MAX_HASHSIZE ], recoveredHash[ CRYPT_MAX_HASHSIZE ];
	int length, hashSize, recoveredHashSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->signatureLength >= 60 );

	/* Get various algorithm parameters */
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE, &hashAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_HASHVALUE );
		hashSize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Format the input data as required for the sig check to work */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_GETATTRIBUTE, &length,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		status = adjustPKCS1Data( decryptedSignature,
					mechanismInfo->signature, mechanismInfo->signatureLength,
					length );
	if( cryptStatusError( status ) )
		return( status );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGCHECK, decryptedSignature,
							  length );
	if( cryptStatusError( status ) )
		return( status );

	/* Undo the PKCS #1 padding, which for signed data is
	   [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ].  Note that some
	   implementations may have bignum code that zero-truncates the result,
	   which produces a CRYPT_ERROR_BADDATA error, it's the responsibility
	   of the lower-level crypto layer to reformat the data to return a
	   correctly-formatted result if necessary */
	sMemConnect( &stream, decryptedSignature, length );
	if( sgetc( &stream ) || sgetc( &stream ) != 1 )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		int ch = 1, i;

		for( i = 0; i < length - 3; i++ )
			if( ( ch = sgetc( &stream ) ) != 0xFF )
				break;
		if( ch != 0 || \
			cryptStatusError( \
				readMessageDigest( &stream, &recoveredHashAlgo,
								   recoveredHash, &recoveredHashSize ) ) )
			status = CRYPT_ERROR_BADDATA;
		}
	sMemDisconnect( &stream );
	zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, make sure that the two hash values match */
	if( hashAlgo != recoveredHashAlgo || hashSize != recoveredHashSize || \
		memcmp( hash, recoveredHash, recoveredHashSize ) )
		status = CRYPT_ERROR_SIGNATURE;

	/* Clean up */
	zeroise( hash, hashSize );
	zeroise( recoveredHash, recoveredHashSize );
	return( status );
	}

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
	int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData );
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
		if( cryptStatusError( pgpAlgoID ) )
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

	/* Encode the payload using the format given in PKCS #1, which for
	   encrypted data is [ 0 ][ 2 ][ nonzero random padding ][ 0 ][ payload ].
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
	BYTE decryptedData[ CRYPT_MAX_PKCSIZE ];
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

	/* Undo the PKCS #1 padding, which for encrypted data is
	   [ 0 ][ 2 ][ random nonzero padding ][ 0 ][ payload ] with a minimum of
	   8 bytes padding.  Note that some implementations may have bignum code
	   that zero-truncates the result, producing a CRYPT_ERROR_BADDATA error, 
	   it's the responsibility of the lower-level crypto layer to reformat 
	   the data to return a correctly-formatted result if necessary */
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
	int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData );
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

	/* Format the key block: [length][check value][key][padding], copy the
	   payload in at the last possible moment, then perform two passes of
	   encryption retaining the IV from the first pass for the second pass */
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
		STREAM stream;

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
		STREAM stream;
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
			packetChecksum = ( sgetc( &stream ) << 8 ) | sgetc( &stream );
			if( checkSum != packetChecksum )
				status = CRYPT_ERROR_WRONGKEY;
			}
		}
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

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
